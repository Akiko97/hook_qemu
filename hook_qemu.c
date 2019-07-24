#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <linux/binfmts.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>

#include "hook_qemu.h"

static unsigned long hook_address = DEFAULT_ADDRESS;
module_param(hook_address, ulong, 0644);
MODULE_PARM_DESC(hook_address, "address of function copy_strings");

int (*real_copy_strings)(int argc, struct user_arg_ptr argv,
		struct linux_binprm *bprm);
int (*real_copy_strings_kernel)(int argc, const char *const *__argv,
		struct linux_binprm *bprm);

static unsigned int count = 0;
static struct ftrace_hook hooked_functions[] = {
	HOOK("copy_strings.isra", fh_copy_strings, &real_copy_strings),
};

int fh_copy_strings(int argc, struct user_arg_ptr argv, struct linux_binprm *bprm) {
	int ret;
	if (!strcmp("/usr/bin/qemu-system-x86_64", bprm->filename)) {
		count++;
		if (count == BEFORE_PUSH_ARG) {
			// push modify arg
			char *arg[] = {
				"-tpmdev",
				"passthrough,id=tpm0,path=/dev/vtcm1,cancel-path=/dev/null",
				"-device",
				"tpm-tis,tpmdev=tpm0"
			};
			int arg_c = 4;
			real_copy_strings_kernel(arg_c, (const char * const*)arg, bprm);
			bprm->argc += arg_c;
			printk("hook: filename=%s argc=%d\n", bprm->filename, bprm->argc);
			ret = real_copy_strings(argc, argv, bprm);
			get_argv_from_bprm(bprm);
		}
		else if (count == PUSH_MOD_ARG) {
			count = 0;
			ret = real_copy_strings(argc, argv, bprm);
		}
		else {
			ret = real_copy_strings(argc, argv, bprm);
		}
	}
	else {
		ret = real_copy_strings(argc, argv, bprm);
	}
	return ret;
}

static int get_argv_from_bprm(struct linux_binprm *bprm) {
	int ret = 0;
	unsigned long offset, pos;
	char *kaddr;
	struct page *page;
	char *argv = NULL;
	int i = 0;
	int argc = 0;
	int count = 0;
	argv = vzalloc(PAGE_SIZE);
	if (!bprm || !argv) {
		goto out;
	}
	argc = bprm->argc;
	pos = bprm->p;
	do {
		offset = pos & ~PAGE_MASK;
		page = get_arg_page(bprm, pos, 0);
		if (!page) {
			ret = 0;
			goto out;
		}
		kaddr = kmap_atomic(page);
		for (i = 0; offset < PAGE_SIZE && count < argc  && i < PAGE_SIZE; offset++, pos++) {
			if (kaddr[offset] == '\0') {
				count++;
				pos++;
				printk("argv: %s\n", argv);
				memset(argv, 0, PAGE_SIZE);
				i = 0;
				continue;
			}
			argv[i] = kaddr[offset];
			i++;
		}
		kunmap_atomic(kaddr);
		put_arg_page(page);
	} while (offset == PAGE_SIZE);
	ret = 0;
out:
	vfree(argv);
	return ret;
}

static struct page *get_arg_page(struct linux_binprm *bprm, unsigned long pos, int write) {
	struct page *page;
	int ret;
	unsigned int gup_flags = FOLL_FORCE;
#ifdef CONFIG_STACK_GROWSUP
	if (write) {
		ret = expand_downwards(bprm->vma, pos);
		if (ret < 0) {
			return NULL;
		}
	}
#endif
	if (write) {
		gup_flags |= FOLL_WRITE;
	}
	ret = get_user_pages_remote(current, bprm->mm, pos, 1, gup_flags, &page, NULL, NULL);
	if (ret <= 0) {
		return NULL;
	}
	if (write) {
		acct_arg_size(bprm, vma_pages(bprm->vma));
	}
	return page;
}

static void put_arg_page(struct page *page) {
	put_page(page);
}

static void acct_arg_size(struct linux_binprm *bprm, unsigned long pages) {
	struct mm_struct *mm = current->mm;
	long diff = (long)(pages - bprm->vma_pages);
	if (!mm || !diff) {
		return;
	}
	bprm->vma_pages = pages;
	add_mm_counter(mm, MM_ANONPAGES, diff);
}

static int resolve_hook_address(struct ftrace_hook *hook) {
	hook->address = hook_address;
	if (hook->address == DEFAULT_ADDRESS) {
		printk("No parameters hook_address found! Nuked!");
		return -ENOENT;
    	}
	*((unsigned long*)hook->original) = hook->address;
	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip,
		unsigned long parent_ip,
		struct ftrace_ops *ops,
		struct pt_regs *regs) {
	struct ftrace_hook *hook = container_of(ops,
			struct ftrace_hook,
			ops);
	if (!within_module(parent_ip, THIS_MODULE))
	regs->ip = (unsigned long) hook->function;
}

int fh_install_hook(struct ftrace_hook *hook) {
	int err;
	err = resolve_hook_address(hook);
	if (err)
		return err;
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
			| FTRACE_OPS_FL_IPMODIFY;
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		printk("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}
	err = register_ftrace_function(&hook->ops);
	if (err) {
		printk("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0); 
		return err;
	}
	return 0;
}

void fh_remove_hook(struct ftrace_hook *hook) {
	int err;
	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		printk("unregister_ftrace_function() failed: %d\n", err);
	}
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		printk("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

static int __init ftrace_hook_init(void) {
	int ret;
	ret = fh_install_hook(&(hooked_functions[0]));
	real_copy_strings_kernel = (COPY_STRINGS_KERNEL_T)kallsyms_lookup_name("copy_strings_kernel");
	printk("hook installed with return value %d\n", ret);
	return 0;
}

static void __exit ftrace_hook_exit(void) {
	fh_remove_hook(&(hooked_functions[0]));
	printk("hook removed\n");
}

module_init(ftrace_hook_init);
module_exit(ftrace_hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Silver");
MODULE_DESCRIPTION("hook qemu and add vtcm support");
MODULE_ALIAS("hook_qemu");
