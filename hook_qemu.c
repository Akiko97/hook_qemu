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
#include <linux/slab.h>
#include <net/sock.h>
#include <linux/netlink.h>

#include "hook_qemu.h"

static unsigned long hook_address = DEFAULT_ADDRESS;
module_param(hook_address, ulong, 0644);
MODULE_PARM_DESC(hook_address, "address of function copy_strings");

int (*real_copy_strings)(int argc, struct user_arg_ptr argv, struct linux_binprm *bprm);
int (*real_copy_strings_kernel)(int argc, const char *const *__argv, struct linux_binprm *bprm);

static unsigned int count = 0;

struct sock *nlsk = NULL;
extern struct net init_net;
struct netlink_kernel_cfg cfg = {
	.input = rcv_msg
};

static struct ftrace_hook hooked_functions[] = {
	HOOK("copy_strings.isra", fh_copy_strings, &real_copy_strings),
};

char vtcm_name[TPM_DEV_SIZE];

static int netlink_connect(void) {
	int ret = 0;
	if (!nlsk) {
		nlsk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_UNIT, &cfg);
		if (!nlsk) {
			printk("failed in netlink_kernel_create\n");
			ret = -EINVAL;
			goto out;
		}
		printk("connect netlink!\n");
	}
	else {
		printk("already have a netlink connetion\n");
	}
out:
	return ret;
}

static void netlink_disconnect(void) {
	if (nlsk) {
		sock_release(nlsk->sk_socket);
		netlink_kernel_release(nlsk);
		nlsk = NULL;
		printk("netlink exit!\n");
	}
	else {
		printk("vtcm netlink NULL!\n");
	}
}

int send_msg(const char *pbuf, uint16_t len) {
	int ret = 0;
	struct sk_buff *nl_skb;
	struct nlmsghdr * nlh;

	nl_skb = nlmsg_new(len, GFP_ATOMIC);
	if (!nl_skb) {
		printk("netlink alloc failure\n");
		ret = -1;
		goto out;
	}

	nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_UNIT, len, 0);
	if(!nlh) {
		printk("nlmsg_put failaure\n");
		nlmsg_free(nl_skb);
		ret = -1;
		goto out;
	}

	printk("send data len %d data %s\n", len, pbuf);
	memcpy(nlmsg_data(nlh), pbuf, len);
	ret = netlink_unicast(nlsk, nl_skb, USER_PORT, MSG_DONTWAIT);
out:
	return ret;
}

static void rcv_msg(struct sk_buff *skb) {
	struct nlmsghdr *nlh = NULL;
	int len = 0;
	unsigned char *umsg;

	if (skb->len >= nlmsg_total_size(0)) {
		nlh = nlmsg_hdr(skb);
		umsg = NLMSG_DATA(nlh);
		if (!umsg) {
			printk("netlink rcv msg error!\n");
			goto out;
		}
		len = nlmsg_len(nlh);
		printk("receive message: %s (size %d)\n", umsg, len);
		strcpy(vtcm_name, umsg);
	}
out:
	return;
}

int fh_copy_strings(int argc, struct user_arg_ptr argv, struct linux_binprm *bprm) {
	int ret = 0;
	int i = 0;
	char **args = NULL;
	char *arg[INSERT_ARG_NUM] = {
		"-tpmdev",
		NULL,
		"-device",
		"tpm-tis,tpmdev=tpm0"
	};
	int flag = 0;
	char uuid[VM_UUID_SIZE];
	int c = 0;
	if (!strcmp("/usr/bin/qemu-system-x86_64", bprm->filename)) {
		count++;
		if (count == BEFORE_PUSH_ARG) {
			// start
			args = vzalloc(sizeof(char *) * argc);
			for (i = 0; i < argc; i++) {
				args[i] = vzalloc(PAGE_SIZE);
			}
			ret = get_argv_from_argv(argc, argv, args);
			if (ret < 0) {
				printk("error in get_argv_from_argv\n");
			}
			for (i = 0; i < argc; i++) {
				if (flag) {
					flag = 0;
					memcpy(uuid, args[i], VM_UUID_SIZE);
					break;
				}
				if (!strcmp(args[i], "-uuid")) {
					flag = 1;
				}
			}
			for (i = 0; i < argc; i++) {
				vfree(args[i]);
				args[i] = NULL;
			}
			vfree(args);
			args = NULL;
			// end
			send_msg(uuid, VM_UUID_SIZE);
			while (!strlen(vtcm_name)) {
				msleep(10);
				c++;
				if (c > 99) {
					printk("ERROR: receive db message timeout!\n");
					c = 0;
					goto out;
				}
			}
			arg[1] = vzalloc(PAGE_SIZE);
			memcpy(arg[1], "passthrough,id=tpm0,path=/dev/", 31);
			strcat(arg[1], vtcm_name);
			strcat(arg[1], ",cancel-path=/dev/null");
			memset(vtcm_name, 0, TPM_DEV_SIZE);
			real_copy_strings_kernel(INSERT_ARG_NUM, (const char * const*)arg, bprm);
			vfree(arg[1]);
			arg[1] = NULL;
			bprm->argc += INSERT_ARG_NUM;
			printk("hook: filename=%s argc=%d\n", bprm->filename, bprm->argc);
			ret = real_copy_strings(argc, argv, bprm);
			// start
			args = vzalloc(sizeof(char *) * bprm->argc);
			for (i = 0; i < bprm->argc; i++) {
				args[i] = vzalloc(PAGE_SIZE);
			}
			get_argv_from_bprm(bprm, args);
			for (i = 0; i < bprm->argc; i++) {
				printk("arg %d: %s\n", i, args[i]);
				vfree(args[i]);
				args[i] = NULL;
			}
			vfree(args);
			args = NULL;
			// end
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
out:
	return ret;
}

static int get_argv_from_argv(int argc, struct user_arg_ptr argv, char **args) {
	int ret = 0;
	int i = 0;
	while (i < argc) {
		const char __user *str;
		int len;
		char *s = vzalloc(PAGE_SIZE);
		str = get_user_arg_ptr(argv, i);
		if (IS_ERR(str)) {
			ret = -EFAULT;
			goto out;
		}
		len = strnlen_user(str, MAX_ARG_STRLEN);
		if (!len) {
			ret = -EFAULT;
			goto out;
		}
		if (copy_from_user(s, str, len)) {
			ret = -EFAULT;
			goto out;
		}
		memcpy(args[i++], s, PAGE_SIZE);
		vfree(s);
	}
out:
	return ret;
}

static int get_argv_from_bprm(struct linux_binprm *bprm, char **args) {
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
				//count++;
				pos++;
				//printk("argv: %s\n", argv);
				memcpy(args[count++], argv, PAGE_SIZE);
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
	int ret = 0;
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

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr) {
	const char __user *native;
#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;
		if (get_user(compat, argv.ptr.compat + nr)) {
			return ERR_PTR(-EFAULT);
		}
		return compat_ptr(compat);
	}
#endif
	if (get_user(native, argv.ptr.native + nr)) {
		return ERR_PTR(-EFAULT);
	}
	return native;
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

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops,struct pt_regs *regs) {
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
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
	int ret = 0;
	ret = fh_install_hook(&(hooked_functions[0]));
	real_copy_strings_kernel = (COPY_STRINGS_KERNEL_T)kallsyms_lookup_name("copy_strings_kernel");
	memset(vtcm_name, 0, TPM_DEV_SIZE);
	printk("hook installed with return value %d\n", ret);
	ret = netlink_connect();
	return ret;
}

static void __exit ftrace_hook_exit(void) {
	fh_remove_hook(&(hooked_functions[0]));
	printk("hook removed\n");
	netlink_disconnect();
}

module_init(ftrace_hook_init);
module_exit(ftrace_hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Silver");
MODULE_DESCRIPTION("hook qemu and add vtcm support");
MODULE_ALIAS("hook_qemu");
