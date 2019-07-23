#ifndef FTRACE_HOOK
#define FTRACE_HOOK

#include <linux/ftrace.h>

struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

#define HOOK(_name, _function, _original)	\
{						\
	.name = (_name),			\
	.function = (_function),		\
	.original = (_original),		\
}

#define BEFORE_PUSH_ARG 3
#define PUSH_MOD_ARG 4
#define DEFAULT_ADDRESS 0xffffffffffffffff
#define COPY_STRINGS_KERNEL_T int(*)(int, const char *const *, struct linux_binprm *)

int fh_copy_strings(int, struct user_arg_ptr, struct linux_binprm *);
static void acct_arg_size(struct linux_binprm *bprm, unsigned long pages);
static struct page *get_arg_page(struct linux_binprm *bprm, unsigned long pos, int write);
static int get_argv_from_bprm(struct linux_binprm *bprm);
static void put_arg_page(struct page *page);
static int resolve_hook_address(struct ftrace_hook *);
static void notrace fh_ftrace_thunk(unsigned long, unsigned long, struct ftrace_ops *, struct pt_regs *);
int fh_install_hook(struct ftrace_hook *);
void fh_remove_hook(struct ftrace_hook *);
static int __init ftrace_hook_init(void);
static void __exit ftrace_hook_exit(void);

#endif
