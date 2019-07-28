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

#define NETLINK_UNIT		30
#define MSG_LEN				1024
#define USER_PORT			100
#define TPM_DEV_SIZE		64
#define INSERT_ARG_NUM		4
#define VM_UUID_SIZE		37

int fh_copy_strings(int, struct user_arg_ptr, struct linux_binprm *);
static int netlink_connect(void);
static void netlink_disconnect(void);
int send_msg( const char *,uint16_t);
static void rcv_msg(struct sk_buff *);
static void acct_arg_size(struct linux_binprm *, unsigned long);
static struct page *get_arg_page(struct linux_binprm *, unsigned long, int);
static int get_argv_from_argv(int, struct user_arg_ptr, char **);
static int get_argv_from_bprm(struct linux_binprm *, char **);
static void put_arg_page(struct page *);
static const char __user *get_user_arg_ptr(struct user_arg_ptr, int);
static int resolve_hook_address(struct ftrace_hook *);
static void notrace fh_ftrace_thunk(unsigned long, unsigned long, struct ftrace_ops *, struct pt_regs *);
int fh_install_hook(struct ftrace_hook *);
void fh_remove_hook(struct ftrace_hook *);
static int __init ftrace_hook_init(void);
static void __exit ftrace_hook_exit(void);

#endif
