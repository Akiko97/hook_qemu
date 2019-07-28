#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
 
#include "data_type.h"
#include "alloc.h"
#include "memfunc.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "ex_module.h"
#include "sys_func.h"
#include "show_vtcm.h"

#include "vtcmdb_struct.h"

int skfd;
struct sockaddr_nl saddr, daddr;

int show_vtcm_init(void *sub_proc, void *para) {
	int ret = 0;

	skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_UNIT);
	if (skfd < 0) {
		perror("create netlink socket error!\n");
		return skfd;
	}
	memset(&saddr, 0, sizeof(saddr));
	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = USER_PORT;
	saddr.nl_groups = 0;
	if (ret = bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr))) {
		perror("bind() error\n");
		close(skfd);
		return ret;
	}
	memset(&daddr, 0, sizeof(daddr));
	daddr.nl_family = AF_NETLINK;
	daddr.nl_pid = 0;
	daddr.nl_groups = 0;

	return ret;
}

int show_vtcm_start(void *sub_proc, void *para) {
	int ret = 0;
	void *recv_msg = NULL;
	int type;
	int subtype;
	int len = 0;
	user_msg_info u_info;
	char vtcm_name[VTCM_NAME_SIZE];

	while (1) {
		usleep(time_val.tv_usec);
		ret = rcv_from_kernel(&u_info, &len);
		if (ret > 0) {
			ret = send_to_db(sub_proc, u_info.msg);
			if (ret < 0) {
				printf("send_to_db error!\n");
				return ret;
			}
		}
		do {
			ret = ex_module_recvmsg(sub_proc, &recv_msg);
		} while (!recv_msg || ret < 0);
		type = message_get_type(recv_msg);
		subtype = message_get_subtype(recv_msg);
		if (!memdb_find_recordtype(type, subtype)) {
			printf("message format (%d %d) is not registered!\n", message_get_type(recv_msg), message_get_subtype(recv_msg));
			continue;
		}
		if ((type == TYPE(VTCM_MEMDB)) && (subtype == SUBTYPE(VTCM_MEMDB,OUT))) {
			fflush(stdout);
			ret = rcv_from_db(recv_msg, vtcm_name);
			if (ret < 0) {
				printf("rcv_from_db error\n");
				return ret;
			}
			ret = send_to_kernel(vtcm_name, ret);
			if (ret < 0) {
				printf("send_to_kernel error\n");
				return ret;
			}
		}
	}
	return ret;
}

int send_to_db(void *sub_proc, char *msg) {
	int ret = 0;
	RECORD(VTCM_MEMDB,IN) *in;

	in = Talloc0(sizeof(*in));
	if(!in) {
		printf("Talloc0 error!\n");
		return -ENOMEM;
	}
	in->img_name = dup_str(msg, 0);
	void *new_msg = message_create(TYPE_PAIR(VTCM_MEMDB,IN), NULL);
	ret = message_add_record(new_msg, in);
	if (ret < 0) {
		printf("message_add_record error!\n");
		return ret;
	}
	ret = ex_module_sendmsg(sub_proc,new_msg);
	if (ret < 0) {
		printf("ex_module_sendmsg error!\n");
		return ret;
	}
	return ret;
}

int rcv_from_db(void *recv_msg, char *vtcm_name) {
	int ret = 0;
	RECORD(VTCM_MEMDB,OUT) *out;

	ret = message_get_record(recv_msg, &out, 0);
	if (ret < 0) {
		printf("message_get_record error\n");
		return ret;
	}
	memset(vtcm_name, 0, VTCM_NAME_SIZE);
	ret = strlen(out->vtcm_name);
	memcpy(vtcm_name, out->vtcm_name, ret);
	return ret;
}

int rcv_from_kernel(user_msg_info *u_info, int *len) {
	int ret = 0;

	memset(u_info, 0, sizeof(user_msg_info));
	ret = recvfrom(skfd, u_info, sizeof(user_msg_info), 0, (struct sockaddr *)&daddr, len);
	if (ret < 0) {
		perror("recv from kernel error\n");
		close(skfd);
		return ret;
	}
	return ret;
}

int send_to_kernel(char *vtcm_name, int len) {
	int ret = 0;
	struct nlmsghdr *nlh = NULL;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
	memset(nlh, 0, sizeof(struct nlmsghdr));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = 0;
	nlh->nlmsg_seq = 0;
	nlh->nlmsg_pid = saddr.nl_pid;
	memcpy(NLMSG_DATA(nlh), vtcm_name, len);
	ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr_nl));
	printf("send message and return %d\n", ret);
	if (!ret) {
		perror("sendto error\n");
		close(skfd);
		return ret;
	}
	return ret;
}
