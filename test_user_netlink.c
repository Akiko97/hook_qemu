#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_UNIT		30
#define MSG_LEN				1024
#define USER_PORT			100
#define MAX_PLOAD			1024

typedef struct _user_msg_info {
	struct nlmsghdr hdr;
	char msg[MSG_LEN];
} user_msg_info;

int main(void) {
	int ret = 0;
	int skfd;
	struct sockaddr_nl saddr, daddr;

	int len = 0;
	int rwstate = 0;

	struct nlmsghdr *nlh = NULL;
	user_msg_info u_info;

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

	while (1) {
		usleep(250000);
		if (!rwstate) {
			len = 0;
			memset(&u_info, 0, sizeof(user_msg_info));
			ret = recvfrom(skfd, &u_info, sizeof(user_msg_info), 0, (struct sockaddr *)&daddr, &len);
			if (ret < 0) {
				perror("recv from kernel error\n");
				close(skfd);
				return ret;
			}
			if (ret > 0) {
				printf("%s\n", u_info.msg);
			}
			rwstate = 1;
		}
		else {
			nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
			memset(nlh, 0, sizeof(struct nlmsghdr));
			nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
			nlh->nlmsg_flags = 0;
			nlh->nlmsg_type = 0;
			nlh->nlmsg_seq = 0;
			nlh->nlmsg_pid = saddr.nl_pid;
			memcpy(NLMSG_DATA(nlh), "Hello~", 7);
			ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr_nl));
			printf("send message and return %d\n", ret);
			if (!ret) {
				perror("sendto error\n");
				close(skfd);
				return ret;
			}
			rwstate = 0;
		}
	}

	return ret;
}
