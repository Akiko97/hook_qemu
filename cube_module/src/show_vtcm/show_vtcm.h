#ifndef SHOW_VTCM_H
#define SHOW_VTCM_H

#define NETLINK_UNIT		30
#define MSG_LEN				1024
#define USER_PORT			100
#define MAX_PLOAD			1024
#define VTCM_NAME_SIZE		32

typedef struct _user_msg_info {
	struct nlmsghdr hdr;
	char msg[MSG_LEN];
} user_msg_info;

int show_vtcm_init(void *, void *);
int show_vtcm_start(void *, void *);

int send_to_db(void *, char *);
int rcv_from_db(void *, char *);
int rcv_from_kernel(user_msg_info *, int *);
int send_to_kernel(char *, int);

#endif
