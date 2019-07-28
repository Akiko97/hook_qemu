#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>
#include <string.h>
 
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
#include "vtcm_memdb.h"

#include "vtcmdb_struct.h"

int vtcm_num = 0;

int vtcm_memdb_init(void *sub_proc, void *para) {
	int ret = 0;
	return ret;
}

int vtcm_memdb_start(void *sub_proc, void *para) {
	int ret = 0;
	void *recv_msg;
	int type;
	int subtype;
	while (1) {
		usleep(time_val.tv_usec);
		ret = ex_module_recvmsg(sub_proc,&recv_msg);
		if (ret < 0) {
			continue;
		}
		if (!recv_msg) {
			continue;
		}
		type = message_get_type(recv_msg);
		subtype = message_get_subtype(recv_msg);
		if (!memdb_find_recordtype(type, subtype)) {
			printf("message format (%d %d) is not registered!\n", message_get_type(recv_msg), message_get_subtype(recv_msg));
			continue;
		}
		if ((type == TYPE(VTCM_MEMDB)) && (subtype == SUBTYPE(VTCM_MEMDB,IN))) {
			ret = proc_get_vtcm(sub_proc, recv_msg);
		}
	}
	return 0;
}
int proc_get_vtcm(void *sub_proc, void *recv_msg) {
	int ret;
	RECORD(VTCM_MEMDB,IN) *in;
	RECORD(VTCM_MEMDB,OUT) *out;
	RECORD(VTCM_MEMDB,STORE) *store = Talloc0(sizeof(*store));
	void *new_msg;

	ret = message_get_record(recv_msg, &in, 0);
	if (ret < 0) {
		return ret;
	}
	printf("%s: ", in->img_name);

	DB_RECORD *db_record;
	db_record = memdb_find_byname(in->img_name, TYPE_PAIR(VTCM_MEMDB, STORE));
	if (!db_record) {
		printf("NO FOUND\n");
		store->img_name = in->img_name;
		char *buff = malloc(sizeof(*buff) * 32);
		get_vtcm_now(buff);
		char vtcm_name[32] = "vtcm";
		strcat(vtcm_name, buff);
		store->vtcm_name = vtcm_name;
		db_record = memdb_store(store, TYPE_PAIR(VTCM_MEMDB, STORE), in->img_name);
		if (!db_record) {
			return -EINVAL;
		}
	}
	else {
		printf("FOUND ------ %s\n", ((RECORD(VTCM_MEMDB,STORE)*)(db_record->record))->vtcm_name);
	}
	out = Talloc0(sizeof(*out));
	if(!out) {
		return -ENOMEM;
	}
	out->vtcm_name = dup_str(((RECORD(VTCM_MEMDB,STORE)*)(db_record->record))->vtcm_name, 0);
	new_msg = message_create(TYPE_PAIR(VTCM_MEMDB,OUT),recv_msg);
	if (!new_msg) {
		return -EINVAL;
	}
	ret = message_add_record(new_msg, out);
	if (ret < 0) {
		return ret;
	}
	ret = ex_module_sendmsg(sub_proc,new_msg);

	return ret;
}

int get_vtcm_now(char *buff) {
	int ret;
	ret = sprintf(buff, "%d", vtcm_num);
	vtcm_num++;
	return ret;
}
