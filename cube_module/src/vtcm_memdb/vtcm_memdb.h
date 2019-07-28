#ifndef VTCM_MEMDB_H
#define VTCM_MEMDB_H
 
 
int vtcm_memdb_init (void * sub_proc, void * para);
int vtcm_memdb_start (void * sub_proc, void * para);

int proc_get_vtcm(void * sub_proc, void * recv_msg);
#endif
