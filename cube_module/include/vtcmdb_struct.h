enum dtype_vtcm_memdb {
	TYPE(VTCM_MEMDB)=0x3100
};
enum subtype_vtcm_memdb {
	SUBTYPE(VTCM_MEMDB,IN)=0x1,
	SUBTYPE(VTCM_MEMDB,OUT),
	SUBTYPE(VTCM_MEMDB,STORE)
};
typedef struct vtcm_memdb_in{
	char * img_name;
}__attribute__((packed)) RECORD(VTCM_MEMDB,IN);

typedef struct vtcm_memdb_out{
	char * vtcm_name;
}__attribute__((packed)) RECORD(VTCM_MEMDB,OUT);

typedef struct vtcm_memdb_store{
	char * img_name;
	char * vtcm_name;
}__attribute__((packed)) RECORD(VTCM_MEMDB,STORE);

