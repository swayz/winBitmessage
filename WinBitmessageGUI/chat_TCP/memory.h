#ifndef MEMORY_H
#define MEMORY_H




#define ALLOC_BLOCK_BUFFER_SIZE(z) ((z / 4096) * 4096)
#define POOL_SIZE ((1024 * 1024) * 1000)
#define MAX_ALLOCS (POOL_SIZE / 4096)


typedef struct {

	LPVOID address;
	BOOL commited;
	DWORD blocks;
	//	each block is 4096 bytes (4kb)
}MEM_BLOCK, *PMEM_BLOCK;


typedef struct {
	MEM_BLOCK list[];
}MEM_BLOCK_LIST, *PMEM_BLOCK_LIST;

typedef struct {
	PMEM_BLOCK block[4];

}MEM_PAGE, *PMEM_PAGE;


namespace Memory {
	extern MEM_BLOCK** list;
	extern LPVOID list_pool;
	extern LPVOID pool;
	extern HANDLE mem_lock;
	extern CRITICAL_SECTION cs;

	DWORD init(void);
	DWORD deinit(void);
	LPVOID alloc(DWORD size);
	
	DWORD free(LPVOID ptr, DWORD size);

	VOID unlock_mem();
	VOID lock_mem();

};

#endif