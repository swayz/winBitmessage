#include "stdafx.h"

#ifndef MEMORY_C
#define MEMORY_C

#include "memory.h"
#include "utils.h"


HANDLE Memory::mem_lock = NULL;
MEM_BLOCK **Memory::list = NULL;
LPVOID Memory::list_pool = NULL;
LPVOID Memory::pool = NULL;
CRITICAL_SECTION Memory::cs;

VOID Memory::lock_mem()
{
	//Sleep(20);
	EnterCriticalSection(&cs);
}


VOID Memory::unlock_mem()
{

	LeaveCriticalSection(&cs);

}

//	call only once
DWORD Memory::init(void) {
	ZERO_(&cs, sizeof(CRITICAL_SECTION));
	InitializeCriticalSection(&cs);

	Memory::pool = (LPVOID*)VirtualAlloc(0, POOL_SIZE, MEM_RESERVE, PAGE_READWRITE);

	Memory::list = (MEM_BLOCK**)VirtualAlloc(0, MAX_ALLOCS * sizeof(LPVOID), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ZERO_(Memory::list, MAX_ALLOCS * sizeof(LPVOID));// or use RtlSecureZeroMem(x,y);


	Memory::list_pool = (MEM_BLOCK**)VirtualAlloc(0, MAX_ALLOCS * sizeof(MEM_BLOCK), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ZERO_(Memory::list_pool, MAX_ALLOCS * sizeof(MEM_BLOCK));


	for (DWORD i = 0; i < MAX_ALLOCS; i++)
		Memory::list[i] = (MEM_BLOCK*)((ULONG_PTR)Memory::list_pool + (sizeof(MEM_BLOCK) * i));


	for (DWORD i = 0; i < MAX_ALLOCS; i++)
		Memory::list[i]->address = (LPVOID)((ULONG_PTR)Memory::pool + (i * 4096));



return FALSE;
}

DWORD if_committed(PMEM_BLOCK in)
{
	return	in->commited;
}

LPVOID find_next_alloc(DWORD blocks)
{
	LPBYTE* alloc_list = (LPBYTE*)0;

	DWORD found_blocks = NULL;
	ULONG_PTR _range = NULL;

	DWORD ranges_found = NULL;

	LPVOID base = NULL;

	DWORD i = 0;

	//blocks

	while (ranges_found < blocks)
	{

		found_blocks = NULL;
		ranges_found = NULL;
		base = NULL;

		/*if (i > MAX_ALLOCS)
			break;*/

		// loop ranges
		for (; i < MAX_ALLOCS; i++)
		{
			if (!Memory::list[i]->commited) 
			{
				if (!base) {
					base = (LPVOID)i;
					
				}
				ranges_found++;
			}else {
				if (base)
				{
					i++;
					ranges_found = NULL;
					break;
				}
				
			}
			if (ranges_found >= blocks)
				break;
		}
	}

//end:

	LPVOID ret = NULL;

	if (ranges_found == blocks) {
		ret = base;
	}

	return ret;
}



LPVOID Memory::alloc(DWORD size) {
	if (!Memory::list)
		return FALSE;

	Memory::lock_mem();

	LPVOID ret = FALSE;

	DWORD blocks = 1;

	if (size > 4096) {
		blocks = (ALLOC_BLOCK_BUFFER_SIZE(size) / 4096) + 1;
	}
	LPVOID base = NULL;
	LPVOID p = NULL;
	ULONG_PTR na = NULL;
	DWORD old = NULL;

	na = (ULONG_PTR)find_next_alloc(blocks);

	p = VirtualAlloc(Memory::list[na]->address,(blocks * 4096), MEM_COMMIT, PAGE_READWRITE);
	if (p)
	{

		if (VirtualProtect(p, (blocks * 4096), PAGE_READWRITE, &old))
		{

			base = p;
					
			Memory::list[na]->blocks = blocks;
				
			for(DWORD bl = 0; bl < blocks; bl++)
				Memory::list[na + bl]->commited = TRUE;
		}
	}
	else {
		
		ret = FALSE;
	}

	if (base)
	{
		//printf("Alloc address:\t%p\tBlocks:\t%u\t\n", base, blocks);
		ret = base;
	}
	Memory::unlock_mem();
	return ret;
}


DWORD Memory::free(LPVOID ptr, DWORD size) {
	if (!Memory::list)
		return FALSE;

	if (!ptr)
		return FALSE;

	Memory::lock_mem();

	DWORD i = NULL;
	DWORD ret = FALSE;
	DWORD blocks = 1;

	if (size > 4096)
		blocks = (ALLOC_BLOCK_BUFFER_SIZE(size)) / 4096;

	for (i = 0; i < MAX_ALLOCS; i++) 
	{
		if ((Memory::list[i]->address == ptr))
		{
			if (VirtualFree(ptr, size, MEM_DECOMMIT))
			{
				for (DWORD b = 0; b < Memory::list[i]->blocks; b++)
					Memory::list[i + b]->commited = FALSE;

				//printf("Freed address:\t%p\tBlocks:\t%u\t\n", Memory::list[i]->address, Memory::list[i]->blocks);
			}
			else {
				//printf("Faild to free:\t%p\tBlocks:\t%u\t\n", Memory::list[i]->address, Memory::list[i]->blocks);
				DBGOUTa("\rFailed to FREE_() memory.\r");
			}

			break;
		}				
	}

	Memory::unlock_mem();
	return ret;
}




//call only once.
DWORD Memory::deinit(void) {
	if (Memory::pool) {
		BOOL r = VirtualFree(Memory::pool, 0, MEM_RELEASE);
		Memory::pool = NULL;
		return r;
	}
	return FALSE;
}

#endif