
#ifndef UTILS_H
#define UTILS_H

#include "stdafx.h"

namespace Utils{

	DWORD myRand();

	LPSTR myRandomStringA(char* out, int outSize);

	void compress_ripe(LPBYTE ripe, DWORD in_size, LPDWORD out_size);

	//C Funcs
	//===================================================================

	DWORD zero_mem(LPVOID mem, DWORD size);

	DWORD copy_mem(LPVOID dest, DWORD dest_size, LPVOID src, DWORD src_size);

	LPVOID in_mem(LPBYTE needle, DWORD n_size, LPBYTE hay_stack, DWORD h_size);

	DWORD mem_cmp(LPBYTE in_1, DWORD in_1_size, LPBYTE in_2, DWORD in_2_size);

	LPSTR hex_to_str(unsigned char *data, int len);

	LPBYTE big_multiply(LPBYTE a, LPBYTE b, DWORD in_size, LPBYTE out, DWORD out_size);

	void SwitchOrder(LPBYTE pBytes, DWORD cb);



};





















#endif