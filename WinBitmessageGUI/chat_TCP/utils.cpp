#include "stdafx.h"
#ifndef UTILS_C
#define UTILS_C


#include "utils.h"
#include "encryption.h"
#include "intrin.h"
#include "AccCtrl.h"


int cpi_p[4];



ULONG Utils::myRand() {
	CHAR ret[8];
	PULONG up = (PULONG)ret;
	ZERO_(ret, 8);
	HCRYPTPROV hProv = NULL;
	CryptAcquireContextA(&hProv, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	CryptGenRandom(hProv, 8, (BYTE*)ret);
	CryptReleaseContext(hProv, NULL);
	return *up;
}

LPSTR Utils::myRandomStringA(char* out, int outSize) {//size must be in chars.
	HCRYPTPROV hProv = NULL;
	ZERO_(out, outSize);
	CryptAcquireContextA(&hProv, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	CryptGenRandom(hProv, outSize, (BYTE*)out);
	CryptReleaseContext(hProv, NULL);
	//static const char alphanum[] = "hoisvA*YNnm@aebTl1J96dU04WuFLkQGO&qMDPzC$wxrXRKjyZc^g2!BtI5SE%78pf#3VH";
	static const char alphanum[] = "0123456789";
	const int stringLength = lstrlenA(alphanum) - sizeof(char);
	BYTE t = NULL;
	DWORD res = NULL;

	for (int i = 0; i < outSize; ++i)
	{
		t = out[i];
		res = t % stringLength;
		out[i] = alphanum[res];
		
	}
	return out;
}


//	C funcs
//======================================================


DWORD Utils::zero_mem(LPVOID mem, DWORD size) {

	DWORD i = 0;
	LPBYTE mem_ = (LPBYTE)mem;
	if (mem) {
		while (i < size) {
			mem_[i] = NULL;
			i++;
		}
		return 1;
	}
	return 0;

}

DWORD Utils::copy_mem(LPVOID dest, DWORD dest_size, LPVOID src, DWORD src_size) {
	if (!dest || !src || !dest_size || !src_size || (src_size > dest_size)) {
		return 0;
	}

	DWORD i = 0;

	LPBYTE src_ = (LPBYTE)src;
	LPBYTE dest_ = (LPBYTE)dest;

	while (i < src_size) {

		dest_[i] = src_[i];

		i++;
	}

	return 1;
}

LPVOID Utils::in_mem(LPBYTE needle, DWORD n_size, LPBYTE hay_stack, DWORD h_size) {

	LPVOID cur_pos = NULL;
	DWORD ret = FALSE;
	LPVOID first_found = NULL;

	for (DWORD i = 0; i < h_size; i++)
	{
		cur_pos = hay_stack + i;

		if (n_size >(h_size - i))
			n_size = (h_size - i);

		if (Utils::mem_cmp((LPBYTE)cur_pos, n_size, needle, n_size)) {
			if(!first_found) first_found = cur_pos;
			ret++;
		}
	}

	return first_found;
}

DWORD Utils::mem_cmp(LPBYTE in_1, DWORD in_1_size, LPBYTE in_2, DWORD in_2_size) {
	if (!in_1_size && !in_2_size) return TRUE;
	if (!in_1_size || !in_2_size) return FALSE;

	
	DWORD a_s = in_1_size, b_s = in_2_size;
	LPBYTE a = in_1, b = in_2;
	DWORD i = NULL;
	if (in_1_size > in_2_size) {
		a = in_2;
		b = in_1;
		a_s = in_2_size;
		b_s = in_1_size;
	}

	for (i = 0; i < a_s; i++)
		if (a[i] != b[i])
			break;

	if (i == a_s)
		return TRUE;

	return FALSE;
}





void Utils::compress_ripe(LPBYTE ripe, DWORD in_size, LPDWORD out_size)
{

	if (!ripe || !in_size || !out_size || in_size > 20) return;

	BOOL found = FALSE;
	DWORD ripe_size = 0;
	BYTE t_ripe[32] = {};
	
	memcpy_s(t_ripe, 32, ripe, in_size);
	ZERO_(ripe, in_size);


	int i = 0;
	int j = 0;


	while (t_ripe[i] == 0x00 && i < 20)
	{
		i++;
		found = TRUE;

	}

	if (found)
	{
		while (i < 20)
		{
			ripe[j] = t_ripe[i];
			i++;
			j++;
		}

		ripe_size = j;
	}

	*out_size = ripe_size;
	ZERO_(t_ripe, 32);
}





LPBYTE Utils::big_multiply(LPBYTE a, LPBYTE b, DWORD in_size, LPBYTE out, DWORD out_size)
{
	return FALSE;
}

typedef struct { 
	unsigned value : 4;
	unsigned valueb : 4;

} uint4;

typedef struct {
	unsigned va : 4;
	unsigned vb : 4;
	unsigned vc : 4;
	unsigned vd : 4;
} nibly;

void Utils::SwitchOrder(LPBYTE pBytes, DWORD cb)
{

	if (!cb) {
		return;
	}
	unsigned char *p = pBytes;
	size_t a, z;
	char tmp = 0x00;
	for (a = 0, z = cb - 1; z>a; a++, z--)
	{
		tmp = 0x00;
		tmp = p[a];
		p[a] = p[z];
		p[z] = tmp;
	}
}

void set_nibble(LPBYTE in, DWORD in_size, DWORD pos, uint4* value)
{
	uint4* entry = NULL;
	DWORD tp = 0;
	
	BOOL is_odd = pos % 2;
	
	if (pos > 1)
		tp = pos / 2;

	if (is_odd)
	{
		((uint4*)&in[tp])->valueb = value->value;
	}
	else {
		((uint4*)&in[tp])->value = value->value;
	}

}

DWORD big_add(LPBYTE a,  LPBYTE b, DWORD a_s, LPBYTE out, DWORD out_s)
{
	
	uint32_t carry = NULL;
	uint8_t sum = NULL;
	uint8_t tsum = NULL;

	uint4* psum = (uint4*)&sum;
	uint8_t* A = (uint8_t*)a;
	uint8_t* B = (uint8_t*)b;
	uint8_t* C = (uint8_t*)out;


	DWORD A_s = a_s;
	DWORD B_s = a_s ;
	DWORD C_s = out_s;

	int i = 0;
	int k = 0;
	for (int j = A_s; j > 0; j--)
	{
		if (k > out_s)	
			break;

		i = j - 1;
		sum = ((uint4*)&A[i])->value + ((uint4*)&B[i])->value + carry;

		if (sum >= 16)
		{
			tsum = psum[0].value;
			carry = psum[0].valueb;

		}else{
			carry = 0;
			tsum = sum;
		}
	
		((uint4*)&out[k])->value = tsum;
		

		sum = ((uint4*)&A[i])->valueb + ((uint4*)&B[i])->valueb + carry;

		if (sum >= 16)
		{
			tsum = psum[0].value;
			carry = psum[0].valueb;

		}
		else {
			carry = 0;
			tsum = sum;
		}

		((uint4*)&out[k])->valueb = tsum;

		if (i == 0 && carry)
		{
			((uint4*)&out[k + 1])->value = carry;
			k++;
			
			break;
		}
		else if (i == 0)
		{
			//break;
		}

		k++;

	}
	
	// we build the sum from the front of the buffer to back to account for additional places
	// we switch everything back afterwards
	Utils::SwitchOrder(out, k);

	return TRUE;
}



DWORD big_mul(LPBYTE a, LPBYTE b, DWORD s, LPBYTE out, DWORD out_s)
{
	uint8_t carry = NULL;
	uint8_t sum = NULL;
	uint8_t tsum = NULL;

	uint8_t mod_c = 0;

	BYTE tmp_a[1024] = {};
	BYTE tmp_b[1024] = {};
	BYTE tmp_c[1024] = {};

	uint4* psum = (uint4*)&sum;
	uint8_t* A = (uint8_t*)a;
	uint8_t* B = (uint8_t*)b;
	uint8_t* C = (uint8_t*)out;

	DWORD a_pos = 0;
	DWORD b_pos = 0;

	DWORD A_s = s;
	DWORD B_s = s;
	DWORD C_s = out_s;


	DWORD t_val = 0;
	int i = 0;
	int c = 0;
	int k = 0;

	int place = 2;

	for (int j = A_s; j > 0; j--)
	{
		i = j - 1;
		place = 2;
		
		do
		{
			carry = 0;
			k = 0;
			t_val = ((place == 1) ? ((uint4*)&B[i])->valueb : ((uint4*)&B[i])->value);
			// loop top number
			a_pos = NULL;
			for (int h = B_s; h > 0; h--)
			{
				c = h - 1;

				sum = (((uint4*)&A[c])->value
					*
					t_val)/*((uint4*)&B[i])->value)*/
					+
					carry;

				mod_c = psum->value;

				carry = psum->valueb;

				tsum = mod_c;

				//((uint4*)&tmp_a[k])->value = tsum;
				set_nibble(tmp_a, 32, b_pos + a_pos, ((uint4*)&tsum));
				a_pos++;

				sum = (((uint4*)&A[c])->valueb
					*
					t_val)
					+
					carry;

				mod_c = psum->value;

				carry = psum->valueb;

				tsum = mod_c;

				//((uint4*)&tmp_a[k])->valueb = tsum;

				set_nibble(tmp_a, 32, b_pos + a_pos, ((uint4*)&tsum));

				if (c == 0 && carry)
				{
					//((uint4*)&tmp_a[k + 1])->value = carry;
					set_nibble(tmp_a, 32, (b_pos + a_pos) + 1, ((uint4*)&carry));
					
					k++;

					continue;
				}
				else if (c == 0)
				{
					//break;
				}
				a_pos++;
				k++;
			}

			b_pos++;
			Utils::SwitchOrder(tmp_a, s);

			big_add(tmp_a, tmp_b, s, tmp_c, s);


			memcpy_s(tmp_b, s, tmp_c, s);

			ZERO_(tmp_a, 1024);
			ZERO_(tmp_c, 1024);
			
			place--;

		} while (place > 0);

	}


	memcpy_s(out, out_s, tmp_b, s);
	

	return FALSE;
}











#endif