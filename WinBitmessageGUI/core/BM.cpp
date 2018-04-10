#include "stdafx.h"
#ifndef BM_C
#define BM_C

#include "bm.h"
#include "Encryption.h"
#include "ecc.h"
#include "rmd160.h"
#include "memory.h"
#include "utils.h"
#include "network.h"
#include "bm_db.h"


_NtQuerySystemTime BM::NtQuerySystemTime = NULL;
_RtlTimeToSecondsSince1970 BM::RtlTimeToSecondsSince1970 = NULL;
_RtlIpv6StringToAddress BM::RtlIpv6StringToAddress = NULL;

DWORD BM::numthreads = 0;

/*	INIT PEER LIST

also:
https://github.com/mrc-g/BitMRC/blob/90b85da9e13fc5b054effdabab2a0c0d9e56cf25/BitMRC/BitMRC.cpp#L73

85.180.139.241
158.222.211.81
72.160.6.112
45.63.64.229
212.47.234.146
84.42.251.196
178.62.12.187
109.147.204.113
158.222.217.190
178.11.46.221
95.165.168.168
213.220.247.85
109.160.25.40
24.188.198.204
75.167.159.54

*/

sqlite3 * BM::db = NULL;

PBM_NODE_LIST BM::node_list = NULL;
PBM_VECT_LIST BM::vector_list = NULL;
HWND BM::main_hwnd = NULL;
HANDLE BM::prop_thread_handle = NULL;
HWND BM::send_data_thread = NULL;





#pragma region CoreBMFunctions


//=================================
// https://techoverflow.net/blog/2013/01/25/efficiently-encoding-variable-length-integers-in-cc/
// thanks much appreciated

size_t BM::encodeVarint(uint64_t value, uint8_t* output) {

	DWORD ret_size = NULL;

	if (value < 0xFD)
	{
		output[0] = (uint8_t)value;
		ret_size = 1;
	}
	else if (value <= 0xFFFF)
	{
		output[0] = 0xFD;
		*((uint16_t *)&output[1]) = htons((u_short)value);
		ret_size = 3;
	}
	else if (value <= 0xFFFFFFFF)
	{
		output[0] = 0xFE;
		*((uint32_t *)&output[1]) = htonl((u_long)value);
		ret_size = 5;
	}
	else
	{
		output[0] = 0xFF;
		*((uint64_t *)&output[1]) = swap64(value);
		ret_size = 9;
	}

	return ret_size;

}

uint64_t BM::decodeVarint(uint8_t* input, size_t inputSize, size_t* int_s) {

	uint64_t ret = NULL;
	DWORD int_len = NULL;

	if (!input)
		return NULL;

	if (input[0] < 0xFD && inputSize >= 1)
	{
		ret = input[0];
		int_len = 1;
	}
	else if (input[0] == 0xFD && inputSize >= 3)
	{
		ret = htons((*(uint16_t*)&input[1]));
		int_len = 3;
	}
	else if (input[0] == 0xFE && inputSize >= 5)
	{
		ret = htonl((*(uint32_t*)&input[1]));
		int_len = 5;
	}
	else if (input[0] == 0xFF && inputSize >= 9)
	{
		ret = swap64((*(uint64_t*)&input[1]));
		int_len = 9;
	}


	if (int_s)
		*int_s = int_len;

	return ret;
}

DWORD BM::encodeVarstr(char* in, LPBYTE out, DWORD out_size)
{
	if (!in || !out || !out_size)
		return FALSE;


	LPBYTE buff = out;
	DWORD str_len = lstrlenA(in);

	DWORD var_int_size = BM::encodeVarint(str_len, buff);
	DWORD rem_buff_size = out_size - var_int_size;

	if (var_int_size + str_len > out_size)
	{
		ZeroMemory(out, out_size);
		return FALSE;
	}

	buff += (ULONG_PTR)var_int_size;

	strcpy_s((char*)buff, rem_buff_size, in);

	return str_len + var_int_size;
}

DWORD BM::decodeVarstr(char* in, int in_size, char* out, int out_size)
{

	if (!in || !in_size || !out || !out_size)
		return FALSE;

	size_t int_len = NULL;

	size_t str_len = (size_t)BM::decodeVarint((uint8_t*)in, in_size, &int_len);

	memcpy_s((char*)out, out_size, &in[int_len], str_len);

	return str_len;

}

DWORD64 BM::var_net_list(LPBYTE in, size_t in_size, PBM_NET_ADDR* out)
{

	size_t int_len = NULL;

	DWORD64 n = NULL;

	n = BM::decodeVarint(in, in_size, &int_len);

	*out = (PBM_NET_ADDR)in + (ULONG_PTR)int_len;

	return n;
}

uint64_t BM::swap64(uint64_t in)
{
	uint64_t t = in;
	uint64_t y = NULL;

	LPBYTE n = (LPBYTE)&t;
	LPBYTE m = (LPBYTE)&y;

	m[7] = n[0];
	m[6] = n[1];
	m[5] = n[2];
	m[4] = n[3];
	m[3] = n[4];
	m[2] = n[5];
	m[1] = n[6];
	m[0] = n[7];

	return *((uint64_t*)m);

}



void BM::init()
{
	
	LPWSTR ntdll = L"ntdll.dll";
	

	BM::NtQuerySystemTime = (_NtQuerySystemTime)GetProcAddress(GetModuleHandle(ntdll), "NtQuerySystemTime");
	BM::RtlTimeToSecondsSince1970 = (_RtlTimeToSecondsSince1970)GetProcAddress(GetModuleHandle(ntdll), "RtlTimeToSecondsSince1970");
	BM::RtlIpv6StringToAddress = (_RtlIpv6StringToAddress)GetProcAddress(GetModuleHandle(ntdll), "RtlIpv6StringToAddress");



}

ULONG BM::unix_time()
{
	ULONG unix_time = NULL;
	LARGE_INTEGER sys_time = {};
	BM::NtQuerySystemTime(&sys_time);
	BM::RtlTimeToSecondsSince1970(&sys_time, &unix_time);

	ZeroMemory(&sys_time, sizeof(LARGE_INTEGER));

	return unix_time;
}

DWORD64 BM::calc_pow_target(DWORD64 TTL,DWORD payloadLength, DWORD payloadLengthExtraBytes, DWORD64 averageProofOfWorkNonceTrialsPerByte)
{
	///*
	//Both averageProofOfWorkNonceTrialsPerByte and payloadLengthExtraBytes are set by the owner of a Bitmessage address. 
	//The default and minimum for each is 1000. 
	//(This is the same as difficulty 1. If the difficulty is 2, then this value is 2000). 
	//The purpose of payloadLengthExtraBytes is to add some extra weight to small messages. 
	//*/
	//ULONGLONG pleb = payloadLength + payloadLengthExtraBytes;

	//ULONGLONG ttl_pleb = TTL * pleb;

	//ULONGLONG ttl_pleb_2x16 = ttl_pleb / (ULONGLONG)pow(2, 16);
	//
	//ULONGLONG pleb_2x16 = pleb + ttl_pleb_2x16;

	//ULONGLONG TPBpleb = (averageProofOfWorkNonceTrialsPerByte * pleb_2x16);
	////2000000000000000
	//ULONGLONG target = (ULONGLONG)18446744073709551616;// pow(2, 64);
	//
	//target /= TPBpleb;


	const uint64_t two_63 = UINT64_C(0x8000000000000000);
	uint64_t divisor;
	uint64_t target;
	if (TTL < 300)
		TTL = 300;
	divisor = ((((payloadLength + payloadLengthExtraBytes) * TTL) / UINT64_C(0x10000)) + 1000 + payloadLength) * 1000;

	/* We need to divide 2?? by divisor. We can't represent 2?? in
	* a 64-bit variable so instead we divide 2?� by the divisor
	* twice and add the result */
	target = two_63 / divisor * 2;
	/* If the fractional part of the result would be greater than
	* or equal to a half then we would get an extra 1 when we
	* multiply by two */
	if ((two_63 % divisor) * 2 >= divisor)
		target++;

	return target;
	//return target;
}



int64_t LongLongSwap(int64_t i)
{
	unsigned char b1, b2, b3, b4, b5, b6, b7, b8;

	b1 = i & 255;
	b2 = (i >> 8) & 255;
	b3 = (i >> 16) & 255;
	b4 = (i >> 24) & 255;
	b5 = (i >> 32) & 255;
	b6 = (i >> 40) & 255;
	b7 = (i >> 48) & 255;
	b8 = (i >> 56) & 255;

	return ((int64_t)b1 << 56) + ((int64_t)b2 << 48) + ((int64_t)b3 << 40) + ((int64_t)b4 << 32) + ((int64_t)b5 << 24) + ((int64_t)b6 << 16) + ((int64_t)b7 << 8) + b8;
}


void BM::getnumthreads()
{
	

	DWORD_PTR dwProcessAffinity = NULL, dwSystemAffinity = NULL;

	size_t len = sizeof(dwProcessAffinity);

	if (BM::numthreads > 0)
		return;

	GetProcessAffinityMask(GetCurrentProcess(), &dwProcessAffinity, &dwSystemAffinity);

	for (unsigned int i = 0; i < len * 8; i++)
	{
		if (dwProcessAffinity & (1i64 << i))
		{
			BM::numthreads++;
		}
	}

	if (BM::numthreads == 0) // something failed
		BM::numthreads = 1;
	
}


DWORD64 BM::do_pow(LPBYTE payload, DWORD in_size, DWORD64 TTL)
{
	HANDLE threads[32] = {};
	PBM_POW_THREAD_DETAILS thread_details[32] = {};


	if (BM::numthreads == 0)
		BM::getnumthreads();

	HANDLE pow_event = CreateEvent(0, TRUE, 0, 0);
	DWORD64 final_nonce = 0;



	for (DWORD i = 1; i <= BM::numthreads; i++)
	{
		thread_details[i] = (PBM_POW_THREAD_DETAILS)ALLOC_(sizeof(BM_POW_THREAD_DETAILS));
		thread_details[i]->payload = payload;
		thread_details[i]->in_size = in_size;
		thread_details[i]->TTL = TTL;
		thread_details[i]->thread_number = i;
		thread_details[i]->final_nonce = &final_nonce;
		thread_details[i]->pow_event = pow_event;


		threads[i] = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)BM::do_pow_proc, thread_details[i], 0, 0);

	}


	if (!WaitForSingleObject(pow_event, INFINITE))
	{

		if (!WaitForMultipleObjects(BM::numthreads, &threads[1], TRUE, INFINITE))
		{
			return final_nonce;
		}

	}

	return FALSE;

}

DWORD64 BM::do_pow_proc(PBM_POW_THREAD_DETAILS in)
{
	

	//	payloadLength = the length of payload, in bytes, + 8 (to account for the nonce which we will append later)
	DWORD payloadLength = in->in_size;

	uint64_t trialValue = -1; // just a high number to start off the loop successfuly
	DWORD64 nonce = in->thread_number;

	BYTE initialHash[MAX_PATH] = {};
	BYTE resultHash[MAX_PATH] = {};
	BYTE tmpHash[MAX_PATH] = {};
	BYTE tmp_buff[MAX_PATH] = {};
	
	//===============================================================
	//	calculate pow

	/*
	oth averageProofOfWorkNonceTrialsPerByte and payloadLengthExtraBytes are set by the owner of a Bitmessage address.
	The default and minimum for each is 1000.
	(This is the same as difficulty 1. If the difficulty is 2, then this value is 2000).
	The purpose of payloadLengthExtraBytes is to add some extra weight to small messages.
	*/

	uint64_t target = calc_pow_target(in->TTL, payloadLength, 1000, 1000);


	Encryption::create_hash((LPSTR)initialHash, in->payload, payloadLength, NULL, NULL, CALG_SHA_512);

	memcpy_s(&tmpHash[8], 64, initialHash, 64);

	while (trialValue > target)
	{
		if(!WaitForSingleObject(in->pow_event, 0)) break;

		nonce = (nonce + BM::numthreads);

		//	resultHash = hash(hash(nonce || initialHash))
		
		*(ULONGLONG*)tmpHash = BM::swap64(nonce);
		
		Encryption::create_hash((LPSTR)tmp_buff, tmpHash, 8 + 64, NULL, NULL, CALG_SHA_512);

		Encryption::create_hash((LPSTR)resultHash, tmp_buff, 64, NULL, NULL, CALG_SHA_512);

		//	trialValue = the first 8 bytes of resultHash, converted to an integer
		trialValue = LongLongSwap(*(int64_t*)resultHash);

	}


	if (trialValue < target)
	{
		SetEvent(in->pow_event);
		*in->final_nonce = nonce;
	}

	ZERO_(initialHash, MAX_PATH);

	ExitThread(0);
	//return nonce; //ot trialValue;

}

DWORD BM::check_pow(LPBYTE payload, DWORD in_size, DWORD64 TTL)
{
	BOOL ret = FALSE;

	LPBYTE buff = (LPBYTE)ALLOC_(4096);
	ZERO_(buff, 4096);

	LPBYTE initialHash = buff;
	LPBYTE resultHash = &buff[1024];
	LPBYTE tmpHash = &buff[2048];
	LPBYTE tmp_buff = &buff[3072];

	DWORD64 payloadLength = in_size - 8; // payload + 8 byte nonce

	//	nonce = the first 8 bytes of payload
	DWORD64 nonce = BM::swap64(*(DWORD64*)payload);


	//  dataToCheck = the ninth byte of payload on down (thus it is everything except the nonce)
	LPBYTE dataToCheck = &payload[8];

	//	initialHash = hash(dataToCheck)
	Encryption::create_hash((LPSTR)initialHash, dataToCheck, (DWORD)payloadLength, NULL, NULL, CALG_SHA_512);

	//	resultHash = hash(hash(nonce || initialHash))
	*((DWORD64*)tmp_buff) = BM::swap64(nonce);

	memcpy_s(&tmp_buff[8], 64, initialHash, 64);

	Encryption::create_hash((LPSTR)resultHash, tmp_buff, 8 + 64, NULL, NULL, CALG_SHA_512);
	Encryption::create_hash((LPSTR)tmp_buff, resultHash, 64, NULL, NULL, CALG_SHA_512);

	//	POWValue = the first eight bytes of resultHash "converted to an integer!"
	uint64_t POWValue = LongLongSwap(*(int64_t*)tmp_buff);



	//	If POWValue is less than or equal to target, then the POW check passes. 
	uint64_t target = calc_pow_target(TTL, (DWORD)payloadLength, 1000, 1000);

	//	Do the POW check
	if (POWValue <= target)
		ret = TRUE;

	// cleanup

	ZEROFREE_(buff, 128);
	
	return ret;
}












DWORD BM::validate_address(LPSTR address, DWORD length, PBM_MSG_ADDR out_addr)
{
	
	
	DWORD is_valid = NULL;
	DWORD addr_size = lstrlenA(address);
	BYTE tmp_buff[MAX_PATH] = {};
	size_t tmp_buff_size = MAX_PATH;

	char hash_buff[MAX_PATH] = {};
	DWORD hash_buff_size = NULL;

	DWORD ripe = NULL;
	DWORD ripe_size = NULL;
	DWORD chcksum = NULL;

	if (length != addr_size) return FALSE;
	if (addr_size > 64 || addr_size < 32) return FALSE;
	if (address[0] != 'B' || address[1] != 'M' || address[2] != '-') return FALSE;

	LPSTR b58 = &address[3];
	DWORD b58_size = lstrlenA(b58);

	if (Encryption::base58_decode(tmp_buff, &tmp_buff_size, b58, b58_size) && Encryption::base58_decode(tmp_buff, &tmp_buff_size, b58, b58_size))
	{

		size_t varint_size = 0;
		
		DWORD64 version = BM::decodeVarint(tmp_buff, tmp_buff_size, &varint_size);

		if (version < 2) goto fail;

		ripe += varint_size;

		DWORD64 stream = BM::decodeVarint(&tmp_buff[varint_size], tmp_buff_size, &varint_size);

		if (stream != 1) goto fail;

		ripe += varint_size;
		
		ripe_size = tmp_buff_size - ripe - 4;//(tmp_buff_size - offset_to_ripe - checksum_size)

		chcksum = tmp_buff_size - 4;

		Encryption::create_hash(hash_buff, tmp_buff, chcksum, NULL, FALSE, CALG_SHA_512);
		Encryption::create_hash((LPSTR)&hash_buff[64], (LPBYTE)hash_buff, 64, NULL, FALSE, CALG_SHA_512);



		if (Utils::mem_cmp((LPBYTE)&hash_buff[64], 4, &tmp_buff[chcksum], 4))
		{

			is_valid = TRUE;

			if (out_addr != FALSE)
			{

				out_addr->version = (DWORD)version;
				out_addr->stream = (DWORD)stream;

				Utils::copy_mem(out_addr->readable, 128, address, length);

				Utils::copy_mem(out_addr->first_tag, 32, &hash_buff[64], 32);
				Utils::copy_mem(out_addr->tag, 32, &hash_buff[64 + 32], 32);

				Utils::copy_mem(out_addr->checksum, 4, &tmp_buff[chcksum], 4);
				Utils::copy_mem(out_addr->hash, 20, &tmp_buff[ripe], ripe_size);

				out_addr->hash_size = ripe_size;
				
			}

		}

	}


fail:

	ZERO_(hash_buff, MAX_PATH);
	ZERO_(tmp_buff, MAX_PATH);


	return is_valid;
}






PBM_MSG_ADDR BM::create_readable_addr(DWORD version, DWORD stream, LPBYTE ripe, DWORD ripe_size, LPBYTE checksum)
{
	PBM_MSG_ADDR ret = FALSE;

	if (version < 3 || version > 4) return FALSE;
	if (stream != 1) return FALSE;
	if (!ripe_size || ripe_size > 20) return FALSE;

	
	PBM_MSG_ADDR _addr = (PBM_MSG_ADDR)ALLOC_(sizeof(BM_MSG_ADDR));

	
	CHAR t[128] = {};
	CHAR x[128] = {};

	BYTE bm_buff[128] = {};
	BYTE _chksm[8] = {};

	DWORD write_offset = 0;

	write_offset += BM::encodeVarint(version, (uint8_t*)&bm_buff[write_offset]);
	write_offset += BM::encodeVarint(stream, (uint8_t*)&bm_buff[write_offset]);


	Utils::copy_mem(&bm_buff[write_offset], 20, ripe, ripe_size);

	write_offset += ripe_size;


	//	Take a double SHA512(hash of a hash) of G 
	Encryption::create_hash((LPSTR)t, (LPBYTE)bm_buff, write_offset, NULL, FALSE, CALG_SHA_512);


	//	and use the first four bytes as a checksum, that you append to the end. (H)
	Encryption::create_hash((LPSTR)x, (LPBYTE)t, 64, _chksm, FALSE, CALG_SHA_512);







	// create the "first_tag" for encrypting the public keys for sending(private usage)
	memcpy_s(_addr->first_tag, 32, x, 32);

	// create the "tag" for identification (public usage)
	memcpy_s(_addr->tag, 32, &x[32], 32);



	// clean up
	ZeroMemory(t, 128);
	ZeroMemory(x, 128);

	// create the address blob to be base58 encoded
	memcpy_s(&bm_buff[2 + ripe_size], 128 - 2 - ripe_size, _chksm, 4);


	//base58 encode H. (J)
	//Put "BM-" in front J. (K)

	strcpy_s((char*)x, 128, "BM-");

	// base58 (address version [04] || stream # [01] || hash [<20] || chechsum [== 4]

	size_t out_s = 125;
	Encryption::b58enc((char*)x + (ULONG_PTR)3, &out_s, bm_buff, 2 + ripe_size + 4);

	DBGOUTa((LPSTR)x);

	strcpy_s((char*)_addr->readable, 64, (char*)x);

	ZeroMemory(x, 128);


	_addr->version = version;
	_addr->stream = stream;
	
	memcpy_s(_addr->checksum, 4, _chksm, 4);
	memcpy_s(_addr->hash, ripe_size, ripe, ripe_size);




	ret = _addr;



	return ret;
}









DWORD BM::create_addr(PBM_MSG_ADDR * in)
{

	if (!in) return FALSE;





	//				(version, stream} 
	BYTE chksm[128] = {	0x04, 0x01 };

	BYTE enc_key_buff[512] = {};
	BYTE sig_key_buff[512] = {};

	BYTE t[512] = {};
	BYTE hash_buff[512] = {};


	LPBYTE tmp_buff = t;
	LPBYTE ripe_hash = NULL;

	PBM_MSG_ADDR addr = NULL;


	addr = (PBM_MSG_ADDR)ALLOC_( sizeof(BM_MSG_ADDR));
	*in = addr;
	/*
	
	Create a private and a public key for encryption and signing(resulting in 4 keys)
	Merge the public part of the signing key and the encryption key together. (encoded in uncompressed X9.62 format) (A)
	
	*/





	addr->version = 4;
	addr->stream = 1;






	//


	int i = 0;
	int j = 0;
	DWORD buff_size = 512;
	DWORD tbuff_size = 512;
	DWORD blob_size = 0;
	BOOL found = FALSE;
	DWORD ripe_size = 20;

	PBCRYPT_ECCKEY_BLOB pblobkey = NULL;

	do {
		tbuff_size = 512;
		tmp_buff = t;

		ZeroMemory(t, 512);
		ZeroMemory(hash_buff, 512);
		
		ZeroMemory(addr->pub_sig_blob, 128);
		ZeroMemory(addr->pub_enc_blob, 128);

		ZeroMemory(addr->prv_sig_blob, 128);
		ZeroMemory(addr->prv_enc_blob, 128);


		addr->enc_handle = NULL;
		addr->sig_handle = NULL;

		DWORD prv_k_s = 128;
		buff_size = 128;

		//	Create SIGN Key
		ECC::create_key_pair(&addr->sig_handle, (PBCRYPT_ECCKEY_BLOB)addr->pub_sig_blob, (PBCRYPT_ECCKEY_BLOB)addr->prv_sig_blob,  &buff_size, &prv_k_s);

		//	Copy to buffer
		memcpy_s(tmp_buff, tbuff_size, &sig_key_buff[8], 64);

		// set new location in buffer
		tmp_buff = tmp_buff + (ULONG_PTR)64;
		tbuff_size = tbuff_size - 64;

		blob_size = 64;

		prv_k_s = 128;
		buff_size = 128;
		

		//	Create Encryption Key
		ECC::create_key_pair(&addr->enc_handle, (PBCRYPT_ECCKEY_BLOB)addr->pub_enc_blob, (PBCRYPT_ECCKEY_BLOB)addr->prv_enc_blob, &buff_size, &prv_k_s);

		blob_size += 64;

		//	Merge with SIGN key. (sign || enc)
		memcpy_s(tmp_buff, tbuff_size, &addr->pub_enc_blob[8], 64);


		//	Take the SHA512 hash of A. (B)
		Encryption::create_hash((LPSTR)hash_buff, t, blob_size, NULL, NULL, CALG_SHA_512);

		ZeroMemory(t, 512);

		//	Take the RIPEMD-160 of B. (C)
		ripmd::calc(addr->hash, hash_buff, 64);

		/*

		Repeat step 1 - 4 until you have a result that starts with a zero(Or two zeros, if you want a short address). (D)
		Remove the zeros at the beginning of D. (E)
		
		*/

		//Utils::compress_ripe(addr->hash, 20, &ripe_size);

		// if compress successfull break;
		//if (ripe_size && ripe_size < 20)
		//{
		found = TRUE;
			break;
		//}
		//else 
		//{
		//	ZERO_(addr->hash, 20);
		//	BCryptDestroyKey(addr->enc_handle);
		//	BCryptDestroyKey(addr->sig_handle);
		//	continue;
		//}


	} while (!found);


	if (found)
	{
		ZeroMemory(t, 512);
		//	Put the stream number(as a var_int) in front of E. (F)
		//	Put the address version(as a var_int) in front of F. (G)

		//memcpy_s(addr->hash, 20, ripe_hash, ripe_size);
		addr->hash_size = ripe_size;

		memcpy_s(&chksm[2], 128 - 2, addr->hash, addr->hash_size);

		//	Take a double SHA512(hash of a hash) of G 
		Encryption::create_hash((LPSTR)t, (LPBYTE)chksm, addr->hash_size + 2, NULL, FALSE, CALG_SHA_512);
		
		ZeroMemory(hash_buff, 512);

		//	and use the first four bytes as a checksum, that you append to the end. (H)
		Encryption::create_hash((LPSTR)hash_buff, (LPBYTE)t, 64, (LPBYTE)&addr->checksum, FALSE, CALG_SHA_512);

		
		// create the "first_tag" for encrypting the public keys for sending(private usage)
		memcpy_s(addr->first_tag, 32, hash_buff, 32);

		// create the "tag" for identification (public usage)
		memcpy_s(addr->tag, 32, &hash_buff[32], 32);



		// clean up
		ZeroMemory(t, 512);
		ZeroMemory(hash_buff, 512);

		// create the address blob to be base58 encoded
		memcpy_s(&chksm[2 + addr->hash_size], 128 - 2 - addr->hash_size, addr->checksum, 4);

	
		//base58 encode H. (J)
		//Put "BM-" in front J. (K)
	
		strcpy_s((char*)hash_buff, 128, "BM-");

		// base58 (address version [01 03] || stream # [01 01] || hash [<20] || chechsum [== 4]

		size_t out_s = 128;
		Encryption::b58enc((char*)hash_buff + (ULONG_PTR)3, &out_s, chksm, 2 + addr->hash_size + 4);

		DBGOUTa((LPSTR)hash_buff);

		strcpy_s((char*)addr->readable, 64, (char*)hash_buff);

		ZeroMemory(hash_buff, 128);

		return TRUE;
	}

	return FALSE;
}


#pragma endregion


#pragma region Encryption


//
//
//	Encryption functions
//
//


DWORD BM::encrypt_payload(PBM_MSG_ADDR dest_addr, LPBYTE in_buff, DWORD in_size, PBM_ENC_PL_256 out, LPDWORD out_size)
{

	//if (in_size > 100)
	//	return FALSE;

	DWORD ret = FALSE;
	BCRYPT_HANDLE tmp_crypt_handle = NULL;

	BYTE tmp_buff_a[512] = {};
	BYTE tmp_buff_b[512] = {};
	BYTE tmp_buff_c[512] = {};
	BYTE tmp_buff_d[512] = {};



	PBCRYPT_ECCKEY_BLOB msg_pub_key = (PBCRYPT_ECCKEY_BLOB)tmp_buff_a;
	PBCRYPT_ECCKEY_BLOB msg_priv_key = (PBCRYPT_ECCKEY_BLOB)tmp_buff_b;

	DWORD pub_key_size = 512;
	DWORD priv_key_size = 512;


	DWORD s = NULL;

	//	The destination public key is called K.

	LPBYTE K = (LPBYTE)dest_addr->pub_enc_blob;



	//	Generate 16 random bytes using a secure random number generator. Call it IV.

	CryptGenRandom(Encryption::context, 16, out->iv);

	//	Generate a new random EC key pair with private key called r and public key called R.

	s = 512;
	ECC::create_key_pair(&tmp_crypt_handle, msg_pub_key, msg_priv_key, &pub_key_size, &priv_key_size);

	LPBYTE r = (LPBYTE)msg_priv_key /*+ (ULONG_PTR)8*/;

	LPBYTE R = (LPBYTE)msg_pub_key + (ULONG_PTR)8;


	//
	//
	//
	//	Do an EC point multiply with public key K and private key r.
	//	This gives you public key P.

	LPBYTE P = NULL;
	BCRYPT_KEY_HANDLE n_r_handle = NULL;
	BCRYPT_KEY_HANDLE n_K_handle = NULL;
	BCRYPT_KEY_HANDLE sec_handle = NULL;

	int e = BCryptImportKeyPair(
		ECC::main_handle,						// Provider handle
		NULL,									// Parameter not used
		BCRYPT_ECCPUBLIC_BLOB,					// Blob type (Null terminated unicode string)
		&n_K_handle,							// Key handle that will be recieved								
		K,										// Buffer than points to the key blob
		64 + 8,	// Buffer length in bytes
		NULL);



	e = BCryptImportKeyPair(
		ECC::main_handle,			// Provider handle
		NULL,                       // Parameter not used
		BCRYPT_ECCPRIVATE_BLOB,     // Blob type (Null terminated unicode string)
		&n_r_handle,				// Key handle that will be recieved

		r,							// Buffer than points to the key blob
		priv_key_size,				// Buffer length in bytes
		NULL);


	BCryptSecretAgreement(n_r_handle, n_K_handle, &sec_handle, NULL);

	s = NULL;


	//	Use the X component of public key P and calculate the SHA512 hash H.

	//	BCryptDeriveKey(HMAC, SHA512);

	BCryptBuffer b_list[1] = {};

	BCryptBufferDesc b_params = {};

	b_list[0].BufferType = KDF_HASH_ALGORITHM;
	b_list[0].cbBuffer = (DWORD)((wcslen(BCRYPT_SHA512_ALGORITHM) + 1) * sizeof(WCHAR));
	b_list[0].pvBuffer = BCRYPT_SHA512_ALGORITHM;

	b_params.cBuffers = 1;
	b_params.pBuffers = b_list;
	b_params.ulVersion = BCRYPTBUFFER_VERSION;
	
	BYTE H[70] = {};


	BCryptDeriveKey(sec_handle, BCRYPT_KDF_HASH, &b_params, H, 70, &s, NULL);

	//	The first 32 bytes of H are called 'key_e' and the last 32 bytes are called 'key_m'.

	BYTE key_e[32] = {};
	BYTE key_m[32] = {};

	memcpy_s(key_e, 32, H, 32);
	memcpy_s(key_m , 32, &H[32], 32);

	ZeroMemory(H, 70);

	s = 0;

	//	Pad the input text to a multiple of 16 bytes, in accordance to PKCS7.

	DWORD new_pad_len = (((in_size / AES_BLOCK_SIZE_) + 1) * AES_BLOCK_SIZE_);
	
	LPBYTE padded_buff =  (LPBYTE)ALLOC_(new_pad_len + 1024);
	
	memset(padded_buff, new_pad_len - in_size, new_pad_len);
	//ZeroMemory(padded_buff, 512);
	
	memcpy_s(padded_buff, new_pad_len, in_buff, in_size);

	//	Encrypt the data with AES - 256 - CBC, using IV as initialization vector
	//	key_e as encryption key 
	//	the padded input text as payload.
	//	Call the output cipher text.
	
	CRYPT_CONTEXT_ context = {};

	//	 signature context
	CRYPT_CONTEXT_ sig_context = {};

	sig_context.context = Encryption::context;
	sig_context.aes_key_size = AES_KEY_SIZE_;

	memcpy_s(sig_context.aes_key, AES_KEY_SIZE_, key_m, AES_KEY_SIZE_);

	Encryption::aes_import_key(&sig_context);

	// Encryption context
	context.context = Encryption::context;
	context.aes_key_size = AES_KEY_SIZE_;
	
	memcpy_s(context.aes_key, AES_KEY_SIZE_, key_e, AES_KEY_SIZE_);

	context.in_buff = padded_buff;
	context.in_size = new_pad_len;// in_size;

	memcpy_s(context.iv, 16, out->iv, 16);


	//	Import the key_e in to the WINCAPI
	Encryption::aes_import_key(&context);





	Encryption::aes_encrypt(&context);





	// make sure to release the context.out_buff

	//	Calculate a 32 byte MAC with HMACSHA256, using key_m as salt and IV + R + cipher text as data.Call the output MAC.

	DWORD sig_buff_size = 16 + 32 + 32 + context.out_size;


	LPBYTE sig_buff = (LPBYTE)ALLOC_(sig_buff_size);

	ZeroMemory(sig_buff, sig_buff_size);

	//if (context.out_size > 512)
	//	return FALSE;

	memcpy_s(sig_buff, 16, out->iv, 16);

	memcpy_s(&sig_buff[16], 64, R, 64);

	memcpy_s(&sig_buff[16 + 32 + 32], sig_buff_size - (16 + 64), context.out_buff, context.out_size);


	LPBYTE MAC = (LPBYTE)Encryption::create_hmac(Encryption::context, sig_buff, sig_buff_size, sig_context.aes_hKey);

	// Build the Encryption blob
	// I use a static buffer to send the text

	// out->iv already set

	if (*out_size < sizeof(BM_ENC_PL_256) + context.out_size + HMAC_LEN)
	{
		ret = FALSE;
		goto clean_up;
	}

	out->curve_type = htons(0x02CA);
	
	out->x_len = htons(32);
	
	memcpy_s(out->x, 32, R, 32);

	out->y_len = htons(32);

	memcpy_s(out->y, 32, &R[32], 32);

	memcpy_s(out->ciph_text, context.out_size, context.out_buff, context.out_size); // we keep a constant message size if the message is MAX 350~ then just make static ...

	memcpy_s(&out->ciph_text[context.out_size], HMAC_LEN, MAC, HMAC_LEN);

	*out_size = sizeof(BM_ENC_PL_256) + context.out_size + HMAC_LEN;

	///------------
	//	Success
	///------------
	ret = TRUE;
clean_up:


	if (padded_buff)
		ZEROFREE_(padded_buff, new_pad_len + 1024);

	if (sec_handle)
		BCryptDestroySecret(sec_handle);

	sec_handle = NULL;

	if (context.aes_hKey)
		CryptDestroyKey(context.aes_hKey);

	if (sig_context.aes_hKey)
		CryptDestroyKey(context.aes_hKey);


	if (context.out_buff && context.out_size)
	{
		ZEROFREE_(context.out_buff, context.out_size);
	}

	ZeroMemory(&context, sizeof(CRYPT_CONTEXT_));
	ZeroMemory(&sig_context, sizeof(CRYPT_CONTEXT_));

	if (sig_buff)
	{
		ZEROFREE_(sig_buff, sig_buff_size);
		sig_buff = NULL;
	}

	if (MAC)
	{
		ZEROFREE_(MAC, HMAC_LEN);
		MAC = NULL;
	}

	return ret;
}










DWORD BM::decrypt_payload(PBM_MSG_ADDR recv_addr, PBM_ENC_PL_256 in_buff, DWORD in_size)
{
	if (in_size <= sizeof(BM_ENC_PL_256) + 32 + 16)
		return FALSE;

	DWORD ret = FALSE;
	
	DWORD enc_pl_size =  in_size - (86 + 32);
	
	//	Dynamic payload size so we must locate the make.........stupid as fuck
	LPBYTE tgt_mac = &in_buff->ciph_text[enc_pl_size];
	//LPBYTE tgt_mac = in_buff->mac;


	BYTE tmp_buff_a[512] = {};

	//	The private key used to decrypt is called k.

	LPBYTE k = (LPBYTE)recv_addr->prv_enc_blob;


	//	Do an EC point multiply with private key k and public key R.This gives you public key P.
	//	Use the X component of public key P and calculate the SHA512 hash H.

	PBCRYPT_ECCKEY_BLOB pub_blob = (PBCRYPT_ECCKEY_BLOB)tmp_buff_a;

	pub_blob->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
	pub_blob->cbKey = (ULONG)htons(in_buff->x_len);

	memcpy_s(&tmp_buff_a[8], 32, in_buff->x, 32);
	memcpy_s(&tmp_buff_a[8 + 32], 32, in_buff->y, 32);

	BCRYPT_ALG_HANDLE pub_handle = NULL;
	BCRYPT_ALG_HANDLE priv_handle = NULL;
	BCRYPT_SECRET_HANDLE sec_handle = NULL;


	int e = BCryptImportKeyPair(
		ECC::main_handle,						// Provider handle
		NULL,									// Parameter not used
		BCRYPT_ECCPUBLIC_BLOB,					// Blob type (Null terminated unicode string)
		&pub_handle,							// Key handle that will be recieved								
		(PUCHAR)pub_blob,						// Buffer than points to the key blob
		64 + 8,									// Buffer length in bytes
		NULL);


	e = BCryptImportKeyPair(
		ECC::main_handle,						// Provider handle
		NULL,									// Parameter not used
		BCRYPT_ECCPRIVATE_BLOB,					// Blob type (Null terminated unicode string)
		&priv_handle,							// Key handle that will be recieved								
		(PUCHAR)recv_addr->prv_enc_blob,		// Buffer than points to the key blob
		32 + 32 + 32 + 8,						// Buffer length in bytes
		NULL);

	BCryptSecretAgreement(priv_handle, pub_handle, &sec_handle, NULL);

	DWORD s = NULL;


	//	Use the X component of public key P and calculate the SHA512 hash H.

	//	BCryptDeriveKey(HMAC, SHA512);
	
	BYTE H[70] = {};
	BCryptBuffer b_list[1] = {};
	BCryptBufferDesc b_params = {};


	b_list[0].BufferType = KDF_HASH_ALGORITHM;
	b_list[0].cbBuffer = (DWORD)((wcslen(BCRYPT_SHA512_ALGORITHM) + 1) * sizeof(WCHAR));
	b_list[0].pvBuffer = BCRYPT_SHA512_ALGORITHM;


	b_params.cBuffers = 1;
	b_params.pBuffers = b_list;
	b_params.ulVersion = BCRYPTBUFFER_VERSION;

	
	BCryptDeriveKey(sec_handle, BCRYPT_KDF_HASH, &b_params, H, 70, &s, NULL);

	//	The first 32 bytes of H are called key_e and the last 32 bytes are called key_m.

	BYTE key_e[BM_TAG_LEN] = {};
	BYTE key_m[BM_TAG_LEN] = {};

	memcpy_s(key_e, BM_TAG_LEN, H, BM_TAG_LEN);
	memcpy_s(key_m, BM_TAG_LEN, &H[BM_TAG_LEN], BM_TAG_LEN);

	ZeroMemory(H, 70);

	//	Calculate MAC with HMACSHA256, using key_m as salt and IV + R + cipher text as data.

	

	DWORD sig_buff_size = 16 + 32 + 32 + enc_pl_size;

	LPBYTE sig_buff = (LPBYTE)ALLOC_( sig_buff_size);

	memcpy_s(sig_buff, 16, in_buff->iv, 16);							//	IV
	memcpy_s(&sig_buff[16], 32, in_buff->x, 32);						//	R
	memcpy_s(&sig_buff[16 + 32], 32, in_buff->y, 32);					//	"
	memcpy_s(&sig_buff[16 + 32 + 32], enc_pl_size, in_buff->ciph_text, enc_pl_size);//	cipher_text


	CRYPT_CONTEXT_ sig_context = {};

	sig_context.context = Encryption::context;
	memcpy_s(sig_context.aes_key, AES_KEY_SIZE_, key_m, AES_KEY_SIZE_);

	Encryption::aes_import_key(&sig_context);

	LPBYTE MAC = (LPBYTE)Encryption::create_hmac(Encryption::context, sig_buff, sig_buff_size, sig_context.aes_hKey);

	//	Compare MAC with MAC. If not equal, decryption will fail.


	if (!MAC || memcmp(tgt_mac, MAC, HMAC_LEN))
	{
		//DBGOUTa("\rHMAC Failed to validate.\r");
		return FALSE;
	}


	//	Decrypt the cipher text with AES - 256 - CBC, using IV as initialization vector, key_e as decryption key and the cipher text as payload.The output is the padded input text.

	CRYPT_CONTEXT_ context = {};
	
	context.context = Encryption::context;
	
	memcpy_s(context.aes_key, AES_KEY_SIZE_, key_e, AES_KEY_SIZE_);
	
	context.aes_key_size = AES_KEY_SIZE_;
	context.in_buff = in_buff->ciph_text;
	context.in_size = enc_pl_size;// in_size - 106;// 106 is the size of static data in the payload blob
	
	memcpy_s(context.iv, 16, in_buff->iv, 16);

	
	Encryption::aes_import_key(&context); // import the key and store in context->aes_hkey



	Encryption::aes_decrypt(&context); //	decrypt the buffer and create new in context->out_buff
	




	ret = context.out_size;

	ZeroMemory(in_buff->ciph_text, enc_pl_size);
	
	memcpy_s(in_buff->ciph_text, context.out_size, context.out_buff, context.out_size);// upon succes, copy the decrypted buffer in the old cipher text buffer

	
	///------------
	//	SUCCESS
	///------------

	if (sec_handle)
		BCryptDestroySecret(sec_handle);

	sec_handle = NULL;

	if (context.aes_hKey)
		CryptDestroyKey(context.aes_hKey);

	if (sig_context.aes_hKey)
		CryptDestroyKey(context.aes_hKey);


	if (context.out_buff && context.out_size)
	{
		ZEROFREE_(context.out_buff, context.out_size);
	}

	ZeroMemory(&context, sizeof(CRYPT_CONTEXT_));
	ZeroMemory(&sig_context, sizeof(CRYPT_CONTEXT_));

	if (sig_buff)
	{
		ZEROFREE_(sig_buff, sig_buff_size);
		sig_buff = NULL;
	}

	if (MAC)
	{
		ZEROFREE_(MAC, HMAC_LEN);
		MAC = NULL;
	}

	return ret;
}

#pragma endregion


#pragma region ObjectHandling


//
//
//	Object handling functions
//
//

BOOL BM::create_vector_tag(LPBYTE payload, DWORD pl_size, LPBYTE out, DWORD size)
{

	// ADD ERROR CHECKING!!
	char tmp[MAX_PATH] = {};
	char hash[MAX_PATH] = {};
	
	BOOL ret = FALSE;

	ret = Encryption::create_hash(tmp, payload, pl_size, NULL, FALSE, CALG_SHA_512);
	ret = Encryption::create_hash(hash, (LPBYTE)tmp, 64, NULL, FALSE, CALG_SHA_512);

	memcpy_s(out, size, hash, 32);

	return ret;
}

DWORD BM::process_object(PBM_OBJECT object, DWORD object_size, LPBYTE vector)
{

	LPBYTE buff = (LPBYTE)ALLOC_(1024);
	ZERO_(buff, 1024);
	//LPSTR hash = (LPSTR)buff;
	//ZERO_(hash, 64);
	//LPSTR old_hash = (LPSTR)&buff[512];
	//ZERO_(old_hash, 64);

	DWORD ret = FALSE;
	//	Calculate a double sha512 from the payload. the first 32 bytes are the hash.
	//	Store the object as a vector if it doesnt already exist.
	//	If it does exist then exit.
 

	uint64_t curr_time = BM::unix_time();
	uint64_t exp_time = swap64(object->expiresTime);


	if (curr_time >= exp_time)
	{
	
		DBGOUTa("\rObject has expired!!\r");
		
		goto fail;

	}

	DWORD64 ttl = exp_time - curr_time;

	if (!BM::check_pow((LPBYTE)object, object_size, ttl))
	{
		DBGOUTa("\robject - Proof of Work FAILED!\r");
		
		goto fail;
	}



	// parse the version and the stream.
	
	size_t v_offset = 0;
	size_t s_offset = 0;
	size_t read_offset = 0;



	DWORD version = 0;// Should be >= 4 or 1 for msg type
	DWORD stream = 0;// Should most often be 1

	version = (DWORD)BM::decodeVarint(object->objectVersion, 2, &v_offset);
	stream = (DWORD)BM::decodeVarint((uint8_t*)(((ULONG_PTR)object->objectVersion) + read_offset), 2, &s_offset);

	read_offset = v_offset + s_offset;

	ULONG_PTR payload = ((ULONG_PTR)object->objectVersion) + read_offset;

	DWORD obj_hdr_s = (20 + read_offset);

	DWORD payload_size = object_size - (obj_hdr_s);



	PBM_MSG_HDR msg_hdr = NULL;
	DWORD msg_hdr_s = BM_OPK_BS;

//	PBM_OBJECT obj_hdr = NULL;
	

	LPBYTE pl = NULL;

	CHAR dbgs[512] = { NULL };
	wsprintfA(dbgs, "Size of payload %u\r", payload_size);
	DBGOUTa(dbgs);
	ZERO_(dbgs, 512);




	switch (htonl(object->objectType))
	{

	case BM_OBJ_GETPUBKEY:
	{
		// search objects for the matching key
		// return the keys via pubkey object
		// otherwise propogate request

		DBGOUTa("\rin->obj->getpubkey\r");

		BM_MSG_ADDR address_info = {};

		if (version < 4)
			break;

		if (!BMDB::address_find(NULL, NULL, (LPBYTE)payload, &address_info))
			break;

		
		if (!*(DWORD64*)&address_info.pub_enc_blob[0])
			break;


		PBM_MSG_HDR msg_hdr = (PBM_MSG_HDR)ALLOC_(BM_OPK_BS); // Let APC Thread Handle the memory
		ZERO_(msg_hdr, BM_OPK_BS);

		pl = GET_OBJ_PL(LPBYTE, msg_hdr);

		PBM_OBJECT _obj = (PBM_OBJECT)msg_hdr->payload;

		DWORD pl_size = PK_PL_BS;

		// set the expires time before the init_object function to use it for DSA signing.
		_obj->expiresTime = swap64(unix_time() + (60 * 60) + 100);
		_obj->objectType = htonl(BM_OBJ_PUBKEY);
		
		DWORD write_offset = BM::encodeVarint(4, _obj->objectVersion);
		write_offset = BM::encodeVarint(1, &_obj->objectVersion[write_offset]);


		// locate the keys if we have them.
		DWORD found = BM::obj_getpubkey(_obj, &address_info, pl, &pl_size);
		
		

		if (found)
		{

			// propogate the newly found pubkeys.
			
			
			DWORD obj_size = BM::init_object(_obj, 512, BM_OBJ_PUBKEY, pl, pl_size);

			BM::init_msg_hdr(msg_hdr, obj_size, "object");

			BYTE vect[32] = {};

			BM::create_vector_tag(msg_hdr->payload, obj_size, vect, 32);

			BMDB::vector_add(vect, (PBM_OBJECT)msg_hdr->payload, obj_size);
			
			DWORD inv_id = BMDB::vector_find(0, vect, 0, 0);

			network::queue_obj(0, inv_id);

			ret = TRUE;
			
		}
		else

		{
			// if not found propgate the getpubkey object
			ret = FALSE;

			// Free msg_hdr here otherwise let the APC handle it.
			ZEROFREE_(msg_hdr, BM_OPK_BS);
		}


		break;

	}

	case BM_OBJ_PUBKEY:
	{
		// https://bitmessage.org/wiki/Protocol_specification#pubkey
	
		// receive a public key
		// attempt to locate
		// if found then decrypt using the priv_tag and ECDH
		// otherwise propgate the pubkey object
		// store in adress_book
	
		
		DBGOUTa("in->obj->pubkey\r");
	
		ret = FALSE; // FALSE == propogate

		BM_MSG_ADDR _addr = {};

		BOOL found = BMDB::address_find(NULL, NULL, (LPBYTE)payload, &_addr);
		
		if (found)			
			ret = BM::obj_pubkey(&_addr, object, obj_hdr_s, (PBM_PUBKEY_V4_OBJ)payload, payload_size);

		if (ret)
		{
			DBGOUTa("\nSuccessfully decrypted and added public keys to the DB for ");
			DBGOUTa(_addr.readable);
			DBGOUTa("\n");
		}




		break;
	}

	case BM_OBJ_MSG:
	{
		DBGOUTa("in->obj->msg\r");

		ret = FALSE;
		if (payload_size <= 400)
		{
			DBGOUTa("Found our msg?\r");
		}
		//attempt to decrypt the msg, if not then propogate.
		BM::obj_msg(object, (PBM_ENC_PL_256)payload, payload_size);


		break;
	}

	case BM_OBJ_BROADCAST:
	{
		DBGOUTa("\rin->obj->broadcast\r");

		ret = FALSE;

		// do not process just add to inventory
		// let it propagate

		//BM::obj_broadcast();
		break;
	}

	default:
	{
		DBGOUTa("\rin->obj->????\r");

		break;
	}


	}


	BMDB::vector_add(vector, object, object_size);



fail:


	ZEROFREE_(buff, 1024);

	// return wether or not we want to propagate the object further.
	return ret;
}





DWORD BM::init_object(PBM_OBJECT out_obj, DWORD out_size, uint32_t type, LPBYTE pl, DWORD payload_len)
{
	uint64_t t = BM::unix_time();
	uint64_t ttl = 60 * 60 + 100; // one hour plus some.
	uint64_t exp = (t + ttl);

	// init
	if (!out_obj->expiresTime)
	{
		out_obj->expiresTime = BM::swap64(exp);	
	}	


	out_obj->objectType = htonl(type);
	

	size_t write_offset = 0;

	if (type == BM_OBJ_MSG)
	{
		write_offset += BM::encodeVarint(1, out_obj->objectVersion);	
	}
	else {
		
		write_offset += BM::encodeVarint(4, out_obj->objectVersion);	
	}

	write_offset += BM::encodeVarint(1, (uint8_t*)((ULONG_PTR)out_obj->objectVersion) + write_offset);

	memcpy_s((uint8_t*)(((ULONG_PTR)&out_obj->objectVersion) + write_offset), out_size, pl, payload_len);
	

	out_obj->nonce = BM::swap64(BM::do_pow((LPBYTE)&out_obj->expiresTime, ((20 + write_offset) - 8) + payload_len, ttl));



	return (20 + write_offset + payload_len);
}






DWORD BM::create_tags(LPBYTE enc, LPBYTE sig, LPBYTE out)
{

	BYTE t_buff_a[128] = {};
	BYTE t_buff_b[128] = {};
	DWORD new_ripe_s = NULL;

	memcpy_s(t_buff_a, 64, enc, 64);
	memcpy_s(&t_buff_a[64], 64, sig, 64);


	// Step one create SHA512 of the public keys
	Encryption::create_hash((LPSTR)t_buff_b, t_buff_a, 64 + 64, NULL, NULL, CALG_SHA_512);
	ZERO_(t_buff_a, 128);

	//	Take the RIPEMD-160 of B. (C)
	ripmd::calc(t_buff_a, t_buff_b, 64);

	ZERO_(t_buff_b, 64);

	// remove leading 00s
	Utils::compress_ripe(t_buff_a, 20, &new_ripe_s);

	//version
	t_buff_b[0] = 0x04;

	// stream number
	t_buff_b[1] = 0x01;

	// copy the compressed ripe
	memcpy_s(&t_buff_b[2], 64 - 2, t_buff_a, new_ripe_s);

	ZERO_(t_buff_a, 64);

	// create the double sha512;
	Encryption::create_hash((LPSTR)t_buff_a, t_buff_b, new_ripe_s + 2, NULL, NULL, CALG_SHA_512);

	ZERO_(t_buff_b, 64);
	// "
	Encryption::create_hash((LPSTR)t_buff_b, t_buff_a, 64, NULL, NULL, CALG_SHA_512);
	
	ZERO_(t_buff_a, 64);

	memcpy_s(out, 64, t_buff_b, 64);

	ZERO_(t_buff_b, 64);

	return TRUE;
}









DWORD BM::obj_getpubkey(PBM_OBJECT in, PBM_MSG_ADDR address_info, LPBYTE pl, LPDWORD out_size)// difference between v3-4 is encryption
{

	BYTE tmp_buff_a[64] = {};

	DWORD hash_size = 0;
	LPBYTE hash = tmp_buff_a;

	size_t ver_len = 0;

	//
	//	start to build the packet
	//

	ZERO_(tmp_buff_a, 64);

	BYTE temp_obj[512] = {};
	
	
	
	PBM_PUBKEY_V3_OBJ tb = NULL;
	
	LPBYTE priv_tag = address_info->first_tag;
	LPBYTE pub_tag = address_info->tag;

	DSA_CONTEXT dsa_context = {};
	DWORD j = NULL;

	
	//	Here we set up the ECDSA signature buffer

	memcpy_s(temp_obj, 14, &in->expiresTime, 14);
	//memcpy_s(&temp_obj[8], 4, &in->objectType, 4);
	//memcpy_s(&temp_obj[8 + 4], 1, &in->objectVersion[0], 1);
	//memcpy_s(&temp_obj[8 + 4 + 1], 1, &in->objectVersion[1], 1);


	tb = (PBM_PUBKEY_V3_OBJ)&temp_obj[14];

	// More ECDSA but we will use this struct to encrypt + send out as well.

	//	https://bitmessage.org/wiki/Protocol_specification#Pubkey_bitfield_features (optional)
	tb->behavior = NULL;// 29 	extended_encoding 	// 30 	include_destination // 31 	does_ack // 


	memcpy_s(tb->sign_key, 64, &address_info->pub_sig_blob[8], 64);

	memcpy_s(tb->enc_key, 64, &address_info->pub_enc_blob[8], 64);

	DWORD write_offset = NULL;
	

	//nonce_trails_per_byte
	write_offset += BM::encodeVarint(1000, &tb->nonce_trials_per_byte[0]);
	//extra_bytes
	write_offset += BM::encodeVarint(1000, &tb->nonce_trials_per_byte[write_offset]);




	//
	//	start ECDSA signature stuffz
	//	____________________________
	//
	//

	ZERO_(tmp_buff_a, 64);

	dsa_context.buffer = temp_obj;
	dsa_context.sign_size = 14 + 132 + write_offset;

	dsa_context.private_key = priv_tag;
	dsa_context.priv_key_size = 32;

	dsa_context.out_sig = tmp_buff_a;
	dsa_context.sig_size = 64;

	// Create the ECDSA signature
	DBGOUTw(L"\nCreate DSA signature - size:");
	wchar_t ss[8] = {};
	wsprintfW(ss, L"%d\n", dsa_context.sign_size);
	DBGOUTw(ss);


	j = ECC::create_dsa_sig(&dsa_context);

	if (!j)
		return FALSE;

	//	success
	//	insert the ECDSA signature.



	// sig size
	write_offset += BM::encodeVarint(64, &tb->nonce_trials_per_byte[write_offset]);

	memcpy_s(&tb->nonce_trials_per_byte[write_offset], 64, dsa_context.out_sig, 64);

	write_offset += 64;




	ZERO_(tmp_buff_a, 64);
	// Encrypt the pubkeys...finally..

	//BM_ENC_PL_256 pl = {};
	DWORD payload_len = *out_size;

	BM_MSG_ADDR km = {};
	BCRYPT_KEY_HANDLE kh = NULL;
	BYTE kb[128] = {};
	BYTE kb_pub[128] = {};


	((PBCRYPT_ECCKEY_BLOB)kb)->dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
	((PBCRYPT_ECCKEY_BLOB)kb)->cbKey = 32;

	//	Insert the priv_tag to the ecc key blob
	memcpy_s(&kb[8 + 32 + 32], 32, priv_tag, 32);

	//	importing the key blob gives us our public key.
	BCryptImportKeyPair(ECC::main_handle, NULL, BCRYPT_ECCPRIVATE_BLOB, &kh, kb, 8 + 32 + 32 + 32, BCRYPT_NO_KEY_VALIDATION);

	

	//	Retrieve the public key
	BCryptExportKey(kh, NULL, BCRYPT_ECCPUBLIC_BLOB, kb_pub, 128, &j, NULL);

	//	encrypt the pubkey struct in to a payload struct.
	memcpy_s(km.pub_enc_blob, 128, kb_pub, 8 + 32 + 32);
	//memcpy_s(km.prv_enc_blob, 32, kb, 8 + 32 + 32 + 32);


	memcpy_s(pl, BM_TAG_LEN, pub_tag, BM_TAG_LEN);

	

	// create a "tagged envelope" as the payload
	PBM_ENC_PL_256 out_pl = (PBM_ENC_PL_256)&pl[32];

	BM::encrypt_payload(&km, (LPBYTE)tb, sizeof(BM_PUBKEY_V3_OBJ) + write_offset, out_pl, &payload_len);

	ZERO_(kb, 128);

	if (kh)
		BCryptDestroyKey(kh);


	*out_size = BM_TAG_LEN + payload_len;

	return TRUE;

}





DWORD BM::obj_pubkey(PBM_MSG_ADDR addr, PBM_OBJECT object, DWORD obj_hdr_size, PBM_PUBKEY_V4_OBJ payload, DWORD pl_size)
{
	if (!addr) return FALSE;

	DWORD ret = FALSE;


	PBM_MSG_ADDR km = (PBM_MSG_ADDR)ALLOC_(512);
	BCRYPT_KEY_HANDLE kh = NULL;
	BYTE kb[128] = {};
	BYTE kb_pub[128] = {};


	((PBCRYPT_ECCKEY_BLOB)kb)->dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
	((PBCRYPT_ECCKEY_BLOB)kb)->cbKey = 32;

	//	Insert the priv_tag to the ecc key blob
	memcpy_s(&kb[8 + 32 + 32], 32, addr->first_tag, 32);

	//	importing the key blob gives us our public key.
	//	must use BCRYPT_NO_KEY_VALIDATION or else call to BCryptImportKeyPair will fail
	BCryptImportKeyPair(ECC::main_handle, NULL, BCRYPT_ECCPRIVATE_BLOB, &kh, kb, 8 + 32 + 32 + 32, BCRYPT_NO_KEY_VALIDATION);

	DWORD j = 0;

	//	Retrieve the public key
	BCryptExportKey(kh, NULL, BCRYPT_ECCPUBLIC_BLOB, kb_pub, 128, &j, NULL);

	//	encrypt the pubkey struct in to a payload struct.
	memcpy_s(km->pub_enc_blob, 128, kb_pub, 8 + 32 + 32);
	memcpy_s(km->prv_enc_blob, 128, kb, 8 + 32 + 32 + 32);

	PBM_ENC_PL_256 decrypted_data = (PBM_ENC_PL_256)payload->encrypted;
	

	


	// decrypt data
	DWORD dec_data_size = BM::decrypt_payload(km, decrypted_data, pl_size - 32);




	// extract the info from the decrypted data.

	PBM_PUBKEY_V3_OBJ dec_data = (PBM_PUBKEY_V3_OBJ)decrypted_data->ciph_text;

	

	size_t read_pos = 0;
	size_t rp = 0;

	DWORD nonce_trials = (DWORD)BM::decodeVarint(dec_data->nonce_trials_per_byte, 10, &read_pos);

	rp += read_pos;

	DWORD extra_bytes = (DWORD)BM::decodeVarint(dec_data->nonce_trials_per_byte + rp, 10, &read_pos);

	rp += read_pos;

	DWORD sig_size = (DWORD)BM::decodeVarint(dec_data->nonce_trials_per_byte + rp, 10, &read_pos);

	rp += read_pos;

	LPBYTE _sig = dec_data->nonce_trials_per_byte + rp;

	rp += sig_size;

	// verify DSA sig starting from the object header EXPIRES TIME then appending the decrypted data to extra bytes
	
	// reuse the km buffer
	ZERO_(km, 512);

	DWORD obj_no_nonce_size = obj_hdr_size - 8/*size of nonce*/;
	DWORD pk_no_sig_size = 4 + 64 + 64 + 3 + 3;
	DWORD sign_size = obj_no_nonce_size + pk_no_sig_size;


	// create the buffer to be signed
	// header of the obj
	Utils::copy_mem(km, 512, &object->expiresTime, obj_no_nonce_size);
	
	// decrypted payload without the sig
	Utils::copy_mem((LPBYTE)((ULONG_PTR)km + (ULONG_PTR)obj_no_nonce_size), 512 - obj_no_nonce_size, dec_data, pk_no_sig_size);



	wchar_t ss[8] = {};
	DBGOUTw(L"\nVerify DSA Signature. - size: ");
	wsprintfW(ss,L"%d\n", sign_size);
	DBGOUTw(ss);


	// actual verfication

	if (ECC::verify_dsa_sig(km, sign_size, addr->first_tag, 32, _sig, sig_size))
	{
		// if all is good add the public keys the the DB.

		PBCRYPT_ECCKEY_BLOB peb = (PBCRYPT_ECCKEY_BLOB)addr->pub_enc_blob;
		PBCRYPT_ECCKEY_BLOB psb = (PBCRYPT_ECCKEY_BLOB)addr->pub_sig_blob;

		peb->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
		psb->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;

		peb->cbKey = 32;
		psb->cbKey = 32;
		

		Utils::copy_mem(&addr->pub_enc_blob[8], 120, dec_data->enc_key, 64);
		Utils::copy_mem(&addr->pub_sig_blob[8], 120, dec_data->sign_key, 64);
		

		LPSTR s = "UPDATE address_book SET blob=? WHERE id=?";
		sqlite3_stmt * stmt = NULL;

		sqlite3_prepare(BM::db, s, -1, &stmt, NULL);


		sqlite3_bind_blob(stmt, 1, addr, sizeof(BM_MSG_ADDR), NULL);

		sqlite3_bind_int(stmt, 2, addr->db_id);

		sqlite3_step(stmt);

		sqlite3_finalize(stmt);

		ret = TRUE;
		
	}


	return ret;
}





DWORD BM::obj_msg(PBM_OBJECT obj, PBM_ENC_PL_256 in, DWORD in_size)
{
	DWORD _obj_size = 22 + in_size;
	PBM_OBJECT _obj = (PBM_OBJECT)ALLOC_(_obj_size);
	ZERO_(_obj, _obj_size);


	Utils::copy_mem(_obj, _obj_size, obj, _obj_size);

	DWORD addr_id = BMDB::atmpt_msg_decrypt(in, in_size);

	DWORD dsa_sig_buff_size = NULL;
	LPBYTE dsa_buff = NULL;

	if (!addr_id) {
		DBGOUTa("Message Decryption Failed!\n");
	}
	else{

		DBGOUTa("Message Decryption Successful!\n");

		// check the DSA signature

		BM_MSG_ADDR to_addr = {};

		BMDB::address_find(addr_id, 0, 0, &to_addr);


		size_t read_size = 0;

		DWORD read_offset = 0;

		
		DWORD sender_addr_version = (DWORD)BM::decodeVarint(in->ciph_text, 2, &read_size);
		read_offset += read_size;

		DWORD sender_addr_stream = (DWORD)BM::decodeVarint(&in->ciph_text[read_offset], 2, &read_size);
		read_offset += read_size;

		DWORD sender_behavour_bitfield = (DWORD)htonl(*((DWORD*)&in->ciph_text[read_offset]));
		read_offset += 4;


		LPBYTE sender_pub_sign_key = &in->ciph_text[read_offset];
		read_offset += 64;

		LPBYTE sender_pub_enc_key = &in->ciph_text[read_offset];
		read_offset += 64;


		DWORD sender_nonce_trails_per_byte = (DWORD)BM::decodeVarint(&in->ciph_text[read_offset], 9, &read_size);
		read_offset += read_size;


		DWORD sender_extra_bytes = (DWORD)BM::decodeVarint(&in->ciph_text[read_offset], 9, &read_size);
		read_offset += read_size;


		LPBYTE dest_ripe = &in->ciph_text[read_offset];
		read_offset += 20;

		DWORD encoding_type = (DWORD)BM::decodeVarint(&in->ciph_text[read_offset], 9, &read_size);
		read_offset += read_size;


		DWORD msg_size = (DWORD)BM::decodeVarint(&in->ciph_text[read_offset], 9, &read_size);
		read_offset += read_size;


		LPBYTE encoded_msg = &in->ciph_text[read_offset];
		read_offset += msg_size;


		DWORD ack_length = (DWORD)BM::decodeVarint(&in->ciph_text[read_offset], 9, &read_size);
		read_offset += read_size;



		LPBYTE ack_data = NULL;
		
		if (ack_length > 0)
		{
			ack_data = &in->ciph_text[read_offset];
			read_offset += ack_length;
		}


		DWORD sig_length = (DWORD)BM::decodeVarint(&in->ciph_text[read_offset], 9, &read_size);
		read_offset += read_size;


		LPBYTE _dsa_sig = &in->ciph_text[read_offset];
		read_offset += sig_length;






		DWORD unenc_sig_size = (read_offset - 65);
		
		dsa_sig_buff_size = 14 + unenc_sig_size;
		dsa_buff = (LPBYTE)ALLOC_(dsa_sig_buff_size);
	
		BYTE out_sig[128] = {};

		Utils::copy_mem(dsa_buff, 14, &obj->expiresTime, 14);
		Utils::copy_mem(&dsa_buff[14], unenc_sig_size, in->ciph_text, unenc_sig_size);




		if (!ECC::verify_dsa_sig(dsa_buff, dsa_sig_buff_size, to_addr.first_tag, 32, _dsa_sig, 64))
			goto fail;

		
		{

			DWORD ripe_size = 0;


			LPBYTE tmp_buff = out_sig;
			BYTE hash_buff[128] = {};

			memcpy_s(tmp_buff, 64, sender_pub_sign_key, 64);
			memcpy_s(&tmp_buff[64], 64, sender_pub_enc_key, 64);



			//	Take the SHA512 hash of A. (B)
			Encryption::create_hash((LPSTR)hash_buff, tmp_buff, 128, NULL, NULL, CALG_SHA_512);

			ZERO_(tmp_buff, 128);

			//	Take the RIPEMD-160 of B. (C)
			ripmd::calc(tmp_buff, hash_buff, 64);



		//	Utils::compress_ripe(tmp_buff, 20, &ripe_size);

			LPBYTE sender_ripe = tmp_buff;

			ripe_size = 20;

			PBM_MSG_ADDR _from_addr = BM::create_readable_addr(sender_addr_version, sender_addr_stream, sender_ripe, ripe_size, NULL);


			BCRYPT_ECCKEY_BLOB* psb = (BCRYPT_ECCKEY_BLOB*)&_from_addr->pub_sig_blob[0];
			BCRYPT_ECCKEY_BLOB* peb = (BCRYPT_ECCKEY_BLOB*)&_from_addr->pub_enc_blob[0];

			psb->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
			peb->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;

			psb->cbKey = 32;
			peb->cbKey = 32;
			

			Utils::copy_mem(&_from_addr->pub_sig_blob[8], 120, sender_pub_sign_key, 64);
			Utils::copy_mem(&_from_addr->pub_enc_blob[8], 120, sender_pub_enc_key, 64);

			
			DWORD found = BMDB::address_add(_from_addr, L"none");

			
			found = BMDB::address_find(0, _from_addr->readable, 0, _from_addr);


			if (!found)
			{
				DBGOUTw(L"BM::address_find() failed during BM::obj_msg");
				//goto msg_fail;
			}


			BYTE vect_tag[64] = {};
			BM::create_vector_tag((LPBYTE)_obj, _obj_size, vect_tag, 64);




			BMDB::vector_add(vect_tag, _obj, _obj_size);
			
			DWORD inv_id = BMDB::vector_find(0, vect_tag, 0, 0);


			LPSTR plain_message = NULL;
			LPSTR plain_subject = NULL;


			// https://bitmessage.org/wiki/Protocol_specification#Message_Encodings
			//
			
			if (encoding_type == BM_ENCODING_SIMPLE)
			{
				if (msg_size > 18)
				{
					//
					// messageToTransmit = 'Subject:' + subject + '\n' + 'Body:' + message

					plain_subject = (LPSTR)&encoded_msg[8];

					plain_message = (LPSTR)Utils::in_mem((LPBYTE)"\nBody:", 6, encoded_msg, msg_size);

					if (plain_message)
					{
						plain_message[0] = '\0';

						plain_message = &plain_message[6];

						BMDB::add_message(addr_id, _from_addr->db_id, plain_subject, plain_message, 1, inv_id);
					}
					else {
						DBGOUTw(L"Error! - Message failed to be decoded.");
					}
				}
				else {
					DBGOUTw(L"Error! - Message length should be larger then 18 if encoding of SIMPLE type.");
				}

			}
			else
			{	
				DBGOUTw(L"Error! - This client doe's not support this message encoding type.");
			}


			ZERO_(encoded_msg, msg_size);

		}


//	msg_fail:

		ZEROFREE_(dsa_buff, dsa_sig_buff_size);


	}	




fail:

	ZEROFREE_(_obj, _obj_size);


	return FALSE;

}




#pragma endregion










#pragma region ConnectionHandling


//
//
//	Connection functions
//
//
DWORD BM::receive_addr_list(LPBYTE payload, DWORD in_size)
{

	if (!payload)
		return FALSE;

	DWORD max_addrs = 0;

	size_t int_len = 0;
	DWORD n_entrys = (DWORD)BM::decodeVarint(payload, 4, &int_len);
	DWORD offset = sizeof(BM_ADDR);

	max_addrs = (in_size - int_len) / offset;





	s_list * list = (s_list *)&payload[int_len]; // get position of the list after the Var Int.
	PBM_ADDR addr = NULL;

	ULONGLONG cur_time = BM::unix_time();
	ULONGLONG fwd_time = cur_time + 60 * 60 * 3;
	ULONGLONG bck_time = cur_time - DAY_SECONDS(3);

	ULONGLONG addr_time = NULL;
	ULONGLONG services = NULL;

	PBM_CONN conn = NULL;

	uint32_t ip = NULL;
	uint16_t port = NULL;
	PBM_NODE bma = NULL;


	if (n_entrys > 1000)
		return FALSE;


	for (DWORD i = 0; i < n_entrys && i < max_addrs; i++)
	{
		conn = NULL;
		addr = (PBM_ADDR)&list[i].addr;

		if ((*(uint64_t*)addr->time) == NULL)
			break;

		// correct endianess
		addr_time = BM::swap64((*(uint64_t*)addr->time));
		services = BM::swap64((*(uint64_t*)addr->services));
		ip = htonl(*(uint32_t*)&addr->ip[12]);
		port = htons(*(uint16_t*)addr->port);

		//	Validate time
		if ((addr_time < fwd_time) && (addr_time > bck_time))
		{

			// validate the services
			if ((services & BM_NODE_NETWORK) == BM_NODE_NETWORK)
			{

				// add the node to the list
				BMDB::node_add(addr);

			}
		}


		// enumerate the list.
		//list = &list[offset * i];

	}
	return TRUE;
}

DWORD BM::init_msg_hdr(PBM_MSG_HDR in, DWORD pl_s, LPSTR command)
{

	DWORD ret = FALSE;

	TYPECH(uint32_t, in->magic, BM_MAGIC); //	magic
	
	ZERO_(in->command, 12);
	
	memcpy_s((char*)in->command, 12, command, lstrlenA(command));

	TYPECH(uint32_t, in->length, htonl(pl_s));
	
	LPSTR hash = (LPSTR)LocalAlloc(LPTR,MAX_PATH);

	Encryption::create_hash(hash, in->payload, pl_s, in->checksum, FALSE, CALG_SHA_512);

	LocalFree(hash);

	return 24 + pl_s;

}



DWORD BM::init_con(PBM_MSG_HDR* in_, long toip, uint16_t toport)
{
	DWORD pl_s = sizeof(BM_MSG_HDR) + sizeof(BM_PL_VER) + 64;

	PBM_MSG_HDR in = (PBM_MSG_HDR)ALLOC_(pl_s);
	ZERO_(in, pl_s);
	
	
	PBM_PL_VER ver = (PBM_PL_VER)in->payload;

	BYTE m[4] = { 0xE9,0xBE, 0xB4, 0xD9 };
	memcpy_s(in->magic, 4, m, 4);
	
	memcpy_s((char*)in->command, 12, "version", 7);

	
	// init version payload
	DWORD ver_pl_s = BM::init_ver(ver, toip, toport); // return version payload size
	


	TYPECH(uint32_t, in->length, htonl(ver_pl_s));
	
	LPSTR hash = (LPSTR)ALLOC_(MAX_PATH);
	
	ZERO_(hash, MAX_PATH);

	Encryption::create_hash(hash, in->payload, sizeof(BM_PL_VER), in->checksum, FALSE, CALG_SHA_512);

	ZEROFREE_(hash, MAX_PATH);

	*in_ = in;


	return (sizeof(BM_MSG_HDR) + (ver_pl_s));
}


DWORD BM::init_ver(PBM_PL_VER version_pl, long ip_to, uint16_t port_to)
{
	// THIS CLIENT SUPPORTS V3 ONLY


	uint64_t _time = BM::unix_time();

	PBM_NET_ADDR from_ip = &version_pl->addr_from;
	PBM_NET_ADDR recv_ip = &version_pl->addr_recv;

	// we using version 3 ~
	(*(uint32_t*)version_pl->version) = htonl(4);
	
	uint64_t serv = 1;

	// not using SSL
	(*(uint64_t*)version_pl->services) = swap64(serv);

	//	timestamp
	(*(uint64_t*)version_pl->timestamp) = swap64(_time);


	uint16_t portn = htons(8444);
	


	BM::set_net_addr(from_ip, htonl(inet_addr("127.0.0.1")), false, false, portn, serv, (int)_time);
	


	const char * userAgent = "/PyBitMessage:0.6.0/";
	

	
	BM::set_net_addr(recv_ip, ip_to, false, false, port_to, serv, (int)_time);

	ULONGLONG nonce = Utils::myRand();
	nonce <<= 32;
	*(ULONG*)&nonce = (ULONG)Utils::myRand();

	//	random nonce
	TYPECH(uint64_t, version_pl->nonce, nonce); // FIX ME use random value ???

	//	not using  user agent
	ULONG streams_offset = 0;// BM::encodeVarstr((char*)userAgent, version_pl->user_agnt, 0x16) - 1;
	
	DWORD len = sizeof(BM_PL_VER);// +streams_offset;

	TYPECH(BYTE, version_pl->user_agnt, 0x00);

	//	only one stream, and its stream # one. hence 01 01
	TYPECH(WORD, version_pl->streams, 0x0101);
	//TYPECH(WORD, ((ULONG_PTR)version_pl->user_agnt + (ULONG_PTR)streams_offset), 0x0101);

	return len;
}

DWORD BM::verify_version(PBM_PL_VER in)
{
	if (!in)
		return FALSE;
	
	uint32_t version = htonl((*(uint32_t*)in->version));

	if (version < 3) 
		return FALSE;
	//Sleep(2000);
	uint64_t time = BM::unix_time() + 30;
	uint64_t ver_time = swap64((*(uint64_t*)in->timestamp));

	char out_str[0x30] = {};

	BM::decodeVarstr((char*)in->user_agnt, 0x30, out_str, 0x30);

	DBGOUTa("\nVersion: ");
	DBGOUTa(out_str);
	DBGOUTa("\n\n");


	//if (time >= ver_time && (time - ver_time) <= DAY_SECONDS(4))
	return TRUE;


	return FALSE;
}

DWORD BM::init_verack(PBM_MSG_HDR in)
{

	TYPECH(int, in->magic, BM_MAGIC);

	memset(in->command, NULL, 12);

	lstrcpynA((char*)in->command, "verack", 12);

	memcpy_s(in->checksum, 4, "\xCF\x83\xE1\x35", 4);

	TYPECH(int, in->length, 0);

	return FALSE;

}

DWORD BM::set_net_addr(PBM_NET_ADDR in, long char_ip, long* long_ip, BOOL ipv6, uint16_t port, uint64_t services, int time)
{

	struct ip_ {
		BYTE a[10];
		BYTE b[2];
		BYTE c[4];
	};

	ip_ _ip = {};

	ZeroMemory(&_ip, sizeof(ip_));

	_ip.b[0] = 0xFF;
	_ip.b[1] = 0xFF;

	long hostname = NULL;
	LPBYTE net_addr = NULL;

	if (char_ip)
	{
		//	convert from string to netowrk byte order (from the initial list of IPs)
		hostname = char_ip;

		TYPECH(long, _ip.c, hostname);

		net_addr = (LPBYTE)&_ip;
	}
	else if (ipv6)
	{
		// if ipv6 then we recieved from a node
		// meaning we gave a pointer to the 16 bytes to this funtion
		net_addr = (LPBYTE)long_ip;
	}
	else if (!ipv6 && long_ip) {

		//	if not ipv6 but we received an address already formatted
		//	then
		hostname = *long_ip;
		TYPECH(long, _ip.c, hostname);
		net_addr = (LPBYTE)&_ip;
	}

	//	set time
	//TYPECH(int, in->time, time);

	//	set stream (currently always 1)
	//TYPECH(int, in->stream, 1);

	//	set the services
	TYPECH(uint64_t, in->services, swap64(services));

	//	set the ip address
	//	copy the IP bytes in the the struct
	memcpy_s(in->ip, 16, net_addr, 16);

	//	set network port
	TYPECH(uint16_t, in->port, port);


	return FALSE;
}



#pragma endregion


#pragma region GUI

//
//
// GUI functions
// meant to be easily called from GUI code
//

DWORD BM::encrypt_msg(PBM_MSG_HDR* out_msg, LPDWORD out_pl_size, PBM_MSG_ADDR to_addr, PBM_MSG_ADDR from_addr, LPSTR subject, LPSTR body)
{
	if (!out_msg)
		return FALSE;


	PBM_MSG_HDR msg_hdr = (PBM_MSG_HDR)ALLOC_(BM_RECV_BUFF_SIZE);
	PBM_OBJECT obj = (PBM_OBJECT)&msg_hdr->payload[0];
	PBM_ENC_PL_256 pl = (PBM_ENC_PL_256)&obj->objectVersion[2];
	
	DWORD pl_size = BM_RECV_BUFF_SIZE - 22;
	
	*out_msg = msg_hdr;

	// set up object to create the DSA signature

	obj->expiresTime = BM::swap64(BM::unix_time() + (60 * 60) + 100);
	obj->objectType = htonl(BM_OBJ_MSG);

	DWORD write_offset = BM::encodeVarint(1, obj->objectVersion); // version

	write_offset = BM::encodeVarint(1, &obj->objectVersion[write_offset]);// stream


	// set up the unencrypted payload for DSA signing



	DWORD _msg_size = lstrlenA("Subject:\nBody:") + lstrlenA(subject) + lstrlenA(body) + 1;
	DWORD unec_buff_size = _msg_size + 1024;


	LPSTR _msg = (LPSTR)ALLOC_(_msg_size);
	ZERO_(_msg, _msg_size);


	LPBYTE unenc_payl = (LPBYTE)ALLOC_(unec_buff_size);
	ZERO_(unenc_payl, unec_buff_size);


	lstrcatA(_msg, "Subject:");
	lstrcatA(_msg, subject);
	lstrcatA(_msg, "\nBody:");
	lstrcatA(_msg, body);

	write_offset = 0;


	// address version
	write_offset += BM::encodeVarint(from_addr->version, &unenc_payl[write_offset]);


	// address stream
	write_offset += BM::encodeVarint(from_addr->stream, &unenc_payl[write_offset]);


	// behavour bitfield
	uint32_t * behavour_bitfield = (uint32_t *)&unenc_payl[write_offset];
	*behavour_bitfield = 0;

	write_offset += sizeof(uint32_t);


	// public keys
	LPBYTE pub_sign_key = &unenc_payl[write_offset];

	write_offset += 64;

	LPBYTE pub_enc_key = &unenc_payl[write_offset];

	write_offset += 64;

	Utils::copy_mem(pub_sign_key, 64, &from_addr->pub_sig_blob[8], 64);
	Utils::copy_mem(pub_enc_key, 64, &from_addr->pub_enc_blob[8], 64);

	
	


	//nonce_trails_per_byte 
	write_offset += BM::encodeVarint(1000, &unenc_payl[write_offset]);

	// extra bytes
	write_offset += BM::encodeVarint(1000, &unenc_payl[write_offset]);


	// destination ripe
	LPBYTE dest_ripe = &unenc_payl[write_offset];

	Utils::copy_mem(dest_ripe, 20, to_addr->hash, to_addr->hash_size);

	write_offset += 20;

	// encoding
	write_offset += BM::encodeVarint(BM_ENCODING_SIMPLE, &unenc_payl[write_offset]);


	// msg_length
	write_offset += BM::encodeVarint(_msg_size, &unenc_payl[write_offset]);


	// message
	LPBYTE msg_offset = &unenc_payl[write_offset];

	Utils::copy_mem(msg_offset, unec_buff_size - write_offset, _msg, _msg_size);

	write_offset += _msg_size;


	// ack data (null)
	write_offset += BM::encodeVarint(0, &unenc_payl[write_offset]);


	DWORD dsbs = write_offset;


	// dsa sig size
	write_offset += BM::encodeVarint(64, &unenc_payl[write_offset]);


	// dsa sig
	LPBYTE dsa_sig = &unenc_payl[write_offset];



	DSA_CONTEXT dsa_context = {};
	BYTE out_sig[128] = {};


	LPBYTE dsa_buffer = (LPBYTE)ALLOC_(22 + dsbs);



	Utils::copy_mem(dsa_buffer, 14, &obj->expiresTime, 14);
	Utils::copy_mem(&dsa_buffer[14], dsbs, unenc_payl, dsbs);


	dsa_context.buffer = (LPBYTE)dsa_buffer;
	dsa_context.sign_size = 14 + dsbs;
	dsa_context.private_key = to_addr->first_tag;
	dsa_context.priv_key_size = 32;
	dsa_context.out_sig = out_sig;
	dsa_context.sig_size = 64;


	// create the signature
	ECC::create_dsa_sig(&dsa_context);



	Utils::copy_mem(dsa_sig, 64, out_sig, 64);

	write_offset += 64;




	// do the encryption.
	BM::encrypt_payload(to_addr, unenc_payl, write_offset, pl, &pl_size);

	if (pl_size)
		*out_pl_size = pl_size;

	//Utils::copy_mem()
	return TRUE;
}






void BM::send_msg(DWORD from_id, DWORD to_id, LPSTR subject, LPSTR body)
{
	BM_MSG_ADDR to_addr = {};
	BM_MSG_ADDR from_addr = {};

	DWORD address_id = NULL;
	//BM::create_addr(&addr);
	//if (addr)
	//{
	//	address_id = BMDB::address_add(addr, L"Debug");
	//}
	//
	

	if (!BMDB::address_find(to_id, NULL, NULL, &to_addr)) return;
	if (!BMDB::address_find(from_id, NULL, NULL, &from_addr)) return;


	PBM_MSG_HDR msg_hdr = NULL;
	PBM_OBJECT out_obj = NULL;
	DWORD out_pl_size = NULL;

	PBM_ENC_PL_256 pl = NULL;
	DWORD pl_size = NULL;

	
	BM::encrypt_msg(&msg_hdr, &out_pl_size, &to_addr, &from_addr, subject, body);


	out_obj = (PBM_OBJECT)msg_hdr->payload;

	pl = (PBM_ENC_PL_256)&out_obj->objectVersion[2];

	pl_size = out_pl_size;





	PBM_CONN is_connected = FALSE;



	// initialize object header

	pl_size = BM::init_object(out_obj, BM_RECV_BUFF_SIZE - (24 + 22), BM_OBJ_MSG, (LPBYTE)pl, pl_size);

	// initialize msg header

	BM::init_msg_hdr(msg_hdr, pl_size, "object");



	BYTE vect_tag[MAX_PATH] = {};

	BM::create_vector_tag((LPBYTE)out_obj, pl_size, vect_tag, MAX_PATH);


	BMDB::vector_add(vect_tag, out_obj, pl_size);

	DWORD inv_id = BMDB::vector_find(NULL, vect_tag, NULL, NULL);

	// propogate!

	DBGOUTw(L"\r\r===== SENDING MESSAGE =====\r\r");
	network::queue_obj(0, inv_id);


	if (msg_hdr)
		ZEROFREE_(msg_hdr, BM_RECV_BUFF_SIZE);





	ZERO_(&to_addr, sizeof(BM_MSG_ADDR));
	ZERO_(&from_addr, sizeof(BM_MSG_ADDR));


}



#pragma endregion



#endif
