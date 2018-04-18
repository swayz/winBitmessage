#include "stdafx.h"

#ifndef ENCRYPTION_C
#define ENCRYPTION_C

#include "Encryption.h"
//#include "memory.h"
#include "utils.h"

HCRYPTPROV Encryption::context = NULL;
BCRYPT_ALG_HANDLE Encryption::cng_handle = NULL;

void Encryption::init()
{

	CryptAcquireContextW(&Encryption::context, 0, L"Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	BCryptOpenAlgorithmProvider(&Encryption::cng_handle, BCRYPT_ECDH_P256_ALGORITHM, NULL, NULL);
	

}


DWORD Encryption::aes_import_key(PCRYPT_CONTEXT context)
{
	context->last_error = NULL;

	const BYTE key[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	//	BLOBHEADER	<--	Handled below
		0x00, 0x00, 0x00, 0x00,							//	Key size	<--	DWORD
		0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e,	//	AES.KEY.	<--	32 bytes
		0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e,	//	........
		0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e,	//	........
		0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e	//	........
	};

	BLOBHEADER* hdr = (BLOBHEADER*)key;
	hdr->aiKeyAlg = CALG_AES_256;
	hdr->bType = PLAINTEXTKEYBLOB;
	hdr->bVersion = CUR_BLOB_VERSION;//default value
	hdr->reserved = NULL;//reserved, default value

	LPDWORD key_size = (LPDWORD)&key[sizeof(BLOBHEADER)];

	*key_size = AES_KEY_SIZE_;

	LPBYTE key_offset = (LPBYTE)&key[sizeof(BLOBHEADER) + sizeof(DWORD)];

	memcpy_s(key_offset, AES_KEY_SIZE_, context->aes_key, AES_KEY_SIZE_);

	if (!CryptImportKey(context->context, key, 44, 0, CRYPT_EXPORTABLE, &context->aes_hKey))
	{
		context->last_error = GetLastError();
	}

	ZeroMemory((LPVOID)key, sizeof(key));

	return context->last_error;
}





LPVOID Encryption::create_hmac(HCRYPTPROV hProv, LPVOID buffer, DWORD size, HCRYPTKEY hKey)
{
	LPVOID ret = NULL;
	HCRYPTHASH  hHash = NULL;
	HCRYPTHASH  hHmacHash = NULL;
	PBYTE       pbHash = NULL;
	HMAC_INFO   HmacInfo;
	ZeroMemory(&HmacInfo, sizeof(HMAC_INFO));
	HmacInfo.HashAlgid = CALG_SHA_256;

	if (!CryptCreateHash(
		hProv,                    // handle of the CSP.
		CALG_HMAC,                // HMAC hash algorithm ID
		hKey,                     // key for the hash (see above)
		0,                        // reserved
		&hHmacHash))              // address of the hash handle
	{
		//WPI _wsprintfW(_buffer, L"Error in CryptCreateHash 0x%08x \n", GetLastError());
		//DBGOUTw(_buffer);
		goto ErrorExit;
	}

	if (!CryptSetHashParam(
		hHmacHash,                // handle of the HMAC hash object
		HP_HMAC_INFO,             // setting an HMAC_INFO object
		(BYTE*)&HmacInfo,         // the HMAC_INFO object
		0))                       // reserved
	{
		//WPI _wsprintfW(_buffer, L"Error in CryptSetHashParam 0x%08x \n", GetLastError());
		//DBGOUTw(_buffer);
		goto ErrorExit;
	}

	if (!CryptHashData(
		hHmacHash,                // handle of the HMAC hash object
		(LPBYTE)buffer,                    // message to hash
		size,            // number of bytes of data to add
		0))                       // flags
	{
		//printf("Error in CryptHashData 0x%08x \n",GetLastError());
		goto ErrorExit;
	}

	//--------------------------------------------------------------------
	// Call CryptGetHashParam twice. Call it the first time to retrieve
	// the size, in bytes, of the hash. Allocate memory. Then call 
	// CryptGetHashParam again to retrieve the hash value.
	DWORD dwDataLen = NULL;
	if (!CryptGetHashParam(
		hHmacHash,                // handle of the HMAC hash object
		HP_HASHVAL,               // query on the hash value
		NULL,                     // filled on second call
		&dwDataLen,               // length, in bytes, of the hash
		0))
	{
		//printf("Error in CryptGetHashParam 0x%08x \n",GetLastError());
		goto ErrorExit;
	}

	pbHash = (BYTE*)ALLOC_( HMAC_BUFF_LEN + 1);

	if (!pbHash)
		goto ErrorExit;
	

	if (!CryptGetHashParam(
		hHmacHash,                 // handle of the HMAC hash object
		HP_HASHVAL,                // query on the hash value
		pbHash,                    // pointer to the HMAC hash value
		&dwDataLen,                // length, in bytes, of the hash
		0))
	{
		
		goto ErrorExit;
	}

	if (hHmacHash)
		CryptDestroyHash(hHmacHash);

	if (hHash)
		CryptDestroyHash(hHash);

	return pbHash;

	
	// Free resources.
ErrorExit:
	if (hHmacHash)
		CryptDestroyHash(hHmacHash);

	if (hHash)
		CryptDestroyHash(hHash);

	if (pbHash)
	{
		ZeroMemory(pbHash, HMAC_LEN);
		FREE_(pbHash, HMAC_LEN);
	}

	return FALSE;
}






DWORD Encryption::create_hash(LPSTR hash, LPBYTE in, DWORD in_size, LPBYTE firstfour, BOOL readable, DWORD calgid)
{
	DWORD dwStatus = FALSE;
	HCRYPTPROV hProv = Encryption::context;
	HCRYPTHASH hHash = NULL;
	BYTE* rgbFile = in;
	DWORD cbRead = in_size;
	DWORD cbHash = NULL;
	CHAR rgbDigits[] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','\0' };

	LPBYTE rgbHash = (LPBYTE)LocalAlloc(LPTR,MAX_PATH);
	LPSTR tmp = (LPSTR)LocalAlloc(LPTR, MAX_PATH);
	
	ZERO_(hash, 64);



	cbHash = MAX_PATH;

	// not supported on windows xp sp1 - sp2
	DWORD calg_id = calgid;



	if (!CryptCreateHash(hProv, calg_id, 0, 0, &hHash))
	{
		DBGOUTw(L"\nCryptAcquireContext failed.");
		goto end;
	}


	if (!CryptHashData(hHash, rgbFile, cbRead, 0))
	{
		DBGOUTw(L"\nCryptHashData failed.");
		goto end;
	}



	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		if (firstfour)
			memcpy_s(firstfour, 4, rgbHash, 4);

		if (readable)
		{
			for (DWORD i = 0; i < cbHash; i++)
			{
				wsprintfA((LPSTR)tmp, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
				lstrcatA(hash, tmp);

				ZERO_(tmp, MAX_PATH);

			}
		}else{
			
			memcpy_s(hash, cbHash, rgbHash, cbHash);

		}
		dwStatus = TRUE;
	
	}
	
	

end:

	
	LocalFree(rgbHash);
	LocalFree(tmp);

	CryptDestroyHash(hHash);

	return dwStatus;
}





LPVOID Encryption::aes_encrypt(PCRYPT_CONTEXT context) {

	LPBYTE plain_bytes = (LPBYTE)context->in_buff;
	DWORD pl_s = context->in_size;

	HCRYPTKEY aes_hkey = NULL;
	DWORD dwMode = CRYPT_MODE_CBC;
	LPVOID aes_key = NULL;
	LPBYTE new_bytes = NULL;
	DWORD p_block_size = AES_BLOCK_SIZE_;
	DWORD msg_size = NULL;

	BOOL eof = FALSE;

	//	Duplicate they key for usage!
	CryptDuplicateKey(context->aes_hKey, 0, 0, &aes_hkey);

	if (!aes_hkey)
	{
		DBGOUTw(L"Failed To Duplicate Encryption Key");
		return (LPVOID)GetLastError();
	}

	//	Create Buffers
	DWORD tmp_blk_buff_size = TMP_BLOCK_BUFFER_SIZE(context->in_size);

	BYTE tmp_blk_buff[64];

	context->out_buff = ALLOC_(tmp_blk_buff_size);
	context->out_size = tmp_blk_buff_size;

	//LPVOID iv_ = ALLOC_(AES_BLOCK_SIZE_);
	LPVOID encrypted_msg = context->out_buff;

	ZeroMemory(tmp_blk_buff, 64);
//	ZeroMemory(iv_, AES_BLOCK_SIZE_);
	ZeroMemory(encrypted_msg, context->in_size);


	if (aes_hkey) {
		if (!context->iv[0])
		{
			// Generate Initialization Vector
			BCryptGenRandom(Encryption::cng_handle, (LPBYTE)context->iv, AES_BLOCK_SIZE_, NULL);

			//	Return the IV
			//context->iv = (LPBYTE)iv_;
		}

		// set CBC mode
		CryptSetKeyParam(aes_hkey, KP_MODE, (BYTE*)&dwMode, 0);

		// Set the Initialization Vector.
		CryptSetKeyParam(aes_hkey, KP_IV, (BYTE*)&context->iv, 0);


		//	Set buffer
		new_bytes = (LPBYTE)context->out_buff;
		BOOL first_block = TRUE;
		BYTE fb[16];
		ZeroMemory(fb, 16);
		// Encrypt data
		do {
			ZeroMemory(tmp_blk_buff, 64);

			
			//	block magic
			if (pl_s <= AES_BLOCK_SIZE_) {
				p_block_size = pl_s;
				eof = TRUE;
			}
			else {
				p_block_size = AES_BLOCK_SIZE_;
				pl_s -= AES_BLOCK_SIZE_;
				if (pl_s < 50000 && pl_s > 40000) {

					int e = 0;
				}
			}


			//	Copy block in to temp buffer for encryption
			memcpy_s(tmp_blk_buff, 64, plain_bytes, p_block_size);
			

			//	Encryption!
			if (!CryptEncrypt(aes_hkey, NULL, eof, 0, (LPBYTE)tmp_blk_buff, &p_block_size, tmp_blk_buff_size))
			{
				context->last_error = GetLastError();

				OutputDebugStringW(L"\n---Encryption Error---\n ");

				eof = TRUE;
			}

			//	Copy the Encrypted bytes to new buffer
			memcpy_s(new_bytes, p_block_size, tmp_blk_buff, p_block_size);

			//	Keep track of bytes encrypted

			plain_bytes += AES_BLOCK_SIZE_;

		//	first_block = FALSE;
			new_bytes += p_block_size;

			//	Sanity checks
			if (msg_size <= context->out_size) {
				msg_size += AES_BLOCK_SIZE_;
			}
			else {

				DBGOUTw(L"----\n\nMSG encryption: buffer size error!!\n\n----");

				eof = TRUE;
			}


		} while (!eof);

	}

	DWORD e = NULL;

	if (msg_size)
	{

		//DWORD based_size = NULL;
		//LPSTR based_msg = (LPSTR)Encryption::base_me(context->out_buff, msg_size, &based_size, 0, 0, 0);

		//ZEROFREE_(context->out_buff, tmp_blk_buff_size);

		//context->out_buff = based_msg;
		//context->out_size = based_size;

	}
	else {
		e = GetLastError();
		//printf("Encryption Error: %X\n", e);
	}

	if (aes_hkey)
		CryptDestroyKey(aes_hkey);

	aes_hkey = NULL;
	//context->aes_key = NULL;
	context->aes_key_size = NULL;



	return (LPVOID)e;
}


DWORD Encryption::aes_decrypt(PCRYPT_CONTEXT context) {
	if (!context || !context->in_buff) {
		return 0;
	}
	context->last_error = NULL;

	HCRYPTKEY aes_hkey = NULL;
	DWORD dwMode = CRYPT_MODE_CBC;

	//context->aes_hKey = NULL;

	if (context->aes_hKey) {

		CryptDuplicateKey(context->aes_hKey, 0, 0, &aes_hkey);
		if (!aes_hkey)
			return FALSE;

		CryptSetKeyParam(aes_hkey, KP_MODE, (BYTE*)&dwMode, 0);
		CryptSetKeyParam(aes_hkey, KP_IV, context->iv, NULL);

	}
	else {
		return FALSE;
	}

	LPBYTE enc_bytes = (LPBYTE)context->in_buff;
	DWORD pl_s = context->in_size;

	LPVOID tmp_blk_buff = NULL;
	LPVOID plain_text = NULL;
	DWORD block_size = AES_BLOCK_SIZE_;
	DWORD p_block_size = NULL;
	BOOL eof = FALSE;
	DWORD tbbs = TMP_BLOCK_BUFFER_SIZE(pl_s);
	DWORD out_size_ = NULL;

	tmp_blk_buff = ALLOC_( tbbs);
	plain_text = ALLOC_( context->in_size);

	LPBYTE new_bytes = (LPBYTE)plain_text;
	context->out_size = context->in_size;

	do {
		ZeroMemory(tmp_blk_buff, tbbs);

		if (pl_s <= block_size) {
			p_block_size = pl_s;
			eof = TRUE;
		}
		else {
			p_block_size = block_size;
			pl_s -= block_size;
		}

		memcpy_s(tmp_blk_buff, tbbs, enc_bytes, p_block_size);

		if (!CryptDecrypt(aes_hkey, NULL, eof, 0, (LPBYTE)tmp_blk_buff, &p_block_size))
		{
			context->last_error = GetLastError();
			eof = TRUE;
		}
		else {

			memcpy_s(new_bytes, context->out_size, tmp_blk_buff, p_block_size);

			enc_bytes += block_size;
			new_bytes += p_block_size;
			out_size_ += p_block_size;
		}

	} while (!eof);

	context->out_buff = plain_text;
	context->out_size = out_size_;

	if (out_size_ < context->out_size) {
		LPVOID rem_buff = (LPVOID)((ULONG_PTR)plain_text + out_size_);
		ZeroMemory(rem_buff, context->out_size - out_size_);
	}

	CryptDestroyKey(aes_hkey);

	aes_hkey = NULL;

	FREE_(tmp_blk_buff, tbbs);

	return context->last_error;
}







//	BASE58 FUNCTIONS
//
//	THANKS TO: https://github.com/luke-jr/libbase58/blob/master/base58.c
//
//

/*
* Copyright 2012-2014 Luke Dashjr
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the standard MIT license.  See COPYING for more details.
*/
static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool Encryption::b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz)
{
	const uint8_t *bin = (const uint8_t *)data;
	int carry;
	size_t i, j, high, zcount = 0;
	size_t size = 0;

	while (zcount < binsz && !bin[zcount])
		++zcount;

	size = (binsz - zcount) * 138 / 100 + 1;
	
	
	uint8_t * buf = (uint8_t*)LocalAlloc(LPTR, size);

	memset(buf, 0, size);

	for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
	{
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
		{
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
		}
	}

	for (j = 0; j < size && !buf[j]; ++j);

	if (*b58sz <= zcount + size - j)
	{
		*b58sz = zcount + size - j + 1;
		LocalFree(buf);
		return false;
	}

	if (zcount)
		memset(b58, '1', zcount);
	for (i = zcount; j < size; ++i, ++j)
		b58[i] = b58digits_ordered[buf[j]];
	b58[i] = '\0';
	*b58sz = i + 1;

	LocalFree(buf);

	return true;
}


static const int8_t b58digits_map[] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};


DWORD Encryption::base58_decode(void *bin, size_t *binszp, const char *b58, size_t b58sz)
{
	size_t binsz = *binszp;
	const unsigned char *b58u = (const unsigned char *)b58;
	unsigned char *binu = (unsigned char *)bin;
	size_t outisz = (binsz + 3) / 4;
	
	uint32_t* outi = (uint32_t*)ALLOC_(outisz);
	ZERO_(outi, outisz);

	uint64_t t;
	uint32_t c;
	size_t i, j;
	uint8_t bytesleft = binsz % 4;
	uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
	unsigned zerocount = 0;

	if (!b58sz)
		b58sz = strlen(b58);

	memset(outi, 0, outisz * sizeof(*outi));

	// Leading zeros, just count
	for (i = 0; i < b58sz && b58u[i] == '1'; ++i)
		++zerocount;

	for (; i < b58sz; ++i)
	{
		if (b58u[i] & 0x80)
			// High-bit set on invalid digit
			return false;
		if (b58digits_map[b58u[i]] == -1)
			// Invalid base58 digit
			return false;
		c = (unsigned)b58digits_map[b58u[i]];
		for (j = outisz; j--; )
		{
			t = ((uint64_t)outi[j]) * 58 + c;
			c = (t & 0x3f00000000) >> 32;
			outi[j] = t & 0xffffffff;
		}
		if (c)
			// Output number too big (carry to the next int32)
			return false;
		if (outi[0] & zeromask)
			// Output number too big (last int32 filled too far)
			return false;
	}

	j = 0;
	switch (bytesleft) {
	case 3:
		*(binu++) = (outi[0] & 0xff0000) >> 16;
	case 2:
		*(binu++) = (outi[0] & 0xff00) >> 8;
	case 1:
		*(binu++) = (outi[0] & 0xff);
		++j;
	default:
		break;
	}

	for (; j < outisz; ++j)
	{
		*(binu++) = (outi[j] >> 0x18) & 0xff;
		*(binu++) = (outi[j] >> 0x10) & 0xff;
		*(binu++) = (outi[j] >> 8) & 0xff;
		*(binu++) = (outi[j] >> 0) & 0xff;
	}

	// Count canonical base58 byte count
	binu = (unsigned char*)bin;
	for (i = 0; i < binsz; ++i)
	{
		if (binu[i])
			break;
		--*binszp;
	}
	*binszp += zerocount;

	ZEROFREE_(outi, outisz);

	return true;
}






#endif