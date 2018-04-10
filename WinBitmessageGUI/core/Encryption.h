#pragma once
#include "stdafx.h"

#ifndef ENCRYPTION_H
#define ENCRYPTION_H


namespace Encryption {

	extern HCRYPTPROV context;
	extern BCRYPT_ALG_HANDLE cng_handle;



	void init(void);

	bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz);
	DWORD base58_decode(void *bin, size_t *binszp, const char *b58, size_t b58sz);

	LPVOID aes_encrypt(PCRYPT_CONTEXT context);
	DWORD aes_decrypt(PCRYPT_CONTEXT context);

	DWORD aes_import_key(PCRYPT_CONTEXT context);

	DWORD create_hash(LPSTR hash, LPBYTE in, DWORD in_size, LPBYTE firstfour, BOOL readable, DWORD calgid);

	LPVOID create_hmac(HCRYPTPROV hProv, LPVOID buffer, DWORD size, HCRYPTKEY hKey);
	



};



















#endif // !ENCRYPTION_H