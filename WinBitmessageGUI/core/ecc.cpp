#include "stdafx.h"

#ifndef BM_ECC_C
#define BM_ECC_C

#include "bm.h"
#include "ecc.h"
#include "Encryption.h"
#include "utils.h"

//#include "ntdef.h"


BCRYPT_ALG_HANDLE ECC::main_handle = NULL;
BCRYPT_KEY_HANDLE ECC::cur_key_handle = NULL;
NCRYPT_PROV_HANDLE ECC::ncrypt_handle = NULL;

void ECC::init()
{

	BCryptOpenAlgorithmProvider(&ECC::main_handle, BCRYPT_ECDH_P256_ALGORITHM, MS_PRIMITIVE_PROVIDER, NULL);
	
	//NCryptOpenStorageProvider(&ECC::ncrypt_handle,	MS_KEY_STORAGE_PROVIDER, NULL);

}

DWORD ECC::create_key_pair(BCRYPT_KEY_HANDLE * out_handle, PBCRYPT_ECCKEY_BLOB pub_key, PBCRYPT_ECCKEY_BLOB priv_key, LPDWORD pub_size, LPDWORD priv_size)
{
	ULONG key_blob_size = 0;
	BYTE tmp_key[512] = {};

	int e = 0;

	if (!out_handle || !pub_key || !pub_size || !*pub_size)
		return FALSE;

	//	Generate the Key Pair

	e = BCryptGenerateKeyPair(ECC::main_handle, out_handle, 256, NULL);

	e = BCryptFinalizeKeyPair(		// Dont forget to Finalize
		*out_handle,				// Key handle
		0);

	e = BCryptExportKey(
		*out_handle,				// handle to the key pair
		NULL,						// we are exporting as plain text so use NULL
		BCRYPT_ECCPUBLIC_BLOB,		// key type
		(PUCHAR)tmp_key,			// out buff
		512,						// size of out buff
		&key_blob_size,				// out size
		NULL						// flags
	);

	if(key_blob_size)
	{

		if (key_blob_size) {
			

			memcpy_s(pub_key, *pub_size, tmp_key, key_blob_size);
			*pub_size = key_blob_size;
		}

	}

	ZeroMemory(tmp_key, 512);

	if (priv_key && priv_size && *priv_size)
	{

		e = BCryptExportKey(
			*out_handle,				// handle to the key pair
			NULL,						// we are exporting as plain text so use NULL
			BCRYPT_ECCPRIVATE_BLOB,		// key type
			(PUCHAR)tmp_key,			// out buff
			512,						// size of out buff
			&key_blob_size,				// out size
			NULL						// flags
		);

		if (key_blob_size)
		{

			if (key_blob_size) {

				memcpy_s(priv_key, *priv_size, tmp_key, key_blob_size);
				*priv_size = key_blob_size;
			}

		}
	}

	ZeroMemory(tmp_key, 512);
	e = GetLastError();
	
	return FALSE;
}


DWORD ECC::verify_dsa_sig(LPVOID buffer, DWORD size, LPVOID priv_key, DWORD priv_key_size, LPVOID sig, DWORD sig_size)
{

	DWORD j = FALSE;
	BCRYPT_ALG_HANDLE dsa_handle = NULL;
	BCRYPT_ALG_HANDLE dsa_key_handle = NULL;

	BYTE dsa_key_buff[128] = {};

	BYTE _hash[64] = {};

	BCryptOpenAlgorithmProvider(&dsa_handle, BCRYPT_ECDSA_P256_ALGORITHM, NULL, NULL);

	((PBCRYPT_ECCKEY_BLOB)dsa_key_buff)->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
	((PBCRYPT_ECCKEY_BLOB)dsa_key_buff)->cbKey = 32;

	memcpy_s(&dsa_key_buff[8 + 32 + 32], 32, priv_key, priv_key_size);

	j = BCryptImportKeyPair(dsa_handle, NULL, BCRYPT_ECCPRIVATE_BLOB, &dsa_key_handle, dsa_key_buff, 8 + 32 + 32 + 32, NULL);


	Encryption::create_hash((LPSTR)_hash, (LPBYTE)buffer, size, NULL, NULL, CALG_SHA1);


#ifdef DEBUG_MODE

	LPWSTR h = (LPWSTR)GlobalAlloc(GPTR, 0x800);
	
	LPBYTE pk = (LPBYTE)priv_key;
	wsprintfW(h, L"\nverify DSA private key: %X%X%X%X", pk[0], pk[1], pk[2], pk[3]);
	DBGOUTw(h);

	ZERO_(h, 0x800);
	wsprintfW(h, L"\nverify DSA hash: %X%X%X%X", _hash[0], _hash[1], _hash[2], _hash[3]);
	DBGOUTw(h);

	ZERO_(h, 0x800);
	LPSTR dsa_buff_string = Utils::hex_to_str((unsigned char*)buffer, size);
	wsprintfA((LPSTR)h, "\nverify DSA buffer: %s", dsa_buff_string);
	DBGOUTa((LPSTR)h);

	GlobalFree(dsa_buff_string);

	ZERO_(h, 0x800);
	LPBYTE _sig = (LPBYTE)sig;
	wsprintfW(h, L"\nverify DSA sig: %X%X%X%X", _sig[0], _sig[1], _sig[2], _sig[3]);
	DBGOUTw(h);

	GlobalFree(h);

#endif


	// the actual verification.
	j = BCryptVerifySignature(dsa_key_handle, NULL, _hash, 0x14, (LPBYTE)sig, sig_size, NULL);

	return (j) ? FALSE : TRUE;

}


DWORD ECC::create_dsa_sig(PDSA_CONTEXT dsa_context)
{
	BCRYPT_ALG_HANDLE dsa_handle = NULL;
	BCRYPT_ALG_HANDLE dsa_key_handle = NULL;

	BYTE dsa_key_buff[128] = {};
	BYTE signature[128] = {};

	BYTE _hash[64] = {};

	DWORD ds = NULL;

	BCryptOpenAlgorithmProvider(&dsa_handle, BCRYPT_ECDSA_P256_ALGORITHM, NULL, NULL);

	((PBCRYPT_ECCKEY_BLOB)dsa_key_buff)->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
	((PBCRYPT_ECCKEY_BLOB)dsa_key_buff)->cbKey = 32;

	memcpy_s(&dsa_key_buff[8 + 32 + 32], 32, dsa_context->private_key, dsa_context->priv_key_size);

	int j = BCryptImportKeyPair(dsa_handle, NULL, BCRYPT_ECCPRIVATE_BLOB, &dsa_key_handle, dsa_key_buff, 8 + 32 + 32 + 32, NULL);

	// Create the SHA1 of the buffer

	Encryption::create_hash((LPSTR)_hash, dsa_context->buffer, dsa_context->sign_size, NULL, NULL, CALG_SHA1);
	ds = NULL;


	// Create the Signature with the key and the SHA1 hash
	j = BCryptSignHash(dsa_key_handle, NULL, _hash, 0x14, signature, 128, &ds, NULL);


#ifdef DEBUG_MODE

	LPWSTR h = (LPWSTR)GlobalAlloc(GPTR, 0x800);

	wsprintfW(h, L"\ncreate DSA private key: %X%X%X%X", dsa_context->private_key[0], dsa_context->private_key[1], dsa_context->private_key[2], dsa_context->private_key[3]);
	DBGOUTw(h);

	ZERO_(h, 0x800);
	wsprintfW(h, L"\ncreate DSA hash: %X%X%X%X", _hash[0], _hash[1], _hash[2], _hash[3]);
	DBGOUTw(h);

	ZERO_(h, 0x800);
	LPSTR dsa_buff_string = Utils::hex_to_str((unsigned char*)dsa_context->buffer, dsa_context->sign_size);
	wsprintfA((LPSTR)h, "\ncreate DSA buffer: %s", dsa_buff_string);
	DBGOUTa((LPSTR)h);

	ZERO_(h, 0x800);
	wsprintfW(h, L"\ncreate DSA signature: %X%X%X%X", signature[0], signature[1], signature[2], signature[3]);
	DBGOUTw(h);

	GlobalFree(h);

#endif



	// double check everything is ok.
	j = BCryptVerifySignature(dsa_key_handle, NULL, _hash, 0x14, signature, ds, NULL);

	if (!j)
	{
		if (ds <= dsa_context->sig_size)
			memcpy_s(dsa_context->out_sig, dsa_context->sig_size, signature, ds);

	}

	ZERO_(signature, 128);
	ZERO_(_hash, 64);
	ZERO_(dsa_key_buff, 64);


	if (dsa_key_handle)
		BCryptDestroyKey(dsa_key_handle);

	if (dsa_handle)
		BCryptCloseAlgorithmProvider(dsa_handle, NULL);


	return !(j);
}








#endif // !BM_ECC_C