#include "stdafx.h"
#pragma once
#ifndef BM_ECC_H
#define BM_ECC_H


namespace ECC {

	extern BCRYPT_ALG_HANDLE main_handle;
	extern BCRYPT_KEY_HANDLE cur_key_handle;
	extern NCRYPT_PROV_HANDLE ncrypt_handle;


	void init();
	DWORD create_key_pair(BCRYPT_KEY_HANDLE * out_handle, PBCRYPT_ECCKEY_BLOB pub_key, PBCRYPT_ECCKEY_BLOB priv_key, LPDWORD pub_size, LPDWORD priv_size);

	DWORD verify_dsa_sig(LPVOID buffer, DWORD size, LPVOID priv_key, DWORD priv_key_size, LPVOID sig, DWORD sig_size);
	DWORD create_dsa_sig(PDSA_CONTEXT dsa_context);

	//DWORD encrypt();
	//DWORD decrypt();


};


















#endif