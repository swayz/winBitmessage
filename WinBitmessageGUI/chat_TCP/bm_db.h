#pragma once
#ifndef BM_DB_H
#define BM_DB_H

#include "bm.h"


namespace BMDB{

	void init();
	void deinit();
	void show_error();

	//
	//
	// messages
	//
	//



	BOOL add_message(DWORD to, DWORD from, LPWSTR subject, LPWSTR body, DWORD folder, DWORD inv_id);

	

	//
	//
	// nodes
	//
	//


	int node_update_last_conn(uint64_t last_conn, uint64_t node_id, BOOL connected);
	uint64_t node_add(PBM_ADDR in);
	PBM_ADDR node_find(LPBYTE ip, DWORD* node_list_id);
	BOOL node_disconnect(uint64_t nid);
	DWORD addr_list(DWORD limit, LPVOID out, DWORD out_size);

	//
	//
	//	Inventory
	//
	//


	uint64_t vector_add(LPBYTE vect, PBM_OBJECT object, DWORD object_size);
	uint64_t vector_find(LPBYTE vect, PBM_OBJECT obj, LPDWORD obj_size);
	DWORD vect_list(DWORD limit, LPVOID out, DWORD out_size);


	//
	//
	// Adress
	//
	//


	DWORD atmpt_msg_decrypt(PBM_ENC_PL_256 in, DWORD size);
	DWORD address_find(DWORD id, LPSTR addr, PBM_MSG_ADDR pAddr);
	DWORD address_add(PBM_MSG_ADDR in, LPWSTR label);
	DWORD address_remove(DWORD id);


};




#endif // !BM_DB_H