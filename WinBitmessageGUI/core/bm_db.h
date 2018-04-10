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
	// Misc

	BOOL delete_row_from_table(DWORD row_id, LPSTR table);

	//
	//
	// messages

	DWORD add_message(DWORD to, DWORD from, LPSTR subject, LPSTR body, DWORD folder, DWORD inv_id);

	//
	//
	// nodes

	int node_update_last_conn(uint64_t last_conn, uint64_t node_id, BOOL connected);
	DWORD node_add(PBM_ADDR in);
	PBM_ADDR node_find(LPBYTE ip, DWORD* node_list_id);
	BOOL disc_all_conn_nodes(DWORD nid);
	DWORD addr_list(DWORD limit, LPVOID out, DWORD out_size);
	BOOL set_is_node_connected(PBM_CONN conn, DWORD is_conn);

	//
	//
	//	Inventory

	DWORD vector_add(LPBYTE vect, PBM_OBJECT object, DWORD object_size);
	DWORD vector_find(DWORD inv_id, LPBYTE vect, PBM_OBJECT obj, LPDWORD obj_size);
	DWORD vect_list(DWORD limit, LPVOID out, DWORD out_size);
	DWORD vect_from_id(DWORD id, LPBYTE vect);

	//
	//
	// Adress

	DWORD atmpt_msg_decrypt(PBM_ENC_PL_256 in, DWORD size);
	DWORD address_find(DWORD id, LPSTR addr, LPBYTE tag, PBM_MSG_ADDR pAddr);
	DWORD address_add(PBM_MSG_ADDR in, LPWSTR label);
	DWORD address_remove(DWORD id);


};




#endif // !BM_DB_H