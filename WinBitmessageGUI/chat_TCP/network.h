#pragma once
#include "stdafx.h"

#ifndef BM_NETWORK_H
#define BM_NETWORK_H

namespace network {

	extern DWORD cur_conn_id;
	extern BM_SEED seed_list[16];
	extern PBM_CONN_LIST con_list;
	extern LPCRITICAL_SECTION lock_conn_list;
	


	void init();
	//	connection function
	int start(HWND hwnd);
	int connect(HWND hwnd, PBM_CONN* out, long hostname, int PortNo, uint64_t sqlite_node_id);
	void init_connect(PBM_CONN_THREAD_DATA in);

	PBM_CONN reg_conn(SOCKET s, long ipv4, LPBYTE ipv6, int PortNo, uint64_t sqlite_node_id);
	PBM_CONN* find_conn(SOCKET s, DWORD * id);
	PBM_CONN add_conn(SOCKET s, long to_ip, int to_port);
	BOOL remove_conn(SOCKET s);
	BOOL is_conn_ready(PBM_CONN conn);
	PBM_CONN has_connection();

	BOOL queue_obj(PBM_CONN conn, LPBYTE vector);
	BOOL send_raw_data(PBM_CONN in, PBM_MSG_HDR msg, DWORD size);
	int send_chunks(SOCKET s, LPBYTE in, DWORD in_size);
	BOOL send_ready_objs(PBM_CONN in);

	//	threads
	VOID CALLBACK start_work(PBM_CONN in, PBM_MSG_HDR msg);
	int CALLBACK send_thread(PBM_CONN in);

	VOID CALLBACK recv_thread(PBM_CONN in);
	VOID CALLBACK maintain_health();




	// Message Handling functions

	//int handle_msg(PBM_CONN conn_, PBM_MSG_HDR in, DWORD in_size, DWORD msg_type);
	//DWORD is_msg_hdr_valid(PBM_MSG_HDR in);
	DWORD is_msg_valid(PBM_MSG_HDR in, DWORD in_size);

	//int handle_version(PBM_CONN in, PBM_PL_VER vers);
	////int handle_verack();
	int handle_addr(PBM_CONN conn, LPVOID in, DWORD in_size);
	DWORD send_addr_list(PBM_CONN in);

	DWORD handle_inv(PBM_CONN conn, LPVOID in, DWORD in_size);
	DWORD send_inv_list(PBM_CONN in);


	DWORD get_getdata_list(LPBYTE v_list, DWORD v, LPBYTE getdata_list);


	//	Object Handling Functions

	//int handle_obj_getpubkey();
	//int handle_obj_pubkey();
	//int handle_obj_msg();
	//int handle_obj_broadcast();


	// peer list handling functions



	//uint64_t list_add_node(PBM_ADDR in);
	//PBM_ADDR list_find_node(LPBYTE ip, DWORD* node_list_id);





}
















#endif // !BM_NETWORK_H