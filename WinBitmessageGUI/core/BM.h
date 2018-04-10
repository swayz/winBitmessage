#pragma once
#include "stdafx.h"

#ifndef BM_H
#define BM_H



namespace BM { //BitMessage (BM is easier to type :P)

	extern PBM_VECT_LIST vector_list;
	extern PBM_NODE_LIST node_list;
	extern HWND main_hwnd;
	extern HWND send_data_thread;
	//extern HINST h_inst;

	//
	// The SQLite3 DB
	//
	extern sqlite3 * db;

	extern HANDLE prop_thread_handle;

	//
	//	Initialization
	//	Call init() at the begining of main()
	//

	void init();

	//
	//
	//	Address functions
	//
	//

	DWORD validate_address(LPSTR address, DWORD length, PBM_MSG_ADDR out_addr);
	DWORD create_addr(PBM_MSG_ADDR * in);
	PBM_MSG_ADDR create_readable_addr(DWORD version, DWORD stream, LPBYTE ripe, DWORD ripe_size, LPBYTE checksum);
	DWORD create_tags(LPBYTE enc, LPBYTE sig, LPBYTE out);



	//
	//
	//	Communication functions
	//
	//

	DWORD set_net_addr(PBM_NET_ADDR in, long char_ip, long* long_ip, BOOL ipv6, uint16_t port, uint64_t services, int time);
	DWORD init_msg_hdr(PBM_MSG_HDR in, DWORD pl_s, LPSTR command);
	DWORD init_con(PBM_MSG_HDR* in_, long toip, uint16_t fromip);
	DWORD init_verack(PBM_MSG_HDR in);
	DWORD verify_version(PBM_PL_VER in);
	DWORD init_ver(PBM_PL_VER version_pl, long ip_to, uint16_t ip_from);
	
	
	//
	//
	//	Object processing functions
	//
	//
	
	DWORD init_object(PBM_OBJECT out_obj, DWORD out_size, uint32_t type, LPBYTE pl, DWORD payload_len);

	DWORD process_object(PBM_OBJECT object, DWORD in_size, LPBYTE vector);
	
	DWORD obj_getpubkey(PBM_OBJECT in, PBM_MSG_ADDR address_info, LPBYTE out, LPDWORD out_size);
	
	DWORD obj_pubkey(PBM_MSG_ADDR addr, PBM_OBJECT object, DWORD obj_hdr_size, PBM_PUBKEY_V4_OBJ payload, DWORD pl_size);
	
	DWORD obj_msg(PBM_OBJECT obj, PBM_ENC_PL_256 in, DWORD in_size);

//	DWORD obj_broadcast(); 






	//
	//
	//	Encryption functions
	//
	//

	DWORD encrypt_msg(PBM_MSG_HDR* out_msg, LPDWORD out_pl_size, PBM_MSG_ADDR to_addr, PBM_MSG_ADDR from_addr, LPSTR subject, LPSTR body);

	DWORD encrypt_payload(PBM_MSG_ADDR dest_addr, LPBYTE in_buff, DWORD in_size, PBM_ENC_PL_256 out, LPDWORD out_size);
	DWORD decrypt_payload(PBM_MSG_ADDR recv_addr, PBM_ENC_PL_256 in_buff, DWORD in_size);


	//
	//
	//	POW functions
	//
	//

	DWORD64 calc_pow_target(DWORD64 TTL, DWORD payloadLength, DWORD payloadLengthExtraBytes, DWORD64 averageProofOfWorkNonceTrialsPerByte);
	DWORD64 do_pow(LPBYTE payload, DWORD in_size, DWORD64 TTL);
	DWORD64 do_pow_proc(PBM_POW_THREAD_DETAILS in);
	DWORD check_pow(LPBYTE payload, DWORD in_size, DWORD64 TTL);

	
	//
	//
	//	Vector list functions
	//
	//

	BOOL create_vector_tag(LPBYTE payload, DWORD pl_size, LPBYTE out, DWORD size);
	DWORD receive_addr_list(LPBYTE payload, DWORD in_size);


	//
	//
	//	Utils
	//
	//

	size_t encodeVarint(uint64_t value, uint8_t* output);
	uint64_t decodeVarint(uint8_t* input, size_t inputSize, size_t* int_len);

	DWORD encodeVarstr(char* in, LPBYTE out, DWORD out_size);
	DWORD decodeVarstr(char* in, int in_size, char* out, int out_size);

	DWORD64 var_net_list(LPBYTE in, size_t in_size, PBM_NET_ADDR* out);

	ULONG unix_time();


	//
	//
	//	Other
	//
	//

	extern _NtQuerySystemTime NtQuerySystemTime;
		
	extern _RtlTimeToSecondsSince1970 RtlTimeToSecondsSince1970;

	extern _RtlIpv6StringToAddress RtlIpv6StringToAddress;

	uint64_t swap64(uint64_t in);

	void getnumthreads();

	extern DWORD numthreads;

	//GUI

	void send_msg(DWORD from_id, DWORD to_id, LPSTR subject, LPSTR body);


};










#endif // !BM_H