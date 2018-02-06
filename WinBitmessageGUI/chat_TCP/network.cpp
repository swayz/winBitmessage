#include "stdafx.h"

#ifndef BM_NETWORK_C
#define BM_NETWORK_C

#include "network.h"
#include "bm.h"
#include "memory.h"
#include "utils.h"
#include "bm_db.h"
#include "Encryption.h"

//185.21.216.183
//104.238.172.254
//95.211.231.240
//91.134.140.163:33574
//89.76.45.238 : 45211
//84.0.129.242
//64.92.0208
//64.34.219.38



DWORD network::cur_conn_id = 0;

LPCRITICAL_SECTION network::lock_conn_list;


BM_SEED network::seed_list[16] = {
	{ "127.0.0.1", "8444" },

	{ "185.21.216.183", "8444" },
	{ "104.238.172.254", "8444" },
	{ "95.211.231.240", "8444" },
	{ "91.134.140.163", "33574" },
	{ "89.76.45.238", "45211" },
	{ "84.0.129.242", "8444" },
	{ "64.92.0.208", "8444" },
	{ "64.34.219.38", "8444" }
};

PBM_CONN_LIST network::con_list = NULL;






//
//
//	Initialization
//
//


void network::init()
{

	network::con_list = (PBM_CONN_LIST)ALLOC_(BM_MAX_CONNECTIONS * sizeof(PBM_CONN));
	ZERO_(network::con_list, BM_MAX_CONNECTIONS * sizeof(PBM_CONN));

	ULONG_PTR conn_pool = (ULONG_PTR)ALLOC_(BM_MAX_CONNECTIONS * sizeof( BM_CONN));
	ZERO_((LPVOID)conn_pool, BM_MAX_CONNECTIONS * sizeof(BM_CONN));

	for (int i = 0; i < BM_MAX_CONNECTIONS; i++)
	{
		network::con_list->list[i] = (PBM_CONN)conn_pool;
		conn_pool += sizeof(BM_CONN);
	}

	network::lock_conn_list = (LPCRITICAL_SECTION)ALLOC_(sizeof(CRITICAL_SECTION));


	//network::send_buffer_lock = (LPCRITICAL_SECTION)ALLOC_(sizeof(CRITICAL_SECTION));


	InitializeCriticalSection(network::lock_conn_list);
	//InitializeCriticalSection(network::send_buffer_lock);

	WSADATA w; //Winsock startup info
	int error = WSAStartup(0x0202, &w);   // Fill in WSA info

	if (w.wVersion != 0x0202)
	{ // wrong WinSock version!
		WSACleanup(); // unload ws2_32.dll
		ExitProcess(0);
	}
}














//
//
//	Connection Functions
//
//



int network::start(HWND hwnd)
{

	long to_ip = NULL;
	int to_port = NULL;

	uint64_t node_id = NULL;
	SOCKET s = NULL;
	PBM_CONN last_conn = NULL;
	PBM_MSG_HDR packet = NULL;
	DWORD packet_size = NULL;
	PBM_ADDR _addr = (PBM_ADDR)ALLOC_(sizeof(BM_ADDR));

	PBM_CONN new_conn = NULL;

	for (int i = 0; i < 9; i++) //only attempt 5 connections for now.
	{
		ZERO_(_addr, sizeof(BM_ADDR));
		//	enumerate seed list and convert appropriately.
		new_conn = NULL;
	
		to_ip = inet_addr(network::seed_list[i].ip);
		to_port = atoi(network::seed_list[i].port);

		*(uint32_t*)&_addr->ip[12] = to_ip;
		*(uint16_t*)_addr->port = htons((uint16_t)to_port);
		*(uint32_t*)_addr->stream = htonl((uint32_t)1);
		*(uint64_t*)_addr->services = BM::swap64((uint64_t)1);
		*(uint64_t*)_addr->time = BM::swap64(BM::unix_time());


		node_id = BMDB::node_add(_addr);


		PBM_CONN_THREAD_DATA td = (PBM_CONN_THREAD_DATA)ALLOC_(sizeof(BM_CONN_THREAD_DATA));
		td->ipv4 = to_ip;
		td->port = to_port;
		td->sqlite_node_id = node_id;

		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)init_connect, (LPVOID)td, NULL, 0);


	}

	ZEROFREE_(_addr, sizeof(BM_ADDR));

	return TRUE;
}











int network::connect(HWND hwnd, PBM_CONN* out, long hostname, int PortNo, uint64_t sqlite_node_id)
{
	SOCKET s = NULL;

	SOCKADDR_IN target = {};

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
	
	if (s == INVALID_SOCKET) return FALSE;
	

	target.sin_family = AF_INET;        
	target.sin_port = htons(PortNo);       
	target.sin_addr.s_addr = hostname; 


	if (connect(s, (SOCKADDR *)&target, sizeof(target)) == SOCKET_ERROR) return FALSE;
	

	if (out)
		*out = network::reg_conn(s, hostname, NULL, PortNo, sqlite_node_id);


	return TRUE; 
}














void network::init_connect(PBM_CONN_THREAD_DATA in)
{
	
	if (!in) ExitThread(0);
	//if (!in) return;


	

	PBM_MSG_HDR packet = NULL;
	DWORD packet_size = NULL;

	PBM_CONN out = NULL;

	int connected = network::connect(BM::main_hwnd, &out, in->ipv4, in->port, in->sqlite_node_id);
	


	if (out && connected)
	{
		DBGOUTw(L"\rFound super node!\r");
		//EnterCriticalSection(network::lock_conn_list);
		
		out->recv_buffer = (LPBYTE)ALLOC_(BM_RECV_BUFF_SIZE);
		out->send_buffer = (LPBYTE)ALLOC_(BM_SEND_BUFF_SIZE);

		ZERO_(out->send_buffer, BM_SEND_BUFF_SIZE);
		ZERO_(out->recv_buffer, BM_RECV_BUFF_SIZE);


		out->recv_buff_size = 0; // data inside the buffer currently none.
		out->send_buff_size = 0; // 


		out->send_buffer_lock = (LPCRITICAL_SECTION)ALLOC_(sizeof(CRITICAL_SECTION));
		InitializeCriticalSection(out->send_buffer_lock);

		out->event_status = CreateEvent(NULL, FALSE, FALSE, NULL);

		
		out->recv_ = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)network::recv_thread, out, 0, 0);			
		out->send_ = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)network::send_thread, out, 0, 0);
		

		

		Sleep(500);
		
		// initiallize first packet
		packet_size = BM::init_con(&packet, in->ipv4, in->port);

		
		if (packet)
		{

			network::send_raw_data(out, packet, packet_size);

			ZEROFREE_(packet, packet_size);
			//BMDB::node_update_last_conn(BM::unix_time(), in->sqlite_node_id, TRUE);
		}
		else {
			DBGOUTw(L"\rFailed to create packet.\r");
		}

		//LeaveCriticalSection(network::lock_conn_list);

	}
	else {
		
		if (out)
			network::remove_conn(out->s);
	}

	BMDB::node_update_last_conn(BM::unix_time(), in->sqlite_node_id, connected);
	
	ZEROFREE_(in, sizeof(BM_CONN_THREAD_DATA));

	ExitThread(0);
	return;
}







// connection functions.


PBM_CONN network::reg_conn(SOCKET s, long ipv4, LPBYTE ipv6, int PortNo, uint64_t sqlite_node_id)
{

	PBM_CONN conn = NULL;// (PBM_CONN)ALLOC_(sizeof(BM_CONN));
	//ZERO_(conn, sizeof(BM_CONN));

	int i = 0;
	int found = FALSE;

	do
	{

		if (network::con_list->list[i]->status == BM_CS_FREE)
		{
			//network::con_list->list[i] = conn;
			conn = network::con_list->list[i];
			found = TRUE;
			break;
		}
		i++;

	} while (i < BM_MAX_CONNECTIONS);


	if (found)
	{

		conn->id = sqlite_node_id;

		conn->ipv4 = ipv4;

		if (ipv6)
		{
			memcpy_s(conn->ipv6, 16, ipv6, 16);
			conn->ipv4 = NULL;
		}

		conn->port = PortNo;
		conn->s = s;
		conn->time_started = BM::unix_time();
		conn->status = BMCS_INITIAL;
		

		network::cur_conn_id++;

	}
	else {

		//ZEROFREE_(conn, sizeof(BM_CONN));
		conn = FALSE;
	}

	return conn;
}







PBM_CONN network::add_conn(SOCKET s, long to_ip, int to_port)
{
	network::cur_conn_id++;
	BOOL found = FALSE;
	PBM_CONN conn = NULL;

	EnterCriticalSection(network::lock_conn_list);

	for (int i = 0; i < BM_MAX_CONNECTIONS; i++)
	{
		// find an empty entry
		if (!network::con_list->list[i]->ipv4 && !network::con_list->list[i]->status)
		{
			//	cleans the code up.
			conn = network::con_list->list[i];

			// set the information
			conn->id = network::cur_conn_id++;
			conn->ipv4 = to_ip;

			ZERO_(conn->ipv6, 16);

			conn->port = to_port;
			conn->s = s;
			conn->status = TRUE;
			conn->time_started = BM::unix_time();

			found = TRUE;
			break;
		}

	}

	LeaveCriticalSection(network::lock_conn_list);

	if (found)
		return conn;

	return FALSE;
}






PBM_CONN* network::find_conn(SOCKET s, DWORD * id)
{

	PBM_CONN conn = NULL;
	PBM_CONN* pconn = NULL;

	EnterCriticalSection(network::lock_conn_list);

	for (int i = 0; i < BM_MAX_CONNECTIONS; i++)
	{
		conn = network::con_list->list[i];
		pconn = &network::con_list->list[i];

		if (s && !*id && conn && conn->s == s)
		{
			*id = i;
			LeaveCriticalSection(network::lock_conn_list);
			return pconn;
			break;
		}else if(!s && *id && *id == conn->id){
			
			*id = i;
			LeaveCriticalSection(network::lock_conn_list);
			return pconn;
			break;

		}
	}

	LeaveCriticalSection(network::lock_conn_list);

	return FALSE;
}






BOOL network::is_conn_ready(PBM_CONN conn)
{
	if (conn && conn->s && conn->time_started && conn->verack /*&& conn->peerswap*/ && conn->status)
	{
		return TRUE;
	}
	return FALSE;
}







BOOL network::remove_conn(SOCKET s)
{
	BOOL ret = FALSE;
	DWORD i = NULL;
	
	//EnterCriticalSection(network::lock_conn_list);

	PBM_CONN* pconn = network::find_conn(s, &i);

	if (!pconn) return ret;

	PBM_CONN conn = *pconn;


	
	if (conn && i < BM_MAX_CONNECTIONS)
	{
		
		//BMDB::node_update_last_conn(BM::unix_time(), conn->id, FALSE);

		//TerminateThread(conn->send_, TRUE);
		//TerminateThread(conn->recv_, TRUE);

		conn->status = FALSE;

		shutdown(conn->s, 2);
		closesocket(conn->s);
		

		WaitForSingleObject(conn->recv_, INFINITE);
		WaitForSingleObject(conn->send_, INFINITE);




	//	Sleep(2000);

		if (conn->recv_buffer)
		{
			ZEROFREE_(conn->recv_buffer, BM_RECV_BUFF_SIZE);
			conn->recv_buffer = NULL;
			conn->recv_buff_size = NULL;
		}

		if (conn->send_buffer)
		{
			ZEROFREE_(conn->send_buffer, BM_SEND_BUFF_SIZE);
			conn->send_buffer = NULL;
			conn->send_buff_size = NULL;

		}

		CloseHandle(conn->event_status);
	
		DeleteCriticalSection(conn->send_buffer_lock);
		ZEROFREE_(conn->send_buffer_lock, sizeof(CRITICAL_SECTION));

		ZERO_(conn, sizeof(BM_CONN));

		
		ret = TRUE;
	}

	//LeaveCriticalSection(network::lock_conn_list);


	return ret;

}



//
//
//
//
//



VOID CALLBACK network::maintain_health()
{
	////
	//// Attempt a connection to all the nodes in the list that arent connected.
	//// call this function every 30 min?

	DBGOUTw(L"\rAttempting connection to the current list of nodes.\r");

	BOOL found = FALSE;
	sqlite3_stmt * stmt = NULL;
	LPSTR st = "SELECT ID,IPV4,PORT,LAST_CONN FROM NODES WHERE IS_CONNECTED = 0 AND LAST_CONN >= 0 OR LAST_CONN_ATMPT <= ? ORDER BY LAST_CONN_ATMPT DESC LIMIT 150";

	PBM_MSG_HDR packet = NULL;
	DWORD packet_size = NULL;

	//PBM_CONN_THREAD_DATA mem_list[150] = {};

	int rc = NULL;
	DWORD len = 0;
	PBM_ADDR _addr = NULL;
	DWORD _id = 0;

	PBM_CONN _conn = NULL;

	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	//	Find a node that is older then 15 mins
	sqlite3_bind_int64(stmt, 1, (BM::unix_time() - (1000 * 60 * 15)));

	uint32_t ipv4 = 0;
	uint32_t port = 0;

	DWORD rows = 0;
	DWORD id = 0;
	int connected = FALSE;

	PBM_CONN_THREAD_DATA cd = NULL;

	if (rc == SQLITE_OK)
	{
		rc = sqlite3_step(stmt);

		//
		//	Step over all the rows and create a thread for each one.
		//	speeding this node discovery shit up :>.
		//

		
		

		EnterCriticalSection(network::lock_conn_list);

		for (DWORD i = 0; i < BM_MAX_CONNECTIONS; i++)
		{
			if (network::con_list && 
				network::con_list->list[i] &&
				network::con_list->list[i]->status > 0 &&
				network::con_list->list[i]->s > 0)
			{
				if (WaitForSingleObject(network::con_list->list[i]->event_status, 5000) == WAIT_TIMEOUT)
				{
					network::remove_conn(network::con_list->list[i]->s);
				}
			}else if(network::con_list &&
				network::con_list->list[i] &&
				network::con_list->list[i]->status == NULL &&
				network::con_list->list[i]->s > 0)
			{
				network::remove_conn(network::con_list->list[i]->s);
			}
		}

		LeaveCriticalSection(network::lock_conn_list);





		do {

			ipv4 = NULL;
			port = NULL;
			connected = FALSE;
			id = NULL;
			_addr = NULL;

			if (rc == SQLITE_ROW)
			{
				
				cd = (PBM_CONN_THREAD_DATA)ALLOC_(sizeof(BM_CONN_THREAD_DATA));

		
				cd->hwnd = BM::main_hwnd;
				cd->sqlite_node_id = id = sqlite3_column_int64(stmt, 0);
				cd->ipv4 = ipv4 = inet_addr((LPSTR)sqlite3_column_text(stmt, 1));
				cd->port = port = sqlite3_column_int(stmt, 2);
				
				
				CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)network::init_connect, cd,0,0);

				Sleep(500);

			}

			rc = sqlite3_step(stmt);
			Sleep(1);
			rows++;
		} while (rc == SQLITE_ROW && rows < 150);



	}


	sqlite3_finalize(stmt);
	ExitThread(0);


}












PBM_CONN network::has_connection()
{
	for (int i = 0; i < BM_MAX_CONNECTIONS; i++)
	{
		if (network::con_list->list[i])
		{
			if (network::con_list->list[i]->status == BMCS_CONNECTED)
			{

				return network::con_list->list[i];

			}
		}
	}
	return FALSE;
}





//DWORD network::is_msg_hdr_valid(PBM_MSG_HDR in)
//{
//
//	return TRUE;
//
//}

DWORD network::is_msg_valid(PBM_MSG_HDR in, DWORD in_size)
{
	
	DWORD ret = 0;

	if (!in)
	{
		return FALSE;
	}
	DWORD m = BM_MAGIC;

	if (memcmp(in->magic, &m, 4))
	{
		//DBGOUTa("\rMSG Magic ERROR\r");
		ret |= BM_MSG_MAGIC_ERROR;

		goto end;
	}

	DWORD pl_size = htonl(*(uint32_t*)in->length);

	if (!in_size || in_size < sizeof(BM_MSG_HDR)) {
		DBGOUTa("\rMSG Size ERROR\r");
		ret |= BM_MSG_LEN_ERROR;
		goto end;
	}

	if (pl_size < in_size)
	{

		BYTE *hash = (BYTE*)ALLOC_(MAX_PATH);
		ZERO_(hash, MAX_PATH);

		Encryption::create_hash((LPSTR)hash, in->payload, pl_size, hash, 0, CALG_SHA_512);

		if (memcmp(hash, in->checksum, 4))
		{
			//DBGOUTa("MSG Hash ERROR!");
			//ZEROFREE_(hash, MAX_PATH);
			ret |= BM_MSG_HASH_ERROR;
		}


		ZEROFREE_(hash, MAX_PATH);
	}
	else {
		ret |= BM_MSG_HASH_ERROR;
	}

end:

	return ret;
}









//

BOOL sendloop()
{
	while (1)
	{
		// recv

		// t = is msg valid

		// if (t) start work

		// if ((recv_size > pl_size + 24) && is_msg_magic_valid) copy data to start of buffer

		// continue;






	}
}










VOID CALLBACK network::recv_thread(PBM_CONN in)
{
	SleepEx(500, TRUE);
	DWORD shutdown = FALSE;

	BMDB::node_update_last_conn(BM::unix_time(), in->id, FALSE);

//
//
//	Thread Functions
//
	LPBYTE chunk = (LPBYTE)ALLOC_(BM_CHUNK_SIZE);

	DWORD ret = 0;
	PBM_MSG_HDR msg_hdr = 0;
	DWORD pl_size = 0;
	int recv_size = 0;
	//BOOL too_big = FALSE;
	DWORD is_msg_valid = BM_MSG_IS_VALID;
	int i = 0;
	DWORD msg_size = 0;
	
	do
	{
		ret = 0;
		msg_hdr = 0;
		//
		// Receive Data
		//
		///DBGOUTw(L"-");

		SetEvent(in->event_status);

		ret = recv(in->s, (char*)&in->recv_buffer[recv_size], BM_CHUNK_SIZE, 0);



		if (ret && ret != SOCKET_ERROR)
		{
			msg_hdr = (PBM_MSG_HDR)in->recv_buffer;
			msg_size = htonl(*(uint32_t*)msg_hdr->length) + 24;
			recv_size += ret;
			
			is_msg_valid = network::is_msg_valid((PBM_MSG_HDR)in->recv_buffer, recv_size);

			if (!is_msg_valid )
			{

				DWORD total = 0;

				if (recv_size > msg_size)
				{
					while (!is_msg_valid && in->status)
					{


						// get total msg size


						network::start_work(in, msg_hdr);
						
						ZERO_(msg_hdr, msg_size);

						total += msg_size;

						msg_hdr = (PBM_MSG_HDR)&in->recv_buffer[msg_size];
						msg_size = htonl(*(uint32_t*)msg_hdr->length) + 24;

						is_msg_valid = network::is_msg_valid(msg_hdr, msg_size);

					}

					if (total < recv_size && is_msg_valid == BM_MSG_HASH_ERROR)
					{
						DWORD rem_buff_s = (recv_size - total);

						memcpy_s(chunk, BM_CHUNK_SIZE, msg_hdr, rem_buff_s);
						
						ZERO_(in->recv_buffer, BM_RECV_BUFF_SIZE);

						memcpy_s(in->recv_buffer, BM_RECV_BUFF_SIZE, chunk, rem_buff_s);

						ZERO_(chunk, BM_CHUNK_SIZE);

						recv_size = rem_buff_s;
					}
					else if(total == recv_size){
						recv_size = 0;
						ZERO_(in->recv_buffer, BM_RECV_BUFF_SIZE);

					}

					int t = 0;
				}
				else {
					///DBGOUTw(L"\n");
					
					
					
					network::start_work(in, msg_hdr);



					recv_size = 0;
					ZERO_(in->recv_buffer, BM_RECV_BUFF_SIZE)
				}



				is_msg_valid = -1;
			}
			else if(is_msg_valid == BM_MSG_HASH_ERROR)
			{

				
				continue;

			}
			else {

				recv_size = 0;
				ZERO_(in->recv_buffer, BM_RECV_BUFF_SIZE)
			}

		}
		else if (ret == SOCKET_ERROR)
		{
			DWORD e = WSAGetLastError();

			switch (e)
			{
				case WSAESHUTDOWN:
					shutdown = TRUE;
					break;
				case WSAECONNABORTED:
					shutdown = TRUE;
					break;
				case WSAETIMEDOUT:
					shutdown = TRUE;
					break;
				case WSAECONNRESET:
					shutdown = TRUE;
					break;
				case WSAENETRESET:
					shutdown = TRUE;
					break;
				case WSAENOTCONN:
					shutdown = TRUE;
					break;

				default:
					shutdown = TRUE;
					break;
			}
			
			//Sleep(200);
		}
		else if (!ret)
		{
			// connection lost			
			shutdown = TRUE;
			
		}

		if (shutdown)
		{
			//network::remove_conn(in->s);
			break;
		}

		//Sleep(200);

	} while (in->status != FALSE);


	in->status = FALSE;

	ExitThread(0);
}










int CALLBACK network::send_thread(PBM_CONN in)
{

	int i = 0;

	while (in->status != FALSE)
	{

		Sleep(15);

		if (i > 1000)
		{
			network::send_ready_objs(in);
			i = 0;
		}
		i++;
	}

	ExitThread(0);
	return 0;
	
}


















BOOL network::send_raw_data(PBM_CONN in, PBM_MSG_HDR msg, DWORD size)
{

	if (!in || !in->send_buffer_lock) 
		return 0;

	EnterCriticalSection(in->send_buffer_lock);

	ZERO_(in->send_buffer, BM_SEND_BUFF_SIZE);
	memcpy_s(in->send_buffer, BM_SEND_BUFF_SIZE, msg, size);

	in->send_buff_size = size;

	network::send_chunks(in->s, (LPBYTE)msg, size);

	LeaveCriticalSection(in->send_buffer_lock);
	return TRUE;
}









BOOL network::queue_obj(PBM_CONN conn, LPBYTE vector)
{

	LPSTR st = "INSERT INTO obj_send_queue(conn_id, vector, delay_expires) VALUES(?,?,?)";
	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	sqlite3_bind_int(stmt, 1, conn->id);
	sqlite3_bind_blob(stmt, 2, vector, 32, NULL);
	
	DWORD delay = (DWORD)(LOWORD(Utils::myRand()) / 1000);
	DWORD delay_expires = BM::unix_time() + delay;
	
	sqlite3_bind_int(stmt, 3, delay_expires);

	rc = sqlite3_step(stmt);

	sqlite3_finalize(stmt);


	return TRUE;
}







BOOL network::send_ready_objs(PBM_CONN in)
{
	EnterCriticalSection(in->send_buffer_lock);

	BOOL ret = FALSE;
	LPSTR del_st = "DELETE FROM obj_send_queue WHERE delay_expires < ? AND conn_id = ?";
	LPSTR st = "SELECT * FROM obj_send_queue WHERE delay_expires < ? AND conn_id = ?";
	sqlite3_stmt* stmt = NULL;
	sqlite3_stmt* del_stmt = NULL;

	int rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);
	int del_rc = sqlite3_prepare(BM::db, del_st, -1, &del_stmt, NULL);


	if (rc == SQLITE_OK)
	{

		DWORD vector_size = 0;
		LPBYTE vector = NULL;


		PBM_MSG_HDR msg = (PBM_MSG_HDR)in->send_buffer;
		DWORD t = BM::unix_time();

		rc = sqlite3_bind_int(stmt, 1, t);
		rc = sqlite3_bind_int(stmt, 2, in->id);

		rc = sqlite3_bind_int(del_stmt, 1, t);
		rc = sqlite3_bind_int(del_stmt, 2, in->id);



		rc = sqlite3_step(stmt);
		

		while (rc == SQLITE_ROW)
		{
			ZERO_(msg, BM_SEND_BUFF_SIZE);
			vector_size = sqlite3_column_bytes(stmt, 2);
			if (vector_size == 32)
			{
				vector = (LPBYTE)sqlite3_column_blob(stmt, 2);

				DWORD bs = BM_SEND_BUFF_SIZE - 24;

				if (BMDB::vector_find(vector, (PBM_OBJECT)msg->payload, &bs))
				{

					DWORD msg_size = BM::init_msg_hdr(msg, bs, BM_MTS_OBJECT);

					BOOL send_it = TRUE;
					
					DBGOUTa("\nout->");
					
					switch (htonl(((PBM_OBJECT)msg->payload)->objectType))
					{
						
					case 0:
						DBGOUTa("getpubkey\n");
						break;
					case 1:
						DBGOUTa("pubkey\n");
						break;
					case 2:
						DBGOUTa("msg\n");
						break;
					case 3:
						DBGOUTa("broadcast\n");
						break;

					default:
						DBGOUTa("object type error!\n");
						send_it = FALSE;
						break;
					}

					if (send_it)
						network::send_chunks(in->s, (LPBYTE)msg, msg_size);

				}

			}

			rc = sqlite3_step(stmt);

		};
		
	}
	
	sqlite3_finalize(stmt);
	
	del_rc = sqlite3_step(del_stmt);
	sqlite3_finalize(del_stmt);




	LeaveCriticalSection(in->send_buffer_lock);

	return ret;

	
}












int network::send_chunks(SOCKET s, LPBYTE in, DWORD in_size)
{
	typedef struct  {
		BYTE chunk[BM_CHUNK_SIZE];
	}chunk;

	int ret = 0;

	if (in_size < BM_CHUNK_SIZE)
	{
		
		ret = send(s, (const char *)in, in_size, NULL);

	}else
	{
	
		chunk* ch = (chunk*)in;

		DWORD rem_chunk = in_size % BM_CHUNK_SIZE;

		DWORD chunks_n = !rem_chunk ? (in_size / BM_CHUNK_SIZE) : (in_size / BM_CHUNK_SIZE) + 1;

		DWORD chunk_size = BM_CHUNK_SIZE;

		int i = 0;

		while (chunks_n)
		{

			if (chunks_n == 1 && rem_chunk)
			{
				chunk_size = rem_chunk;
			}

			ret = send(s, (const char *)&ch[i].chunk, chunk_size, NULL);

			i++;
			chunks_n--;
		}

	}

	return ret;
}






VOID CALLBACK network::start_work(PBM_CONN in, PBM_MSG_HDR msg)
{
	
	
	if (!in || !msg)
	{
		goto end;
	}
	

	DWORD msg_type = NULL;
	DWORD con_ret = NULL;

	PBM_MSG_HDR msg_hdr = msg;

	if (!msg_hdr) goto end;

	LPSTR command = (LPSTR)msg_hdr->command;

	DWORD payload_size = htonl(*(uint32_t*)msg_hdr->length);
		
	do
	{
		

		if (!lstrcmpA(command, "version"))
		{
				
			DBGOUTa(command);
			DBGOUTa("\r");
			//	verify version
			//	send verack packet in response
			msg_type = BM_MT_VERSION;

			//  check if this is valid
//			if (!(in->status | BMCS_INITIAL)) return;

			if (!BM::verify_version((PBM_PL_VER)msg_hdr->payload))
			{

				DBGOUTw(L"\r\r--Version failed to verify--\r\r");
				break;
				// close connection

			}
			else {

				//	success
				//	send verack

				//ZERO_(in->recv_buffer, BM_RECV_BUFF_SIZE);

				BYTE tmp[512] = {};
				PBM_MSG_HDR mdr = (PBM_MSG_HDR)tmp;


				BM::init_verack(mdr);

				//send(in->s, (const char*)msg_hdr, sizeof(BM_MSG_HDR), NULL);
				network::send_raw_data(in, mdr, 24);

				Sleep(1000);

				network::send_addr_list(in);

				Sleep(1000);

				network::send_inv_list(in);


			}

				
		}
		else if (!lstrcmpA(command, "verack"))
		{
			DBGOUTa("\r");
			DBGOUTa(command);
			DBGOUTa("\r");
			//	Received and accpeted my version complete
			msg_type = BM_MT_VERACK;
			
				
			in->verack = TRUE;
			in->status = BMCS_CONNECTED;
			



		}
		else if (!lstrcmpA(command, "addr"))
		{
			DBGOUTa("\r");
			DBGOUTa(command);
			DBGOUTw(L"\r");
			//	to be received in response to sending out a verack msg
			//	parse the incoming list of known IPs
			//	add them to the main peer list
			//	
			//	also send out a random list of known IPs
			size_t int_len = NULL;

			uint32_t payload_size = htonl(*(uint32_t*)msg_hdr->length);

			if (payload_size > 1024 * 50)
				break;

			BM::receive_addr_list(msg_hdr->payload, payload_size);
				
				

			

			if (in && in->peerswap == FALSE)
			{
					
				// Send list of nodes
				network::send_addr_list(in);

			}
				

				
		}
		else if (!lstrcmpA(command, "inv"))
		{
			DBGOUTa(command);
			DBGOUTa("\r");

			//	to be received in response to sending out an addr msg
			//	or if new if new inventory is available
			//	if we do not have a vector then request the object via "getdata" request
			//	"getdata" is in response to "inv".
			//	store new vectors only when we receive a valid object



			size_t int_len = 0;
			LPBYTE v_list = NULL;
			uint64_t v = BM::decodeVarint(msg_hdr->payload, 6, &int_len);

			if (v <= BM_MAX_VECT_LIST_ENTRYS && int_len < 5)
			{

				v_list = (LPBYTE)&msg_hdr->payload[int_len];



				DWORD out_size = 24 + BM_VECT_LIST_BUFF_SIZE + MAX_VARINT_SIZE;
					
				PBM_MSG_HDR out_msg = (PBM_MSG_HDR)ALLOC_(out_size);
				ZERO_(out_msg, out_size);
					
				LPBYTE getdata_list = out_msg->payload + (ULONG_PTR)MAX_VARINT_SIZE;

					

				//
				//
				//	Find Vectors that we dont have and add them to the getdata_list
				//
				//
					
				DWORD v_cnt = network::get_getdata_list(v_list, v, getdata_list);

				//
				//	prepare to send getdata msg.
				//

				DWORD varint_size = BM::encodeVarint(v_cnt, out_msg->payload);
				LPBYTE new_list = NULL;
				DWORD getdata_list_size = NULL;
				LPBYTE padding = NULL;
				DWORD padding_size = NULL;
				DWORD rem_buff = NULL;
				DWORD payload_size = NULL;

					

				if (v_cnt && varint_size <= 3)
				{
					DBGOUTa("\rPreparing getdata msg!\r");
					getdata_list_size = (v_cnt * BM_VECTOR_SIZE);
					new_list = (out_msg->payload + (ULONG_PTR)varint_size);
					//padding = (out_msg->payload + (ULONG_PTR)(varint_size + getdata_list_size));
					//padding_size = BM_VECT_LIST_BUFF_SIZE - (varint_size + getdata_list_size);
					rem_buff = BM_VECT_LIST_BUFF_SIZE - varint_size;
					payload_size = varint_size + getdata_list_size;

		
					LPBYTE tmp = (LPBYTE)ALLOC_(getdata_list_size);

					memcpy_s(tmp, getdata_list_size, getdata_list, getdata_list_size);

					ZERO_(new_list, rem_buff);

					memcpy_s(new_list, rem_buff, tmp, getdata_list_size);

					ZEROFREE_(tmp, getdata_list_size);


					if (BM::init_msg_hdr(out_msg, payload_size, BM_MTS_GETDATA))
					{
						DWORD msg_size = 24 + payload_size;

						network::send_raw_data(in, out_msg, msg_size);
						//send(in->s, (const char *)out_msg, msg_size, NULL);

						ZERO_(out_msg, 24 + BM_VECT_LIST_BUFF_SIZE);

					}



				}



				if (in && !in->invswap)
				{

					network::send_inv_list(in);

				}

				ZEROFREE_(out_msg, sizeof(BM_MSG_HDR) + BM_VECT_LIST_BUFF_SIZE);

					

			}
			msg_type = BM_MT_INV;


		}
		else if (!lstrcmpA(command, "getdata"))
		{
			DBGOUTa(command);
			//	in response to sending an INV message
			//	requesting the content of an object 
			//	
			size_t vect_cnt = 0;

			DWORD read_offset = BM::decodeVarint(msg_hdr->payload, 7, &vect_cnt);

			typedef struct s_vect{
				BYTE vect[32];
			};

			s_vect * vect_list = (s_vect *)&msg_hdr->payload[read_offset];
			DWORD inv_id = NULL;



			do
			{ 
				inv_id = BMDB::vector_find(vect_list->vect, NULL, NULL);

				if (inv_id)
				{
					network::queue_obj(in, vect_list->vect);
				}


				vect_cnt--;
			}while(vect_cnt);


			msg_type = BM_MT_GETDATA;


		}
		else if (!lstrcmpA(command, "object"))
		{
			DBGOUTa(command);
			//	The only message that is propagated throughout the network entirely.
			//
			//	Create Inventory hash by taking the first 32 bytes of SHA512(SHA512(object))
			//	as well as store the hash along with object in the vectors list.
				

			msg_type = BM_MT_OBJECT;

			size_t int_len = htonl(*(uint32_t*)msg_hdr->length);
			PBM_OBJECT obj = (PBM_OBJECT)msg_hdr->payload;

			BYTE vector[MAX_PATH] = {};

			BM::create_vector_tag((LPBYTE)obj, int_len, vector, MAX_PATH);

			// attempt to find object

			if (!BMDB::vector_find(vector, NULL, NULL))
			{
				if (!BM::process_object(obj, int_len, vector))
				{

				
					// propogate the msg/object			
					//
					network::queue_obj(in, vector);
				
				
				}
			}
				
		}
		else if (!lstrcmpA(command, "pong"))
		{
			DBGOUTa("Server Hearbeat (PONG)\n");

			//Utils::copy_mem(in->send_buffer, BM_SEND_BUFF_SIZE, "ping", 5);

			network::send_raw_data(in, (PBM_MSG_HDR)"ping", 5);
		}
		else {
			DBGOUTa(command);
				
		}

		DBGOUTa("\r");
		

		break;
	}while (1);

dealloc:

	//LeaveCriticalSection(network::lock_conn_list);
	//DBGOUTa("FREE NETWORK BUFFER\n");
	//ZERO_(in->recv_buffer, BM_RECV_BUFF_SIZE);
	//in->recv_buff_size = 0;

		

end:
	
	//ExitThread(0);
	return;

}




int network::handle_addr(PBM_CONN conn, LPVOID in, DWORD in_size)
{
	if (!in || !in_size)
		return FALSE;

	size_t int_len = NULL;

	uint64_t count = BM::decodeVarint((uint8_t*)in, in_size, &int_len);

	if (count < 1)
		return FALSE;

	PBM_ADDR addr_list = (PBM_ADDR)in + (ULONG_PTR)int_len;

	for (int i = 0; i < count; i++)
	{
		//	check if node is already in the list

		if (!BMDB::node_find(addr_list[i].ip, NULL))
		{
			BMDB::node_add(&addr_list[i]); // add it if not
		}

	}


	// should send back list of IPs
	// spec says "should" so maybe we dont have to ??
	// send(conn->s, 0, 0, 0);

	return TRUE;
}






DWORD network::handle_inv(PBM_CONN conn, LPVOID in, DWORD in_size)
{

	if (!in || !in_size)
		return FALSE;

	//size_t int_len = NULL;

	//uint64_t count = BM::decodeVarint((uint8_t*)in, in_size, &int_len);

	//if (count < 1)
	//	return FALSE;

	//PBM_VECTOR vector = (PBM_VECTOR)in + (ULONG_PTR)int_len;

	//for (int i = 0; i < count; i++)
	//{
	//	//	check if node is already in the list

	//	if (!BMDB::vector_find(vector->hash))
	//		BMDB::vector_add(vector->hash); // add it if not

	//}


	//// should send back list of vectors
	//// spec says "should" so maybe we dont have to ??
	//// send(conn->s, 0, 0, 0);

	return TRUE;

}








DWORD network::send_addr_list(PBM_CONN in)
{
	// Send list of nodes
	PBM_MSG_HDR msg_hdr = (PBM_MSG_HDR)ALLOC_(24 + BM_ADDR_LIST_BUFF_SIZE);
	LPVOID node_list = msg_hdr->payload;
	DWORD msg_size = NULL;
	DWORD ret = FALSE;
	DWORD pl_size = BMDB::addr_list(1000, node_list, BM_ADDR_LIST_BUFF_SIZE);

	if (pl_size)
	{

		msg_size = BM::init_msg_hdr(msg_hdr, pl_size, BM_MTS_ADDR);

		//send(in->s, (const char *)msg_hdr, msg_size, NULL);
		network::send_raw_data(in, msg_hdr, msg_size);

		in->peerswap = TRUE;
		ret = TRUE;
	}

	ZEROFREE_(msg_hdr, 24 + BM_ADDR_LIST_BUFF_SIZE);

	return TRUE;
}







DWORD network::send_inv_list(PBM_CONN in)
{
	// Send list of nodes
	PBM_MSG_HDR msg_hdr = (PBM_MSG_HDR)ALLOC_(sizeof(BM_MSG_HDR) + BM_VECT_LIST_BUFF_SIZE);
	LPVOID vect_list = msg_hdr->payload;
	DWORD msg_size = NULL;
	DWORD ret = FALSE;
	DWORD pl_size = BMDB::vect_list(50000, vect_list, BM_VECT_LIST_BUFF_SIZE);

	if (pl_size)
	{

		msg_size = BM::init_msg_hdr(msg_hdr, pl_size, BM_MTS_INV);

		//send(in->s, (const char *)msg_hdr, msg_size, NULL);
		network::send_raw_data(in, msg_hdr, msg_size);

		in->invswap = TRUE;
		ret = TRUE;
	}

	ZEROFREE_(msg_hdr, sizeof(BM_MSG_HDR) + BM_ADDR_LIST_BUFF_SIZE);

	return TRUE;
}










DWORD network::get_getdata_list(LPBYTE v_list, DWORD v, LPBYTE getdata_list)
{
	// Send list of nodes


	DWORD v_cnt = 0;
	LPBYTE bmv = NULL;
	BOOL is_valid = FALSE;


	for (int i = 0; i < v && i < BM_MAX_VECT_LIST_ENTRYS; i++)
	{
		is_valid = TRUE;

		// This needs more looking!!!
		if (i * BM_VECTOR_SIZE > BM_RECV_BUFF_SIZE)
			break;

		bmv = (LPBYTE)&v_list[i * BM_VECTOR_SIZE];

		//	test if hash is valid.
		is_valid = TRUE;

		for (uint32_t j = 0; j < BM_VECTOR_SIZE; j++)
		{
			if (!bmv[j])
			{
				//is_valid = FALSE;
				break;
			}
		}

		if (is_valid)
		{
			// if we dont have it add it to getdata_list for sending

			if (!BMDB::vector_find(bmv, NULL, NULL))
			{
				Sleep(1);
				memcpy_s(&getdata_list[v_cnt * BM_VECTOR_SIZE], BM_VECTOR_SIZE, bmv, BM_VECTOR_SIZE);
				v_cnt++;
			}


		}
		else {
			break;
		}

	}

	return v_cnt;
}












#endif