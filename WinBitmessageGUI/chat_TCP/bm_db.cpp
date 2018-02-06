#ifndef BM_DB_C
#define BM_DB_C

#include "bm_db.h"
#include "memory.h"
#include "utils.h"
#include "Encryption.h"

//
//
//	SQLite3 Database Functions.
//
//


void BMDB::init()
{

}



void BMDB::deinit()
{

}


void BMDB::show_error()
{
	LPSTR e = (LPSTR)sqlite3_errmsg(BM::db);

	DBGOUTa("SQL ERROR: ");
	DBGOUTa(e);
	DBGOUTa("\r");

	sqlite3_free(e);
}





//
//
// Message functions
//
//

BOOL BMDB::add_message(DWORD to, DWORD from, LPWSTR subject, LPWSTR body, DWORD folder, DWORD inv_id)
{

	BOOL ret = FALSE;
	LPSTR st = "INSERT INTO msgs(id, inv_id, folder, to, from, subject, body, date) VALUES(NULL, ?, ?, ?, ?, ?, ?, ?)";
	sqlite3_stmt * stmt = NULL;
	int rc = NULL;
	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	if (rc != SQLITE_OK)
		return FALSE;

	sqlite3_bind_int(stmt, 1, inv_id);
	sqlite3_bind_int(stmt, 2, folder);
	sqlite3_bind_int(stmt, 3, to);
	sqlite3_bind_int(stmt, 4, from);

	sqlite3_bind_text16(stmt, 5, subject, -1, NULL);
	sqlite3_bind_text16(stmt, 6, body, -1, NULL);

	sqlite3_bind_int64(stmt, 7, BM::unix_time());
	
	rc = sqlite3_step(stmt);

	rc = sqlite3_step(stmt);

	if (rc != SQLITE_DONE)
	{

		BMDB::show_error();

	}
	else {
		ret = TRUE;
	}

	sqlite3_finalize(stmt);

	if (ret) ret = sqlite3_last_insert_rowid(BM::db);

	return ret;

}


















//
//
//	Adress Functions
//
//




DWORD BMDB::address_find(DWORD id, LPSTR addr, PBM_MSG_ADDR pAddr)
{
	if (!pAddr) return FALSE;

	DWORD entry = NULL;
	BOOL found = FALSE;
	sqlite3_stmt * stmt = NULL;
	LPSTR st = "SELECT * FROM address_book";

	PBM_MSG_ADDR _addr = NULL;
	int rc = NULL;
	DWORD len = 0;
	
	DWORD _id = 0;
	

	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	if (rc != SQLITE_OK)
		return FALSE;


	
	if (rc == SQLITE_OK)
	{
		rc = sqlite3_step(stmt);

		int row_id = 0;
		LPSTR row_addr = NULL;
		int row_addr_size = NULL;


		do {


			if (rc == SQLITE_ROW)
			{
				if (id)
				{
					row_id = sqlite3_column_int(stmt, 0);
				}
				else if (addr)
				{
					row_addr_size = sqlite3_column_bytes(stmt, 3);
					row_addr = (LPSTR)sqlite3_column_text(stmt, 3);
				}

				if (id && id == row_id)
				{
					found = TRUE;
				}else if(addr && Utils::mem_cmp((LPBYTE)addr, lstrlenA(addr), (LPBYTE)row_addr, row_addr_size))
				{
					found = TRUE;
				}

				if (found)
				{

					len = sqlite3_column_bytes(stmt, 1);
					if (len)
					{
						//*pAddr = (PBM_MSG_ADDR)ALLOC_(sizeof(BM_MSG_ADDR));
						//PBM_MSG_ADDR mAddr = *pAddr;

						_addr = (PBM_MSG_ADDR)sqlite3_column_blob(stmt, 1);
						memcpy_s(pAddr, sizeof(BM_MSG_ADDR), _addr, len);

						rc = sqlite3_step(stmt);
						entry = TRUE;
						break;
					}
				}
			}

			rc = sqlite3_step(stmt);

		} while (!found && rc == SQLITE_ROW);



	}
	else {


		BMDB::show_error();

	}

	
	sqlite3_finalize(stmt);
	stmt = NULL;

	return entry;
}

DWORD BMDB::address_add(PBM_MSG_ADDR in, LPWSTR label)
{
	if (!in) return FALSE;

	BM_MSG_ADDR a = {};

	if (BMDB::address_find(0, in->readable, &a))
		return FALSE;


	DWORD ret = FALSE;
	PBM_MSG_ADDR addr = NULL;
	PBM_MSG_ADDR _addr = NULL;

	BOOL found = NULL;
	sqlite3_stmt * stmt = NULL;
	LPSTR st = "INSERT INTO ADDRESS_BOOK(ID, LABEL, ADDR, BLOB, DATE_ADDED, IS_PRIV) VALUES(NULL, ?, ?, ?, ?, ?)";
	int rc = NULL;
	DWORD len = 0;
	DWORD id = NULL;


	uint64_t entry = NULL;
	LPSTR tbuff = (LPSTR)ALLOC_(512);

	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	if (rc != SQLITE_OK)
	{

		show_error();

	}
	else {
		// Set up statement.

		rc = sqlite3_bind_text16(stmt, 1, label, -1, NULL);

		rc = sqlite3_bind_text(stmt, 2, in->readable, -1, NULL);

		rc = sqlite3_bind_blob(stmt, 3, in, sizeof(BM_MSG_ADDR), SQLITE_STATIC); // Date Added

		rc = sqlite3_bind_int(stmt, 4, BM::unix_time()); // Date Added

		if (*(DWORD*)(&in->prv_enc_blob))
		{
			rc = sqlite3_bind_int(stmt, 5, TRUE); // priv 
		}
		else {
			rc = sqlite3_bind_int(stmt, 5, FALSE); // priv 
		}


	}

	rc = sqlite3_step(stmt);

	if (rc != SQLITE_DONE)
	{

		show_error();

	}
	else {
		//entry = sqlite3_last_insert_rowid(BM::db);// sqlite3_column_int(stmt, 0);
		
		found = TRUE;

		DBGOUTw(L"Added BM Address: ");
		DBGOUTa(in->readable);
		DBGOUTa("\n");

	}

	sqlite3_finalize(stmt);

	ZEROFREE_(tbuff, 512);

	if (found) found = sqlite3_last_insert_rowid(BM::db);

	
	ZERO_(&a, sizeof(BM_MSG_ADDR));


	return found;
}
	
DWORD BMDB::address_remove(DWORD id)
{

	if (!id) return FALSE;

	DWORD entry = NULL;
	BOOL found = FALSE;
	sqlite3_stmt * stmt = NULL;
	LPSTR st = "DELETE FROM address_book WHERE id = ?";

	PBM_MSG_ADDR _addr = NULL;
	int rc = NULL;
	DWORD len = 0;

	DWORD _id = 0;


	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	if (rc != SQLITE_OK)
		return FALSE;

	rc = sqlite3_bind_int(stmt, 1, id);

	if (rc == SQLITE_OK)
	{
		rc = sqlite3_step(stmt);
		
	}
	else {


		BMDB::show_error();

	}


	sqlite3_finalize(stmt);
	stmt = NULL;

	return entry;
}





DWORD BMDB::atmpt_msg_decrypt(PBM_ENC_PL_256 in, DWORD size)
{
	if (!in || size < 1) return FALSE;

	DWORD ret = FALSE;
	PBM_MSG_ADDR addr = NULL;
	PBM_MSG_ADDR _addr = NULL;


	BOOL found = NULL;
	sqlite3_stmt * stmt = NULL;
	LPSTR st = "SELECT * FROM address_book";
	int rc = NULL;
	DWORD len = 0;
	DWORD id = NULL;


	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	addr = (PBM_MSG_ADDR)ALLOC_(sizeof(BM_MSG_ADDR));

	

	if (rc == SQLITE_OK)
	{
		rc = sqlite3_step(stmt);

		do {


			if (rc == SQLITE_ROW)
			{


				id = sqlite3_column_int(stmt, 0);

				len = sqlite3_column_bytes(stmt, 1);
				if (len)
				{
					_addr = (PBM_MSG_ADDR)sqlite3_column_blob(stmt, 1);
					memcpy_s(addr, sizeof(BM_MSG_ADDR), _addr, len);
				
					if (BM::decrypt_payload(addr, (PBM_ENC_PL_256)in, size))
					{
						found = TRUE;

						sqlite3_step(stmt);
						break;
					}
				}

			}

			rc = sqlite3_step(stmt);

		} while (!found && rc == SQLITE_ROW);



	}
	else {


		show_error();

	}

	sqlite3_finalize(stmt);
	ZEROFREE_(addr, sizeof(BM_MSG_ADDR));
	return found;
}


//
//
//	Node Functions
//
//

PBM_ADDR BMDB::node_find(LPBYTE ip, DWORD* node_list_id)
{
	PBM_ADDR entry = NULL;
	BOOL found = FALSE;
	sqlite3_stmt * stmt = NULL;
	LPSTR st = "SELECT ID,STRUCT,IPV4 FROM NODES WHERE IPV4 = ?";

	int rc = NULL;
	DWORD len = 0;
	PBM_ADDR _addr = NULL;
	DWORD _id = 0;

	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	if (rc != SQLITE_OK)
		return FALSE;

	LPSTR ipv4 = (LPSTR)ALLOC_(MAX_PATH);
	ZERO_(ipv4, MAX_PATH);
	

	//	last 4 bytes is the ipv4 address.

	wsprintfA(ipv4, "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);

	rc = sqlite3_bind_text(stmt, 1, ipv4,-1 , SQLITE_STATIC);
	
	

	if (rc == SQLITE_OK)
	{
		rc = sqlite3_step(stmt);

		do {


			if (rc == SQLITE_ROW)
			{


				_id = sqlite3_column_int(stmt, 0);

				len = sqlite3_column_bytes(stmt, 1);

				_addr = (PBM_ADDR)sqlite3_column_blob(stmt, 1);

				if (_addr && len == sizeof(BM_ADDR))
				{
					if (!memcmp(&_addr->ip[12], &ip[12], 4))
					{
						found = TRUE;
						entry = PBM_ADDR (1);
						//entry = (PBM_ADDR)ALLOC_(sizeof(BM_ADDR));
						//memcpy_s(entry, sizeof(BM_ADDR), _addr, len);
						*node_list_id = _id;
						sqlite3_step(stmt);
						break;
					}
				}

			}

			rc = sqlite3_step(stmt);

		} while (!found && rc == SQLITE_ROW);



	}
	else {


		show_error();

	}
	
	ZEROFREE_(ipv4, MAX_PATH);

	sqlite3_finalize(stmt);
	stmt = NULL;
	
	return entry;
}

uint64_t BMDB::node_add(PBM_ADDR in)
{
	if (!in) return FALSE;


	int rc = NULL;
	DWORD lid = 0;
	PBM_ADDR addr_ = BMDB::node_find(in->ip, &lid);
	LPSTR st = "INSERT INTO NODES(ID, STRUCT, IPV4, IPV6, PORT, STREAM, SERVICES, TIME, LAST_CONN, LAST_CONN_ATMPT, IS_CONNECTED) VALUES(NULL, ?, ?, NULL, ?, ?, ?, ?, 0, 0, 0)";


	if (lid || addr_)
	{
		//ZEROFREE_(addr_, sizeof(BM_ADDR));
		return lid;
	}
	                                                                                                                                             
	uint64_t entry = NULL;
	LPSTR tbuff = (LPSTR)ALLOC_(512);

	sqlite3_stmt * stmt = NULL;

	rc = sqlite3_prepare(BM::db,
		st,
		-1, &stmt, NULL);

	if (rc != SQLITE_OK)
	{

		show_error();

	}
	else {

		rc = sqlite3_bind_blob(stmt, 1, in, sizeof(BM_ADDR), SQLITE_STATIC);

		ZERO_(tbuff, 512);
		wsprintfA(tbuff, "%u.%u.%u.%u", in->ip[12], in->ip[13], in->ip[14], in->ip[15]);

		rc = sqlite3_bind_text(stmt, 2, tbuff,-1, SQLITE_STATIC);



		rc = sqlite3_bind_int(stmt, 3, htons(BM_PORT(in->port)));
		rc = sqlite3_bind_int(stmt, 4, htonl(*(uint32_t*)in->stream));
		
		
		rc = sqlite3_bind_int64(stmt, 5, BM::swap64(*(uint64_t*)in->services));
		rc = sqlite3_bind_int64(stmt, 6, BM::swap64(*(uint64_t*)in->time));

		//rc = sqlite3_bind_int64(stmt, 7, 0);
		//rc = sqlite3_bind_int64(stmt, 8, 0);


		if (rc != SQLITE_OK)
		{
			DBGOUTw(L"Failed to bind parameter to statement.\r");
		}
		else {

			rc = sqlite3_step(stmt);

			entry = sqlite3_last_insert_rowid(BM::db);// sqlite3_column_int(stmt, 0);

			if (rc != SQLITE_DONE)
			{
			
				show_error();

			}
			else {
				DBGOUTw(L"Added node.\r");
			}


		}



	}

	sqlite3_finalize(stmt);
	stmt = NULL;
	ZEROFREE_(tbuff, 512);


	return entry;
}

int BMDB::node_update_last_conn(uint64_t last_conn, uint64_t node_id, BOOL connected)
{
	LPSTR st = "UPDATE NODES SET LAST_CONN_ATMPT = ?,LAST_CONN = ?,IS_CONNECTED = ? WHERE ID = ?";

	sqlite3_stmt * stmt = NULL;
	sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	
	sqlite3_bind_int64(stmt, 1, last_conn);

	if (connected)
	{
		sqlite3_bind_int64(stmt, 2, last_conn);

		// is connected
		sqlite3_bind_int64(stmt, 3, TRUE);


	}
	else {
		sqlite3_bind_int64(stmt, 2, 0);

		sqlite3_bind_int64(stmt, 3, NULL);
	}

	sqlite3_bind_int64(stmt, 4, node_id);

	sqlite3_step(stmt);

	sqlite3_finalize(stmt);

	return TRUE;

}

DWORD BMDB::addr_list(DWORD limit, LPVOID out, DWORD out_size)
{

	if (limit > 1000)
		return FALSE;

	// This epic statmemnt will return a row count for us as well...:/

	LPSTR st = "SELECT id, struct, (SELECT count(id) FROM NODES WHERE LAST_CONN_ATMPT > 0 ORDER BY LAST_CONN_ATMPT DESC LIMIT ?) as cnt  FROM NODES WHERE LAST_CONN_ATMPT > 0 ORDER BY LAST_CONN_ATMPT DESC LIMIT ?";
	sqlite3_stmt * stmt = NULL;
	int rc = NULL;

	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	if (rc)
		goto fail;

	rc = sqlite3_bind_int(stmt, 1, (ULONG)limit);
	rc = sqlite3_bind_int(stmt, 2, (ULONG)limit);

	if (rc)
		goto fail;

	rc = sqlite3_step(stmt);

	

	PBM_ADDR addr = NULL;
	DWORD count = sqlite3_column_int(stmt, 2);


	if (count > BM_MAX_ADDR_LIST_ENTRYS)
	{
		count = BM_MAX_ADDR_LIST_ENTRYS;
	}

	size_t varint_len = BM::encodeVarint(count, (uint8_t*)out);

	PBM_ADDR list = (PBM_ADDR)((ULONG_PTR)out + (ULONG_PTR)varint_len);

	DWORD buff_size = BM_ADDR_LIST_BUFF_SIZE;
	DWORD blob_size = NULL;
	buff_size -= varint_len;

	do {
	

		blob_size = NULL;
		addr = NULL;

		blob_size = sqlite3_column_bytes(stmt, 1);
		addr = (PBM_ADDR)sqlite3_column_blob(stmt, 1);
		

	if (addr && blob_size == sizeof(BM_ADDR))
	{
	
		// Fill the entry in the list.
		memcpy_s(list, buff_size, addr, sizeof(BM_ADDR));
	
		// watch the buffer size !
		buff_size -= sizeof(BM_ADDR);
		
		// watch the list count
		count--;
	
		// move through the list
		list = (PBM_ADDR)((ULONG_PTR)list + (ULONG_PTR)sizeof(BM_ADDR));
	}
		rc = sqlite3_step(stmt);
		

	} while (rc == SQLITE_ROW && count && buff_size > 0);



	
		sqlite3_finalize(stmt);

	return  BM_ADDR_LIST_BUFF_SIZE - buff_size;

fail:

	show_error();

	if (stmt)
		sqlite3_finalize(stmt);

	return FALSE;
}




//
//
//	Inventory functions
//
//


uint64_t BMDB::vector_find(LPBYTE vect, PBM_OBJECT obj, LPDWORD obj_size)
{

	uint64_t ret = FALSE;
	//LPSTR st = "SELECT * FROM INVENTORY WHERE UID = ?";
	LPSTR st = "SELECT ID, DATA FROM INV WHERE UID = ?";

	int rc = FALSE;

	sqlite3_stmt * stmt = NULL;
	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	if (rc)
		goto end;

	DWORD data_size = 0;
	LPBYTE blob = NULL;
	LPSTR uid = (LPSTR)ALLOC_(512);

	wsprintfA(uid, "%x%x", ((uint32_t*)vect)[0], ((uint32_t*)vect)[1]);

	rc = sqlite3_bind_text(stmt, 1, uid, -1, SQLITE_STATIC);

	if (rc)
		goto fail;

	rc = sqlite3_step(stmt);

	do {


		if (rc == SQLITE_ROW)
		{

			ret = sqlite3_column_int64(stmt, 0);

			if (obj && obj_size && *obj_size)
			{

				data_size = sqlite3_column_bytes(stmt, 1);
				if (data_size < *obj_size)
				{

					blob = (LPBYTE)sqlite3_column_blob(stmt, 1);
					
					memcpy_s(obj, *obj_size, blob, data_size);
					
					*obj_size = data_size;

				}
			}

		}

		rc = sqlite3_step(stmt);
		break;
	} while (!ret && rc != SQLITE_ROW);


fail:


	sqlite3_finalize(stmt);

	ZEROFREE_(uid, 512);

	return ret;

end:

	sqlite3_finalize(stmt);

	show_error();


	return FALSE;

}


uint64_t BMDB::vector_add(LPBYTE vect, PBM_OBJECT object, DWORD object_size)
{
	
	int v = BMDB::vector_find(vect, NULL, NULL);
	DWORD v_size = sizeof(BM_VECTOR);

	if (v)
		return FALSE;

	uint64_t ret = FALSE;
	//LPSTR st = "INSERT INTO INVENTORY(ID, UID, TAG, OBJECT, DATE_ADDED) VALUES(NULL, ?, ?, ?, ?)";
	LPSTR st = "INSERT INTO INV(ID, UID, HASH, VERSION, TYPE, EXPIRES, DATE_ADDED, DATA) VALUES(NULL, ?, ?, ?, ?, ?, ?, ?)";

	int rc = FALSE;

	uint64_t obj_version = NULL;


	obj_version = BM::decodeVarint(object->objectVersion, 2, NULL);


	


	sqlite3_stmt * stmt = NULL;
	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	if (rc)
		goto end;



	LPSTR uid = (LPSTR)ALLOC_(512);
	wsprintfA(uid, "%x%x", ((uint32_t*)vect)[0], ((uint32_t*)vect)[1]);


	DBGOUTa("Vector tag added to the inventory: ");
	DBGOUTa(uid);
	DBGOUTa(".\r");


	// UID
	rc = sqlite3_bind_text(stmt, 1, uid, -1, SQLITE_STATIC);

	if (rc)
		goto fail;


	// HASH
	rc = sqlite3_bind_blob(stmt, 2, vect, 32, SQLITE_STATIC);

	if (rc)
		goto fail;


	// VERSION
	rc = sqlite3_bind_int(stmt, 3, (uint32_t)obj_version);

	if (rc)
		goto fail;


	// TYPE
	rc = sqlite3_bind_int(stmt, 4, ntohl(object->objectType));

	if (rc)
		goto fail;


	// EXPIRES
	rc = sqlite3_bind_int64(stmt, 5, BM::swap64(object->expiresTime));

	if (rc)
		goto fail;


	// DATE ADDED
	rc = sqlite3_bind_int64(stmt, 6, BM::unix_time());

	if (rc)
		goto fail;


	// DATA
	rc = sqlite3_bind_blob(stmt, 7, (const void *)object, object_size, SQLITE_STATIC);

	if (rc)
		goto fail;

	//
	//
	//

	rc = sqlite3_step(stmt);

fail:

	if(stmt)
		sqlite3_finalize(stmt);

	ZEROFREE_(uid, 512);

	return TRUE;


end:

	if (stmt)
		sqlite3_finalize(stmt);

	show_error();

	return FALSE;

}


DWORD BMDB::vect_list(DWORD limit, LPVOID out, DWORD out_size)
{

	if (limit > 50000)
		return FALSE;

	// This epic statmemnt will return a row count for us as well...:/
	//LPSTR stdddd = "SELECT id, tag, (SELECT count(id) FROM INVENTORY ORDER BY DATE_ADDED DESC LIMIT ?) as cnt  FROM INVENTORY ORDER BY DATE_ADDED DESC LIMIT ?";
	LPSTR stdddd = "SELECT id, hash, (SELECT count(id) FROM INV ORDER BY DATE_ADDED DESC LIMIT ?) as cnt  FROM INV ORDER BY DATE_ADDED DESC LIMIT ?";

	sqlite3_stmt * stmt = NULL;
	int rc = NULL;

	rc = sqlite3_prepare(BM::db, stdddd, -1, &stmt, NULL);

	if (rc)
		goto fail;

	rc = sqlite3_bind_int(stmt, 1, (ULONG)limit);
	rc = sqlite3_bind_int(stmt, 2, (ULONG)limit);

	if (rc)
		goto fail;

	rc = sqlite3_step(stmt);



	LPBYTE addr = NULL;
	DWORD count = sqlite3_column_int(stmt, 2);


	if (count > BM_MAX_VECT_LIST_ENTRYS)
	{
		count = BM_MAX_VECT_LIST_ENTRYS;
	}

	size_t varint_len = BM::encodeVarint(count, (uint8_t*)out);

	LPBYTE list = (LPBYTE)((ULONG_PTR)out + (ULONG_PTR)varint_len);

	DWORD buff_size = BM_VECT_LIST_BUFF_SIZE;
	DWORD blob_size = NULL;
	buff_size -= varint_len;

	do {


		blob_size = NULL;
		addr = NULL;

		blob_size = sqlite3_column_bytes(stmt, 1);
		addr = (LPBYTE)sqlite3_column_blob(stmt, 1);


		if (addr && blob_size == 32)
		{

			// Fill the entry in the list.
			memcpy_s(list, buff_size, addr, 32);

			// watch the buffer size !
			buff_size -= 32;

			// watch the list count
			count--;

			// move through the list
			list = (LPBYTE)((ULONG_PTR)list + (ULONG_PTR)32);
		}
		rc = sqlite3_step(stmt);


	} while (rc == SQLITE_ROW && count && buff_size > 0);



	if (stmt)
		sqlite3_finalize(stmt);

	return  BM_VECT_LIST_BUFF_SIZE - buff_size;

fail:

	show_error();

	if (stmt)
		sqlite3_finalize(stmt);

	return FALSE;
}















#endif // !BM_DB_C