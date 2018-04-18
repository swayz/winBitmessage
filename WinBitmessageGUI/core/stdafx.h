#pragma once

//#include "Ws2def.h"

#include "windows.h"
#include "Windowsx.h"
#include "In6addr.h"
#include "sqlite\sqlite3.h"
#include "Wincrypt.h"
#include "bcrypt.h"
#include <cstdint>
#include "math.h"

#define MSG_WAITALL 0x8

#define DEBUG_MODE


// current client version
#define BM_CLIENT_VERSION "/WinBitMessage:0.0.1/"


#define IPV4_AD(x) *(u_long*)&x[12]
#define BM_PORT(x) *(u_short*)&x[0]
//=====================================================


#define BM_WND_MSG 1045

#define TYPECH(type, pointer, value) (*((type*)pointer) = value) 
#define TYPEVAL(type, pointer) (*((type*)pointer)) 

#define BM_CONN_TIMEOUT (1000 * 20) // 20 seconds roughly

#define BM_MAGIC 0xD9B4BEE9
#define BM_MAGICB 0xD9B4BEE9


// Messege Type (MT) 

#define BM_MT_VERSION 0x1
#define BM_MT_VERACK 0x2
#define BM_MT_ADDR 0x3
#define BM_MT_INV 0x4
#define BM_MT_GETDATA 0x5
#define BM_MT_OBJECT 0x6

// Messege Type String (MTS) 

#define BM_MTS_VERSION "version"
#define BM_MTS_VERACK "verack"
#define BM_MTS_ADDR "addr"
#define BM_MTS_INV "inv"
#define BM_MTS_GETDATA "getdata"
#define BM_MTS_OBJECT "object"



#define BM_VERACK_SENT 0x1	// Valid version SENT
#define BM_VERACK_RECV 0x2	// Valid version RECEIVD

#define BM_N_NODE_SLOTS 102400
#define BM_NODE_LIST_SIZE (sizeof(PBM_CONN) * BM_N_NODE_SLOTS)

#define BM_N_VECT_SLOTS 102400
#define BM_VECT_LIST_SIZE (sizeof(PBM_VECTOR) * BM_N_VECT_SLOTS)

#define BM_MAX_ADDR_LIST_ENTRYS 1000
#define MAX_VARINT_SIZE 9
#define BM_ADDR_LIST_BUFF_SIZE (MAX_VARINT_SIZE + (BM_MAX_ADDR_LIST_ENTRYS * sizeof(BM_ADDR)))

#define BM_MAX_VECT_LIST_ENTRYS 5000
#define BM_VECT_LIST_BUFF_SIZE (MAX_VARINT_SIZE + (BM_MAX_VECT_LIST_ENTRYS * 32))
#define BM_VECTOR_SIZE 32

#define RIPMD160_SIZE 20


#define BM_RECV_BUFF_SIZE (1024 * 1700)
#define BM_SEND_BUFF_SIZE (1024 * 1700)

#define BM_VECT_BUFF_SIZE 2048

// message types


// Object Payload sizes


//payload buffer sizes
#define BM_OPK_BS 1024 // Object: pubkey Buffer Size (OPK_BS);

#define PK_PL_BS (BM_OPK_BS - (sizeof(BM_MSG_HDR) + 20)) // PAYLOAD of the pubkey object



// object types

#define BM_OBJ_GETPUBKEY 0
#define BM_OBJ_PUBKEY 1
#define BM_OBJ_MSG 2
#define BM_OBJ_BROADCAST 3

#define BM_TAG_LEN 32

// object payload macro

#define GET_OBJ_PL(t,o) (t)(((ULONG_PTR)&o->payload) + 20 + 2);


// BM Connection status's the CS in BMCS

#define BM_CS_FREE 0
#define BMCS_DISCONNECTED -1
#define BMCS_INITIAL 1
#define BMCS_VERACK 2
#define BMCS_ADDR_NOTIFY 4	// after we receive nodes, and send out ours

#define BM_MAX_CONNECTIONS 128

#define BM_CHUNK_SIZE 4096


#define BMCS_VERIFIED (BMCS_INITIAL | BMCS_VERACK)
#define BMCS_CONNECTED (BMCS_VERIFIED | BMCS_ADDR_NOTIFY)

#define BM_MSG_IS_VALID 0
#define BM_MSG_MAGIC_ERROR 1
#define BM_MSG_LEN_ERROR 2
#define BM_MSG_HASH_ERROR 4
#define BM_OBJ_POW_ERROR 8


//
//services

#define BM_NODE_NETWORK 1
#define BM_NODE_SSL 2

//


//
// Message Encodings

#define BM_ENCODING_IGNORE 0
#define BM_ENCODING_TRIVIAL 1
#define BM_ENCODING_SIMPLE 2
#define BM_ENCODING_EXTENDED 3

//

#define AES_KEY_SIZE_ 32
#define AES_BLOCK_SIZE_ 16
#define TMP_BLOCK_BUFFER_SIZE(z) (((z / AES_BLOCK_SIZE_) + 1) * AES_BLOCK_SIZE_)
#define HMAC_BUFF_LEN 128
#define HMAC_LEN 32




#define ZERO_(a,b) Utils::zero_mem(a, b);
#define ZEROw_(a,b) ZERO_(a,b * sizeof(WCHAR));

#define ALLOC_(a) VirtualAlloc(0, a, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); //malloc(a);//Memory::alloc(a);//
#define ALLOCw_(a) ALLOC_(a * sizeof(WCHAR))
#define ALLOCt_(x, a) (x)ALLOC_(a)


#define FREE_(a,b) VirtualFree(a, 0, MEM_RELEASE);//free(a);//Memory::free(a,b);//
#define FREEw_(a,b) FREE_(a,b * sizeof(WCHAR))

#define ZEROFREE_(a,b) ZERO_(a,b) FREE_(a,b)
#define ZEROFREEw_(a,b) ZEROFREE_(a,b * sizeof(WCHAR))




#define DAY_SECONDS(d) (60 * 60 * 24 * d)



#ifdef DEBUG_MODE
#define DBGOUTa(a) OutputDebugStringA(a)
#define DBGOUTw(w) OutputDebugStringW(w)
#else

#define DBGOUTa(a) //	null
#define DBGOUTw(w) //	null

#endif
#ifdef VERBOSE_DEBUG_MODE
#define VDBGOUTa(a) DBGOUTa(a)
#define VDBGOUTw(w) DBGOUTw(w)
#else

#define VDBGOUTa(a) //	null
#define VDBGOUTw(w) //	null

#endif















typedef struct {

	BYTE magic[4];		// 0xE9BEB4D9
	BYTE command[12];	// version or addr
	BYTE length[4];		// length of payload
	BYTE checksum[4];	// first 4 bytes of sha512 of payload
	BYTE payload[];

}BM_MSG_HDR, *PBM_MSG_HDR;


//	used for the initial connection.
typedef struct {


	BYTE services[8];	//uint64t always 0 | NODE_NETWORK
	BYTE ip[16];		//00 00 00 00 00 00 00 00 00 00 FF FF [4 byte IPv4 address]
	BYTE port[2];		//uint16t


}BM_NET_ADDR, *PBM_NET_ADDR;

// used eveytime thereafter
typedef struct {

	BYTE time[8];		//uint64 unix?
	BYTE stream[4];		//uint32 (always 1[for now])
	BYTE services[8];	//uint64t always 0 | NODE_NETWORK
	BYTE ip[16];		//00 00 00 00 00 00 00 00 00 00 FF FF [4 byte IPv4 address]
	BYTE port[2];		//uint16t

}BM_ADDR, *PBM_ADDR;



typedef struct {
	BM_ADDR addr;
}s_list, *ps_list;




typedef struct {

	BYTE version[4];		//int32t
	BYTE services[8];		//uint64t
	BYTE timestamp[8];		//int64t
	BM_NET_ADDR addr_recv;
	BM_NET_ADDR addr_from;
	BYTE nonce[8];			//uint64
	BYTE user_agnt[0x1];		// none always 00
	BYTE streams[2];		// always 01 01
	//var_str user_agent; can be static as well. /test:1.1.1;
	//var_int_list stream_numbers; always 01 01

}BM_PL_VER, *PBM_PL_VER;







enum {
	bm_version = 0x1,
	bm_addr,
	bm_inv
};


typedef NTSTATUS (WINAPI * _NtQuerySystemTime)(
	_Out_ PLARGE_INTEGER SystemTime
);


typedef BOOLEAN (WINAPI * _RtlTimeToSecondsSince1970)(
	_In_  PLARGE_INTEGER Time,
	_Out_ PULONG         ElapsedSeconds
);


typedef LONG (NTAPI * _RtlIpv6StringToAddress)(
	_In_  PCTSTR   S,
	_Out_ PCTSTR   *Terminator,
	_Out_ IN6_ADDR *Addr
);


typedef struct {

	uint64_t id;
	SOCKET s;
	long ipv4;
	BYTE ipv6[16];
	uint16_t port;
	DWORD status;
	ULONG time_started;
	DWORD verack;
	BOOL peerswap;
	BOOL invswap;
	LPBYTE recv_buffer;
	DWORD recv_buff_size;
	LPBYTE send_buffer;
	DWORD send_buff_size;
	LPCRITICAL_SECTION send_buffer_lock;
	HANDLE recv_;
	HANDLE send_;
	DWORD is_complete;
	HANDLE event_status;



}BM_CONN, *PBM_CONN;

typedef struct {

	DWORD type;
	LPBYTE buffer;
	DWORD buffer_size;
	PBM_CONN conn;


}BM_SEND_APC_DATA, *PBM_SEND_APC_DATA;


typedef struct {
	LPSTR ip;
	LPSTR port;
}BM_SEED, PBM_SEED;

typedef struct {

	PBM_CONN list[];


}BM_CONN_LIST, *PBM_CONN_LIST;


typedef struct {

	HWND hwnd;
	long ipv4;
	uint16_t port;
	DWORD sqlite_node_id;

}BM_CONN_THREAD_DATA, *PBM_CONN_THREAD_DATA;

typedef struct {
	LPBYTE private_key;
	DWORD priv_key_size;
	LPBYTE buffer;
	DWORD sign_size;
	LPBYTE out_sig;
	DWORD sig_size;
}DSA_CONTEXT, *PDSA_CONTEXT;










//typedef struct {
//	long ip;
//	BYTE ipv6[16];
//	uint16_t port;
//}BM_NODE, *PBM_NODE;
typedef struct {

	uint64_t nonce;
	uint64_t expiresTime;
	uint32_t objectType;
	BYTE objectVersion[];
	//BYTE streamNumber[1];
	//BYTE objectPayload[]; // this is :L

}BM_OBJECT, *PBM_OBJECT;

typedef struct {
	BM_ADDR addr;
	BOOL connected;
	uint64_t last_con_atmpt;
	PBM_CONN conn;
}BM_NODE, *PBM_NODE;

typedef struct {

	PBM_NODE list[];
	
}BM_NODE_LIST, *PBM_NODE_LIST;



typedef struct {

	BYTE hash[32];			// the vector hash, the first 32 bytes of a double sha512 hash of an object + payload
	BYTE pub_key_hash[32];	// if object is of type pubkey, create the ripe and store it along with for future reference.
							// support for v4 pubkey response
	DWORD vector_size;			// size of object + payload
	PBM_OBJECT obj;			// the object struct
	
}BM_VECTOR, *PBM_VECTOR;

typedef struct  {
	BYTE vect[32];
}s_vect, *ps_vect;

typedef struct {
	PBM_VECTOR list[];			
}BM_VECT_LIST, *PBM_VECT_LIST;



typedef struct {
	BCRYPT_KEY_HANDLE sig_handle;
	BCRYPT_KEY_HANDLE enc_handle;
	
	char readable[128];

	BYTE first_tag[32];
	BYTE tag[32];
	
	BYTE pub_sig_blob[128];
	BYTE pub_enc_blob[128];

	BYTE prv_sig_blob[128];
	BYTE prv_enc_blob[128];
	
	DWORD version;
	DWORD stream;

	DWORD hash_size;
	BYTE hash[20];
	BYTE checksum[4];
	DWORD db_id;
	

}BM_MSG_ADDR, *PBM_MSG_ADDR;


typedef struct {

	BYTE iv[16];			// AES random IV
	uint16_t curve_type;	// will always be 0x02CA // 256 bit ECDH curve
	uint16_t x_len;			
	BYTE x[32];
	uint16_t y_len;			// should always be 64?
	BYTE y[32];
	
	
	BYTE ciph_text[];
	
	// this is stupid like, fuck why cant you be infront of the payload....
	
	// I recommend structuring the "data structures" more like c/c++ structs....its more straight forward and easy for me :D


	//dont forget the HMAC
	//BYTE hmac[32];			// AES HMAC

}BM_ENC_PL_256, *PBM_ENC_PL_256; // Bit Message ENCrypted PayLoad 256 bit ECDH curve



typedef struct CRYPT_CONTEXT_ {

	HCRYPTPROV  context;
	HCRYPTKEY aes_hKey;

	DWORD aes_key_size;
	BYTE aes_key[32];
	BYTE iv[16];

	LPVOID in_buff;
	LPVOID out_buff;

	DWORD in_size;
	DWORD out_size;

	DWORD last_error;

}CRYPT_CONTEXT_, *PCRYPT_CONTEXT;

typedef struct {
	BYTE ripe[20]; // 20 byte ripemd-160
}BM_GETPUBKEY_OBJ, *PBM_GETPUBKEY_OBJ;

typedef struct {
	BYTE tag[32]; 
}BM_GETPUBKEY_V4_OBJ, *PBM_GETPUBKEY_V4_OBJ;



typedef struct {
	BM_GETPUBKEY_V4_OBJ tag[]; 
}BM_VECTOR_LIST, *PBM_VECTOR_LIST;




typedef struct {

	uint32_t behavior;
	BYTE sign_key[64];
	BYTE enc_key[64];
	BYTE nonce_trials_per_byte[];	// 02 10 00	// variable int, default value == 1000
	//BYTE extra_bytes[];			// 02 10 00		
	//BYTE sig[];									// var int -> sig_length; byte* -> sig

}BM_PUBKEY_V3_OBJ, *PBM_PUBKEY_V3_OBJ;

typedef struct {

	BYTE tag[32];
	BYTE encrypted[];

}BM_PUBKEY_V4_OBJ, *PBM_PUBKEY_V4_OBJ;


typedef struct {
	LPBYTE buffer;
	DWORD length;
}BM_PROP_OBJ_ITEM, *PBM_PROP_OBJ_ITEM;



// POW MULTIR THREAD STRUCT

typedef struct {

	LPBYTE payload;
	DWORD in_size;
	DWORD64 TTL;
	DWORD thread_number;
	DWORD64* final_nonce;
	HANDLE pow_event;

}BM_POW_THREAD_DETAILS, *PBM_POW_THREAD_DETAILS;





