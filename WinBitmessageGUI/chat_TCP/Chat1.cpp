#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include <winsock.h>
#include "Chat1.h"
#include "Encryption.h"
#include "BM.h"
#include "ecc.h"
#include "memory.h"
#include "utils.h"
#include "network.h"
#include "bm_db.h"




//Dialog procedures
BOOL CALLBACK DlgProc(HWND hdwnd, UINT Message, WPARAM wParam, LPARAM  lParam);
BOOL CALLBACK ConnectDlgProc(HWND hdwnd, UINT Message, WPARAM wParam, LPARAM  lParam);
BOOL CALLBACK ListenDlgProc(HWND hdwnd, UINT Message, WPARAM wParam, LPARAM  lParam);



int TryConnect(long hostname, int PortNo);
int ListenOnPort(int PortNo);

char Title[] = "WinMessage";


extern "C"
{
	typedef int (WINAPI * lite_db_open_PROC)(const char * filename, sqlite3 **ppDb);
	typedef int (WINAPI * lite_db_close_PROC)(sqlite3 *ppDb);

	lite_db_open_PROC db_open = NULL;
	lite_db_close_PROC db_close = NULL;
}

HINSTANCE hInst = NULL;
HWND hwnd, hStatus;

SOCKET s;
SOCKADDR_IN from;
int fromlen = sizeof(from);


void set_net_health()
{
	int t = SetTimer(NULL, NULL, 1000 * 60 * 15, (TIMERPROC)network::maintain_health);
	//int t = SetTimer(NULL, NULL, 1000 * 30, (TIMERPROC)network::maintain_health);

}



void load_lite_db()
{
	HMODULE dll = LoadLibraryW(L"sqlite3.dll");
	db_open = (lite_db_open_PROC)GetProcAddress(dll, "sqlite3_open");
	db_close = (lite_db_close_PROC)GetProcAddress(dll, "sqlite3_close");

}

void send_msg()
{
	PBM_MSG_ADDR addr = NULL;

	BM::create_addr(&addr);
	if (addr)
	{
		BMDB::address_add(addr, L"Debug");
	}


	PBM_MSG_HDR msg_hdr = (PBM_MSG_HDR)ALLOC_(BM_RECV_BUFF_SIZE);
	PBM_OBJECT obj = (PBM_OBJECT)msg_hdr->payload;
	PBM_ENC_PL_256 pl = (PBM_ENC_PL_256)(((ULONG_PTR)msg_hdr + BM_RECV_BUFF_SIZE) - 1024);
	DWORD pl_size = 512;

	BM::encrypt_payload(addr, (LPBYTE)"hello world!", 12, pl, &pl_size);
	//	BM::decrypt_payload(addr,pl, pl_size);

	//BMDB::atmpt_msg_decrypt(obj, pl_size + sizeof(BM_OBJECT));


	BOOL is_connected = FALSE;

	do {
		is_connected = network::has_connection()->status;
		Sleep(1000);
	} while (!is_connected);


	// initialize object header

	pl_size = BM::init_object(obj, 1024 - 24, BM_OBJ_MSG, (LPBYTE)pl, pl_size);

	// initialize msg header

	pl_size = BM::init_msg_hdr(msg_hdr, pl_size, BM_MTS_OBJECT);



	int e = network::is_msg_valid(msg_hdr, pl_size);



	// propogate!

	//BM::propagate_obj(msg_hdr, BM_OBJ_MSG, NULL, FALSE);

	//
	//PBM_CONN conn = (PBM_CONN)ALLOC_(sizeof(BM_CONN));;
	//conn->buffer = (LPBYTE)msg_hdr;
	//conn->buffer_size = pl_size;

	//network::start_work(conn);

	
	//Sleep(2000);

	//ZEROFREE_(msg_hdr, BM_RECV_BUFF_SIZE);

}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{

	//	load_lite_db();

	sqlite3 * db = NULL;

	Memory::init();

	BM::init();

	Encryption::init();

	ECC::init();

	network::init();

	int rc = sqlite3_open("WM.db", &BM::db);

	//char path_to_db[MAX_PATH];
	//ZERO_(path_to_db, MAX_PATH);

	//int e = GetModuleFileNameA(NULL, path_to_db, MAX_PATH);
	//e = SetCurrentDirectoryA(path_to_db);

	if (rc)
	{
		DBGOUTw(L"\rFailed to open database!\r");

	}


	

	//CreateThread(0, 0, (LPTHREAD_START_ROUTINE)send_msg, 0, 0, 0);

	hInst = hInstance;



	DialogBox(hInstance, MAKEINTRESOURCE(DLG_MAIN), NULL, DlgProc);




	return FALSE;

}

void GetTextandAddLine(char Line[], HWND hParent, int IDC)
{
    HWND hEdit = GetDlgItem(hParent, IDC);
	int nTxtLen = GetWindowTextLength(hEdit); // Get length of existing text
	SendMessage(hEdit, EM_SETSEL, nTxtLen, nTxtLen);	// move caret to end
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)Line);	    // append text
	SendMessage(hEdit, EM_SCROLLCARET, 0, 0);		// scroll to caret
} //End function   

BOOL CALLBACK DlgProc(HWND hdwnd, UINT Message, WPARAM wParam, LPARAM
  lParam)
{

	SOCKET _s = 0;
	PBM_CONN conn = 0;
	PBM_CONN* pconn = 0;

	DWORD node_id = NULL;

switch(Message)
    {
    
    case WM_INITDIALOG:
    {
        //Our dialog box is being created
		hwnd = hdwnd;
		BM::main_hwnd = hdwnd;

		int t = SetTimer(hwnd, NULL, 1000 * 60 * 30, NULL);

		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)network::start, BM::main_hwnd, NULL, NULL);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)network::maintain_health, NULL, NULL, NULL);
		//BM::prop_thread_handle = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)BM::obj_prop_server, NULL, NULL, NULL);
		//set_net_health();

        hStatus = GetDlgItem(BM::main_hwnd, ID_STATUS_MAIN);
    }
    return TRUE;
	




	case WM_TIMER:
		

		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)network::maintain_health, NULL, NULL, NULL);
	
		break;



    //Winsock related message...
	//
	//
	//
	
    case BM_WND_MSG:

		_s = wParam;
		pconn = network::find_conn(_s, &node_id);

		if (!pconn)
			return 0;

		conn = *pconn;

		// update last connection time.
		if (conn)
		{
			BMDB::node_update_last_conn(BM::unix_time(), conn->id, TRUE);
		}
		else {
			DBGOUTw(L"\rUnkown connection.\r");
		}
		
		
		switch(lParam)
        {
                case FD_CONNECT: //Connected OK
                    MessageBeep(MB_OK);

               
                break;
                
                case FD_CLOSE: //Lost connection
                    //MessageBeep(MB_ICONERROR);
					
					
					///DBGOUTw(L"\rConnection Lost!\r");
					
					
					//MessageBoxW(NULL, L"Connection Closed", L"", MB_OK);
                    //Clean up
					network::remove_conn(_s);
                    if (s) closesocket(s);
                   // WSACleanup();
					//ExitProcess(0);
                break;
                
                case FD_READ: //Incoming data to receive
				{
					
					




					//DBGOUTw(L"Recieved Data.\r");
					

					//need to verify that we have all the data sent to us.
					
					//DBGOUTa("ALLOC NETWORK BUFFER\n");

					
					DWORD con_ret = NULL;
					
					
					con_ret = recv(conn->s, (char*)conn->send_buffer, BM_RECV_BUFF_SIZE, 0);
						
			
					
					
					if ((con_ret && con_ret != SOCKET_ERROR))
					{

						conn->send_buff_size = con_ret;	

						DWORD is_complete = network::is_msg_valid((PBM_MSG_HDR)conn->send_buffer, con_ret);

						if (is_complete)
						{

							DWORD pl_size = htonl(*(uint32_t*)((PBM_MSG_HDR)conn->send_buffer)->length);
		
							
							conn->send_buff_size = con_ret; // msg size?
							//CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)network::start_work, pconn, NULL, NULL);
							//network::start_work(pconn);
							QueueUserAPC((PAPCFUNC)network::start_work, BM::prop_thread_handle, (ULONG_PTR)pconn);
						}	
					}
					


					break;
				}
                case FD_ACCEPT: //Connection request
				{
					MessageBeep(MB_OK);

					break;
				}
        }
    break;






















    case WM_COMMAND:
        switch(LOWORD(wParam))
        {
                case ID_BTN_CONNECT:
                 
					sqlite3_close(BM::db);
					ExitProcess(0);
					return 0;
					// return DialogBox(hInst, MAKEINTRESOURCE(DLG_CONNECT), NULL, ConnectDlgProc);
                break;

                case ID_BTN_LISTEN:
                  return DialogBox(hInst, MAKEINTRESOURCE(DLG_LISTEN), NULL, ListenDlgProc);                
                break;
                
                case ID_BTN_CLEAR: //Clear edit and disconnect
                {
                    
                        int a = MessageBox(hdwnd, "Are you sure you want to end all of the current connections?", "End Connection", MB_ICONQUESTION | MB_YESNO);
                        
						if (a == IDYES)
                        {

                            //SendDlgItemMessage(hdwnd, ID_EDIT_DATA, WM_SETTEXT, 0, (LPARAM)"");
                           
							for (int i = 0; i < BM_MAX_CONNECTIONS; i++)
							{
								
								if (network::con_list->list[i] && network::con_list->list[i]->s)
								{
								
									network::remove_conn(network::con_list->list[i]->s); //Shut down socket
								
								}

								
							}

                 
							WSACleanup(); //Clean up Winsock
							//Memory::deinit();
           	                        
						}
						sqlite3_close(BM::db);

						//_CrtDumpMemoryLeaks();




						ExitProcess(0);
                }
                break;
                
                case ID_BTN_SEND: //Send data
                {
           //         int len = GetWindowTextLength(GetDlgItem(hdwnd, ID_EDIT_SEND));
			        //
          	//        if (len && len < MAX_PATH - sizeof(char)) //If there's text in the reply box...
			        //{
			        //   

							//PBM_MSG_HDR msg = (PBM_MSG_HDR)GlobalAlloc(GPTR, sizeof(BM_MSG_HDR) + sizeof(BM_PL_VER) + 1);

							////BM::init_con(msg, "178.254.29.171", "127.0.0.1");

							//send(s, (const char*)msg, sizeof(BM_MSG_HDR) + sizeof(BM_PL_VER), NULL);


							//GlobalFree((HANDLE)msg); //Free the memory: Important!!
					// }
							
					
					send_msg();


			           
			       
                }
                break;
                
                case IDCANCEL:
                    //Clean up
                    if (s) closesocket(s);
                    WSACleanup();
                    
                    EndDialog(hdwnd, IDOK);
                break;
        } //End switch
        default:
            return FALSE;
    break;
    } //End Message switch
    return TRUE;
}

BOOL CALLBACK ConnectDlgProc(HWND hdwnd, UINT Message, WPARAM wParam, LPARAM
  lParam)
{
switch(Message)
    {
    case WM_INITDIALOG:
    {
        //Our dialog box is being created
    }
    return TRUE;

    case WM_COMMAND:
        switch(LOWORD(wParam))
        {
                case ID_BTN_GO:
                {
                    int len = GetWindowTextLength(GetDlgItem(hdwnd, ID_EDIT_HOST));
                    int lenport = GetWindowTextLength(GetDlgItem(hdwnd, ID_EDIT_PORT));
                    
                    if (!lenport) return 0; //Was the port specified?
                    
                    int portno = GetDlgItemInt(hdwnd, ID_EDIT_PORT, 0, 0);
                    
                    if (len)
                    {
                            char* Data;
                            Data = (char*)GlobalAlloc(GPTR, len + 1); //Allocate memory
                    
                            GetDlgItemText(hdwnd, ID_EDIT_HOST, Data, len + 1); //Get text into buffer
                    
                            if (!gethostbyname(Data))
                            {
                            //Couldn't get hostname; assume it's an IP Address
                                long hostname = inet_addr(Data);
                                if(!TryConnect(hostname, portno))
                                {
                                    MessageBox(hdwnd, "Could not connect to remote host.", Title, MB_ICONERROR | MB_OK);
                                    if (s) closesocket(s); //Shut down socket
                                }
                            }
                            
                            GlobalFree((HANDLE)Data); //Free memory
                            
                            EndDialog(hdwnd, IDOK);
                    }
                }
                break;

                case IDCANCEL:
                    EndDialog(hdwnd, IDOK);
                break;
        } //End switch
        default:
            return FALSE;
    break;
    } //End Message switch
    return TRUE;
}

BOOL CALLBACK ListenDlgProc(HWND hdwnd, UINT Message, WPARAM wParam, LPARAM
  lParam)
{
switch(Message)
    {
    case WM_INITDIALOG:
    {
        //Our dialog box is being created
    }
    return TRUE;

    case WM_COMMAND:
        switch(LOWORD(wParam))
        {
                case ID_BTN_GO:
                {
                    int lenport = GetWindowTextLength(GetDlgItem(hdwnd, ID_EDIT_PORT));
                    if (!lenport) return 0; //Was the port specified?
                    
                    int portno = GetDlgItemInt(hdwnd, ID_EDIT_PORT, 0, 0);
                    
                    if (!ListenOnPort(portno)) 
                    {
                        if (s) closesocket(s);
                        MessageBox(hdwnd, "Error listening on specified port.", Title, MB_ICONERROR | MB_OK);
                    }                                                            
                    EndDialog(hdwnd, IDOK);
                }
                break;

                case IDCANCEL:
                    EndDialog(hdwnd, IDOK);
                break;
        } //End switch
        default:
            return FALSE;
    break;
    } //End Message switch
    return TRUE;
}



// Programming Windows TCP Sockets in C++ for the Beginner -  lol.
// http://www.codeproject.com/Articles/13071/Programming-Windows-TCP-Sockets-in-C-for-the-Begin

int TryConnect(long hostname, int PortNo)
{
    WSADATA w; //Winsock startup info
    SOCKADDR_IN target; //Information about host
    
    int error = WSAStartup (0x0202, &w);   // Fill in WSA info
     
    if (error)
    { // there was an error
      return 0;
    }
    if (w.wVersion != 0x0202)
    { // wrong WinSock version!
      WSACleanup (); // unload ws2_32.dll
      return 0;
    }
    
    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP); // Create socket
    if (s == INVALID_SOCKET)
    {
        return 0;
    }

    target.sin_family = AF_INET;           // address family Internet
    target.sin_port = htons (PortNo);        // set server’s port number
    target.sin_addr.s_addr = hostname;  // set server’s IP
     
    //Try connecting...
    if (connect(s, (SOCKADDR *)&target, sizeof(target)) == SOCKET_ERROR) //Try binding
    { // error
          return 0;
    }      
	
	
	//Switch to Non-Blocking mode
    WSAAsyncSelect (s, hwnd, 1045, FD_READ | FD_CONNECT | FD_CLOSE); 

      




    SendMessage(hStatus, WM_SETTEXT, 0, (LPARAM)"Connected to Remote Host.");
    
    return 1; //OK
}

int ListenOnPort(int PortNo)
{
    WSADATA w;
    
    int error = WSAStartup (0x0202, &w);   // Fill in WSA info
     
    if (error)
    { // there was an error
        SendMessage(hStatus, WM_SETTEXT, 0, (LPARAM)"Could not initialize Winsock.");
      return 0;
    }
    if (w.wVersion != 0x0202)
    { // wrong WinSock version!
      WSACleanup (); // unload ws2_32.dll
      SendMessage(hStatus, WM_SETTEXT, 0, (LPARAM)"Wrong Winsock version.");
      return 0;
    }
    
    SOCKADDR_IN addr; // the address structure for a TCP socket
    SOCKET client; //The connected socket handle
    
    addr.sin_family = AF_INET;      // Address family Internet
    addr.sin_port = htons (PortNo);   // Assign port to this socket
    addr.sin_addr.s_addr = htonl (INADDR_ANY);   // No destination
    
    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP); // Create socket
    
    if (s == INVALID_SOCKET)
    {
        SendMessage(hStatus, WM_SETTEXT, 0, (LPARAM)"Could not create socket.");
        return 0;
    }
    
    if (bind(s, (LPSOCKADDR)&addr, sizeof(addr)) == SOCKET_ERROR) //Try binding
    { // error
        SendMessage(hStatus, WM_SETTEXT, 0, (LPARAM)"Could not bind to IP.");
        return 0;
    }
    
    listen(s, 10); //Start listening
    WSAAsyncSelect (s, hwnd, 1045, FD_READ | FD_CONNECT | FD_CLOSE | FD_ACCEPT); //Switch to Non-Blocking mode
    
    char szTemp[100];
    wsprintf(szTemp, "Listening on port %d...", PortNo);
    
    SendMessage(hStatus, WM_SETTEXT, 0, (LPARAM)szTemp);  
    return 1;
}


