// WinBitmessageGUI.cpp : Defines the entry point for the application.
//

#include "stdafx.h"


extern "C"
{
	typedef int (WINAPI * lite_db_open_PROC)(const char * filename, sqlite3 **ppDb);
	typedef int (WINAPI * lite_db_close_PROC)(sqlite3 *ppDb);

	lite_db_open_PROC db_open = NULL;
	lite_db_close_PROC db_close = NULL;
}



#ifndef MAIN_WIN_SETTINGS_C
#define MAIN_WIN_SETTINGS_C


// Global Variables:
HINSTANCE MainWin::hInst = NULL;
HWND MainWin::h_main = NULL;




WCHAR MainWin::szTitle[MAX_LOADSTRING] = {};                  // The title bar text
WCHAR MainWin::szWindowClass[MAX_LOADSTRING] = {};            // the main window class name




LONG WINAPI VectoredHandlerSkip1(
	struct _EXCEPTION_POINTERS *ExceptionInfo
)
{

	if(MessageBox(SendTab::send_tab_h, L"ERROR", TEXT("Fatal Exception!"), MB_ICONERROR))
	{

	
		PCONTEXT Context = {};
		
		Context = ExceptionInfo->ContextRecord;
		
	#ifdef _AMD64_
		Context->rip = (DWORD64)ExitThread;
		*((DWORD64*)(Context->rsp)) = 0;
	#else
		Context->Eip = (DWORD)ExitThread;
		*((DWORD*)(Context->Esp)) = 0;
	#endif  

	}
  
	return EXCEPTION_CONTINUE_EXECUTION;
}




int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);


	AddVectoredExceptionHandler(TRUE, VectoredHandlerSkip1);
	


	
	//int o = 0;
	//int f = 1 / o;

    // TODO: Place code here.

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, MainWin::szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_WINBITMESSAGEGUI, MainWin::szWindowClass, MAX_LOADSTRING);
	MainWin::MyRegisterClass(hInstance);


	sqlite3 * db = NULL;

	Memory::init();

	BM::init();

	Encryption::init();

	ECC::init();

	network::init();

//	int rc = sqlite3_open("C:/Users/John/Documents/Visual Studio 2015/Projects/WinBitmessageGUI/WinBitmessageGUI/chat_TCP/WM.db", &BM::db);
	int rc = sqlite3_open("WM.db", &BM::db);

	
	


    // Perform application initialization:
    if (!MainWin::InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

	

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_WINBITMESSAGEGUI));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MainWin::MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_WINBITMESSAGEGUI));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_WINBITMESSAGEGUI);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}



// test for using a readable bitmessage address to create a new ECC key pair
// then encrypt/decrypt a payload with it.

DWORD address_test()
{

	PBM_MSG_ADDR alice = NULL;
	PBM_MSG_ADDR bob = NULL;


	BM::create_addr(&alice);
	BM::create_addr(&bob);


	LPSTR hello = 
		"AAAAAAAAAAAAAAAA"
		"BBBBBBBBBBBBBBBB"
		"CCCCCCCCCCCCCCCC"
		"DDDDDDDDDDDDDDDD"
		"EEEEEEEEEEEEEEEE"
		"FFFFFFFFFFFFFFFF"
		"GGGGGGGGGGGGGGGG"
		"HHHHHHHHHHHHHHHH"
		"IIIIIIIIIIIIIIII"
		"JJJJJJJJJJJJJJJJ"
		"KKKKKKKKKKKKKKKK"
		"LLLLLLLLLLLLLLLL"
		"MMMMMMMMMMMMMMMM"
		"NNNNNNNNNNNNNNNN"
		"OOOOOOOOOOOOOOOO"
		"PPPPPPPPPPPPPPPP"
		"QQQQQQQQQQQQQQQQ"
		"RRRRRRRRRRRRRRRR"
		"SSSSSSSSSSSSSSSS"
		"TTTTTTTTTTTTTTTT"

		;


	BYTE pl_buff[512] = {};
	PBM_ENC_PL_256 pl = (PBM_ENC_PL_256)pl_buff;
	DWORD pl_size = 512;

	

	PBM_MSG_ADDR km = (PBM_MSG_ADDR)ALLOC_(512);
	BCRYPT_KEY_HANDLE kh = NULL;
	BYTE kb[128] = {};
	BYTE kb_pub[128] = {};


	((PBCRYPT_ECCKEY_BLOB)kb)->dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
	((PBCRYPT_ECCKEY_BLOB)kb)->cbKey = 32;

	//	Insert the priv_tag to the ecc key blob
	memcpy_s(&kb[8 + 32 + 32], 32, bob->first_tag, 32);

	//	importing the key blob gives us our public key.
	BCryptImportKeyPair(ECC::main_handle, NULL, BCRYPT_ECCPRIVATE_BLOB, &kh, kb, 8 + 32 + 32 + 32, BCRYPT_NO_KEY_VALIDATION);

	DWORD j = 0;

	//	Retrieve the public key
	BCryptExportKey(kh, NULL, BCRYPT_ECCPUBLIC_BLOB, kb_pub, 128, &j, NULL);

	//	encrypt the pubkey struct in to a payload struct.
	memcpy_s(km->pub_enc_blob, 128, kb_pub, 8 + 32 + 32);
	memcpy_s(km->prv_enc_blob, 128, kb, 8 + 32 + 32 + 32);



	BM::encrypt_payload(km, (LPBYTE)hello, lstrlenA(hello), pl, &pl_size);
	BM::decrypt_payload(km, pl, pl_size);



	return FALSE;
}

// AKA shareing public keys using getpubkey and pubkey objects
DWORD dsa_test()
{

	// prepare everything.

	PBM_MSG_ADDR alice = NULL;
	PBM_MSG_ADDR bob = NULL;
	
	BM::create_addr(&bob);

	BMDB::address_add(bob, L"bob");

	PBM_OBJECT obj = (PBM_OBJECT)ALLOC_(1024);
	LPBYTE pl = (LPBYTE)ALLOC_(1024);
	DWORD pl_size = 512;

	obj->expiresTime = BM::swap64(BM::unix_time() + 60 * 60 + 100);
	obj->objectType = htonl(1);

	DWORD w = BM::encodeVarint(4, obj->objectVersion);

	w += BM::encodeVarint(1, &obj->objectVersion[w]);

	// we are Alice and we want to request bobs public keys.
	// we have his Bitmessage Address in the form of BM-???
	// but we need his public keys in order to encrpt messages for him.
	// so we send out a getpubkey request to the bitmessage network
	BM::obj_getpubkey(obj, bob, pl, &pl_size);

	// once a node has processed the getpubkey request
	// it then sends out bobs encrypted public keys
	// anyone who has bobs readable bitmessage address BM-????
	// can then decrypt the public keys for future use.
	BM::obj_pubkey(bob, obj, 20 + w, (PBM_PUBKEY_V4_OBJ)pl, pl_size);


	return 0;

}











DWORD msg_test()
{

	PBM_MSG_ADDR alice = NULL;
	PBM_MSG_ADDR bob = NULL;

	BM::create_addr(&alice);
	BM::create_addr(&bob);


	BMDB::address_add(bob, L"bob");
	
	
	
	PBM_MSG_HDR msg_hdr = NULL;
	DWORD pl_size = 0;


	BM::encrypt_msg(&msg_hdr, &pl_size, bob, alice, "test", "AAAA");


	BM::obj_msg((PBM_OBJECT)msg_hdr->payload, (PBM_ENC_PL_256)&msg_hdr->payload[22], pl_size);



	return FALSE;



}









BOOL MainWin::InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	

	//address_test();
	//dsa_test();
	//msg_test();
	
	
	MainWin::hInst = hInstance; // Store instance handle in our global variable

	HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW | WS_DLGFRAME, CW_USEDEFAULT, 0, 923, 530, nullptr, nullptr, hInstance, nullptr);
   
	if (!hWnd)	return FALSE;
	
	// initialize the Core Threads.
	SendMessage(hWnd, WM_INITDIALOG, NULL, NULL);

	MainWin::h_main = hWnd;

	HWND tb = CreateDialog(MainWin::hInst, MAKEINTRESOURCE(4), hWnd, Tabs::TabControlDlgProc);
 
	NMHDR nmhdr = {};
	nmhdr.code = TCN_SELCHANGE;

	// Set to the First Tab.
	SendMessage(tb, WM_NOTIFY, 0, (LPARAM)&nmhdr);

	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);

	

	return TRUE;
}







//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK MainWin::WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{

    switch (message)
    {

	case WM_INITDIALOG:
	{
		
		BM::main_hwnd = hWnd;

		int t = SetTimer(hWnd, NULL, 1000 * 60 * 2, NULL);
		
#ifdef BM_ENABLE_NETWORK

		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)network::start, BM::main_hwnd, NULL, NULL);
		
		BM::prop_thread_handle = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)network::obj_prop_thread, NULL, NULL, NULL);

#endif

		return TRUE;
	}
	





	case WM_TIMER:
#ifdef BM_ENABLE_NETWORK
		// check if thread is already running.
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)network::maintain_health, NULL, NULL, NULL);

#endif

		break;





    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(MainWin::hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, MainWin::About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code that uses hdc here...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        
	{
	

			//SendDlgItemMessage(hdwnd, ID_EDIT_DATA, WM_SETTEXT, 0, (LPARAM)"");

			//for (int i = 0; i < BM_MAX_CONNECTIONS; i++)
			//{

			//	if (network::con_list->list[i] && network::con_list->list[i]->s)
			//	{

			//		//network::remove_conn(network::con_list->list[i]->s); //Shut down socket

			//	}


			//}


			WSACleanup(); //Clean up Winsock
						  //Memory::deinit();

		}

		
		BMDB::disc_all_conn_nodes(NULL);


		sqlite3_close(BM::db);


		PostQuitMessage(0);
	
        break;


	case 1101: // BM_DATA
	{
		int e = 0;
	}


    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK MainWin::About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    //UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }

	

    return (INT_PTR)DefWindowProc(hDlg, message, wParam, lParam);;
}

#endif