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









int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);



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

	int rc = sqlite3_open("C:/Users/John/Documents/Visual Studio 2015/Projects/WinBitmessageGUI/WinBitmessageGUI/chat_TCP/WM.db", &BM::db);
	
	//CHAR path[512] = {};

	//LPSTR db_name = "\\WM.db";

	//GetCurrentDirectoryA(512, path);


	//if (lstrlenA(path) < 512 - (lstrlenA(db_name) + 1))
	//{
	//	
	//	
	//	lstrcatA(path, db_name);
	//
	//


	//	int rc = sqlite3_open(path, &BM::db);


	//}
	//else {
	//	return FALSE;
	//}

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

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL MainWin::InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	MainWin::hInst = hInstance; // Store instance handle in our global variable

	HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, 923, 530, nullptr, nullptr, hInstance, nullptr);
   
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
		
		///CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)network::start, BM::main_hwnd, NULL, NULL);
		//CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)network::maintain_health, NULL, NULL, NULL);
		//BM::prop_thread_handle = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)BM::obj_prop_server, NULL, NULL, NULL);

		return TRUE;
	}
	





	case WM_TIMER:

		// check if thread is already running.
		///CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)network::maintain_health, NULL, NULL, NULL);

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