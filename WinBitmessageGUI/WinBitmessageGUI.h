#ifndef MAIN_WIN_SETTINGS_H
#define MAIN_WIN_SETTINGS_H


//#define IDD_MAIN_TAB_WIN 2

#define MAX_LOADSTRING 100

namespace MainWin
{
	// Global Variables:
	extern HINSTANCE hInst;
	extern HWND h_main;

	extern WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
	extern WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

													// Forward declarations of functions included in this code module:
	ATOM                MyRegisterClass(HINSTANCE hInstance);
	BOOL                InitInstance(HINSTANCE, int);
	LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
	INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);



}
// TODO: reference additional headers your program requires here
#endif