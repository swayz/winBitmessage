#include "stdafx.h"

#ifndef TABS_C
#define TABS_C


HWND Tabs::display = NULL;
HWND Tabs::h_tab = NULL;
HWND Tabs::h_tab_container = NULL;

HWND Tabs::h_msg_tab = NULL;
HWND Tabs::h_send_tab = NULL;

//HWND Tabs::h_msg_display = NULL;
//HWND Tabs::tv_messages = NULL;
//HWND Tabs::lv_messages = NULL;
//


// MSDN: Tab
// http://msdn.microsoft.com/en-us/library/bb760548.aspx

//
//   FUNCTION: OnTabSize(HWND, UINT, int, int)
//
//   PURPOSE: Process the WM_SIZE message

//


void Tabs::OnTabSize(HWND hWnd, UINT state, int cx, int cy)
{
	// Get the Tab control handle which was previously stored in the 
	// user data associated with the parent window.
	HWND hTab = (HWND)GetWindowLongPtr(hWnd, GWLP_USERDATA);

	// Resize tab control to fill client area of its parent window
	MoveWindow(hTab, 2, 2, cx - 4, cy - 4, TRUE);
}

int Tabs::InsertTabItem(HWND hTab, LPTSTR pszText, int iid)
{
	TCITEM ti = { 0 };
	ti.mask = TCIF_TEXT;
	ti.pszText = pszText;
	ti.cchTextMax = wcslen(pszText);

	return (int)SendMessage(hTab, TCM_INSERTITEM, iid, (LPARAM)&ti);
}
HWND Tabs::DoCreateDisplayWindow(HWND hwndTab, HINSTANCE hInst)
{
	HWND hwndStatic = CreateWindow(WC_STATIC, L"",
		WS_CHILD | WS_VISIBLE | WS_BORDER,
		100, 100, 100, 100,        // Position and dimensions; example only.
		hwndTab, NULL, hInst,    // hInst is the global instance handle
		NULL);
	return hwndStatic;
}

//
//   FUNCTION: OnInitTabControlDialog(HWND, HWND, LPARAM)
//
//   PURPOSE: Process the WM_INITDIALOG message
//
BOOL Tabs::OnInitTabControlDialog(HWND hWnd, HWND hWndFocus, LPARAM lParam)
{
	// Load and register Tab control class
	INITCOMMONCONTROLSEX iccx;
	iccx.dwSize = sizeof(INITCOMMONCONTROLSEX);
	iccx.dwICC = ICC_TAB_CLASSES;
	if (!InitCommonControlsEx(&iccx))
		return FALSE;

	// Create the Tab control 
	RECT rc;
	GetClientRect(hWnd, &rc);
	HWND hTab = CreateWindowEx(0, WC_TABCONTROL, 0,
		TCS_FIXEDWIDTH | WS_CHILD | WS_VISIBLE,
		rc.left + 2, rc.top + 17, rc.right - 4, rc.bottom - 20,
		hWnd, (HMENU)IDC_TAB, MainWin::hInst, 0);

	Tabs::h_tab = hTab;

	// Set the font of the tabs to a more typical system GUI font
	SendMessage(hTab, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), 0);

	// Store the Tab control handle as the user data associated with the 
	// parent window so that it can be retrieved for later use.
	SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)hTab);


	/////////////////////////////////////////////////////////////////////////
	// Add items to the tab common control.
	// 

	InsertTabItem(hTab, L"Messages", 0);
	InsertTabItem(hTab, L"Send", 1);
	InsertTabItem(hTab, L"Subscriptions", 2);
	InsertTabItem(hTab, L"Chans", 3);
	InsertTabItem(hTab, L"Blacklist", 4);
	InsertTabItem(hTab, L"Network", 5);


	h_tab_container = DoCreateDisplayWindow(hTab, MainWin::hInst);


	return TRUE;
}

BOOL Tabs::OnNotify(HWND hwndTab, HWND hwndDisplay, LPARAM lParam)
{
	TCHAR achTemp[256] = {}; // temporary buffer for strings

	switch (((LPNMHDR)lParam)->code)
	{
	case TCN_SELCHANGING:
	{
		// Return FALSE to allow the selection to change.

		return FALSE;
	}

	case TCN_SELCHANGE:
	{
		int iPage = TabCtrl_GetCurSel(hwndTab);

		if (Tabs::h_tab_container)
		{
			//DestroyWindow(Tabs::h_tab_container);
			ShowWindow(Tabs::h_tab_container, SW_HIDE);
			Tabs::h_tab_container = NULL;
		}

		HWND p = NULL;

		if (iPage == 0)
		{
			if (!Tabs::h_msg_tab)
				Tabs::h_msg_tab = CreateDialog(MainWin::hInst, MAKEINTRESOURCE(2), hwndTab, MessagesTab::Messages_tabProc);

			Tabs::h_tab_container = Tabs::h_msg_tab;

		}
		else if (iPage == 1)
		{
			if (!Tabs::h_send_tab)
				Tabs::h_send_tab = CreateDialog(MainWin::hInst, MAKEINTRESOURCE(3), hwndTab, SendTab::Send_tabProc);

			Tabs::h_tab_container = Tabs::h_send_tab;
		}

		ShowWindow(Tabs::h_tab_container, SW_SHOW);
		SetFocus(Tabs::h_tab_container);



		LRESULT result = SendMessage(Tabs::h_tab_container, WM_SETTEXT, 0,
			(LPARAM)achTemp);
		break;
	}
	}
	return TRUE;
}

void Tabs::OnClose(HWND hWnd)
{
	EndDialog(hWnd, 0);
}

//
//  FUNCTION: TabControlDlgProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the TabControl control dialog.
//
//
INT_PTR CALLBACK Tabs::TabControlDlgProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
		// Handle the WM_INITDIALOG message in OnInitTabControlDialog
		HANDLE_MSG(hWnd, WM_INITDIALOG, OnInitTabControlDialog);

		// Handle the WM_CLOSE message in OnClose
		HANDLE_MSG(hWnd, WM_CLOSE, OnClose);

		// Handle the WM_SIZE message in OnTabSize
		HANDLE_MSG(hWnd, WM_SIZE, OnTabSize);

	case WM_NOTIFY:
	{
		OnNotify(h_tab, display, lParam);
	}

	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
		//return DefDlgProcW(hWnd, message, wParam, lParam);	// Let system deal with msg
	}
	return 0;
}










#endif
