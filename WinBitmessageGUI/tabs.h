
#ifndef TABS_H
#define TABS_H



#define IDC_TAB			8990




namespace Tabs
{
	extern HWND display;
	extern HWND h_tab;
	extern HWND h_tab_container;
	extern HWND h_msg_tab;
	extern HWND h_send_tab; 


	void OnTabSize(HWND hWnd, UINT state, int cx, int cy);
	int InsertTabItem(HWND hTab, LPTSTR pszText, int iid);

	HWND DoCreateDisplayWindow(HWND hwndTab, HINSTANCE hInst);
	BOOL OnInitTabControlDialog(HWND hWnd, HWND hWndFocus, LPARAM lParam);
	BOOL OnNotify(HWND hwndTab, HWND hwndDisplay, LPARAM lParam);
	void OnClose(HWND hWnd);
	INT_PTR CALLBACK TabControlDlgProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
	//INT_PTR CALLBACK    Messages_tabProc(HWND, UINT, WPARAM, LPARAM);
	//BOOL init_msg_tab(HWND hWnd, HWND focus, LPARAM lParam);
	//BOOL ntfy_msg_tab(HWND hWnd, HWND focus, LPARAM lParam);

	INT_PTR CALLBACK    Send_tabProc(HWND, UINT, WPARAM, LPARAM);
	//INT_PTR CALLBACK    Messages_tabProc(HWND, UINT, WPARAM, LPARAM);
	//INT_PTR CALLBACK    Messages_tabProc(HWND, UINT, WPARAM, LPARAM);




}



#endif
