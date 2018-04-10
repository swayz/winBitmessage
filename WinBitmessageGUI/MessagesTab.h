#pragma once
#include "stdafx.h"


#ifndef MESSAGES_TAB_H
#define Messages_TAB_H

#define INBOX_FOLDER	0x010000
#define NEW_FOLDER		(INBOX_FOLDER | 0x020000)
#define SENT_FOLDER		0x040000
#define TRASH_FOLDER	0x080000




namespace MessagesTab
{

	// Address List / TreeView
	extern HWND addr_list_h;

	// Message List / ListView
	extern HWND msg_list_h;

	// Address List / TreeView
	extern HWND msg_disp_h;

	// the selected address in the address tree. 
	extern DWORD selected_addr_id;





	BOOL on_init(HWND hWnd, HWND focus, LPARAM lParam);
	BOOL on_notify(HWND hWnd, WPARAM wPAaram, NMHDR* lParam);
	BOOL on_cmd(HWND hWnd, WPARAM wParam, LPARAM lParam);
	INT_PTR CALLBACK Messages_tabProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
	INT_PTR CALLBACK add_label_proc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

	DWORD my_addr_right_click_menu();
	DWORD crcm_proc(DWORD selection);// address tree RIGHT CLICK menu


	void init_msg_list(HWND lv);
	BOOL update_msg_list(HWND hml, DWORD to_id, DWORD folder_id);
	VOID fill_msg_list(DWORD to_id, DWORD folder_id);

	void init_addr_tree(HWND tv);
	DWORD fill_addr_tree();

	BOOL update_msg_display(DWORD msg_id);




}





#endif // !MESSAGES_TAB_H