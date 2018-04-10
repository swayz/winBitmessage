#pragma once
#include "stdafx.h"

#ifndef SENDTAB_H
#define SENDTAB_H

#define MAX_BODY_LENGTH 250000


namespace SendTab
{

	// tab handle
	extern HWND send_tab_h;


	// control handles withen the send tab
	extern HWND send_h;
	extern HWND contact_list_h;
	extern HWND to_h;
	extern HWND from_dropdown_h;
	extern HWND subject_h;
	extern HWND body_h;
	extern HWND TTL_trackbar_h;
	extern HWND TTL_label_h;

	// current selections
	extern DWORD selected_contact_id;
	extern DWORD selected_from_id;
	extern DWORD selected_TTL;





	BOOL on_init(HWND hWnd);
	BOOL on_notify(HWND hWnd, WPARAM wPAaram, NMHDR* lParam);
	BOOL on_cmd(HWND hWnd, WPARAM wParam, LPARAM lParam);
	INT_PTR CALLBACK Send_tabProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
	INT_PTR CALLBACK add_contact_proc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

	void init_contact_list();
	BOOL update_contact_list();
	DWORD contact_right_click_menu();
	DWORD crcm_proc(DWORD selection); // contact_right_click_menu_proc

	BOOL update_from_list();


}






















#endif

