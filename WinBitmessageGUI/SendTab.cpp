#ifndef SENDTAB_C
#define SENDTAB_C

#include "SendTab.h"

// Send Button
HWND SendTab::send_h = NULL;
HWND SendTab::contact_list_h = NULL;
HWND SendTab::to_h = NULL;
HWND SendTab::from_dropdown_h = NULL;
HWND SendTab::subject_h = NULL;
HWND SendTab::body_h = NULL;
HWND SendTab::TTL_trackbar_h = NULL;
HWND SendTab::TTL_label_h = NULL;


HWND SendTab::send_tab_h = NULL;



// current selections

DWORD SendTab::selected_contact_id = NULL;
DWORD SendTab::selected_from_id = NULL;
DWORD SendTab::selected_TTL = NULL;

//

BOOL contact_list_init = FALSE;
DWORD from_list[256] = {};
DWORD old_selected_ttl = NULL;



BOOL SendTab::on_init(HWND hWnd)
{
	SendTab::send_tab_h = hWnd;
	contact_list_init = FALSE;


	//


	SendTab::send_h = GetDlgItem(hWnd, IDC_BUTTON1);
	SendTab::contact_list_h = GetDlgItem(hWnd, IDC_LIST1);
	SendTab::to_h = GetDlgItem(hWnd, IDC_EDIT2);
	SendTab::from_dropdown_h = GetDlgItem(hWnd, IDC_COMBO1);
	SendTab::subject_h = GetDlgItem(hWnd, IDC_EDIT3);
	SendTab::body_h = GetDlgItem(hWnd, IDC_EDIT4);
	SendTab::TTL_trackbar_h = GetDlgItem(hWnd, IDC_SLIDER1);
	SendTab::TTL_label_h = GetDlgItem(hWnd, 6969);

	//

	SendMessage(SendTab::TTL_trackbar_h, TBM_SETRANGE, (WPARAM)TRUE, (LPARAM)MAKELONG(1, 23/*hours*/ + 28/*days*/));
	SendMessage(SendTab::TTL_trackbar_h, TBM_SETPOS, (WPARAM)TRUE, 27);

	//

	SendTab::init_contact_list();
	SendTab::update_from_list();

	//



	ExitThread(0);
	return TRUE;
}

void SendTab::init_contact_list()
{

	HWND lv = SendTab::contact_list_h;

	if (contact_list_init == FALSE)
	{

		SendMessage(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);



		LVCOLUMN c = {};
		c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_ORDER;
		c.iOrder = 0;
		c.iSubItem = 0;
		c.pszText = L"Label";
		c.cx = 100;

		ListView_InsertColumn(lv, 0, &c);

		c.iOrder = 1;
		c.iSubItem = 1;
		c.pszText = L"Address";
		c.cx = 200;

		ListView_InsertColumn(lv, 1, &c);

		c.iOrder = 2;
		c.iSubItem = 2;
		c.pszText = L"Ready";
		c.cx = 100;

		ListView_InsertColumn(lv, 2, &c);
	
		contact_list_init = TRUE;
	}
		SendTab::update_contact_list();
	
}



BOOL SendTab::update_contact_list()
{
	// clear the list
	ListView_DeleteAllItems(SendTab::contact_list_h);
	
	DWORD ret = FALSE;
	int rc = NULL;
	sqlite3_stmt* stmt = NULL;

	LPSTR st = "SELECT * FROM address_book WHERE is_priv = 0";

	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	if (rc != SQLITE_OK) return ret;


	rc = sqlite3_step(stmt);

	DWORD id = NULL;
	LPWSTR label = NULL;
	LPWSTR addr = NULL;
	DWORD is_ready = NULL;

	LVITEM lvi = { 0 };
	lvi.mask = LVIF_TEXT | LVIF_PARAM;
	WCHAR szText[200] = {};
	int i = 0;

	do
	{
		if (rc == SQLITE_ROW)
		{

			id = sqlite3_column_int(stmt, 0);
			PBM_MSG_ADDR _addr = (PBM_MSG_ADDR)sqlite3_column_blob(stmt, 1);
			label = (LPWSTR)sqlite3_column_text16(stmt, 2);
			addr = (LPWSTR)sqlite3_column_text16(stmt, 3);
			
			is_ready = (DWORD)((PBCRYPT_ECCKEY_BLOB)_addr->pub_enc_blob)->dwMagic;

			lvi.iItem = i;
			lvi.iSubItem = 0;

			lvi.pszText = szText;
			lvi.cchTextMax = 200;
			lvi.iImage = i;
			lvi.lParam = id; // id of the message 

			swprintf_s(szText, 200, L"%s", label);


			ListView_InsertItem(SendTab::contact_list_h, &lvi);


			swprintf_s(szText, 200, L"%s", addr);
			ListView_SetItemText(SendTab::contact_list_h, i, 1, szText);


			swprintf_s(szText, 200, L"%s", (is_ready ? L"yes" : L"no"));
			ListView_SetItemText(SendTab::contact_list_h, i, 2, szText);


			i++;
		}

		rc = sqlite3_step(stmt);
	} while (rc == SQLITE_ROW);

	sqlite3_finalize(stmt);

	return TRUE;
}




BOOL SendTab::update_from_list()
{
	// clear the drop down
	
	ComboBox_ResetContent(SendTab::from_dropdown_h);
	
	
	DWORD ret = FALSE;
	int rc = NULL;
	sqlite3_stmt* stmt = NULL;

	LPSTR st = "SELECT * FROM address_book WHERE is_priv = 1";

	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	if (rc != SQLITE_OK) return ret;


	rc = sqlite3_step(stmt);

	DWORD id = NULL;
	LPWSTR label = NULL;
	LPWSTR addr = NULL;
	DWORD is_ready = NULL;

	LVITEM lvi = { 0 };
	lvi.mask = LVIF_TEXT | LVIF_PARAM;
	WCHAR szText[200] = {};
	int i = 0;
	DWORD index = 0;

	do
	{
		if (rc == SQLITE_ROW)
		{

			id = sqlite3_column_int(stmt, 0);
			
			label = (LPWSTR)sqlite3_column_text16(stmt, 2);

			addr = (LPWSTR)sqlite3_column_text16(stmt, 3);

			swprintf_s(szText, 200, L"%s(%s)", addr, label);

			index = ComboBox_AddString(SendTab::from_dropdown_h, szText);
			
			ComboBox_SetItemData(SendTab::from_dropdown_h, index, id);
			Sleep(100);
		}

		rc = sqlite3_step(stmt);
	} while (rc == SQLITE_ROW && i < 256);

	sqlite3_finalize(stmt);

	return TRUE;
}


DWORD SendTab::contact_right_click_menu()
{

	

	HMENU rcm = CreatePopupMenu();
	MENUITEMINFOW mi = {};

	mi.cbSize = sizeof(MENUITEMINFO);
	mi.fMask = MIIM_STRING | MIIM_ID | MIIM_STATE;
	mi.fType = MFT_STRING;


	// ADD


	mi.fState = MFS_ENABLED;

	mi.wID = RCM_ADD;
	mi.dwTypeData = RCMS_ADD;
	mi.cch = lstrlenW(RCMS_ADD);

	InsertMenuItemW(rcm, 0x1, TRUE, &mi);


	// COPY


	mi.fState = (!SendTab::selected_contact_id) ? MFS_DISABLED : MFS_ENABLED;

	SendTab::selected_contact_id;

	mi.wID = RCM_COPY;
	mi.dwTypeData = RCMS_COPY;
	mi.cch = lstrlenW(RCMS_COPY);

	InsertMenuItemW(rcm, 0x2, TRUE, &mi);


	// DELETE		
	mi.fState = (!SendTab::selected_contact_id) ? MFS_DISABLED : MFS_ENABLED;

	SendTab::selected_contact_id;

	mi.wID = RCM_DELETE;
	mi.dwTypeData = RCMS_DELETE;
	mi.cch = lstrlenW(RCMS_DELETE);

	InsertMenuItemW(rcm, 0x2, TRUE, &mi);

	//

	POINT p = {};

	GetCursorPos(&p);

	// create right click pop up menu at the POINT p.

	DWORD rcmid = TrackPopupMenuEx(rcm, TPM_RETURNCMD, p.x, p.y, SendTab::send_tab_h, NULL);

	return rcmid;
}









DWORD SendTab::crcm_proc(DWORD selection)
{


	switch (selection)
	{

	case RCM_ADD:
	{
		DialogBox(MainWin::hInst, MAKEINTRESOURCE(IDD_DIALOG1), MainWin::h_main, SendTab::add_contact_proc);
		break;
	}

	case RCM_DELETE:
	{	// validate action with yes/no messagebox.

		//MB_YESNO
		if (MessageBox(SendTab::send_tab_h, TEXT("Are you sure you want to complete this action?"), TEXT("Are you sure?"), MB_YESNO) == IDYES)
		{


			BMDB::address_remove(SendTab::selected_contact_id);
			SendTab::update_contact_list();

		}

		break;
	}

	case RCM_COPY:
	{

		BM_MSG_ADDR addr = {};

		// use the ID to get the BM address

		if (BMDB::address_find(SendTab::selected_contact_id, NULL, NULL, &addr))
		{
			// Copy BM address to the clipboard

			size_t size = sizeof(CHAR)*(1 + lstrlenA(addr.readable));

			HGLOBAL hResult = GlobalAlloc(GMEM_MOVEABLE, size);

			LPSTR lptstrCopy = (LPSTR)GlobalLock(hResult);

			memcpy(lptstrCopy, addr.readable, size);


			GlobalUnlock(hResult);

			OpenClipboard(SendTab::send_tab_h);
			EmptyClipboard();
			SetClipboardData(CF_TEXT, hResult);
			CloseClipboard();

		}

		ZERO_(&addr, sizeof(BM_MSG_ADDR));


		break;
	}

	default:
		break;
	}


	return TRUE;

}


BOOL SendTab::on_notify(HWND hWnd, WPARAM wParam, NMHDR* lParam)
{
	NMHDR* nhdr = (NMHDR*)lParam;

	switch (nhdr->code)
	{


	case NM_RCLICK:
	{

	
		DWORD right_click_selection = SendTab::contact_right_click_menu();

		// handle menu selection

		SendTab::crcm_proc(right_click_selection);


		break;
	}

	

	// new message selected
	case LVN_ITEMCHANGED:
	{
		tagNMLISTVIEW* lv_info = (tagNMLISTVIEW*)lParam;
		if (lv_info->hdr.hwndFrom == SendTab::contact_list_h) {


			SendTab::selected_contact_id = lv_info->lParam;



		}
		// lParam == Message ID
		//SendTab::update_msg_display(lv_info->lParam);

		break;
	}


		default:
			break;
	}

	return TRUE;
}


BOOL SendTab::on_cmd(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
	WORD cid = LOWORD(wParam);
	WORD code = HIWORD(wParam);

	HWND hButton = (HWND)lParam;

	switch (code)
	{

	case BN_CLICKED:

	{
		switch (cid)
		{

		case IDC_BUTTON1: //
		{
			// send message

			//
			int item_n = ComboBox_GetCurSel(SendTab::from_dropdown_h);
			int from_address = ComboBox_GetItemData(SendTab::from_dropdown_h, item_n);
			LPSTR to_address = (LPSTR)ALLOC_(MAX_PATH);
			//LPWSTR to_address_w = (LPWSTR)ALLOCw_(MAX_PATH);

			LPSTR subject = (LPSTR)ALLOCw_(MAX_PATH);
			LPSTR body = (LPSTR)ALLOCw_(MAX_BODY_LENGTH);


			//DWORD to_s = GetWindowTextLengthA(SendTab::to_h);
			//DWORD to_s_w = GetWindowTextLengthW(SendTab::to_h);

			//DWORD subject_s = GetWindowTextLengthW(SendTab::subject_h);
			//DWORD body_s = GetWindowTextLengthW(SendTab::body_h);

			GetWindowTextA(SendTab::to_h, to_address, MAX_PATH);
			//GetWindowTextW(SendTab::to_h, to_address_w, MAX_PATH);


			DWORD TTL_position = SendMessage(SendTab::TTL_trackbar_h, TBM_GETPOS, 0, 0);



			// check if we have the address
			// if not get the public keys.
			// 

			BM_MSG_ADDR _to_addr = {};

			if (!BM::validate_address(to_address, lstrlenA(to_address), NULL))
			{
				MessageBoxW(hWnd, L"Invalid Bitmessage Adress!", L"ERROR", MB_ICONERROR);
				break;
			}


			if (BMDB::address_find(0, to_address, 0, &_to_addr))
			{



				GetWindowTextA(SendTab::subject_h, subject, MAX_PATH);

				if (lstrlenA(subject) == 0)
				{
					MessageBoxW(hWnd, L"Enter a subject!", L"ERROR", MB_ICONERROR); 
					break;
				}
				

				
				GetWindowTextA(SendTab::body_h, body, MAX_BODY_LENGTH);

				if (lstrlenA(body) == 0)
				{
					MessageBoxW(hWnd, L"Enter a message!", L"ERROR", MB_ICONERROR);
					break;
				}


				//
				// Send the Message!


				BM::send_msg(from_address, _to_addr.db_id, subject, body);


				//
				//

			}

			break;
		}


		}
		break;
	}


	case CBN_SELCHANGE:
	{
		int index = ComboBox_GetCurSel(SendTab::from_dropdown_h);

		SendTab::selected_from_id = ComboBox_GetItemData(SendTab::from_dropdown_h, index);

		break;
	}


	}

	

	return TRUE;
}



INT_PTR CALLBACK SendTab::Send_tabProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{

	PAINTSTRUCT ps;
	HDC hdc;


	switch (message)
	{
		// Handle the WM_INITDIALOG message in OnInitTabControlDialog
		///HANDLE_MSG(hWnd, WM_INITDIALOG, SendTab::on_init);

	case WM_INITDIALOG:
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SendTab::on_init, hWnd, 0, 0);
		break;

		// Handle the WM_CLOSE message in OnClose
		//HANDLE_MSG(hWnd, WM_CLOSE, OnClose);

	case WM_COMMAND:

		SendTab::on_cmd(hWnd, wParam, lParam);
		break;




	case WM_MENUCOMMAND:
		
		break;


	case WM_HSCROLL:
		
		SendTab::selected_TTL = SendMessage(SendTab::TTL_trackbar_h, TBM_GETPOS, 0, 0);
		if (old_selected_ttl != SendTab::selected_TTL)
			SendMessage(SendTab::send_tab_h, WM_PAINT, 0, 0);

		break;

	case WM_PAINT:
	{

		if (old_selected_ttl != SendTab::selected_TTL)
		{
			hdc = BeginPaint(hWnd, &ps);


			DWORD n_ticks = 23 + 28;
			TCHAR buff[MAX_PATH] = {};


			if (SendTab::selected_TTL <= 23)
			{

				wsprintf(buff, TEXT("%u hours"), SendTab::selected_TTL);

			}
			else {

				wsprintf(buff, TEXT("%u days"), SendTab::selected_TTL - 23);

			}

			BOOL set = Static_SetText(SendTab::TTL_label_h, buff);

			old_selected_ttl = SendTab::selected_TTL;

			//Static_SetText();

			EndPaint(hWnd, &ps);
		}

		break;
	}






		HANDLE_MSG(hWnd, WM_NOTIFY, SendTab::on_notify);


	default:
		return FALSE;	// Let system deal with msg
	}

	DefWindowProc(hWnd, message, wParam, lParam);

	return 0;


}



DWORD do_getpubkey_proc(LPVOID in)
{

	PBM_MSG_ADDR msg_addr = (PBM_MSG_ADDR)in;

	

	PBM_MSG_HDR msg_hdr = (PBM_MSG_HDR)ALLOC_(2048);
	ZERO_(msg_hdr, 2048);

	PBM_OBJECT obj = (PBM_OBJECT)msg_hdr->payload;
	PBM_ENC_PL_256 pl = (PBM_ENC_PL_256)(((ULONG_PTR)msg_hdr + 2048) - 1024);
	DWORD pl_size = 1024;





	// Copy the public tag to the payload buffer.

	memcpy_s(pl, 1024, msg_addr->tag, 32);

	pl_size = 32;




	// initialize object header

	pl_size = BM::init_object(obj, 128, BM_OBJ_GETPUBKEY, (LPBYTE)pl, pl_size);

	// initialize msg header


	BM::init_msg_hdr(msg_hdr, pl_size, "object");




	BYTE vect_tag[MAX_PATH] = {};

	BM::create_vector_tag((LPBYTE)obj, pl_size, vect_tag, MAX_PATH);


	BMDB::vector_add(vect_tag, obj, pl_size);


	DWORD inv_id = BMDB::vector_find(NULL, vect_tag, NULL, NULL);


	// propogate!
	//Sleep(20000);
	DBGOUTw(L"\r\r===== SENDING GETPUBKEY =====\r\r");
	network::queue_obj(0, inv_id);

	

	if (in)
	{
		ZERO_(in, sizeof(BM_MSG_ADDR));
		GlobalFree(in);
	}
	ExitThread(0);

}



INT_PTR CALLBACK SendTab::add_contact_proc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	INT_PTR ret = NULL;
	switch (message)
	{

	case WM_INITDIALOG:

		SetWindowText(hWnd, TEXT("Create Contact"));
		SetWindowText(GetDlgItem(hWnd, IDC_STATIC), TEXT("Bitmessage Address: "));

		SetFocus(GetDlgItem(hWnd, IDC_EDIT1));

		break;

	case WM_NOTIFY:
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;

	case WM_COMMAND:
	{

		switch (HIWORD(wParam))
		{

		case BN_CLICKED:


			switch (LOWORD(wParam))
			{

			case IDOK:
			{
				//
				// Do ID Creation HERE!
				//
				//LPWSTR label = NULL;
				CHAR bm_addr[MAX_PATH] = {};

				
				GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT1), bm_addr, MAX_PATH);


				PBM_MSG_ADDR msg_addr = (PBM_MSG_ADDR)GlobalAlloc(GPTR, 0x400);
				

				if (BM::validate_address(bm_addr, lstrlenA(bm_addr), msg_addr))
				{

					if (BMDB::address_add(msg_addr, TEXT("none")))
					{
						SendTab::init_contact_list();


						CreateThread(0, 0, (LPTHREAD_START_ROUTINE)do_getpubkey_proc, (LPVOID)msg_addr, 0, 0);
						
						
					}
					else
					{
						MessageBoxW(hWnd, L"This address is already in the Database!", L"ERROR", MB_ICONERROR);
					}
				}
				else {
					MessageBoxW(hWnd, L"Invalid Bitmessage Adress!", L"ERROR", MB_ICONERROR);
				}
				
				

				EndDialog(hWnd, TRUE);
				break;
			}

			case IDCANCEL:

				EndDialog(hWnd, FALSE);
				break;


			default:
				break;
			}




			break;



		default:
			break;
		}

		break;
	}

	default:
		DefWindowProc(hWnd, message, wParam, lParam);
		break;
	}

	return ret;

}


















#endif