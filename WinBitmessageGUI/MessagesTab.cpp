

#ifndef MESSAGES_TAB_C
#define Messages_TAB_C
#include "MessagesTab.h"

// Address List / TreeView
 HWND MessagesTab::addr_list_h = NULL;

// Message List / ListView
 HWND MessagesTab::msg_list_h = NULL;

// Address List / TreeView
 HWND MessagesTab::msg_disp_h = NULL;


BOOL MessagesTab::on_init(HWND hWnd, HWND focus, LPARAM lParam)
{
	MessagesTab::addr_list_h = GetDlgItem(hWnd, IDC_TREE1);
	MessagesTab::msg_list_h = GetDlgItem(hWnd, IDC_LIST1);
	MessagesTab::msg_disp_h = GetDlgItem(hWnd, IDC_EDIT1);


	MessagesTab::init_msg_list(MessagesTab::msg_list_h);

	MessagesTab::init_addr_tree(MessagesTab::addr_list_h);


	return TRUE;
}


BOOL MessagesTab::on_notify(HWND hWnd, WPARAM wParam, NMHDR* lParam)
{
	NMHDR* nhdr = (NMHDR*)lParam;

	switch (nhdr->code)
	{

	// new folder selected
	case TVN_SELCHANGED:
	{
		HTREEITEM hti = TreeView_GetSelection(MessagesTab::addr_list_h);

		TVITEM item = {};

		item.hItem = hti;
		item.mask = TVIF_PARAM;
		item.pszText = NULL;
		item.cchTextMax = NULL;

		if (TreeView_GetItem(MessagesTab::addr_list_h, &item))
		{
			int e = 0;

			DWORD id = LOWORD(item.lParam);
			DWORD folder = HIWORD(item.lParam);


			MessagesTab::update_msg_list(hWnd, id, folder);
			
		}

		int e = 0;

		break;
	}

	// new message selected
	case LVN_ITEMCHANGED:
		
	{
		tagNMLISTVIEW* lv_info = (tagNMLISTVIEW*)lParam;

		// lParam == Message ID
		MessagesTab::update_msg_display(lv_info->lParam);

		break;
	}

	default:
		break;
	}

	return TRUE;
}


BOOL MessagesTab::on_cmd(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
	WORD cid = LOWORD(wParam);
	WORD code = HIWORD(wParam);

	HWND hButton = (HWND)lParam;

	switch (code)
	{

	case BN_CLICKED:


		switch (cid)
		{

		case IDC_BUTTON1: // New Identity
			
			INT_PTR r = DialogBox(MainWin::hInst, MAKEINTRESOURCE(IDD_DIALOG1), MainWin::h_main, MessagesTab::add_label_proc);
			int e = GetLastError();
			int f = 0;


			break;

		}

		break;

	}



	return TRUE;
}


INT_PTR CALLBACK MessagesTab::Messages_tabProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
		// Handle the WM_INITDIALOG message in OnInitTabControlDialog
		HANDLE_MSG(hWnd, WM_INITDIALOG, MessagesTab::on_init);

		// Handle the WM_CLOSE message in OnClose
		//HANDLE_MSG(hWnd, WM_CLOSE, OnClose);

	case WM_COMMAND:

		MessagesTab::on_cmd(hWnd, wParam, lParam);
		break;
		

		HANDLE_MSG(hWnd, WM_NOTIFY, MessagesTab::on_notify);
		

	default:
		return FALSE;	// Let system deal with msg
	}
	return 0;


}




INT_PTR CALLBACK MessagesTab::add_label_proc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	INT_PTR ret = NULL;
	switch (message)
	{

	case WM_INITDIALOG:

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
				WCHAR label[MAX_PATH] = {};
				Edit_GetText(GetDlgItem(hWnd, IDC_EDIT1), label, MAX_PATH);


				PBM_MSG_ADDR msg_addr = NULL;
				BM::create_addr(&msg_addr);
				BMDB::address_add(msg_addr, label);

				MessagesTab::init_addr_tree(NULL);

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



void MessagesTab::init_msg_list(HWND lv)
{
	SendMessage(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);


	LVCOLUMN c = {};
	c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_ORDER;
	c.iOrder = 0;
	c.iSubItem = 0;
	c.pszText = L"From";
	c.cx = 100;

	ListView_InsertColumn(lv, 0, &c);

	c.iOrder = 1;
	c.iSubItem = 1;
	c.pszText = L"Subject";
	c.cx = 300;

	ListView_InsertColumn(lv, 1, &c);

	c.iOrder = 2;
	c.iSubItem = 2;
	c.pszText = L"Date Received";
	c.cx = 100;

	ListView_InsertColumn(lv, 2, &c);
}

void MessagesTab::init_addr_tree(HWND tv)
{
	TreeView_DeleteAllItems(MessagesTab::addr_list_h);

	MessagesTab::fill_addr_tree();
	
}


// TODO: name this function to update_addr_tree

DWORD MessagesTab::fill_addr_tree()
{
	DWORD ret = FALSE;
	LPSTR st = "SELECT id, label, addr FROM address_book WHERE is_priv = 1;";
	int rc = NULL;
	sqlite3_stmt * stmt = NULL;

	LPTSTR addr = NULL;
	LPTSTR label = NULL;
	int id = NULL;
	HTREEITEM hti = NULL;
	WCHAR tmp[MAX_PATH] = {};

	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	if (rc != SQLITE_OK)
	{

		BMDB::show_error();

	}
	else {

		rc = sqlite3_step(stmt);

		do {
			if (rc != SQLITE_ROW) break;

			id = sqlite3_column_int(stmt, 0);
			label = (LPTSTR)sqlite3_column_text16(stmt, 1);
			addr = (LPTSTR)sqlite3_column_text16(stmt, 2);
		
			
			wsprintfW(tmp, L"(%s)%s", label, addr);

			hti = TreeView::InsertItem(MessagesTab::addr_list_h, tmp, id, TVI_ROOT);


			TreeView::InsertItem(MessagesTab::addr_list_h, L"inbox", id | INBOX_FOLDER, hti);
			TreeView::InsertItem(MessagesTab::addr_list_h, L"sent", id | SENT_FOLDER, hti);
			TreeView::InsertItem(MessagesTab::addr_list_h, L"new", id | NEW_FOLDER, hti);
			TreeView::InsertItem(MessagesTab::addr_list_h, L"trash", id | TRASH_FOLDER, hti);

			ret = TRUE;

			rc = sqlite3_step(stmt);
		} while (rc == SQLITE_ROW);


	}

	return ret;

}


BOOL MessagesTab::update_msg_list(HWND hml, DWORD to_id, DWORD folder)
{
	// clear the list
	ListView_DeleteAllItems(MessagesTab::msg_list_h);
	Edit_SetText(MessagesTab::msg_disp_h, L"");

	DWORD ret = FALSE;
	int rc = NULL;
	sqlite3_stmt* stmt = NULL;

	LPSTR st = "SELECT * FROM msgs WHERE to_id = ? AND folder = ?";

	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	if (rc != SQLITE_OK) return ret;

	rc = sqlite3_bind_int(stmt, 1, to_id);
	rc = sqlite3_bind_int(stmt, 2, folder);
	

	rc = sqlite3_step(stmt);

	DWORD id = NULL;
	DWORD from = NULL;
	DWORD64 date = NULL;
	LPWSTR subject = NULL;

	LVITEM lvi = { 0 };
	lvi.mask = LVIF_TEXT | LVIF_PARAM;
	WCHAR szText[200] = {};
	int i = 0;

	do
	{
		if (rc == SQLITE_ROW)
		{

			id = sqlite3_column_int(stmt, 0);
			from = sqlite3_column_int(stmt, 4);
			subject = (LPWSTR)sqlite3_column_text16(stmt, 5);
			date = sqlite3_column_int(stmt, 7);

			lvi.iItem = i;
			lvi.iSubItem = 0;
			
			lvi.pszText = szText;
			lvi.cchTextMax = 200;
			lvi.iImage = i;
			lvi.lParam = id; // id of the message 

			swprintf_s(szText, 200, L"%d", from);

			
			ListView_InsertItem(MessagesTab::msg_list_h, &lvi);


			swprintf_s(szText, 200, L"%s", subject);
			ListView_SetItemText(MessagesTab::msg_list_h, i, 1, szText);

			tm __tm = {};
			tm* _tm = &__tm;

			_gmtime64_s(&__tm, (const __time64_t*)&date);

			


			swprintf_s(szText, 200, L"%d/%d/%d  %d:%d", _tm->tm_mon + 1, _tm->tm_mday, (_tm->tm_year - 100), _tm->tm_hour + 1, _tm->tm_min);
			ListView_SetItemText(MessagesTab::msg_list_h, i, 2, szText);


			i++;
		}

		rc = sqlite3_step(stmt);
	} while (rc == SQLITE_ROW);

	sqlite3_finalize(stmt);

	return TRUE;
}


BOOL MessagesTab::update_msg_display(DWORD msg_id)
{
	
	DWORD ret = FALSE;
	int rc = NULL;
	sqlite3_stmt* stmt = NULL;

	LPSTR st = "SELECT * FROM msgs WHERE id = ?";

	rc = sqlite3_prepare(BM::db, st, -1, &stmt, NULL);

	if (rc != SQLITE_OK) return ret;

	rc = sqlite3_bind_int(stmt, 1, msg_id);


	rc = sqlite3_step(stmt);

	LPWSTR body = NULL;
	

	do
	{
		if (rc == SQLITE_ROW)
		{

			body = (LPWSTR)sqlite3_column_text16(stmt, 6);

			Edit_SetText(MessagesTab::msg_disp_h, body);
			ret = TRUE;
			rc = sqlite3_step(stmt);
			break;
		}

	} while (rc == SQLITE_ROW);

	sqlite3_finalize(stmt);

	return ret;

	
}


#endif


