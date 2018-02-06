


#ifndef TREEVIEW_C
#define TREEVIEW_C
#include "TreeView.h"

HTREEITEM TreeView::InsertItem(const HWND hTreeview, const LPTSTR pszText, int id,  HTREEITEM htiParent)
{
	TVITEM tvi = { 0 };
	tvi.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;
	tvi.pszText = pszText;
	tvi.cchTextMax = wcslen(pszText);
	tvi.iImage = 0;
	tvi.lParam = id;

	TVINSERTSTRUCT tvis = { 0 };
	tvi.iSelectedImage = 1;
	tvis.item = tvi;
	tvis.hInsertAfter = 0;
	tvis.hParent = htiParent;

	return (HTREEITEM)SendMessage(hTreeview, TVM_INSERTITEM, 0, (LPARAM)&tvis);
}


#endif