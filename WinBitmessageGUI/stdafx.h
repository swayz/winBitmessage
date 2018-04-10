// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <windowsx.h>
#include <Prsht.h>
#include "resource.h"

#include <winsock.h>
#include <commctrl.h>
#pragma comment(lib, "comctl32.lib")


// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <time.h>



#include "WinBitmessageGUI.h"
#include "TreeView.h"
#include "tabs.h"
#include "MessagesTab.h"
#include "SendTab.h"




#include "./core/Encryption.h"
#include "./core/BM.h"
#include "./core/ecc.h"
#include "./core/memory.h"
#include "./core/utils.h"
#include "./core/network.h"
#include "./core/bm_db.h"



#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")




// GUI



#define BM_ENABLE_NETWORK





// Message Tab
#define MSG_TAB_GUI 2
#define BNEW_ID 2
#define BDELETE 3
#define BRESEND 4

// Send Tab
#define SEND_TAB_GUI 3
#define BADD_CONTACT 2
#define BSEND 3
#define CFROM 5
#define ETO 6
#define ESUBJECT 7
#define EBODY 8
#define STTL 9


//Right Click Menu
#define RCM_ADD 2001
#define RCMS_ADD L"Add"

#define RCM_DELETE 2002
#define RCMS_DELETE L"Delete"

#define RCM_COPY 2003
#define RCMS_COPY L"Copy"




// Dialogs

#define IDD_ADD_LABEL 101

