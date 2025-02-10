// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptwin.cpp - C++ Developer source file.
// (c)2021 by helmut altmann

// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; see the file COPYING.  If not, write to
// the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.

#include <fcntl.h>   // Console
#include <stdlib.h>
#include <stdio.h>
#include <io.h>
#include <iostream>
#include <conio.h>

#include <shlwapi.h>  // Library shlwapi.lib for PathFileExistsA
#include <commctrl.h> // Library Comctl32.lib
#include <commdlg.h>
#include <winuser.h>
#include <windows.h>
                                    
#include <string.h>
#include <string>     // sprintf, etc.
#include <tchar.h>     
#include <strsafe.h>  // <strsafe.h> must be included after <tchar.h>

#include "haCrypt.h"

// Global variables
// Variables (typedefs: see "Large Integer Functions.pdf")

// e.g. typedef wchar_t WCHAR;
//      typedef WCHAR   TCHAR;

// e.g. typedef wchar_t WCHAR;
//      typedef WCHAR*  LPWSTR;

// e.g. typedef char    CHAR;
//      typedef CHAR*   LPSTR;

// e.g. typedef unsigned long  ULONG;
//      typedef unsigned long  DWORD;

//      typedef int            BOOL;

//      typedef __nullterminated CONST CHAR *LPCSTR;

//      typedef CONST WCHAR *LPCWSTR;

// LPCTSTR
//#ifdef UNICODE
//typedef LPCWSTR LPCTSTR;
//else
//typedef LPCSTR LPCTSTR;
//#endif

HWND hKeyTextBox;
HWND hIvTextBox;
HWND hTool;
HWND hStatusbar;
HWND hEdit;
HWND hTooltip;
HWND hButtonIV;
HWND hButtonHex;
HWND hButtonKey;
HWND hButtonDelim;
HWND hwndTT;
HWND hDlgFileExist;

HFONT hFont;

// Extern variables
extern COLORREF ICON_BUTTON_BGND_LIGHT_BLUE; // (158, 217, 235) background when icon hovered
extern COLORREF BUTTON_BGND_LIGHT_GRAY;      // (235, 235, 235) background button released
extern COLORREF BUTTON_FGND_GRAY;            // (160, 160, 160) button text
extern COLORREF BORDER_WHITE;                // (255, 255, 255)  

extern HINSTANCE g_hInst;
extern HWND hMain;

extern ULONG FileProcessingMode;
extern int _valCK, _testContextFlag;
extern int fancyToolbar, keyDisplayMode, _escAbortNoQuery, _multiFileBrowserFlag; // Useful here

// Strings that appear in the application's title bar.
extern TCHAR szEdit[];
extern TCHAR szEditBoxFail[];
extern TCHAR szCreationToolFail[];
extern TCHAR szError[];                    

extern TCHAR _tTimeBuf[];      // File Time&Date
extern int _tTimebufSize;

// Console & Debug
extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

// Extern functions included in this code module:
extern BOOL GetBuildTime(TCHAR*, LPTSTR, DWORD);

// Forward declaration of functions included in this code module:
HFONT SetFont(LPCWSTR, int, int);


//ha//-FOR EDUCATIONAL PURPOSE ONLY--------------------------------------------
//
//                       CreateToolTipForRect
//
// Create a QuickInfo for a rectangular area (Discussion forum Microsoft)
//
// Example how to create a standard QuickInfo comtrol element
//  for the whole Client area of a window.
//
// "Cannot for the life of me get win32 tooltips working - C Board !   :-)
//  That function is directly from MSDN. I pass it my main hwnd after
//  I create the main window. Yet no tooltips ever appear.
//  I feel like there's some message I'm not handling/sending
//  but I haven't been able to figure out what."
//
// Q: What is the correct size of tooltip TOOLINFO?
// A: The correct size is -
//    44 bytes for Win 2000 and Win XP WITHOUT common controls 6.0, and 
//    48 bytes for XP with common controls 6.0.
//
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!! Using the wrong size, some of the tooltip messages don't work, !!!
// !!! while others do                                                !!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//
//  int SIZE_TOOLINFO;
//  ULONG COMCTL_VERSION=0;
//  HMODULE dll = GetModuleHandle(_T("comctl32.dll"));
//  if (dll)
//    {
//    DLLGETVERSIONPROC DllGetVersion = (DLLGETVERSIONPROC)GetProcAddress(dll,"DllGetVersion");
//    if (DllGetVersion)
//      {
//      DLLVERSIONINFO vinfo;
//      memset(&vinfo, 0, sizeof(vinfo));
//      vinfo.cbSize = sizeof(vinfo);
//      DllGetVersion(&vinfo);
//      COMCTL_VERSION = MAKEVERSION(vinfo.dwMajorVersion, vinfo.dwMinorVersion);
//      }
//    }
//  
//  if (COMCTL_VERSION >= MAKEVERSION(6,0))
//    {
//    // common controls version 6 (WinXP with visual styles)
//    SIZE_TOOLINFO=sizeof(TOOLINFO);          // =48 Bytes
//    }
//  else 
//    {
//    // Win2000 or XP without visual styles
//    #ifdef UNICODE
//    SIZE_TOOLINFO = TTTOOLINFOW_V2_SIZE;     // =44 Bytes
//    #else
//    SIZE_TOOLINFO = TTTOOLINFOA_V2_SIZE;     // =44 Bytes
//    #endif
//    }
//
// https://blog.fireheart.in/a?ID=00100-d41c1318-3a1d-4d32-ba3d-21e1f64b883f
//        Solution to the problem that the version of the tooltip
//                 created by win32 API does not match
//
// Fix / Workaround - Tooltip / Quickinfo:
// Using WIN32API to create a tootip in visual studio 2005 and above... 
// After creation, sending messages such as TTM_ADDTOOL will fail. 
// The reason is that the loaded 'commctrl dll 6.0' version does not match. 
//
// The solution is as follows:
// The reason is that when _WIN32_WINNT is greater than 0x0500,
//  the TOOLINFO structure has an additional definition of LPARAM lParam,
//  which causes sizeof(TOOLINFO) to not match the old version.
//
// The following method is recommended, because it does not modify the
//  version number of the entire 'commctrl dll'. A change in the 'manifest' file
//  would causes the entire system to use a lower version of the commctrl dll.
//
// The sample code is as follows:
// 
// HWND hWindow = ::CreateWindowEx(
//         NULL, 
//         TOOLTIPS_CLASS, 
//         NULL,   
//         WS_POPUP|TTS_NOPREFIX|TTS_ALWAYSTIP, 
//         CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
//         NULL, 
//         (HMENU)0, 
//         NULL, 
//         NULL);
// 
// TOOLINFO ti;
// memset(&ti, 0, sizeof(TOOLINFO));
// 
// #if _WIN32_WINNT > 0x0500                       // Windows 10 = 1537
//   ti.cbSize = sizeof(TOOLINFO) - sizeof(void*); // 44 bytes
// #else
//   ti.cbSize = sizeof(TOOLINFO);                 // 48 bytes
// #endif
//
// . . . //Other data filling
//
//::SendMessage(hWindow, TTM_ADDTOOL, 0, &ti);
//
//ha//void CreateToolTipForRect(HWND _hwnd)
//ha//  {
//ha//  // Create a tooltip.
//ha//  hwndTT = CreateWindowEx(
//ha//    WS_EX_TOPMOST, 
//ha//    TOOLTIPS_CLASS, 
//ha//    NULL,
//ha//    WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,    
//ha//    CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 
//ha//    _hwnd, 
//ha//    NULL, 
//ha//    g_hInst, 
//ha//    NULL);
//ha//
//ha//  if (!hwndTT) MessageBox(NULL, TEXT("Failed: HWND hwndTT"), 0, 0);
//ha//
//ha//  SetWindowPos(hwndTT, HWND_TOPMOST, 0, 0, 0, 0,
//ha//               SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
//ha// 
//ha//  // Set up "tool" quick information. 
//ha//  // In this case, the "tool" is the entire parent window.
//ha//  RECT rect;
//ha//                   
//ha//  TOOLINFO ti = {0};
//ha//  ZeroMemory(&ti, sizeof(TOOLINFO));
//ha//
//ha//  // Workaround to prevent fail of 'SendMessage TTM_ADDTOOL'.
//ha//  #if _WIN32_WINNT > 0x0500                                // Windows 10 = 1537
//ha//    #define SIZE_TOOLINFO sizeof(TOOLINFO) - sizeof(void*) // 44 bytes (TTTOOLINFOW_V2_SIZE)  
//ha//  #else                                               
//ha//    #define SIZE_TOOLINFO sizeof(TOOLINFO)                 // 48 bytes (sizeof(TOOLINFO))
//ha//  #endif                                                
//ha//
//ha//  ti.cbSize   = SIZE_TOOLINFO;     // TTTOOLINFOW_V2_SIZE or sizeof(TOOLINFO);
//ha//  ti.uFlags   = TTF_SUBCLASS;
//ha//  ti.hwnd     = _hwnd;
//ha//  ti.hinst    = g_hInst;
//ha//  ti.uId = 0;
//ha//  ti.lpszText = TEXT("A main window");
//ha//  ti.rect.left   =  rect.left;     //100;rect.left;    
//ha//  ti.rect.top    =  rect.top;      //100;rect.top;
//ha//  ti.rect.right  =  rect.right;    //400;rect.right;
//ha//  ti.rect.bottom =  rect.bottom;   //250;rect.bottom;
//ha//
//ha//  GetClientRect(_hwnd, &ti.rect);
//ha//
//ha//  // Associate the tooltip with the "tool" window.
//ha//  if (!SendMessage(hwndTT, TTM_ADDTOOL, 0, (LPARAM)&ti))
//ha//    MessageBox(NULL, TEXT("Failed: TTM_ADDTOOL"), 0, 0);
//ha//  }  // CreateToolTipForRect

//-----------------------------------------------------------------------------
//
//                       CreateToolTip
//
// Create a QuickInfo for any desired window
//
void CreateToolTip(HWND _hDesired, LPWSTR _szTooltipTexthDesired, const int _STYLE)
  {
  // Create "tooltip" quick information for Key Button. 
  hwndTT = CreateWindowEx(
    WS_EX_TOPMOST, 
    TOOLTIPS_CLASS, 
    NULL,
    WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP | _STYLE,   
    CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 
    _hDesired, 
    NULL, 
    g_hInst, 
    NULL);

  if (!hwndTT) MessageBox(NULL, TEXT("Failed: HWND hwndTT"), szError, MB_ICONERROR);

  SetWindowPos(hwndTT, HWND_TOPMOST, 0, 0, 0, 0,
               SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
 
  TOOLINFO ti = {0};
  ZeroMemory(&ti, sizeof(TOOLINFO));

  ti.cbSize   = SIZE_TOOLINFO;     // TTTOOLINFOW_V2_SIZE or sizeof(TOOLINFO);
  ti.uFlags   = TTF_IDISHWND | TTF_SUBCLASS;
  ti.hwnd     = _hDesired;
  ti.hinst    = g_hInst;
  ti.uId      = (UINT_PTR)_hDesired;
  ti.lpszText = _szTooltipTexthDesired;

  // Associate the tooltip with the "tool" window.
  if (!SendMessage(hwndTT, TTM_ADDTOOL, 0, (LPARAM)(LPTOOLINFO)&ti))
    MessageBox(NULL, TEXT("Failed: TTM_ADDTOOL"), szError, MB_ICONERROR);
  
  // Allow long text strings: set display rectangle to 210 pixels. 
  SendMessage(hwndTT, TTM_SETMAXTIPWIDTH, 0, 210);
  }  // CreateToolTip


//-----------------------------------------------------------------------------
//
//                               SetFont
// cHght, cWdth
//  16,     6   for _T("DEFAULT_GUI_FONT")
//  16,     6   for _T("Arial")
//  16,     8   for _T("Courier New")
//  16,     8   for _T("Consolas")
//
HFONT SetFont(LPCWSTR pszFaceName, int cHght, int cWdth)
  {
  // HFONT hFont = CreateFontA(
  //  int     cHeight,  int cWidth,
  //  int     cEscapement,
  //  int     cOrientation,
  //  int     cWeight,
  //  DWORD   bItalic,
  //  DWORD   bUnderline,
  //  DWORD   bStrikeOut,
  //  DWORD   iCharSet,
  //  DWORD   iOutPrecision,
  //  DWORD   iClipPrecision,
  //  DWORD   iQuality,
  //  DWORD   iPitchAndFamily,
  //  LPCWSTR pszFaceName = _T("Courier New");
  //
  HFONT hFont = CreateFont(
    cHght, cWdth,
    0,
    0,
    500,
    FALSE,
    FALSE,
    FALSE,
    DEFAULT_CHARSET,
    OUT_DEFAULT_PRECIS,
    CLIP_DEFAULT_PRECIS,
    DEFAULT_QUALITY,
    DEFAULT_PITCH | FF_DONTCARE,
    pszFaceName);

  return(hFont);
  } // SetFont


//-----------------------------------------------------------------------------
//
//                       CreateCustomToolBar
//
// https://cpp.hotexamples.com/de/examples/-/-/ImageList_AddIcon/cpp-imagelist_addicon-function-examples.html
//
HWND CreateCustomToolbar(HWND _hwnd)
  {
  HIMAGELIST g_hImageList = NULL;

  const int bitmapSize = 16;   // big: ..= 32, small ..= 16;
  const int ImageListID = 0;

  hTool = CreateWindowEx(
    0,                         //or = TBSTYLE_EX_MIXEDBUTTONS,
    TOOLBARCLASSNAME,
    NULL,
    WS_CHILD | WS_VISIBLE | TBSTYLE_TOOLTIPS | CCS_NODIVIDER | TBSTYLE_FLAT,  // 'CreateTooltip' is not required
    0, 0, 0, 0,
    _hwnd,
    (HMENU)IDC_MAIN_TOOL,      // or = NULL, or HINST_COMMCTRL  
    GetModuleHandle(NULL),     // or = g_hinst
    NULL);
  
  TBBUTTON tbb[18];
  TBADDBITMAP tbab;

  // Send the TB_BUTTONSTRUCTSIZE message, 
  //  which is required for backward compatibility.
  SendMessage(hTool, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);

  // Define the Toolbar button images
  tbab.hInst = 0;              // 0 = Custom image list 
  tbab.nID = ImageListID;

  // (WPARM) = Anzahl der Schaltflächenbilder in der Bitmap.
  //  Wenn (LPARM) eine systemdefinierte Bitmap angibt, wird (WPARM) Parameter ignoriert.
  SendMessage(hTool, TB_ADDBITMAP, (WPARAM)10, (LPARAM)&tbab);

  ZeroMemory(&tbb, sizeof(tbb));
  tbb[0].iBitmap   = 6;                 // The width of the separator, in pixels=6
  tbb[0].fsStyle   = BTNS_SEP;          // = TBSTYLE_SEP Separator

  tbb[1].iBitmap   = 0;                 // IDI_TXTNEW
  tbb[1].fsState   = TBSTATE_ENABLED;
  tbb[1].fsStyle   = TBSTYLE_BUTTON;
  tbb[1].idCommand = ID_FILE_TEXT_NEW;

  tbb[2].iBitmap   = 1;                 // IDI_TXTOPN
  tbb[2].fsState   = TBSTATE_ENABLED;
  tbb[2].fsStyle   = TBSTYLE_BUTTON;
  tbb[2].idCommand = ID_FILE_TEXT_OPEN;

  tbb[3].iBitmap   = 2;                 // IDI_TXTSAV
  tbb[3].fsState   = TBSTATE_ENABLED;
  tbb[3].fsStyle   = TBSTYLE_BUTTON;
  tbb[3].idCommand = ID_FILE_TEXT_SAVEAS;

  tbb[4].iBitmap   = 8;                 // The width of the separator, in pixels=8
  tbb[4].fsStyle   = BTNS_SEP;          // = TBSTYLE_SEP Separator

  tbb[5].iBitmap   = 3;                 // IDI_DESE
  tbb[5].fsState   = TBSTATE_ENABLED;
  tbb[5].fsStyle   = TBSTYLE_BUTTON | BTNS_CHECKGROUP;
  tbb[5].idCommand = ID_TOOLBAR_DES;

  tbb[6].iBitmap   = 4;                 // IDI_AESE
  tbb[6].fsState   = TBSTATE_ENABLED;
  tbb[6].fsStyle   = TBSTYLE_BUTTON | BTNS_CHECKGROUP;
  tbb[6].idCommand = ID_TOOLBAR_AES;

  tbb[7].iBitmap   = 7;                 // IDI_3DESE
  tbb[7].fsState   = TBSTATE_ENABLED;
  tbb[7].fsStyle   = TBSTYLE_BUTTON | BTNS_CHECKGROUP;
  tbb[7].idCommand = ID_TOOLBAR_TDES;

  tbb[8].iBitmap   = 8;                 // The width of the separator, in pixels=8
  tbb[8].fsStyle   = BTNS_SEP;          // = TBSTYLE_SEP Separator

  tbb[9].iBitmap   = 10;                // IDI_CRYENC  
  tbb[9].fsState   = TBSTATE_ENABLED;
  tbb[9].fsStyle   = TBSTYLE_BUTTON;
  tbb[9].idCommand = ID_TOOLBAR_ENCRYPT;

  tbb[10].iBitmap   = 5;                //  IDI_CRYDEC
  tbb[10].fsState   = TBSTATE_ENABLED;
  tbb[10].fsStyle   = TBSTYLE_BUTTON;
  tbb[10].idCommand = ID_TOOLBAR_DECIPHER;

  tbb[11].iBitmap   = 11;               // IDI_CRYMAC
  tbb[11].fsState   = TBSTATE_ENABLED;
  tbb[11].fsStyle   = TBSTYLE_BUTTON;
  tbb[11].idCommand = ID_TOOLBAR_MAC;

  tbb[12].iBitmap   = 6;                // The width of the separator, in pixels=6
  tbb[12].fsStyle   = BTNS_SEP;         // = TBSTYLE_SEP Separator

  tbb[13].iBitmap   = 9;                // IDI_CRYREDO
  tbb[13].fsState   = TBSTATE_ENABLED;
  tbb[13].fsStyle   = TBSTYLE_BUTTON;
  tbb[13].idCommand = ID_TOOLBAR_CRYPT_CONTINUE;

  tbb[14].iBitmap   = 8;                // The width of the separator, in pixels=8
  tbb[14].fsStyle   = BTNS_SEP;         // = TBSTYLE_SEP Separator

  tbb[15].iBitmap   = 6;                // IDI_CRYSAV
  tbb[15].fsState   = TBSTATE_ENABLED;
  tbb[15].fsStyle   = TBSTYLE_BUTTON;
  tbb[15].idCommand = ID_FILE_CRYPT_SAVEAS;

  tbb[16].iBitmap   = 6;                // The width of the separator, in pixels=6
  tbb[16].fsStyle   = BTNS_SEP;         // = TBSTYLE_SEP Separator

  tbb[17].iBitmap   = 12;               // IDI_HACRYPT_ICON
  tbb[17].fsState   = TBSTATE_ENABLED;
  tbb[17].fsStyle   = TBSTYLE_BUTTON;
  tbb[17].idCommand = ID_HELP_ABOUT;

  // Create the Custom ImageList (order corresponds to LISTVIEW_IMG_* enumeration)
  g_hImageList = ImageList_Create(bitmapSize, bitmapSize, // Dimensions of individual bitmaps.
                                  ILC_COLOR24 | ILC_MASK, // Ensures transparent background.
                                  1, sizeof tbb);

  // Load and add "tbb[].iBitmap = 0" to Custom ImageList
  HICON _icon;  // The icon to be added to ImageList below

  // Example:
  //hTXTNEW = LoadIcon(NULL, IDI_QUESTION);               // Create a MS standard 'question' icon,
  //hTXTOPN = LoadIcon(hinst, MAKEINTRESOURCE(460));      //  or a custom icon based on a resource.

  //_icon = (HICON)LoadImage((HINSTANCE)GetWindowLong(_hwnd, GWL_HINSTANCE), 
  //                         MAKEINTRESOURCE(IDI_TXTNEW), IMAGE_ICON, 
  //                         bitmapSize, bitmapSize, NULL);

  // Load and add "tbb[].iBitmap = 0" to Custom ImageList
  _icon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_TXTNEW)); // Alternative to "LoadImage(..)" 
  ImageList_AddIcon(g_hImageList, _icon);
  
  // Load and add "tbb[].iBitmap = 1" to Custom ImageList
  _icon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_TXTOPN));
  ImageList_AddIcon(g_hImageList, _icon);
  
  // Load and add "tbb[].iBitmap = 2" to Custom ImageList
  _icon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_TXTSAV));
  ImageList_AddIcon(g_hImageList, _icon);
  
  // Load and add "tbb[].iBitmap = 3" to Custom ImageList
  _icon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_DESE));
  ImageList_AddIcon(g_hImageList, _icon);

  // Load and add "tbb[].iBitmap = 4" to Custom ImageList
  _icon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_AESE));
  ImageList_AddIcon(g_hImageList, _icon);

  // Load and add "tbb[].iBitmap = 5" to Custom ImageList
  _icon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_CRYDEC));
  ImageList_AddIcon(g_hImageList, _icon);

  // Load and add "tbb[].iBitmap = 6" to Custom ImageList
  _icon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_CRYSAV));
  ImageList_AddIcon(g_hImageList, _icon);

  // Load and add "tbb[].iBitmap = 7" to Custom ImageList
  _icon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_3DESE));
  ImageList_AddIcon(g_hImageList, _icon);

  // Load and add "tbb[].iBitmap = 8" to Custom ImageList
  _icon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_AESMAC));
  ImageList_AddIcon(g_hImageList, _icon);
  
  // Load and add "tbb[].iBitmap = 9" to Custom ImageList
  _icon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_CRYREDO));
  ImageList_AddIcon(g_hImageList, _icon);

  // Load and add "tbb[].iBitmap = 10" to Custom ImageList
  _icon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_CRYENC));
  ImageList_AddIcon(g_hImageList, _icon);

  // Load and add "tbb[].iBitmap = 11" to Custom ImageList
  _icon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_CRYMAC));
  ImageList_AddIcon(g_hImageList, _icon);

  // Load and add "tbb[].iBitmap = 12" to Custom ImageList
  _icon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_HAABOUT));
  ImageList_AddIcon(g_hImageList, _icon);
  
  // Finally set imagelist and add the buttons
  SendMessage(hTool, TB_SETIMAGELIST, (WPARAM)ImageListID, (LPARAM)g_hImageList);
  SendMessage(hTool, TB_ADDBUTTONS, sizeof(tbb)/sizeof(TBBUTTON), (LPARAM)&tbb);
  SendMessage(hTool, TB_AUTOSIZE, 0, 0);
  
  // Initially disabled (GRAYED) buttons
  SendMessage(hTool, TB_ENABLEBUTTON, ID_FILE_TEXT_SAVEAS, FALSE); 
  SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_CRYPT_CONTINUE, FALSE); 

  return hTool;
  } // CreateCustomToolbar


//ha////--DEPRECATED------------------------------------------------------------
//ha////
//ha////        HideToolbarButton
//ha////
//ha//// Usage:  HideToolbarButton(hTool, ID_FILE_DES_ECBENCRYPT, TBSTATE_HIDDEN);
//ha////         HideToolbarButton(hTool, ID_FILE_DES_ECBENCRYPT, TBSTATE_ENABLED);
//ha////
//ha//void HideToolbarButton(HWND toolbar, UINT id_command, BYTE tb_state)
//ha//  {
//ha//  TBBUTTONINFOA tbinfo;
//ha//  tbinfo.cbSize = sizeof(tbinfo);
//ha//  tbinfo.dwMask = TBIF_STATE;
//ha//  tbinfo.idCommand = id_command;        // The specific button icon
//ha//  tbinfo.fsState  = tb_state;           // TBSTATE_HIDDEN or TBSTATE_ENABLED
//ha//  SendMessage(toolbar, TB_SETBUTTONINFO, id_command, (LPARAM)&tbinfo);
//ha//  }


//ha////--DEPRECATED------------------------------------------------------------
//ha////
//ha////                       CreateStdToolBar (using MS icons)
//ha////
//ha//HWND CreateStdToolBar(HWND _hwnd)
//ha//  {
//ha//  // Create Toolbar using MS predefined Icons
//ha//  // The parameters to CreateWindow explained:
//ha//  // TOOLBARCLASSNAME: the name of the application
//ha//  // NULL: the text that appears within the edit field window
//ha//  // WS_CHILD | WS_VISIBLE | .. : the type of window to create
//ha//  // 0, 0: initial position (x, y)
//ha//  // 100, 100: initial size (width, length)
//ha//  // NULL: the parent of this window
//ha//  // NULL: this application does not have a menu bar
//ha//  // _hwnd: the handle from the calling window
//ha//  // (HMENU)IDC_MAIN_EDIT: the number of this window
//ha//  // GetModuleHandle(NULL), NULL); not used in this application
//ha//  //
//ha//  hTool = CreateWindowEx(
//ha//    0,
//ha//    TOOLBARCLASSNAME,
//ha//    NULL,
//ha//    WS_CHILD | WS_VISIBLE | TBSTYLE_TOOLTIPS, // 'CreateTooltip' is not required
//ha//    0, 0, 0, 0,
//ha//    _hwnd,
//ha//    (HMENU)IDC_MAIN_TOOL,
//ha//    GetModuleHandle(NULL),
//ha//    NULL);
//ha//
//ha//  if (hTool == NULL)
//ha//    MessageBox(_hwnd, szCreationToolFail, szError, MB_OK | MB_ICONERROR);
//ha//
//ha//  TBBUTTON tbb[10];                          // 10 Button images on toolbar
//ha//  TBADDBITMAP tbab;
//ha//
//ha//  // Send the TB_BUTTONSTRUCTSIZE message, 
//ha//  //  which is required for backward compatibility.
//ha//  SendMessage(hTool, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);
//ha//    
//ha//  tbab.hInst = HINST_COMMCTRL;
//ha//  tbab.nID = IDB_STD_SMALL_COLOR;
//ha//  SendMessage(hTool, TB_ADDBITMAP, 0, (LPARAM)&tbab);       
//ha// 
//ha//  ZeroMemory(tbb, sizeof(tbb));
//ha//  tbb[0].iBitmap = STD_FILENEW;
//ha//  tbb[0].fsState = TBSTATE_ENABLED;
//ha//  tbb[0].fsStyle = TBSTYLE_BUTTON;
//ha//  tbb[0].idCommand = ID_FILE_TEXT_NEW;
//ha//
//ha//  tbb[1].iBitmap = STD_FILEOPEN;
//ha//  tbb[1].fsState = TBSTATE_ENABLED;
//ha//  tbb[1].fsStyle = TBSTYLE_BUTTON;
//ha//  tbb[1].idCommand = ID_FILE_TEXT_OPEN;
//ha//                                                                                                               
//ha//  tbb[2].iBitmap = STD_FILESAVE;
//ha//  tbb[2].fsState = TBSTATE_ENABLED;
//ha//  tbb[2].fsStyle = TBSTYLE_BUTTON;
//ha//  tbb[2].idCommand = ID_FILE_TEXT_SAVEAS;
//ha//
//ha//  tbb[3].iBitmap = 6;                 // The width of the separator, in pixels=6
//ha//  tbb[3].fsStyle = BTNS_SEP;          // = TBSTYLE_SEP Separator
//ha//
//ha//  tbb[4].iBitmap = STD_REPLACE;               
//ha//  tbb[4].fsState = TBSTATE_ENABLED;           
//ha//  tbb[4].fsStyle = TBSTYLE_BUTTON;            
//ha//  tbb[4].idCommand = ID_FILE_DES_ECBENCRYPT;  
//ha//  //tbb[4].iString = SendMessage(hTool, TB_ADDSTRING, 0, (LPARAM)TEXT("/ECBENCRYPT"));
//ha//
//ha//  tbb[5].iBitmap = STD_REDOW;                 
//ha//  tbb[5].fsState = TBSTATE_ENABLED;           
//ha//  tbb[5].fsStyle = TBSTYLE_BUTTON;            
//ha//  tbb[5].idCommand = ID_FILE_DES_ECBDECIPHER; 
//ha//
//ha//  tbb[6].iBitmap = 6;                 // The width of the separator, in pixels=6
//ha//  tbb[6].fsStyle = BTNS_SEP;          // = TBSTYLE_SEP Separator
//ha//
//ha//  tbb[7].iBitmap = STD_REPLACE;               
//ha//  tbb[7].fsState = TBSTATE_ENABLED;           
//ha//  tbb[7].fsStyle = TBSTYLE_BUTTON;            
//ha//  tbb[7].idCommand = ID_FILE_AES_ENCRYPT;     
//ha//
//ha//  tbb[8].iBitmap = STD_REDOW;                 
//ha//  tbb[8].fsState = TBSTATE_ENABLED;           
//ha//  tbb[8].fsStyle = TBSTYLE_BUTTON;            
//ha//  tbb[8].idCommand = ID_FILE_AES_DECIPHER;    
//ha//
//ha//  tbb[9].iBitmap = STD_PASTE;                 
//ha//  tbb[9].fsState = TBSTATE_ENABLED;           
//ha//  tbb[9].fsStyle = TBSTYLE_BUTTON;            
//ha//  tbb[9].idCommand = ID_FILE_CRYPT_SAVEAS;      
//ha//
//ha//  // Show the button images
//ha//  SendMessage(hTool, TB_ADDBUTTONS, sizeof(tbb)/sizeof(TBBUTTON), (LPARAM)&tbb);
//ha//
//ha//  return(hTool);
//ha//  } // CreateStdToolBar

//-----------------------------------------------------------------------------
//
//                       CreateStatusBar
//
HWND CreateStatusBar(HWND _hwnd)
  {
  // 2-Fields statusbar width: left=200, right=remaining rest
  int statwidths[] = {STATUSBAR_P0_WIDTH, STATUSBAR_P1_WIDTH};   

  // Create Status Bar
  // The parameters to CreateWindow explained:
  // STATUSCLASSNAME: the name of the application
  // NULL: the text that appears within the edit field window
  // WS_CHILD | WS_VISIBLE | .. : the type of window to create
  // 0, 0: initial position (x, y)
  // 100, 100: initial size (width, length)
  // _hwnd: the handle from the calling window
  // (HMENU)IDC_MAIN_EDIT: the number of this window
  // GetModuleHandle(NULL), NULL); not used in this application
  //
  hStatusbar = CreateWindowEx(
    0,
    STATUSCLASSNAME,
    NULL,
    WS_CHILD | WS_VISIBLE | CCS_NODIVIDER,// | SBARS_SIZEGRIP,
    0, 0, 0, 0,
    _hwnd,
    (HMENU)IDC_MAIN_STATUS,    // "IDC_MAIN_STATUS"
    GetModuleHandle(NULL), 
    NULL);

  SendMessage(hStatusbar, SB_SETPARTS, sizeof(statwidths)/sizeof(int), (LPARAM)statwidths);

  GetBuildTime(_T("haCrypt.exe"), _tTimeBuf, MAX_PATH);
  SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_tTimeBuf);
  return(hStatusbar);
  } // CreateStatusBar

//-----------------------------------------------------------------------------
//
//                       CreateButtonDelim
//
//    Dummy Button: "Delimiter" for mouse click simulation only
// 
void CreateButtonDelim(HWND _hwnd)
  { 
  hButtonDelim = CreateWindowW(
    _T("BUTTON"),                                     
    _T(""),                                           
    WS_CHILD | BS_PUSHBUTTON,             
    813, 5-2, 1, BUTTON_HEIGHT-1, // x, y, width (=just a vertival line), height
    _hwnd, 
    (HMENU)ID_BUTTON_DELIM, 
    GetModuleHandle(NULL),
    NULL);

  // Remove dotted line on button  
  SendMessage(hButtonDelim, WM_CHANGEUISTATE, (WPARAM)(0x10001),(LPARAM)(0));
  } // CreateButtonDelim


//-----------------------------------------------------------------------------
//
//                       CreateButtonHexText
//
//    Button: "Toggle Hex-Text display"
// 
// w/  BS_NOTIFY works on LBUTTONDOWN
// w/o BS_NOTIFY works on LBUTTONUP
//
void CreateButtonHexText(HWND _hwnd)
  { 
  hButtonHex = CreateWindowW(
    _T("BUTTON"),                                     
    _T("Hex/Text"),
    WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_OWNERDRAW,  // | BS_NOTIFY, // Button style
    820, 5-2, BUTTON_WIDTH, BUTTON_HEIGHT-1,
    _hwnd, 
    (HMENU)ID_HEX_DISPLAY, 
    NULL, 
    NULL);

  // Choose an appropriate font for the "Hex/Text" Button
  hFont = SetFont(_T("DEFAULT_GUI_FONT"), 16, 6);
  SendMessage(hButtonHex, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(FALSE, 0));
  // Remove dotted line on button  
  SendMessage(hButtonHex, WM_CHANGEUISTATE, (WPARAM)(0x10001),(LPARAM)(0));
  } // CreateButtonHexText


//-----------------------------------------------------------------------------
//
//                       CreateInputDialogKey
//
// Horizontal, Vertical, Width, Height
//  for 24 chars max
//
void CreateInputDialogKey(HWND _hwnd)
  {
  hKeyTextBox = CreateWindowEx(
    0L,
    _T("EDIT"),                           
    _T(""),
    WS_CHILD | WS_VISIBLE | ES_LEFT,// | WS_BORDER,// | ES_PASSWORD,  
    315+9, 3, 200-5, 20-1,
    _hwnd, 
    (HMENU)ID_TOOLBAR_KEYEDIT, 
    g_hInst, 
    NULL);
  
  // Choose an appropriate font for the "Set Key" Dialog
  // hFont = (HFONT)GetStockObject(ANSI_FIXED_FONT);
  hFont = SetFont(_T("Courier New"), 16, 8);
  SendMessage(hKeyTextBox, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(FALSE, 0));

  //SendMessage(hKeyTextBox, EM_SETPASSWORDCHAR, (WPARAM)_T('*'), 0);
  //SendMessage(hKeyTextBox, EM_SETPASSWORDCHAR, 0, 0);
  } // CreateInputDialogKey
   
//-----------------------------------------------------------------------------
//
//                       CreateButtonSetKey
//
// w/  BS_NOTIFY works on LBUTTONDOWN
// w/o BS_NOTIFY works on LBUTTONUP
//
void CreateButtonSetKey(HWND _hwnd)
  {
  hButtonKey = CreateWindowW(
    _T("BUTTON"),                                     
    _T("Set Key"),                                            
    WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_OWNERDRAW,  // | BS_NOTIFY, // Button style
    520+3, 5-2, BUTTON_WIDTH, BUTTON_HEIGHT-1,                                
    _hwnd, 
    (HMENU)ID_DIALOG_KEY, 
    NULL, 
    NULL);                    

  // Choose an appropriate font for the "Set Key" Button
  //hFont = SetFont(_T("MS Sans Serif"));
  //hFont = SetFont(_T("Tahoma"));
  hFont = SetFont(_T("DEFAULT_GUI_FONT"), 16, 6);
  SendMessage(hButtonKey, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(FALSE, 0));
  // Remove dotted line on pressed button 
  SendMessage(hButtonKey, WM_CHANGEUISTATE, (WPARAM)(0x10001), (LPARAM)(0));
  } // CreateButtonSetKey 

//-----------------------------------------------------------------------------
//
//                       CreateInputDialogIV
//
// Horizontal, Vertical, Width, Height
//  for 16 chars max
//
void CreateInputDialogIV(HWND _hwnd)
  {
  hIvTextBox = CreateWindowW(
    _T("EDIT"),                           
    _T(""),                                 
    WS_CHILD | WS_VISIBLE | ES_LEFT,// | WS_BORDER,
    595+8, 3, 135-4, 20-1,                   
    _hwnd, 
    (HMENU)ID_TOOLBAR_IVEDIT, 
    NULL, 
    NULL);

  // Choose an appropriate font for the "Set IV" box
  // hFont = (HFONT)GetStockObject(ANSI_FIXED_FONT);
  hFont = SetFont(_T("Courier New"), 16, 8);
  SendMessage(hIvTextBox, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(FALSE, 0));
  } // CreateInputDialogIV 

//-----------------------------------------------------------------------------
//
//                       CreateButtonSetIV
//
// w/  BS_NOTIFY works on LBUTTONDOWN
// w/o BS_NOTIFY works on LBUTTONUP
//
void CreateButtonSetIV(HWND _hwnd)
  {
  hButtonIV = CreateWindowW(
    _T("BUTTON"),                                     
    _T("Set IV"),                                           
    WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_OWNERDRAW,  // | BS_NOTIFY, // Button style
    735+3, 5-2, BUTTON_WIDTH, BUTTON_HEIGHT-1,
    _hwnd, 
    (HMENU)ID_DIALOG_IV, 
    NULL, 
    NULL);

  // Choose an appropriate font for the "Set Key" Button
  hFont = SetFont(_T("DEFAULT_GUI_FONT"), 16, 6);
  SendMessage(hButtonIV, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(FALSE, 0));
  // Remove dotted line on button  
  SendMessage(hButtonIV, WM_CHANGEUISTATE, (WPARAM)(0x10001),(LPARAM)(0));
  } // CreateButtonSetIV 

//-----------------------------------------------------------------------------
//
//                       CreateEditControl
//
HWND CreateEditControl(HWND _hwnd)
  {
  // Create Edit Control
  // The parameters to CreateWindow explained:
  // szEdit: the name of the application
  // NULL: the text that appears within the edit field window
  // WS_CHILD | WS_VISIBLE | .. : the type of window to create
  // 0, 0: initial position (x, y)
  // 100, 100: initial size (width, length)
  // NULL: the parent of this window
  // NULL: this application does not have a menu bar
  // _hwnd: the handle from the calling window
  // (HMENU)IDC_MAIN_EDIT: the number of this window
  // GetModuleHandle(NULL), NULL); not used in this application
  //
  hEdit = CreateWindowExW(
    0, //WS_EX_CLIENTEDGE,
    szEdit,
    NULL, 
    WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE, 
    0, 0, 400, 200,
    _hwnd,
    (HMENU)IDC_MAIN_EDIT,
    GetModuleHandle(NULL),
    NULL);

  if (hEdit == NULL)
    MessageBox(_hwnd, szEditBoxFail, szError, MB_OK | MB_ICONERROR);

  // Choose an appropriate font for the "Text Editor Field"
  // hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
  // hFont = (HFONT)GetStockObject(ANSI_FIXED_FONT);
  // hFont = (HFONT)GetStockObject(OEM_FIXED_FONT);
  // hFont = SetFont("Courier New");
  hFont = SetFont(_T("Consolas"), 16, 8);
  SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(FALSE, 0));
  return(hEdit);
  } // CreateEditControl

//------------------------------------------------------------------------------

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{                
//ha//sprintf(DebugBuf, "ln = %08X\nj = %i [j < %i]\nBytesRd = %llX [=%llu]", ln, j, dwFileSizeBlocks1G, lln, lln);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG STOP 3 haCryptFileT - DoTxtFileCopy", MB_OK);
//ha//}
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%s\ndwFileSize = %i\n_ln = %08X\n_Pcent = %d%%"),
//ha//                                               szCryptModeBuf, dwFileSize, _ln,  _Pcent);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG STOP 0"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

