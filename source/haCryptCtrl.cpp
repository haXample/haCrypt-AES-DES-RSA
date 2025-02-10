// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptCtrl.cpp - C++ Developer source file.
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
HMENU hFileMenu;
HMENU hCryptoMenu;
HMENU hCryptoMenuDES;
HMENU hCryptoMenu3DES;
HMENU hCryptoMenuAES;
HMENU hCryptoMenuRSA;

// Extern variables
extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern char szKeyFileIn[];

extern LPSTR szKeyDialogIn[];

extern int _valCK, multiFileFlag, _cryptMenuFlag, _testContextFlag;

extern DWORD dwKeyFileSize;

extern ULONG ToolProcessingMode, FileProcessingMode, SavedProcessingMode;
extern ULONG FileProcessingModeContinue, ActiveProcessingMode;

extern RECT rcToolbar;

extern TCHAR szCryptAlgo_CONTINUE[];
extern TCHAR szSignonTitle[];
extern TCHAR szStatusClear[];
extern TCHAR szStatusInfoCBC[];
extern TCHAR szStatusInfoECB[];

extern TCHAR* pszCurrentModeTooltip;
extern TCHAR* pszCryptA;            // Crypto algo text
extern TCHAR* pszCryptAM;           // Crypto algo Mode text
extern TCHAR* pszTextKeySaved;

extern HWND hMain;
extern HWND hEdit;
extern HWND hKeyTextBox;
extern HWND hIvTextBox;
extern HWND hButtonIV;
extern HWND hButtonHex;
extern HWND hButtonKey;
extern HWND hTool;
extern HWND hTool;
extern HWND hwndTT;
extern HWND hStatusbar;

extern HMENU hMenu;

extern void DispayKeyDialogHex(HWND, char [], int);
extern void DispayKeyFileHex(HWND, char[], int);
extern void GetCryptoModeText(int cryptMode);
extern void ControlFileMenu(int);
extern void ControlCryptoMenu(int);

extern void PaintColoredStatusMsg(TCHAR*);
extern void PaintColoredStatusInfoMsg(TCHAR*);

// Forward declaration of functions included in this code module:
void ShowWinMouseClick(HWND, int, int, int);
void CtrlHideShowWindow(HWND, int);

//-----------------------------------------------------------------------------
//
//                         UpdateButtons
//
// Example:  HideToolbarButton(hTool, ID_CRYPTO_DES_ECBENCRYPT, TBSTATE_HIDDEN);
//
int UpdateButtons()
  {
  int _bttn = TRUE;                             // Default: Open file enabled

  SendMessage(hEdit, EM_SETREADONLY, FALSE, 0); // Enable rd/wr in edit field 
  SetFocus(hEdit);                              // Set cursor into text field
  ShowWindow(hEdit, SW_SHOW);                   // Enable and show the (white) edit text field

  if (_testContextFlag == FALSE)                // Skip if in TEST-MODE (allows easy retry) 
    SetDlgItemText(hMain, IDC_MAIN_EDIT, NULL); // Clear text edit field

  if (FileProcessingMode & CRYPT_ALGO_MASK)     // Not text mode
    FileProcessingModeContinue = FileProcessingMode;

  // Get algo-text strings into 'pszCryptA' 'pszCryptAM' (mode=dummy)
  GetCryptoModeText(ENCRYPT);   

  if (ActiveProcessingMode & CRYPT_CBCECB_MASK)
    {
    PaintColoredStatusMsg(szStatusClear);          // Clean up statusbar from 'paint'
    SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT);  
    SendMessage(hwndTT, TTM_ACTIVATE, FALSE, 0);   // Disable last hwndTT (=hIvTextBox)  

    // Sucessfully crypto-loaded file
    ControlFileMenu(MF_ENABLED);                   // Allow saving dispayed text
    ControlCryptoMenu(MF_ENABLED);                 // Allow saving crypto data
    
    if (dwKeyFileSize == 0)                               // Key typed in Dialogbox
      DispayKeyDialogHex(hMain, (LPSTR)szKeyDialogIn, 0); // 0: Key-mode
    else                                                  // Key loaded from file
      DispayKeyFileHex(hMain, szKeyFileIn, 0);            // 0: Key-mode

    SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)pszTextKeySaved);
    PostMessage(hMain, WM_COMMAND, ID_DIALOG_KEY, 0);     // Perform 'key button pressed'
    }

  switch(FileProcessingMode & CRYPT_CBCECB_MASK)
    {
    case FILEMODE_TEXT:
    case FILEMODE_TEXTNEW:
      ControlCryptoMenu(MF_GRAYED);
      SetWindowTextA(hEdit, 0);              // Clear text field
      PaintColoredStatusMsg(szStatusClear);  // Clean up statusbar from 'paint'        
      SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT);  
      SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)_T("/TEXT")); // Show string
      SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)_T(""));      // Clear string
      if (ActiveProcessingMode == CRYPT_NONE) break; // No crypto-loaded file

      CtrlHideShowWindow(hButtonHex,  SW_HIDE);  // Hide/Disable Hex/Txt Button
      CtrlHideShowWindow(hButtonKey,  SW_HIDE);  // Hide/Disable key
      CtrlHideShowWindow(hKeyTextBox, SW_HIDE);  // Hide/Disable key
      CtrlHideShowWindow(hIvTextBox,  SW_HIDE);  // Hide/Disable IV
      CtrlHideShowWindow(hButtonIV,   SW_HIDE);  // Hide/Disable IV

      ControlFileMenu(MF_GRAYED);
      UpdateWindow(hMain);
      SendMessage(hwndTT, TTM_ACTIVATE, FALSE, 0);  // Disable last hwndTT (=hIvTextBox)   
      ActiveProcessingMode = CRYPT_NONE;
      break;

    case CRYPT_CBC:
      if (SavedProcessingMode != FileProcessingMode)
        {
        // _bttn = Open file according to _cryptMenuFlag:
        //   FALSE - PaintColoredStatusInfoMsg is displayed instead of file open
        //   <> FALSE = TRUE or ID_TOOLBAR_CRYPT_CONTINUE - File open enabled, no PaintColoredStatusInfoMsg displayed 
        _bttn = _cryptMenuFlag;
        if (_cryptMenuFlag == FALSE)                // Default = tool buttons
          {
          StringCbPrintf(_tDebugBuf, _tDebugbufSize, szStatusInfoCBC, pszCryptA, pszCryptAM);
          PaintColoredStatusInfoMsg(_tDebugBuf);    // Display status info - Crypt mode has changed
          }

        CtrlHideShowWindow(hKeyTextBox, SW_SHOW);   // Show/Enable key
        CtrlHideShowWindow(hButtonKey,  SW_SHOW);   // Show/Enable key                             
        CtrlHideShowWindow(hIvTextBox,  SW_SHOW);   // Show/Enable IV
        CtrlHideShowWindow(hButtonIV,   SW_SHOW);   // Show/Enable IV

        ShowWinMouseClick(hKeyTextBox, 1, 0, 0);    // Simulate Mouseclick to make button & dialog appear
        ShowWinMouseClick(hButtonKey,  1, 0, 0);    // Simulate Mouseclick to make button & dialog appear
        ShowWinMouseClick(hIvTextBox,  1, 0, 0);    // Simulate Mouseclick to make button & dialog appear
        ShowWinMouseClick(hButtonIV,   1, 0, 0);    // Simulate Mouseclick to make button & dialog appear

        UpdateWindow(hMain);
        SetWindowText(hMain, szSignonTitle);        // Display signon-text in mainwindow's title field
        ActiveProcessingMode = CRYPT_CBC;           // This enables "open file"
        break;
        }
      break;                  

    case CRYPT_ECB:
      if (SavedProcessingMode != FileProcessingMode)
        {
        // _bttn = Open file according to _cryptMenuFlag:
        //   FALSE - PaintColoredStatusInfoMsg is displayed instead of file open
        //   <> FALSE = TRUE or ID_TOOLBAR_CRYPT_CONTINUE - File open enabled, no PaintColoredStatusInfoMsg displayed 
        _bttn = _cryptMenuFlag;
        if (_cryptMenuFlag == FALSE)                // Default = tool buttons
          {
          StringCbPrintf(_tDebugBuf, _tDebugbufSize, szStatusInfoECB, pszCryptA,  pszCryptAM);
          PaintColoredStatusInfoMsg(_tDebugBuf);    // Display status info - Crypt mode has changed
          }

        CtrlHideShowWindow(hKeyTextBox, SW_SHOW);   // Show/Enable key
        CtrlHideShowWindow(hButtonKey,  SW_SHOW);   // Hide/Disable key
        CtrlHideShowWindow(hIvTextBox,  SW_HIDE);   // Hide/Disable IV
        CtrlHideShowWindow(hButtonIV,   SW_HIDE);   // Hide/Disable IV

        ShowWinMouseClick(hKeyTextBox, 1, 0, 0);    // Simulate Mouseclick to make button & dialog appear
        ShowWinMouseClick(hButtonKey,  1, 0, 0);    // Simulate Mouseclick to make button & dialog appear

        UpdateWindow(hMain);
        SetWindowText(hMain, szSignonTitle);        // Display signon-text in mainwindow's title field
        ActiveProcessingMode = CRYPT_ECB;           // This enables "open file"
        break;
        }
      break;                  

    default:
      _bttn = TRUE;                              // Default: Open file enabled
      break;
    } // end switch(FileProcessingMode)

  SavedProcessingMode = FileProcessingMode;      // Update SavedProcessingMode
  return(_bttn);                                 // =FALSE, TRUE or ID_TOOLBAR_CRYPT_CONTINUE
  } // UpdateButtons

//-----------------------------------------------------------------------------
//
//                       CtrlHideShowWindow
//
// A Bug in Windows 10 Theme Visual Style messes up hidden gradient rectangles.
// In this case re-drawing is required (Windows system won't do it correctly). 
//
void CtrlHideShowWindow(HWND _hwnd, int _hideshow)
  {
  ShowWindow(_hwnd, _hideshow); // SW_HIDE / SW_SHOW window as usual  

  if (_hideshow == SW_HIDE)     // Redraw is required (Windows Theme Style NOK)
    {
    // Redraw toolbar rectangle
    //rcToolbar.right  = 899; // 899   // Directly coded metrics (also OK)
    //rcToolbar.left   =   0; //   0   // Better use 'GetClientRect(hTool, ..)'
    //rcToolbar.top    =   0; //   0  
    //rcToolbar.bottom =  26; //  26

    GetClientRect(hTool, &rcToolbar);  // Get toolbar rectangle metrics
    RedrawWindow(hTool, &rcToolbar, 0, RDW_ERASE | RDW_INVALIDATE);
    }
  } // CtrlHideShowWindow

//-----------------------------------------------------------------------------
//
//                         ShowWinMouseClick
//
void ShowWinMouseClick(HWND _hwndBtn, int _mode, int x, int y)
  {
  POINT p, csav;

  GetCursorPos(&csav);

  CtrlHideShowWindow(_hwndBtn, SW_SHOW); // Show/Enable Button
  p.x = x; p.y = y;                      // Set mouse pointer (normal=x0,y0)
  ClientToScreen(_hwndBtn, &p);          // Get pointer to button rectangle

  SetCursorPos(p.x, p.y);                // Point to upper left edge of button rectangle
  PostMessage(_hwndBtn, WM_MOUSEMOVE, 0, MAKELPARAM(x, y));
  if (_mode == 1)
    {
    PostMessage(_hwndBtn, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(x, y));
    PostMessage(_hwndBtn, WM_LBUTTONUP, MK_LBUTTON, MAKELPARAM(x, y));
    }
  CtrlHideShowWindow(_hwndBtn, SW_SHOW); // Show/Enable Button
 
  SetCursorPos(csav.x, csav.y);
  } // ShowWinMouseClick

//-----------------------------------------------------------------------------
//
//                       ControlContextMenu
//
void ControlContextMenu(int _mfCtrl)
  {
  _valCK = _mfCtrl;         // Processed in 'HandleContextMenu()'
  } // ControlContextMenu

//-----------------------------------------------------------------------------
//
//                       ControlFileMenu
//
void ControlFileMenu(int _mfCtrl)
  {
  if (_mfCtrl == MF_ENABLED)
    SendMessage(hTool, TB_ENABLEBUTTON, ID_FILE_TEXT_SAVEAS, TRUE); 
  else if (_mfCtrl == MF_GRAYED)
    SendMessage(hTool, TB_ENABLEBUTTON, ID_FILE_TEXT_SAVEAS, FALSE); 

  hMenu = GetMenu(hMain);                          // Menu bar: 0='File', 1='Crypto', etc..
  hFileMenu = GetSubMenu(hMenu, 0);                // Submenu 'File' (=0)
  EnableMenuItem(hFileMenu, ID_FILE_TEXT_SAVEAS, MF_BYCOMMAND | _mfCtrl); // Item of 'File'
  } // ControlFileMenu

//ha////-----------------------------------------------------------------------------
//ha////
//ha////                       ControlTextToolItems
//ha////
//ha//// Enable / Disable (GRAYED) 'save as..' selections in main menu and toolbar
//ha//// 
//ha//void ControlTextToolItems(int _mfCtrl)
//ha//  {
//ha//  if (ToolProcessingMode & CRYPT_ALGO_MASK)
//ha//    {
//ha//    SendMessage(hTool, TB_ENABLEBUTTON, ID_FILE_TEXT_SAVEAS, _mfCtrl);
//ha//    SendMessage(hTool, TB_ENABLEBUTTON, ID_FILE_TEXT_OPEN,  _mfCtrl);
//ha//    SendMessage(hTool, TB_ENABLEBUTTON, ID_FILE_TEXT_NEW,   _mfCtrl); 
//ha//    SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_DECIPHER, _mfCtrl);
//ha//    SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_ENCRYPT, _mfCtrl);
//ha//    SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_MAC,     _mfCtrl); 
//ha//    SendMessage(hTool, TB_ENABLEBUTTON, ID_FILE_CRYPT_SAVEAS,     _mfCtrl);
//ha//      
//ha//    if (pszCurrentModeTooltip == szCryptAlgo_CONTINUE && _mfCtrl == TRUE)   
//ha//      SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_CRYPT_CONTINUE, FALSE); // Keep button disabled   
//ha//    else SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_CRYPT_CONTINUE, _mfCtrl);
//ha//    }
//ha//  DrawMenuBar(hMain);
//ha//  } // ControlTextToolItems

//-----------------------------------------------------------------------------
//
//                       ControlToolWindow
//
// Enable / Disable (GRAYED) all selections in toolbar
// Note: Using 'EnableWindow(hTool, TRUE/FALSE)' looks ugly in fancy (STD THEME)
// 
void ControlToolWindow(int _mfTool)
  {
  SendMessage(hTool, TB_ENABLEBUTTON, ID_FILE_TEXT_NEW,   _mfTool); 
  SendMessage(hTool, TB_ENABLEBUTTON, ID_FILE_TEXT_OPEN,  _mfTool);
  SendMessage(hTool, TB_ENABLEBUTTON, ID_FILE_TEXT_SAVEAS, _mfTool);

  SendMessage(hTool, TB_CHECKBUTTON, ID_TOOLBAR_DES,  _mfTool); 
  SendMessage(hTool, TB_CHECKBUTTON, ID_TOOLBAR_AES,  _mfTool);
  SendMessage(hTool, TB_CHECKBUTTON, ID_TOOLBAR_TDES, _mfTool);

  SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_ENCRYPT,  _mfTool);
  SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_DECIPHER, _mfTool);
  SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_MAC,      _mfTool);
  
  SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_CRYPT_CONTINUE, _mfTool);
  SendMessage(hTool, TB_ENABLEBUTTON, ID_FILE_CRYPT_SAVEAS,      _mfTool);

  EnableWindow(hKeyTextBox, _mfTool);           
  EnableWindow(hButtonKey,  _mfTool);

  EnableWindow(hIvTextBox,  _mfTool);           
  EnableWindow(hButtonIV ,  _mfTool);

  EnableWindow(hButtonHex,  _mfTool);
  } // ControlToolWindow

//-----------------------------------------------------------------------------
//
//                       ControlCryptoToolItems
//
// Enable / Disable (GRAYED) buttons in toolbar
// 
void ControlCryptoToolItems(int _mfCtrl, int _mCrypt)
  {
  // Set start up default condition: DES button pressed down
  if (_mfCtrl == MF_GRAYED && _mCrypt == -1)
    {
    SendMessage(hTool, TB_CHECKBUTTON, ID_TOOLBAR_DES, TRUE);
    return;                                                      
    }

  // Normal run-time controlling
  switch(ToolProcessingMode & CRYPT_ALGO_MASK)
    {
    case FILEMODE_TEXT:  // _mCrypt=FALSE - Uncheck all crypto item buttons
      SendMessage(hTool, TB_CHECKBUTTON, ID_TOOLBAR_TDES, _mCrypt);
      SendMessage(hTool, TB_CHECKBUTTON, ID_TOOLBAR_AES,  _mCrypt);
      SendMessage(hTool, TB_CHECKBUTTON, ID_TOOLBAR_DES,  _mCrypt); 
      break;
    case CRYPT_DES:      // Checking DES automatically unchecks TDES, AES               
      SendMessage(hTool, TB_CHECKBUTTON, ID_TOOLBAR_DES,  _mCrypt); 
      break;                               
    case CRYPT_TDES:     // Checking TDES automatically unchecks DES, AES
      SendMessage(hTool, TB_CHECKBUTTON, ID_TOOLBAR_TDES, _mCrypt);
      break;
    case CRYPT_AES:      // Checking AES automatically unchecks DES, TDES               
      SendMessage(hTool, TB_CHECKBUTTON, ID_TOOLBAR_AES,  _mCrypt);
      break;
    } // end switch

  SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_DECIPHER, _mCrypt);
  SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_ENCRYPT,  _mCrypt);
  SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_MAC,      _mCrypt);

  // Keep button 'CRYPT_CONTINUE' disabled if not activated
  if (pszCurrentModeTooltip == szCryptAlgo_CONTINUE)           
    SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_CRYPT_CONTINUE, FALSE);   
  else SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_CRYPT_CONTINUE, _mCrypt);

  DrawMenuBar(hMain);
  } // ControlCryptoToolItems
  
//-----------------------------------------------------------------------------
//
//                       ControlRenameDialog
//
// Enable / Disable (GRAYED) 'rename' selection in main menu
// 
void ControlRenameDialog(int _mfCtrl)
  {
  hMenu = GetMenu(hMain);                          // Menu bar: 0='File', 1='Crypto', etc..
  hFileMenu = GetSubMenu(hMenu, 0);                // Submenu 'File' (=0)
  EnableMenuItem(hFileMenu, ID_FILE_TEXT_RENAME, MF_BYCOMMAND | _mfCtrl); // Item of 'Rename'
  } // ControlRenameDialog
  
//-----------------------------------------------------------------------------
//
//                       ControlCryptoMenu
//
// Enable / Disable (GRAYED) 'save as..' selections in main Crypto menu
// 
void ControlCryptoMenu(int _mfCtrl)
  {
  if (_mfCtrl == MF_ENABLED && multiFileFlag == FALSE)
    {
    SendMessage(hTool, TB_ENABLEBUTTON, ID_FILE_CRYPT_SAVEAS, TRUE);
    ControlFileMenu(MF_ENABLED);
    }
  else if (_mfCtrl == MF_GRAYED || multiFileFlag == TRUE)
    SendMessage(hTool, TB_ENABLEBUTTON, ID_FILE_CRYPT_SAVEAS, FALSE);  

  hMenu = GetMenu(hMain);                          // Menu bar: 0='File', 1='Crypto', etc..
  hCryptoMenu = GetSubMenu(hMenu, 1);              // Submenu 'Crypto' (=1)
  hCryptoMenuDES  = GetSubMenu(hCryptoMenu, 0);    // Submenu of 'Crypto' (=1) is 'DES'
  EnableMenuItem(hCryptoMenuDES,  ID_FILE_CRYPT_DES_SAVEAS, MF_BYCOMMAND | _mfCtrl);  // Item of 'DES'
  hCryptoMenu3DES = GetSubMenu(hCryptoMenu, 1);    // Submenu of 'Crypto' (=1) is '3DES'
  EnableMenuItem(hCryptoMenu3DES, ID_FILE_CRYPT_TDES_SAVEAS, MF_BYCOMMAND | _mfCtrl); // Item of '3DES'
  hCryptoMenuAES  = GetSubMenu(hCryptoMenu, 2);    // Submenu of 'Crypto' (=1) is 'AES'
  EnableMenuItem(hCryptoMenuAES,  ID_FILE_CRYPT_AES_SAVEAS, MF_BYCOMMAND | _mfCtrl);  // Item of 'AES'
  DrawMenuBar(hMain);
  } // ControlCryptoMenu
  
//-----------------------------------------------------------------------------
//
//                       RsaControlCryptoMenu
//
// Enable / Disable (GRAYED) 'RSA' selection(3) in main Crypto menu
//
void RsaControlCryptoMenu(int _mfCtrl)
  { 
  hMenu = GetMenu(hMain);                          // Menu bar: 0='File', 1='Crypto', etc..
  hCryptoMenu = GetSubMenu(hMenu, 1);              // Submenu 'Crypto' (=1)
  EnableMenuItem(hCryptoMenu, 3, MF_BYPOSITION | (_mfCtrl));   // Submenu [1] 'MF_BYPOSITION' --> hacrypt.rc
  DrawMenuBar(hMain);
  } // RsaControlCryptoMenu

//-----------------------------------------------------------------------------
//
//                       DisplayCryptoMenu
//
// The submenu items of menubar or any other submenu (popu menu)
// can be displayed with TrackPopupMenu(Ex) API function. This function needs
// the menu handle of the submenu and coordinates at which to display it.
// For instance in order to display the File menu of menubar 
// the following actions should be taken:
//  Get file submenu handle with GetSubMenu().
//  Get file menu item rectangle using GetMenuItemRect().
//  Calculate the desired coordinates using the rectangle.
//  TrackPopupMenu(Ex) to display the menu.
//
void DisplayCryptoMenu()
  {
  POINT pt = {32, 0};      // {x,y} The place where it usually pops up

  //  Load the menu template containing the shortcut of the Menu bar
  hMenu = GetMenu(hMain);               // Menu bar: 0='File', 1='Crypto', etc..
  hCryptoMenu = GetSubMenu(hMenu, 1);   // Submenu 'Crypto' (=1)

  // TrackPopupMenu() uses screen coordinates, so convert the 
  //  coordinates of the mouse click to screen coordinates. 
  ClientToScreen(hMain, (LPPOINT) &pt); 

  // BOOL TrackPopupMenu(
  //  [in]           HMENU      hMenu,
  //  [in]           UINT       uFlags,
  //  [in]           int        x,
  //  [in]           int        y,
  //  [in]           int        nReserved,
  //  [in]           HWND       hWnd,
  //  [in, optional] const RECT *prcRect
  // );
  // 
  // Draw and track the shortcut menu.  
  TrackPopupMenu(hCryptoMenu,
                 TPM_LEFTALIGN | TPM_LEFTBUTTON, 
                 pt.x, pt.y,
                 0,
                 hMain,
                 NULL);
  } // DisplayCryptoMenu()                

//----------------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//MessageBoxA(NULL, "STOP", "STOP 1", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
