// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptMenu.cpp - C++ Developer source file.
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

UINT rndItemID[6] = {0,0,0,0,0,0}; // Store to intercept the random-IDs of POPUPs
int ridCount = 0;                  // Random-ID index count

typedef struct tagMENUICON {
  UINT icoFileID;                  // ID of *.ico with transparent background
  UINT menuItemID;                 // ID of the coresponding menu item
} MENUICON, *LPMENUICON;

MENUICON menuIcon[] = {
  // Menu POPUP-items without IDsloaded via 'MF_BYPOSITION'
  //  (special treatment for system-assigned random-IDs required)
  // hMenu[1][0..3] = 'Crypto[DES..RSA]'
  {IDI_DESE,      rndItemID[0]},   // ..ID[0] must stay here in place!
  {IDI_3DESE,     rndItemID[1]},   // ..ID[1] must stay here in place!
  {IDI_AESE,      rndItemID[2]},   // ..ID[2] must stay here in place!
  {IDI_INVISIBLE, rndItemID[3]},   // ..ID[3] must stay here in place!

  // hMenu[4][0..1] = 'Help[Quick instructions..Usage]'
  {IDI_INVISIBLE, rndItemID[4]},   // ..ID[4] must stay here in place!
  {IDI_INVISIBLE, rndItemID[5]},   // ..ID[5] must stay here in place!

  // Menu items with IDs: Loaded via 'MF_BYCOMMAND
  // hMenu[0..4] = All other menu items per unique ID
  {IDI_TXTNEW,    ID_FILE_TEXT_NEW},          // ..ID[6].
  {IDI_TXTOPN,    ID_FILE_TEXT_OPEN},         // ..ID[7].
  {IDI_TXTSAV,    ID_FILE_TEXT_SAVEAS},       // ....
  {IDI_INVISIBLE, ID_FILE_TEXT_RENAME},
  {IDI_EXIT,   ID_FILE_EXIT},

  {IDI_INVISIBLE, ID_CRYPTO_DES_ENCRYPT},     // ..ID[11]
  {IDI_INVISIBLE, ID_CRYPTO_DES_DECIPHER},    
  {IDI_CRYENC,    ID_CRYPTO_DES_ECBENCRYPT},  
  {IDI_CRYDEC,    ID_CRYPTO_DES_ECBDECIPHER}, 
  {IDI_INVISIBLE, ID_CRYPTO_DES_ECBE},
  {IDI_INVISIBLE, ID_CRYPTO_DES_ECBD},
  {IDI_INVISIBLE, ID_CRYPTO_DES_CBCE},
  {IDI_INVISIBLE, ID_CRYPTO_DES_CBCD},
  {IDI_INVISIBLE, ID_CRYPTO_DES_ECBE_PKCS},
  {IDI_INVISIBLE, ID_CRYPTO_DES_ECBD_PKCS},
  {IDI_INVISIBLE, ID_CRYPTO_DES_CBCE_PKCS},
  {IDI_INVISIBLE, ID_CRYPTO_DES_CBCD_PKCS},
  {IDI_CRYMAC,    ID_CRYPTO_DES_MAC},  
  {IDI_CRYSAV,    ID_FILE_CRYPT_DES_SAVEAS},   

  {IDI_CRYENC,    ID_CRYPTO_AES_ENCRYPT},     // ..ID[25]
  {IDI_CRYDEC,    ID_CRYPTO_AES_DECIPHER},   
  {IDI_INVISIBLE, ID_CRYPTO_AES_ECBENCRYPT},  
  {IDI_INVISIBLE, ID_CRYPTO_AES_ECBDECIPHER},  
  {IDI_INVISIBLE, ID_CRYPTO_AES_ECBE},
  {IDI_INVISIBLE, ID_CRYPTO_AES_ECBD},
  {IDI_INVISIBLE, ID_CRYPTO_AES_CBCE},
  {IDI_INVISIBLE, ID_CRYPTO_AES_CBCD},
  {IDI_INVISIBLE, ID_CRYPTO_AES_ECBE_PKCS},
  {IDI_INVISIBLE, ID_CRYPTO_AES_ECBD_PKCS},
  {IDI_INVISIBLE, ID_CRYPTO_AES_CBCE_PKCS},
  {IDI_INVISIBLE, ID_CRYPTO_AES_CBCD_PKCS},
  {IDI_CRYMAC,    ID_CRYPTO_AES_MAC},  
  {IDI_CRYSAV,    ID_FILE_CRYPT_AES_SAVEAS},   

  {IDI_CRYENC,    ID_CRYPTO_TDES_ENCRYPT},    // ..ID[39]
  {IDI_CRYDEC,    ID_CRYPTO_TDES_DECIPHER},
  {IDI_INVISIBLE, ID_CRYPTO_TDES_ECBENCRYPT},  
  {IDI_INVISIBLE, ID_CRYPTO_TDES_ECBDECIPHER},
  {IDI_INVISIBLE, ID_CRYPTO_TDES_ECBE},
  {IDI_INVISIBLE, ID_CRYPTO_TDES_ECBD},
  {IDI_INVISIBLE, ID_CRYPTO_TDES_CBCE},
  {IDI_INVISIBLE, ID_CRYPTO_TDES_CBCD},
  {IDI_INVISIBLE, ID_CRYPTO_TDES_ECBE_PKCS},
  {IDI_INVISIBLE, ID_CRYPTO_TDES_ECBD_PKCS},
  {IDI_INVISIBLE, ID_CRYPTO_TDES_CBCE_PKCS},
  {IDI_INVISIBLE, ID_CRYPTO_TDES_CBCD_PKCS},
  {IDI_CRYMAC,    ID_CRYPTO_TDES_MAC},
  {IDI_CRYSAV,    ID_FILE_CRYPT_TDES_SAVEAS},
     
  {IDI_CONSOLE,   ID_CONSOLE_HEDIT},          // ..ID[53]
  {IDI_CONSOLE,   ID_CONSOLE_HEDIT_FILEOPEN},
  {IDI_CONSOLE,   ID_CONSOLE_HEDIT_CRYPT},

  {IDI_INVISIBLE, ID_HELP_ABOUT_MULTIFILE},   // ..ID[56]
  {IDI_INVISIBLE, ID_HELP_ABOUT_KEYFILE},
  {IDI_INVISIBLE, ID_HELP_ABOUT_TEXTFIELD},
  {IDI_INVISIBLE, ID_HELP_ABOUT_TEST},
  {IDI_INVISIBLE, ID_HELP_ABOUT_VERSION},
  {IDI_HAABOUT, ID_HELP_ABOUT}                // ..ID[61]
  };
                                            
LPMEASUREITEMSTRUCT lpmis;
LPDRAWITEMSTRUCT lpdis;
MENUITEMINFO mii;

COLORREF MENU_ITEM_HOVER_BLUE      RGB(139, 198, 241); // (139, 198, 241) Background when menu item is hovered by mouse
COLORREF MENU_ITEM_FGND_GRAY       RGB(160, 160, 160); // (160, 160, 160) Grayed menu item when item is disabled
COLORREF MENU_ITEM_BGND_LIGHT_GRAY RGB(243, 243, 243); // (243, 243, 243) Background menu item area (WIN10)
COLORREF MENU_ITEM_BGND_WHITE      RGB(255, 255, 255); // (255, 255, 255) Background menu item area (XP only) 

// Extern variables
extern ULONG FileProcessingMode;
extern int _valCK, _testContextFlag;
extern int fancyToolbar, keyDisplayMode, _escAbortNoQuery, _multiFileBrowserFlag; // Useful here

extern HINSTANCE g_hInst;
extern HWND hMain;

// Console & Debug
extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

// Extern functions included in this code module:

// Forward declaration of functions included in this code module:
void WINAPI CreateMenuItemIcons(HWND); 
void WINAPI OnMeasureItem(HWND, LPMEASUREITEMSTRUCT); 
void WINAPI OnDrawItem(HWND, LPDRAWITEMSTRUCT); 

//-----------------------------------------------------------------------------
//
//                       HandleContextMenu  ('HandlePopupMenu')
//
// Context Menu Control: case WM_CONTEXTMENU
// If the mouse click took place inside the client area, 
// execute the application-defined function that displays the shortcut menu.
//
void APIENTRY HandleContextMenu(HWND _hwnd, POINT pt) 
  { 
  HMENU hmenu;            // menu template          
  HMENU hmenuTrackPopup;  // shortcut menu   

  // Load the menu template containing the shortcut menu 
  // from the application's resources. 
  //hmenu = LoadMenu(g_hInstance, _T("PopupMenu")); // Alternatively OK [*.rc]
  hmenu = LoadMenu(g_hInst, MAKEINTRESOURCE(IDC_KEYDLG_CONTEXT)); 
  if (hmenu == NULL) return; 
   
  // Get the first shortcut menu in the menu template. 
  // This is the menu that TrackPopupMenu displays. 
  hmenuTrackPopup = GetSubMenu(hmenu, 0); 
  // Control the context menu 'Key' items (_valCK = MF_GRAYED or MF_ENABLED);
  EnableMenuItem(hmenuTrackPopup, ID_HIDEKEY, MF_BYCOMMAND | _valCK);
  EnableMenuItem(hmenuTrackPopup, ID_SHOWKEY, MF_BYCOMMAND | _valCK);
  
  // Skip if in TEST-MODE (allows ONE easy retry only)
  if (_testContextFlag == WM_CONTEXTMENU) _testContextFlag = FALSE;
  // Skip if in /TEXT Editor Mode (always allow Test-Mode)  
  else if (FileProcessingMode == FILEMODE_TEXT || FileProcessingMode == FILEMODE_TEXTNEW)  _testContextFlag = FALSE;
  else // Disable Test-Mode context menu item(s)
    {
    // The 'Crypto toggle edited text' context menu item is just handled complementary
    // Submenu[0] Pos[6] MenuItem = ID_CRYPTO_TOGGLE_TEXTEDIT 'Crypto toggle edited text'
    EnableMenuItem(hmenuTrackPopup, ID_CRYPTO_TOGGLE_TEXTEDIT, MF_BYCOMMAND | (_valCK ^ MF_GRAYED));

    // Submenu[1] Pos[0] MenuItem = ID_CRYPTO_TEST_TEXTEDIT 'Test: &Crypto edited text'
    //EnableMenuItem(hmenuTrackPopup, ID_CRYPTO_TEST_TEXTEDIT, MF_BYCOMMAND | (_valCK ^ MF_GRAYED)); 
    // Submenu[1] Pos[1] MenuItem = ID_ASCHEX2BIN_TEXTEDIT 'Test: &AscHex2Bin edited text'
    //EnableMenuItem(hmenuTrackPopup, ID_ASCHEX2BIN_TEXTEDIT,  MF_BYCOMMAND | (_valCK ^ MF_GRAYED));

    // The 'Test' context menu item is handled complementary
    // Submenu[0] Pos[7] = PopUp Menu 'Test' --> hacrypt.rc Submenu[0][7]'MF_BYPOSITION'
    EnableMenuItem(hmenuTrackPopup, 7, MF_BYPOSITION | (_valCK ^ MF_GRAYED));

    // Submenu[0] Pos[9] MenuItem = ID_CRYPTO_MFRESULT_BROWSER --> hacrypt.rc Submenu[0][9]'MF_BYPOSITION'
    EnableMenuItem(hmenuTrackPopup, 9, MF_BYPOSITION | _valCK);
    } // end if (_testContextFlag)

  // Control the display of a checked icon in front of the text item 
  CheckMenuItem(hmenuTrackPopup, ID_SHOWKEY, MF_BYCOMMAND | keyDisplayMode);
  CheckMenuItem(hmenuTrackPopup, ID_HIDEKEY, MF_BYCOMMAND | keyDisplayMode ^ MF_CHECKED);
  CheckMenuItem(hmenuTrackPopup, ID_ESC_ABORT_NOQUERY, MF_BYCOMMAND | _escAbortNoQuery);
  CheckMenuItem(hmenuTrackPopup, ID_FANCYTOOLBAR_TOGGLE, MF_BYCOMMAND | fancyToolbar);
  CheckMenuItem(hmenuTrackPopup, ID_CRYPTO_MFRESULT_BROWSER, MF_BYCOMMAND | _multiFileBrowserFlag);

  // Draw and track the shortcut menu.  
  TrackPopupMenu(
    hmenuTrackPopup, 
    TPM_LEFTALIGN | TPM_LEFTBUTTON,  
    pt.x, pt.y, 
    0, 
    _hwnd, 
    NULL); 
  
  DestroyMenu(hmenu);
  return; 
  } // HandleContextMenu ('HandleContextMenu')

// Comment '#define OWNERDRAW_MENU_ICON' out for non-transparent icons *.bmp (simple method, but looks ugly on XP!)
#define OWNERDRAW_MENU_ICON
  
// Preferred: Ownerdraw transparent Icons *.ico (XP compatible)
#ifdef OWNERDRAW_MENU_ICON  
//---------------------------------------------------------------------------------
//
//                     CreateMenuItemIcons - case WM_CREATE:
//
// typedef struct tagMENUITEMINFOW {   // pecifies which menu item attributes to change.
//   UINT      cbSize;                 // sizeof(MENUITEMINFO)
//   UINT      fMask;                  // Members to be retrieved or set. MIIM_TYPE, MIIM_BITMAP, MIIM_STRING, MIIM_SUBMENU
//   UINT      fType;                  // The menu item type. fType is used only if fMask has a value of MIIM_FTYPE.
//                                     //  MFT_OWNERDRAW, MFT_BITMAP
//                                     //  MFT_BITMAP is replaced by MIIM_BITMAP and hbmpItem. MFT_STRING is replaced by MIIM_STRING.
//   UINT      fState;                 // The menu item state. Set fMask to MIIM_STATE to use fState.
//                                     // MFS_GRAYED, MFS_ENABLED This is the default state
//   UINT      wID;                    // An application-defined identifier for menu item. Set fMask to MIIM_ID to use wID.
//   HMENU     hSubMenu;               // A handle to the drop-down menu or submenu associated with the menu item.
//                                     //  If the menu item is not an item that opens a drop-down menu or submenu,
//                                     //  this member is NULL. Set fMask to MIIM_SUBMENU to use hSubMenu.
//   HBITMAP   hbmpChecked;            // A handle to the bitmap to display next to the item if it is selected. 
//   HBITMAP   hbmpUnchecked;          // A handle to the bitmap to display next to the item if it is not selected. 
//   ULONG_PTR dwItemData;             // An application-defined value for menu item. Set fMask to MIIM_DATA to use dwItemData.
//   LPWSTR    dwTypeData;             // The contents of the menu item. The meaning depends on value of fType
//                                     //  and is used only if the MIIM_TYPE flag is set in the fMask member.
//   UINT      cch;                    // The length of the menu item text, in characters, when information is received
//                                     //  about a menu item of the MFT_STRING type. However, cch is used only if 
//                                     //  the MIIM_TYPE flag is set in the fMask member and is zero otherwise.
//   HBITMAP   hbmpItem;               // A handle to the bitmap to be displayed. (HBMMENU_SYSTEM = system default bitmap)
//                                     // To use Ownerdraw set hbmpItem = HBMMENU_CALLBACK ((HBITMAP) -1)
// } MENUITEMINFOW, *LPMENUITEMINFOW;  
//                                     //  A bitmap that is drawn by the window that owns the menu.
//                                     //  The application must process the WM_MEASUREITEM and WM_DRAWITEM messages. 
//
// MFS_CHECKED   Checks the menu item. For more information about checked menu items, see the hbmpChecked member.
// MFS_DEFAULT   Specifies that the menu item is the default. A menu can contain only one bold default menu item.
// MFS_DISABLED  = 3 = MFS_GRAYED Disables the menu item so that it cannot be selected, but does not gray it.
// MFS_ENABLED   = 0 Enables the menu item so that it can be selected. This is the default state.
// MFS_GRAYED    = 3 = MFS_DISABLED Disables the menu item and grays it so that it cannot be selected.
// MFS_HILITE    Highlights the menu item.
// MFS_UNCHECKED Unchecks the menu item. For more information see the hbmpUnchecked member.
// MFS_UNHILITE  Removes the highlight from the menu item. This is the default state.
//
// HANDLE LoadImage(
//   [in, optional] HINSTANCE hInst,   // Main window
//   [in]           LPCWSTR   name,    // Image to be loaded. MAKEINTRESOURCE converts the image ordinal for LoadImage
//   [in]           UINT      type,    // IMAGE_ICON loads an icon, IMAGE_BITMAP loads a bitmap
//   [in]           int       cx,      // The width, in pixels, of the icon
//   [in]           int       cy,      // The height, in pixels, of the icon
//   [in]           UINT      fuLoad   // LR_VGACOLOR, LR_MONOCHROME, LR_DEFAULTCOLOR, LR_LOADTRANSPARENT
// );
//
// BOOL SetMenuItemInfoW(              // Changes information about a menu item.
//   [in] HMENU            hmenu,      // A handle to the menu that contains the menu item.
//   [in] UINT             item,       // The identifier or position of the menu item to change (depending on fByPositon).
//        BOOL             fByPositon, // MF_BYPOSITION, MF_BYCOMMAND
//   [in] LPCMENUITEMINFOW lpmii
// );
// Remarks
// The application must call the DrawMenuBar function whenever a menu changes,
//  whether the menu is in a displayed window.
//
// UINT GetMenuState(
//   [in] HMENU hMenu,    // Handle to the menu containing the item whose flags are to be retrieved.
//   [in] UINT  uId,      // The menu item as determined by the uFlags parameter.
//   [in] UINT  uFlags    // MF_BYCOMMAND, MF_BYPOSITION
// );
// Return value Type: UINT
//  If the specified item does not exist, the return value is -1.
//  If the menu item opens a submenu, the low-order byte of the return value contains the menu flags
//  associated with the item, and the high-order byte contains the number of items in the submenu opened by the item.
//  Otherwise, the return value is a mask (Bitwise OR) of the menu flags.
//  Following are the menu flags associated with the menu item:
//   MF_OWNERDRAW  0x00000100L The item is owner-drawn.
//   MF_SEPARATOR  0x00000800L There is a horizontal dividing line
//   MF_POPUP      0x00000010L
//   MF_GRAYED     0x00000001L The item is disabled and grayed. 
//   MF_DISABLED   0x00000002L The item is disabled
//   MF_ENABLED    !(Flag & (MF_DISABLED | MF_GRAYED))
//   MF_STRING     !(Flag & (MF_BITMAP | MF_OWNERDRAW))
//
void WINAPI CreateMenuItemIcons(HWND hwnd) 
  {
  HMENU _hMenu = GetMenu(hwnd);               // hMenu = Main menu               (MF_BYCOMMAND)
  HMENU _hCryptoMenu = GetSubMenu(_hMenu, 1); // Submenu hMenu[1] = 'Crypto' ... (MF_BYPOSITION)
  HMENU _hHelpMenu = GetSubMenu(_hMenu, 4);   // Submenu hMenu[4] = 'Help' ...   (MF_BYPOSITION)

  ZeroMemory(&mii, sizeof(MENUITEMINFO));                  

  mii.cbSize        = sizeof(MENUITEMINFO); // Size of this structure
  mii.fMask         = MIIM_TYPE;            // MIIM_STRING, MIIM_TYPE, MIIM_SUBMENU,  MIIM_BITMAP, MIIM_STRING
  mii.fType         = MFT_OWNERDRAW;        // MFT_BITMAP, MFT_OWNERDRAW;
  mii.fState        = MFS_ENABLED;          // This is the default state
  mii.wID           = NULL;                 // Application-defined identifier for menu item
  mii.hSubMenu      = NULL;                 // A handle to the drop-down menu or submenu associated with the menu item.
  mii.hbmpChecked   = NULL;                 // A handle to the bitmap to display next to the item if it is selected. 
  mii.hbmpUnchecked = NULL;                 // A handle to the bitmap to display next to the item if it is not selected. 
  mii.dwTypeData    = NULL;                 // Application-defined value for menu item.
  mii.dwItemData    ;                       // The contents of the menu item.
  mii.cch           ;                       // The length of the menu item text. Zero terminated string if mii.cch=0.
  mii.hbmpItem      = HBMMENU_CALLBACK;     // Set = Owner draw

  int i;
  for (i=0; i<sizeof(menuIcon)/sizeof(MENUICON); i++)
    {
    // Only set info if menu item is not a SEPARATOR, i.e. skip mull-text strings 
    if (!(GetMenuState(_hMenu, menuIcon[i].menuItemID, MF_BYCOMMAND) & MF_SEPARATOR))
      SetMenuItemInfo(_hMenu, menuIcon[i].menuItemID, MF_BYCOMMAND, &mii);
    }
 
  // Menu items without IDs: MF_BYPOSITION 
  // The system will assign a random ID at runtime. See special handling in WM_MEASUREITEM.
  SetMenuItemInfo(_hCryptoMenu, 0, MF_BYPOSITION, &mii);  // MF_BYPOSITION = Submenu DES
  SetMenuItemInfo(_hCryptoMenu, 1, MF_BYPOSITION, &mii);  // MF_BYPOSITION = Submenu 3DES (TDES)
  SetMenuItemInfo(_hCryptoMenu, 2, MF_BYPOSITION, &mii);  // MF_BYPOSITION = Submenu AES
  SetMenuItemInfo(_hCryptoMenu, 3, MF_BYPOSITION, &mii);  // MF_BYPOSITION = Submenu RSA

  SetMenuItemInfo(_hHelpMenu, 0, MF_BYPOSITION, &mii);    // MF_BYPOSITION = Submenu Quick Instructions
  SetMenuItemInfo(_hHelpMenu, 1, MF_BYPOSITION, &mii);    // MF_BYPOSITION = Submenu Usage

  // Init start index for menuIcon[0..5].menuItemID (Storage is rndItemID[0..5])
  ridCount = 0;                                           
  } // CreateMenuItemIcons

//---------------------------------------------------------------------------------
//
//                     OnMeasureItem - case WM_MEASUREITEM:
//
// typedef struct tagMEASUREITEMSTRUCT {
//   UINT      CtlType;                // = ODT_MENU Owner-drawn menu
//   UINT      CtlID;                  // This member is not used for a menu.
//   UINT      itemID;                 // The identifier for a menu item
//   UINT      itemWidth;              // The width, in pixels, of a menu item. Before returning from the message,
//                                     //  the owner of the owner-drawn menu item must fill this member.
//   UINT      itemHeight;             // The height, in pixels, of a menu item. Before returning from the message,
//                                     //  the owner of the owner-drawn menu item must fill this member.
//   ULONG_PTR itemData;               // Application-defined value associated with the menu item.
// } MEASUREITEMSTRUCT, *PMEASUREITEMSTRUCT, *LPMEASUREITEMSTRUCT;
//
// Remarks
// The owner window of an owner-drawn control receives a pointer to the MEASUREITEMSTRUCT structure
//  as the lParam parameter of a WM_MEASUREITEM message.
//  The owner-drawn control sends this message to its owner window when the control is created.
//  The owner then fills in the appropriate members in the structure for the control and returns.
//  This structure is common to all owner-drawn controls
//  except the owner-drawn button control whose size is predetermined by its window.
// If an application does not fill the appropriate members of MEASUREITEMSTRUCT,
//  the control or menu item may not be drawn properly.
//
VOID WINAPI OnMeasureItem(HWND hwnd, LPMEASUREITEMSTRUCT lpmis) 
  {
  if (lpmis->CtlType == ODT_MENU)      // Only if menu
    {
    // Store itemID being set via MF_BYPOSITION
    // 'rndItemID[]' holds four random-IDs assigned by the system for resource POPUP menus
    // (see definitions in header file 'haCrypt.h' and resource file 'haCrypt.rc')
    // --ATTENTION--ATTENTION-ATTENTION-ATTENTION-ATTENTION-ATTENTION-ATTENTION-- 
    // Set the itemID assuming unknown random-IDs > ID_FILE_CRYPT_TDES_SAVEAS 
    if (lpmis->itemID > ID_HELP_ABOUT && ridCount < sizeof(rndItemID)/sizeof(UINT))
      menuIcon[ridCount++].menuItemID = lpmis->itemID;
    // Globally lock rndItemID as soon as the structure elements of menuIcon are initialized           
    if (ridCount >= sizeof(rndItemID)/sizeof(UINT)) ridCount = sizeof(rndItemID)/sizeof(UINT);

    // Menu area width based on longest text string item in the designated menu
    // Store menu area width being set via MF_BYCOMMAND
    if (lpmis->itemID == ID_FILE_TEXT_RENAME) lpmis->itemWidth = 120; // = 120 for [File] menu

    else if (lpmis->itemID == ID_CRYPTO_DES_ECBDECIPHER  ||
             lpmis->itemID == ID_CRYPTO_AES_ECBDECIPHER  ||
             lpmis->itemID == ID_CRYPTO_TDES_ECBDECIPHER)  
      lpmis->itemWidth = 260;                                         // = 260 for [Crypto - DES/AES/3DES] submenus 

    else if (lpmis->itemID == ID_CONSOLE_HEDIT_CRYPT)  
      lpmis->itemWidth = 180;                                         // = 260 for [Crypto - DES/AES/3DES] submenus 

    else if (lpmis->itemID == ID_HELP_ABOUT)  
      lpmis->itemWidth = 140;                                         // = 260 for [Crypto - DES/AES/3DES] submenus 

    // Store menu area width being set via MF_BYPOSITION
    else lpmis->itemWidth = 85;                                       // = 85 for [Crypto] menu 
  
    lpmis->itemHeight = 20;  // 20 = Item height for all menu items
    }                                  
  } // OnMeasureItem                                                                         


//---------------------------------------------------------------------------------
//
//                           IsMenuItemEnabled
//
// typedef struct tagMENUITEMINFOW {   // pecifies which menu item attributes to change.
//   UINT      cbSize;                 // sizeof(MENUITEMINFO)
//   UINT      fMask;                  // Members to be retrieved or set. MIIM_TYPE, MIIM_BITMAP, MIIM_STRING, MIIM_SUBMENU
//   UINT      fType;                  // The menu item type. fType is used only if fMask has a value of MIIM_FTYPE.
//                                     //  MFT_OWNERDRAW, MFT_BITMAP
//                                     //  MFT_BITMAP is replaced by MIIM_BITMAP and hbmpItem. MFT_STRING is replaced by MIIM_STRING.
//   UINT      fState;                 // The menu item state. Set fMask to MIIM_STATE to use fState.
//                                     // MFS_GRAYED, MFS_ENABLED This is the default state
//   UINT      wID;                    // An application-defined identifier for menu item. Set fMask to MIIM_ID to use wID.
//   HMENU     hSubMenu;               // A handle to the drop-down menu or submenu associated with the menu item.
//                                     //  If the menu item is not an item that opens a drop-down menu or submenu,
//                                     //  this member is NULL. Set fMask to MIIM_SUBMENU to use hSubMenu.
//   HBITMAP   hbmpChecked;            // A handle to the bitmap to display next to the item if it is selected. 
//   HBITMAP   hbmpUnchecked;          // A handle to the bitmap to display next to the item if it is not selected. 
//   ULONG_PTR dwItemData;             // An application-defined value for menu item. Set fMask to MIIM_DATA to use dwItemData.
//   LPWSTR    dwTypeData;             // The contents of the menu item. The meaning depends on value of fType
//                                     //  and is used only if the MIIM_TYPE flag is set in the fMask member.
//   UINT      cch;                    // The length of the menu item text, in characters, when information is received
//                                     //  about a menu item of the MFT_STRING type. However, cch is used only if 
//                                     //  the MIIM_TYPE flag is set in the fMask member and is zero otherwise.
//   HBITMAP   hbmpItem;               // A handle to the bitmap to be displayed. (HBMMENU_SYSTEM = system default bitmap)
//                                     // To use Ownerdraw set hbmpItem = HBMMENU_CALLBACK ((HBITMAP) -1)
// } MENUITEMINFOW, *LPMENUITEMINFOW;  
//                                     //  A bitmap that is drawn by the window that owns the menu.
//                                     //  The application must process the WM_MEASUREITEM and WM_DRAWITEM messages. 
//
// MFS_CHECKED   Checks the menu item. For more information about checked menu items, see the hbmpChecked member.
// MFS_DEFAULT   Specifies that the menu item is the default. A menu can contain only one bold default menu item.
// MFS_DISABLED  = 3 = MFS_GRAYED Disables the menu item so that it cannot be selected, but does not gray it.
// MFS_ENABLED   = 0 Enables the menu item so that it can be selected. This is the default state.
// MFS_GRAYED    = 3 = MFS_DISABLED Disables the menu item and grays it so that it cannot be selected.
// MFS_HILITE    Highlights the menu item.
// MFS_UNCHECKED Unchecks the menu item. For more information see the hbmpUnchecked member.
// MFS_UNHILITE  Removes the highlight from the menu item. This is the default state.
//
// BOOL GetMenuItemInfoW(
//   [in]      HMENU           hmenu,          // A handle to the menu that contains the menu item.
//   [in]      UINT            uitem,          // The identifier or position of the menu item
//   [in]      BOOL            fByPosition,    // FALSE, uItem is a menu item identifier. Otherwise iT's a menu item position.
//   [in, out] LPMENUITEMINFOW lpmii           // A pointer to a MENUITEMINFO struct specifying the info to retrieve
//                                             //  and receives info about the menu item.
//                                             //  Note that you must set the cbSize member to sizeof(MENUITEMINFO)
//                                             //  before calling this function.
// );
// 
BOOL IsMenuItemEnabled(HMENU hMenu, UINT uId)
 {
 MENUITEMINFO mii = { 0 };
 mii.cbSize = sizeof(MENUITEMINFO);
 mii.fMask = MIIM_STATE;
 GetMenuItemInfo(hMenu, uId, FALSE, &mii);  
 return !(mii.fState & MFS_DISABLED);
 }

//---------------------------------------------------------------------------------
//
//                           DrawMenuItem
//
// typedef struct tagRECT {
//   LONG left;
//   LONG top;
//   LONG right;
//   LONG bottom;
// } RECT, *PRECT, *NPRECT, *LPRECT;
//
// int DrawText(
//   [in]      HDC     hdc,      // A handle to the device context to draw in.
//   [in, out] LPCTSTR lpchText, // Pointer to the string 
//   [in]      int     cchText,  // Length in chars. If -1, then lpchText is 0-terminated string
//   [in, out] LPRECT  lprc,     // Pointer RECT struct (rectangle in which the text is to be formatted).
//   [in]      UINT    format    // The method of formatting the text.
// );                            //  DT_LEFT     (aligns to left) 
//                               //  DT_CALCRECT Determines the width and height of the rectangle.
//                               //   If the largest word is wider than the rectangle, the width is expanded.
//                               //   If the text is less than the width of the rectangle, the width is reduced.
//                               //   If there is only one line of text, DrawText modifies the right side of the rectangle
//                               //   so that it bounds the last character in the line.
//                               //   In either case, DrawText returns the height of the formatted text but does not draw the text.
// 
// // 
// // int GetMenuStringW(
//   [in]            HMENU hMenu,     // A handle to the menu.
//   [in]            UINT  uIDItem,   // The menu item to be affected
//   [out, optional] LPWSTR lpString, // The buffer that receives the null-terminated string
//   [in]            int   cchMax,    // The maximum length (chars) of the string to be copied
//   [in]            UINT  flags      // MF_BYCOMMAND, MF_BYPOSITION
// );
//
// BOOL DrawStateW(                  // ** Using this instead of 'DrawIconEx()' **
//   [in] HDC           hdc,         // A handle to the device context to draw in.
//   [in] HBRUSH        hbrFore,     // A handle to the brush used to draw the image, if the state specified by
//                                   //  the fuFlags parameter is DSS_MONO. This parameter is ignored for other states.
//   [in] DRAWSTATEPROC qfnCallBack, // A pointer to an application-defined callback function used to render the image.
//                                   //  This parameter is required if the image type in fuFlags is DST_COMPLEX.
//                                   //  It is optional and can be NULL if the image type is DST_TEXT.
//                                   //  For all other image types, this parameter is ignored.
//                                   //  For more information about the callback function, see the DrawStateProc function.
//   [in] LPARAM        lData,       // Information about the image. 
//   [in] WPARAM        wData,       // Information about the image. The meaning of this parameter depends on the image type.
//                                   //  It is, however, zero extended for use with the DrawStateProc function.
//   [in] int           x,           // The horizontal location
//   [in] int           y,           // The vertical location
//   [in] int           cx,          // The width of the image. This parameter is required if the image type is DST_COMPLEX.
//                                   //  Otherwise, it can be zero to calculate the width of the image.
//   [in] int           cy,          // The height of the image. This parameter is required if the image type is DST_COMPLEX.
//                                   //  Otherwise, it can be zero to calculate the width of the image.
//   [in] UINT          uFlags       // The image type and state:
// );                                //  DST_ICON     The image is an icon. The lData parameter is the icon handle.
//                                   //  DST_TEXT     The image is text. The lData parameter is a pointer to the string.
//                                   //  DSS_DISABLED Embosses the image.
//                                   //  DSS_UNION    Dithers the image. 
//                                   //  DSS_MONO     Draws the image using the brush specified by the hbrFore parameter. 
//                                   //  DSS_NORMAL   Draws the image without any modification. 
//
// BOOL DrawIconEx(                            // !! DEPRECATED does not work as expected !!
//   [in]           HDC    hdc,                // A handle to the device context to draw in.
//   [in]           int    xLeft,              // Logical x-coordinate of the upper-left corner of the icon
//   [in]           int    yTop,               // logical y-coordinate of the upper-left corner of the icon
//   [in]           HICON  hIcon,              // A handle to the icon
//   [in]           int    cxWidth,            // Logical width of the icon
//   [in]           int    cyWidth,            // Logical height of the icon
//   [in]           UINT   istepIfAniCur,      // Ignored if hIcon does not identify an animated cursor.
//   [in, optional] HBRUSH hbrFlickerFreeDraw, // ignored if hIcon does not identify an animated cursor.
//   [in]           UINT   diFlags             // DI_NORMAL (see remarks)
// );
//
void DrawMenuItem(HWND _hwnd, LPDRAWITEMSTRUCT lpdis, UINT IconID, COLORREF ItemBk)
  {
  TCHAR szMenuString[256];
  HBRUSH bgbrush, iconBrush; // Brushes for menu area background, item text and monochrome icons

  // Background color (transparent)
  bgbrush = (HBRUSH)CreateSolidBrush(ItemBk);
  SelectObject(lpdis->hDC, bgbrush);
  FillRect(lpdis->hDC, &lpdis->rcItem, bgbrush);
  SetBkMode(lpdis->hDC, TRANSPARENT);
  
  // Using 16x16 ICONs *.ico with transparent background
  UINT dsuFlags = DST_ICON;                     
  if (!IsMenuItemEnabled((HMENU)lpdis->hwndItem, lpdis->itemID))
    {
    SetTextColor(lpdis->hDC, MENU_ITEM_FGND_GRAY);             // Display grayed text (disabled)
    dsuFlags |= DSS_MONO;                                      // Display grayed icon (disabled)
    iconBrush = (HBRUSH)CreateSolidBrush(MENU_ITEM_FGND_GRAY); // Icon monochrome color when disabled (DSS_MONO)
    }
  else dsuFlags |= DSS_NORMAL;  // Display normal icon & default text color (enabled)

  // Menu Text
  HMENU _hMenu = GetMenu(_hwnd);  // hMenu = Main menu
  GetMenuString(_hMenu, lpdis->itemID, szMenuString, 250, MF_BYCOMMAND);

  //DrawText(lpdis->hDC, szMenuString, -1, &(lpdis->rcItem), DT_CALCRECT) + 16;
  lpdis->rcItem.left += GetSystemMetrics(SM_CXMENUCHECK) + 16; //+ ::GetSystemMetrics(SM_CXEDGE) + 16;
  lpdis->rcItem.top  += 2;      // +=  2
  DrawText(lpdis->hDC, szMenuString, -1, &(lpdis->rcItem), DT_LEFT); // DT_CALCRECT

  // Menu Icon 16x16 Pixel
  HICON hIcon = (HICON)LoadImage(g_hInst, MAKEINTRESOURCE(IconID), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
  DrawState(lpdis->hDC,
            iconBrush,
            NULL,
            (LPARAM)hIcon, NULL,
            lpdis->rcItem.left - GetSystemMetrics(SM_CXMENUCHECK) - 16/2,
            lpdis->rcItem.top - 2 + (lpdis->rcItem.bottom - lpdis->rcItem.top - 16) / 2,
            16,
            16,
            dsuFlags); // Either (DST_ICON | DSS_NORMAL) or (DST_ICON | DSS_MONO)

  DestroyIcon(hIcon);  // Release system resources
  } // DrawMenuItem


//---------------------------------------------------------------------------------
//
//                     OnDrawItem - case WM_DRAWITEM:
//
// An application must do the following while processing the WM_DRAWITEM message:
//  Determine the type of drawing that is necessary. To do so, check the itemAction member
//  of the DRAWITEMSTRUCT structure.
//  Draw the menu item appropriately, using the bounding rectangle and device context
//  obtained from the DRAWITEMSTRUCT structure.
// 
// typedef struct tagDRAWITEMSTRUCT {  
//   UINT      CtlType;                // = ODT_BUTTON, ODT_MENU
//   UINT      CtlID;                  // This member is not used for a menu item.
//   UINT      itemID;                 // The menu item identifier for a menu item
//   UINT      itemAction;             // ODA_DRAWENTIRE, ODA_SELECT, ODA_FOCUS
//   UINT      itemState;              // ODS_SELECTED, ODS_NOFOCUSRECT
//   HWND      hwndItem;               // For menus, this member is a handle to the menu that contains the item
//   HDC       hDC;                    // A handle to a device context used by drawing operations on the control.
//   RECT      rcItem;                 // A rectangle that defines the boundaries of the control to be drawn
//   ULONG_PTR itemData;               // The application-defined value associated with the menu item
// } DRAWITEMSTRUCT, *PDRAWITEMSTRUCT, *LPDRAWITEMSTRUCT;
//
// ODS_SELECTED     00000001 The menu item's status is selected. 
// ODS_GRAYED       00000002 The item is to be grayed. This bit is used only in a menu.
// ODS_DISABLED     00000004 The item is to be drawn as disabled.
// ODS_CHECKED      00000008 The menu item is to be checked. This bit is used only in a menu.
// ODS_FOCUS        00000010 The item has the keyboard focus.
// ODS_DEFAULT      00000020 The item is the default item.
// ODS_HOTLIGHT     00000040 The item is being hot-tracked, that is, the item will be highlighted when the mouse is on the item.
// ODS_INACTIVE     00000080 The item is inactive and the window associated with the menu is inactive.
// ODS_NOACCEL      00000100 The control is drawn without the keyboard accelerator cues.
// ODS_NOFOCUSRECT  00000200 The control is drawn without focus indicator cues.
// ODS_????????     00000300 ?????
// ODS_COMBOBOXEDIT 00001000 The drawing takes place in the selection field (edit control) of an owner-drawn combo box.
// 
void WINAPI OnDrawItem(HWND _hwnd, LPDRAWITEMSTRUCT lpdis) 
  {
  if (lpdis->CtlType == ODT_MENU)  // Only if menu
    {
    // --IMPORTANT--IMPORTANT--IMPORTANT--IMPORTANT--IMPORTANT--IMPORTANT--
    // POPUP items check: Ensure the POPUP menu random-IDs (MF_BYPOSITION)
    // must reside in the correct menuIcon[] slots as follows:
    //  Crypto menu = Slots menuIcon[0]..[3]
    //  Help menu   = Slots menuIcon[4]..[5]
    // Note: If Help menu is opened before Crypto menu,
    //       then the Help menu random-IDs are put in Crypto menu's slots.
    //       This happens in 'OnMeasureItem()' and must be fixed before
    //       the menu is owner-drawed. Othewise incorect ICONs are assigned.
    //
    if (ridCount == 2)                                  // Help menu was visited first
      {                                                 
      menuIcon[4].menuItemID = menuIcon[0].menuItemID;  // Store rndItemID[4] as Help[0]
      menuIcon[5].menuItemID = menuIcon[1].menuItemID;  // Store rndItemID[5] as Help[1]
      menuIcon[0].menuItemID = 0;                       // Clear rndItemID[0] for Crypto[0]
      menuIcon[1].menuItemID = 0;                       // Clear rndItemID[1] for Crypto[1]
      // Prepare for Crypto menu Slots menuIcon[0]..[3]
      ridCount = 0;                
      }

    switch(lpdis->itemState & ~0x00000300)  // ODS_0x00000300 ?? - Eliminate, undocumented ??!!
      {
      case ODS_SELECTED:
      case ODS_SELECTED | ODS_FOCUS:
        {
        // Menu items loaded via 'MF_BYCOMMAND' as well as via 'MF_BYPOSITION'
        int i;
        for (i=0; i<sizeof(menuIcon)/sizeof(MENUICON); i++)
          {
          if (lpdis->itemID == menuIcon[i].menuItemID)
            {
            // Showing the IDI_CRYREDO icon if appropriate, otherwise showing icoFileID as defined in menuIcon[]
            if (menuIcon[i].icoFileID == IDI_INVISIBLE &&
                (i >= sizeof(rndItemID)/sizeof(UINT)           &&
                 menuIcon[i].menuItemID != ID_FILE_TEXT_RENAME &&
                 menuIcon[i].menuItemID < ID_FILE_CRYPT_AES_SAVEAS))
              DrawMenuItem(_hwnd, lpdis, IDI_CRYREDO, MENU_ITEM_HOVER_BLUE);             // Blue background & "_haRedo16x16.ico"
            else if (menuIcon[i].menuItemID == ID_CONSOLE_HEDIT_FILEOPEN)
              DrawMenuItem(_hwnd, lpdis, IDI_DOS_HEDIT, MENU_ITEM_HOVER_BLUE);   // Blue background & "icoFileID" 
            else
              DrawMenuItem(_hwnd, lpdis, menuIcon[i].icoFileID, MENU_ITEM_HOVER_BLUE);   // Blue background & "icoFileID" 
            }
          } // end for(i)
        }
        break;  // end case ODS_SELECTED:
                          
      case ODS_DISABLED:
      case ODS_FOCUS:
      case ODS_NOFOCUSRECT:
        // Nothing to do on itemState values ODS_NOFOCUSRECT, ODS_DISABLED and ODS_FOCUS 
        //  but SubclassprocButton() must skip 'hButtonHex' (it might be grayed)
        //  if IsWindowEnabled(hButtonHex) == FALSE.
        //  Here we must simultate 'WM_LBUTTONDOWN'
        break;

      default:   // case ODS_NOACCEL:
        {
        // Menu items loaded via 'MF_BYCOMMAND' as well as via 'MF_BYPOSITION'
        int i;
        for (i=0; i<sizeof(menuIcon)/sizeof(MENUICON); i++)                                         
          {
          if (lpdis->itemID == menuIcon[i].menuItemID)
            {
            if ((GetVersion() & 0xFF) == 5) // XP 
              DrawMenuItem(_hwnd, lpdis, menuIcon[i].icoFileID, MENU_ITEM_BGND_WHITE);      // XP White background
            else
              // Equal or greater than Vista (Windows 6) we have a light gray background                             
              DrawMenuItem(_hwnd, lpdis, menuIcon[i].icoFileID, MENU_ITEM_BGND_LIGHT_GRAY); // Win10 light Gray background
            }
          } // end for(i)
        }
        break;
      } // end switch(lpdis->itemState)
    } // end if (ODT_MENU) 
  } // OnDrawItem

#else // MENU_BIMAP_ICON  Using simple method: non-transparent bitmap icons *.bmp
//-----------------------------------------------------------------------------
//
//                       CreateMenuItemIcons
//
// Display icons nexto a menu item
//
// DEPRECATED:
// Simple - no Owner drawing, but using BMP-files with no transparency
// Eventually acceptable with Windows 10. However this looks very ugly on Windows XP!
//
// typedef struct tagMENUITEMINFOW {   // pecifies which menu item attributes to change.
//   UINT      cbSize;
//   UINT      fMask;                  // Members to be retrieved or set. MIIM_TYPE, MIIM_BITMAP, MIIM_STRING, MIIM_SUBMENU
//   UINT      fType;                  // The menu item type. fType is used only if fMask has a value of MIIM_FTYPE.
//                                     //  MFT_OWNERDRAW, MFT_BITMAP
//                                     //  MFT_BITMAP is replaced by MIIM_BITMAP and hbmpItem. MFT_STRING is replaced by MIIM_STRING.
//   UINT      fState;                 // The menu item state. Set fMask to MIIM_STATE to use fState.
//                                     // MFS_GRAYED, MFS_ENABLED This is the default state
//   UINT      wID;                    // An application-defined identifier for menu item. Set fMask to MIIM_ID to use wID.
//   HMENU     hSubMenu;               // A handle to the drop-down menu or submenu associated with the menu item.
//                                     //  If the menu item is not an item that opens a drop-down menu or submenu,
//                                     //  this member is NULL. Set fMask to MIIM_SUBMENU to use hSubMenu.
//   HBITMAP   hbmpChecked;            // A handle to the bitmap to display next to the item if it is selected. 
//   HBITMAP   hbmpUnchecked;          // A handle to the bitmap to display next to the item if it is not selected. 
//   ULONG_PTR dwItemData;             // An application-defined value for menu item. Set fMask to MIIM_DATA to use dwItemData.
//   LPWSTR    dwTypeData;             // The contents of the menu item. The meaning depends on value of fType
//                                     //  and is used only if the MIIM_TYPE flag is set in the fMask member.
//   UINT      cch;                    // The length of the menu item text, in characters, when information is received
//                                     //  about a menu item of the MFT_STRING type. However, cch is used only if 
//                                     //  the MIIM_TYPE flag is set in the fMask member and is zero otherwise.
//   HBITMAP   hbmpItem;               // A handle to the bitmap to be displayed. (HBMMENU_SYSTEM = system default bitmap)
// } MENUITEMINFOW, *LPMENUITEMINFOW;  // HBMMENU_CALLBACK ((HBITMAP) -1)
//                                     //  A bitmap that is drawn by the window that owns the menu.
//                                     //  The application must process the WM_MEASUREITEM and WM_DRAWITEM messages. 
// HANDLE LoadImage(
//   [in, optional] HINSTANCE hInst,   // Main window
//   [in]           LPCWSTR   name,    // Image to be loaded. MAKEINTRESOURCE converts the image ordinal for LoadImage
//   [in]           UINT      type,    // IMAGE_ICON loads an icon, IMAGE_BITMAP loads a bitmap
//   [in]           int       cx,      // The width, in pixels, of the icon
//   [in]           int       cy,      // The height, in pixels, of the icon
//   [in]           UINT      fuLoad   // LR_VGACOLOR, LR_MONOCHROME, LR_DEFAULTCOLOR, LR_LOADTRANSPARENT
// );
//
// BOOL SetMenuItemInfoW(              // Changes information about a menu item.
//   [in] HMENU            hmenu,      // A handle to the menu that contains the menu item.
//   [in] UINT             item,       // The identifier or position of the menu item to change (depending on fByPositon).
//        BOOL             fByPositon, // MF_BYPOSITION, MF_BYCOMMAND
//   [in] LPCMENUITEMINFOW lpmii
// );
// Remarks
// The application must call the DrawMenuBar function whenever a menu changes,
//  whether the menu is in a displayed window.
//
void WINAPI CreateMenuItemIcons(HWND _hwnd)
  { 
  typedef struct tagMENUICON {                // Local struct
    int bmpFileID;
    int menuItemID;
  } MENUICON, *LPMENUICON;

  MENUICON menuIcon[] = {                     // Local struct init
    {IDB_CRYENC, ID_CRYPTO_DES_ECBENCRYPT},   // ..ID[0].
    {IDB_CRYDEC, ID_CRYPTO_DES_ECBDECIPHER},  // ..ID[1].
    {IDB_CRYENC, ID_CRYPTO_AES_ENCRYPT},      // ....
    {IDB_CRYDEC, ID_CRYPTO_AES_DECIPHER},  
    {IDB_CRYENC, ID_CRYPTO_TDES_ENCRYPT},  
    {IDB_CRYDEC, ID_CRYPTO_TDES_DECIPHER},   
    {IDB_CRYMAC, ID_CRYPTO_DES_MAC},   
    {IDB_CRYMAC, ID_CRYPTO_AES_MAC},   
    {IDB_CRYMAC, ID_CRYPTO_TDES_MAC},  
    {IDB_CRYSAV, ID_FILE_CRYPT_DES_SAVEAS},  
    {IDB_CRYSAV, ID_FILE_CRYPT_AES_SAVEAS},  
    {IDB_CRYSAV, ID_FILE_CRYPT_TDES_SAVEAS},
    {IDB_TXTNEW, ID_FILE_TEXT_NEW},  
    {IDB_TXTOPN, ID_FILE_TEXT_OPEN},   
    {IDB_TXTSAV, ID_FILE_TEXT_SAVEAS},

    {IDB_CRYREDO, ID_CRYPTO_DES_ENCRYPT},   
    {IDB_CRYREDO, ID_CRYPTO_DES_DECIPHER},    
    {IDB_CRYREDO, ID_CRYPTO_AES_ECBENCRYPT},  
    {IDB_CRYREDO, ID_CRYPTO_AES_ECBDECIPHER},  
    {IDB_CRYREDO, ID_CRYPTO_TDES_ECBENCRYPT},  
    {IDB_CRYREDO, ID_CRYPTO_TDES_ECBDECIPHER},
    
    {IDB_HAABOUT, ID_FILE_EXIT},
    {IDB_HAABOUT, ID_HELP_ABOUT}
  };

  HMENU _hMenu = GetMenu(_hwnd);            // hMenu = Main menu (MF_BYCOMMAND)

  MENUITEMINFO mii;
  ZeroMemory(&mii, sizeof(MENUITEMINFO));

  mii.cbSize        = sizeof(MENUITEMINFO); // Size of this structure
  mii.fMask         = MIIM_BITMAP;          // MIIM_STRING, MIIM_TYPE, MIIM_SUBMENU,  MIIM_BITMAP, MIIM_STRING
  mii.fType         = MFT_OWNERDRAW;        // MFT_BITMAP, MFT_OWNERDRAW;
  mii.fState        = MFS_ENABLED;          // This is the default state
  mii.wID           = NULL;                 // Application-defined identifier for menu item
  mii.hSubMenu      = NULL;                 // A handle to the drop-down menu or submenu associated with the menu item.
  mii.hbmpChecked   = NULL;                 // A handle to the bitmap to display next to the item if it is selected. 
  mii.hbmpUnchecked = NULL;                 // A handle to the bitmap to display next to the item if it is not selected. 
  mii.dwTypeData    = NULL;                 // Application-defined value for menu item.
  mii.dwItemData    ;                       // The contents of the menu item.
  mii.cch           ;                       // // The length of the menu item text. Zero terminated string if mii.cch=0.
  mii.hbmpItem      = HBMMENU_SYSTEM;       // A handle to the bitmap to be displayed. (HBMMENU_SYSTEM = system default bitmap)

  HBITMAP _hBitmap;
  int i;
  for (i=0; i<sizeof(menuIcon)/sizeof(MENUICON); i++)
    {
    _hBitmap = (HBITMAP)LoadImage(g_hInst,
                                  MAKEINTRESOURCE(menuIcon[i].bmpFileID),
                                  IMAGE_BITMAP, 16, 16,
                                  LR_DEFAULTCOLOR | LR_LOADTRANSPARENT);

    mii.hbmpItem = _hBitmap;        // A handle to the custom bitmap to be displayed
    SetMenuItemInfo(_hMenu, menuIcon[i].menuItemID, MF_BYCOMMAND, &mii);
    }

  HMENU _hCryptoMenu = GetSubMenu(_hMenu, 1);           // 'Crypto' [1]

  // Submenu of 'Crypto' [1][0] is 'DES...'
  _hBitmap = (HBITMAP)LoadImage(g_hInst, MAKEINTRESOURCE(IDB_DESE), IMAGE_BITMAP, 16, 16, LR_DEFAULTCOLOR | LR_LOADTRANSPARENT);
  mii.hbmpItem = _hBitmap;                              // A handle to the custom bitmap to be displayed
  SetMenuItemInfo(_hCryptoMenu, 0, MF_BYPOSITION, &mii);

  // Submenu of 'Crypto' [1][1] is '3DES...'
  _hBitmap = (HBITMAP)LoadImage(g_hInst, MAKEINTRESOURCE(IDB_3DESE), IMAGE_BITMAP, 16, 16, LR_DEFAULTCOLOR | LR_LOADTRANSPARENT);
  mii.hbmpItem = _hBitmap;                              // A handle to the custom bitmap to be displayed
  SetMenuItemInfo(_hCryptoMenu, 1, MF_BYPOSITION, &mii);  

  // Submenu of 'Crypto' [1][2] is 'AES...'
  _hBitmap = (HBITMAP)LoadImage(g_hInst, MAKEINTRESOURCE(IDB_AESE), IMAGE_BITMAP, 16, 16, LR_DEFAULTCOLOR | LR_LOADTRANSPARENT);
  mii.hbmpItem = _hBitmap;                              // A handle to the custom bitmap to be displayed
  SetMenuItemInfo(_hCryptoMenu, 2, MF_BYPOSITION, &mii);  
  } // CreateMenuItemIcons

//---------------------------------------------------------------------------------
//
//                     OnMeasureItem  - case WM_MEASUREITEM:
//
VOID WINAPI OnMeasureItem(HWND _hwnd, LPMEASUREITEMSTRUCT lpmis) 
  {
  // Dummy, not needed
  } 

//---------------------------------------------------------------------------------
//
//                     OnDrawItem - case WM_DRAWITEM:
//
void WINAPI OnDrawItem(HWND _hwnd, LPDRAWITEMSTRUCT lpdis) 
  {
  // Dummy, not needed
  }
#endif  // end #ifdef OWNERDRAW_MENU_ICON

//--------------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "dwKeyFileSize = %i\n", dwKeyFileSize);
//ha//MessageBoxA(NULL, DebugBuf, "case A_KEY STOP 1", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "ridCount = %i\n"
//ha//                  "menuIcon[00] = {%08d,  %08d}\nmenuIcon[01] = {%08d,  %08d}\n"
//ha//                  "menuIcon[02] = {%08d,  %08d}\nmenuIcon[03] = {%08d,  %08d}\n"
//ha//                  "menuIcon[04] = {%08d,  %08d}\nmenuIcon[05] = {%08d,  %08d}\n"
//ha//                  "menuIcon[06] = {%08d,  %08d}\nmenuIcon[07] = {%08d,  %08d}\n"
//ha//                  "menuIcon[08] = {%08d,  %08d}\nmenuIcon[09] = {%08d,  %08d}\n"
//ha//                  "menuIcon[10] = {%08d,  %08d}\nmenuIcon[11] = {%08d,  %08d}\n"
//ha//                  "menuIcon[12] = {%08d,  %08d}\nmenuIcon[13] = {%08d,  %08d}\n"
//ha//                  "menuIcon[14] = {%08d,  %08d}\nmenuIcon[15] = {%08d,  %08d}\n"
//ha//                  "menuIcon[56] = {%08d,  %08d}\nmenuIcon[57] = {%08d,  %08d}\n"
//ha//                  "menuIcon[58] = {%08d,  %08d}\nmenuIcon[59] = {%08d,  %08d}\n"
//ha//                  "menuIcon[60] = {%08d,  %08d}\nmenuIcon[61] = {%08d,  %08d}\n",
//ha//                   ridCount,
//ha//                   menuIcon[ 0].icoFileID, menuIcon[ 0].menuItemID, menuIcon[ 1].icoFileID, menuIcon[ 1].menuItemID,
//ha//                   menuIcon[ 2].icoFileID, menuIcon[ 2].menuItemID, menuIcon[ 3].icoFileID, menuIcon[ 3].menuItemID,
//ha//                   menuIcon[ 4].icoFileID, menuIcon[ 4].menuItemID, menuIcon[ 5].icoFileID, menuIcon[ 5].menuItemID,
//ha//                   menuIcon[ 6].icoFileID, menuIcon[ 6].menuItemID, menuIcon[ 7].icoFileID, menuIcon[ 7].menuItemID,                   
//ha//                   menuIcon[ 8].icoFileID, menuIcon[ 8].menuItemID, menuIcon[ 9].icoFileID, menuIcon[ 9].menuItemID,
//ha//                   menuIcon[10].icoFileID, menuIcon[10].menuItemID, menuIcon[11].icoFileID, menuIcon[11].menuItemID,
//ha//                   menuIcon[12].icoFileID, menuIcon[12].menuItemID, menuIcon[13].icoFileID, menuIcon[13].menuItemID,
//ha//                   menuIcon[14].icoFileID, menuIcon[14].menuItemID, menuIcon[15].icoFileID, menuIcon[15].menuItemID,                   
//ha//                   menuIcon[56].icoFileID, menuIcon[56].menuItemID, menuIcon[57].icoFileID, menuIcon[57].menuItemID,                   
//ha//                   menuIcon[58].icoFileID, menuIcon[58].menuItemID, menuIcon[59].icoFileID, menuIcon[59].menuItemID,
//ha//                   menuIcon[60].icoFileID, menuIcon[60].menuItemID, menuIcon[61].icoFileID, menuIcon[61].menuItemID
//ha//                   );
//ha////MessageBoxA(NULL, DebugBuf, "CreateMenuItemIcons STOP 1", MB_OK);  // display in haCryptMain.cpp ID_EXIT
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
