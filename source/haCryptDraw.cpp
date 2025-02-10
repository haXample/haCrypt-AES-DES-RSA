// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptDraw.cpp - C++ Developer source file.
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

// Console & Debug
extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

// Global variables
extern TCHAR szSignonTitle[];
extern TCHAR szCryptAlgo_CONTINUE[];
extern TCHAR* pszCurrentModeTooltip;

// haCrypt colors
COLORREF BORDER_BLUE                 RGB(  0,   0, 240); // (  0,   0, 240) frame when button / dialogbox hovered
COLORREF BORDER_RED                  RGB(250,   0,   0); // (250,   0,   0) frame when button pressed
COLORREF BORDER_WHITE                RGB(255, 255, 255); // (255, 255, 255) frame when dialogbox released or pressed 

COLORREF BUTTON_BGND_ORANGE_STD      RGB(255, 205, 149); // (255, 205, 149) background when button pressed (TB_STANDARD)
COLORREF BUTTON_BGND_ORANGE_THEME    RGB(210, 187, 167); // (210, 187, 167) background when button pressed (THEME)

COLORREF BUTTON_BORDER_DARK_GRAY     RGB(180, 180, 180); // (180, 180, 180) frame when button released 
COLORREF BUTTON_FGND_GRAY            RGB(160, 160, 160); // (160, 160, 160) button text
COLORREF BUTTON_BGND_LIGHT_GRAY      RGB(235, 235, 235); // (235, 235, 235) background button released
COLORREF BUTTON_BGND_LIGHT_BLUE      RGB(160, 220, 250); // (158, 200, 235) background when button hovered

COLORREF ICON_BGND_LIGHT_ORANGE      RGB(255, 195, 134); // (255, 195, 134) background when icon pressed
COLORREF ICON_BUTTON_BGND_LIGHT_BLUE RGB(158, 217, 235); // (158, 217, 235) background when icon hovered
COLORREF ICON_BORDER_BLUE            RGB( 50,  80, 235); // ( 50,  80, 235) frame when icon hovered
COLORREF ICON_BORDER_FAINTED_BLUE    RGB(100, 100, 240); // (100, 100, 240) frame when icon disabled  (grayed)

COLORREF GRADIENT_LIGHT_BLUE  RGB(  0, 170, 220);  // (  0, 170, 220) fancy background toolbar start 
COLORREF GRADIENT_GREEN       RGB(  0, 220,  80);  // (  0, 220,  80) fancy background toolbar end

COLORREF ERROR_FGND    RGB(223, 223, 223); // (223, 223, 223) Error message text color faded white)
COLORREF ERROR_BGND    RGB(152,  20,  10); // (152,  20,  10) Error message background color (designed w/ paint.exe)
COLORREF STATUS_FGND   RGB(223, 223, 223); // (223, 223, 223) Status message text color (faded white)
COLORREF STATUS_BGND   RGB(  7,  98, 152); // (  7,  98, 152) Status message background color (designed w/ paint.exe)
COLORREF INFO_FGND     RGB(  5, 125,  20); // (  5, 140,  20) Status info message text color  (designed w/ paint.exe)
COLORREF INFO_BGND     RGB(244, 244, 244); // (244, 244, 244) Status info message text color  (designed w/ paint.exe)
COLORREF COPY_FGND     RGB(  5,  20, 140); // (  5,  20, 140) Status copy message text color  (designed w/ paint.exe)
COLORREF STD_FGND      RGB( 20,  20,  20); // ( 20,  20,  20) Status standard message text color  (designed w/ paint.exe)
COLORREF ALERT_FGND    RGB(140,  20,   5); // (140,  20,   5) Status standard message text color  (designed w/ paint.exe)


HDC hdcStatic;
HDC hdcTool;

HGDIOBJ hObjFont;

HPEN pen;
static HBRUSH defaultbrush = NULL;

int mouseHover = FALSE;
int statwidthsAlert[] = {MAINWINDOW_WIDTH, IDC_STATIC};           // 2-Fields statusbar width: left=500, right=remaining rest
int statwidthsNorm[] =  {STATUSBAR_P0_WIDTH, STATUSBAR_P1_WIDTH}; // 2-Fields statusbar width: left=231, right=remaining rest

// Extern variables
extern LPSTR pszCryptFileIn, pszCryptFileDisplay;

extern DWORD dwCryptFileSize;
extern int k, keyDisplayMode, multiFileFlag, fancyToolbar, activeProgbar;
extern int _valCK;
extern int statColor;

extern ULONG FileProcessingMode, CryptoProcessingMode, ToolProcessingMode;

extern HINSTANCE g_hInst;

extern HDC hdcStatusbar;

extern PAINTSTRUCT _ps;   // Holds info about current painting session.

extern RECT rcButton, rcToolbar;

extern HWND hMain;
extern HWND hKeyTextBox;
extern HWND hIvTextBox;
extern HWND hTool;
extern HWND hStatusbar;
extern HWND hEdit;
extern HWND hProgBar;

extern HWND hButtonDelim; // Dummy Button ((almost) invisible)
extern HWND hButtonIV;
extern HWND hButtonHex;
extern HWND hButtonKey;
extern HWND hwndTT;

extern HFONT hFont;

extern HMENU hMenu;
extern HMENU hFileMenu;
extern HMENU hCryptoMenu;
extern HMENU hCryptoMenuDES;
extern HMENU hCryptoMenu3DES;
extern HMENU hCryptoMenuAES;

HMENU hMenuContext;
HMENU hMenuOptions;
HMENU hMenuKeyHide;
HMENU hMenuKeyShow;

// Extern functions included in this code module:
extern HFONT SetFont(LPCWSTR, int, int);
extern void Bin2Txt();
extern void CreateButtonSetKey(HWND);
extern void CreateButtonSetIV(HWND);

extern void InitProgressbar(ULONG);
extern void ShowWinMouseClick(HWND, int, int, int);

// Forward declaration of functions included in this code module:
void ControlFileMenu(int);
void ControlCryptoMenu(int);
void CtrlHideShowWindow(HWND, int);
//void PaintColoredStatusMsg(TCHAR*);

//------------------------------------------------------------------------------
//
//             DrawItemService (for fancy dialogboxes & buttons)
//
// Owner Drawing fancy Buttons for standard and theme builds
// case WM_DRAWITEM: (see haCrypt.cpp)
//
// lpDrawItem->itemState
//  1.) ODS_DISABLED             (paint grayed)
//  2.) ODS_SELECTED | ODS_FOCUS (paint fancy orange)
//  3.) ODS_HOTLIGHT             *(paint fancy blue)  (doesn't work!?) .. see SubclassprocButton() is OK
//  4.) default                  (paint normal, all other itemstates)
//  5.) ODS_FOCUS                (ignore, causes strange effects)
//  6.) ODS_NOFOCUSRECT          (ignore)
//  7.) ODS_0x00000300           (undocumented. Mask this value to prvent  strange effects)
//
//typedef struct tagDRAWITEMSTRUCT {
//  UINT CtlType;
//  UINT CtlID;
//  UINT itemID;
//  UINT itemAction;
//  UINT itemState;
//  HWND hwndItem;
//  HDC hDC;
//  RECT rcItem;
//  ULONG_PTR itemData;
//} DRAWITEMSTRUCT, *PDRAWITEMSTRUCT, *LPDRAWITEMSTRUCT;
//
long int DrawItemService(LPARAM lParam, WPARAM wParam)
  {
  LPDRAWITEMSTRUCT lpDrawItem = (LPDRAWITEMSTRUCT)lParam;

  int drawItemState = lpDrawItem->itemState & ~0x00000300;  // ODS_0x00000300 ?? - Eliminate, undocumented ??!!

  // Owner drawing dedicated buttons on toolbar only
  if (lpDrawItem->hwndItem == hButtonHex ||
      lpDrawItem->hwndItem == hButtonKey ||
      lpDrawItem->hwndItem == hButtonIV
     )              
    {
    switch(drawItemState)
      {
      case ODS_DISABLED:
        {
        // Button is disabled, so paint it gray
        // (rather than "Paint It Black" by Rolling Stones)
        // Paint the Button with grayed text and background
        SetTextColor(lpDrawItem->hDC, BUTTON_FGND_GRAY);                // Grayed text

        HBRUSH defaultbrush = CreateSolidBrush(BUTTON_BGND_LIGHT_GRAY); // Gray background
        FillRect(lpDrawItem->hDC, &lpDrawItem->rcItem, defaultbrush);
        SetBkMode(lpDrawItem->hDC, TRANSPARENT);

        // Render the button edges as if released or nothing if button is flat style
        if (fancyToolbar == MF_CHECKED)
          DrawEdge(lpDrawItem->hDC, &lpDrawItem->rcItem, EDGE_RAISED, BF_TOPLEFT | BF_BOTTOMRIGHT);

        SelectObject(lpDrawItem->hDC, SetFont(_T("DEFAULT_GUI_FONT"), 16, 6));
        lpDrawItem->rcItem.top++;     // Adjust text position 1 pixel downwards

        int len;
        len = GetWindowTextLength(lpDrawItem->hwndItem);

        LPSTR lpBuff;
        lpBuff = new char[len+1];

        GetWindowTextA(lpDrawItem->hwndItem, lpBuff, len+1);
        DrawTextA(lpDrawItem->hDC, lpBuff, len, &lpDrawItem->rcItem, DT_CENTER);
        }
        break;

      case ODS_SELECTED:
      case ODS_SELECTED | ODS_FOCUS:
        {
        // The button is pressed down (Mouse - 'case WM_LBUTTONDOWN') 
        // Paint a fancy light orange button when pressed down
        if (fancyToolbar == MF_CHECKED)
          defaultbrush = CreateSolidBrush(BUTTON_BGND_ORANGE_STD);   // Orange STD button background
        else if (fancyToolbar == MF_UNCHECKED)
          defaultbrush = CreateSolidBrush(BUTTON_BGND_ORANGE_THEME); // Orange THEME button background

        FillRect(lpDrawItem->hDC, &lpDrawItem->rcItem, defaultbrush);
        SetBkMode(lpDrawItem->hDC, TRANSPARENT);

        // Button edges when pressed down or red frame if button is flat style
        if (fancyToolbar == MF_CHECKED)
          DrawEdge(lpDrawItem->hDC, &lpDrawItem->rcItem, EDGE_SUNKEN, BF_TOPRIGHT | BF_BOTTOMLEFT);
        else if (fancyToolbar == MF_UNCHECKED)
          FrameRect(lpDrawItem->hDC,  &lpDrawItem->rcItem, CreateSolidBrush(BORDER_RED)); // Border (red)

        SelectObject(lpDrawItem->hDC, SetFont(_T("DEFAULT_GUI_FONT"), 16, 6));
        lpDrawItem->rcItem.top++;     // Adjust text position 1 pixel downwards

        int len;
        len = GetWindowTextLength(lpDrawItem->hwndItem);

        LPSTR lpBuff;
        lpBuff = new char[len+1];

        GetWindowTextA(lpDrawItem->hwndItem, lpBuff, len+1);
        DrawTextA(lpDrawItem->hDC, lpBuff, len, &lpDrawItem->rcItem, DT_CENTER);
        }
        break;

      case ODS_FOCUS:
      case ODS_NOFOCUSRECT:
        // Nothing to do on itemState values ODS_NOFOCUSRECT and ODS_FOCUS 
        //  but SubclassprocButton() must skip 'hButtonHex' (it might be grayed)
        //  if IsWindowEnabled(hButtonHex) == FALSE.
        //  Here we must simultate 'WM_LBUTTONDOWN'
        break;

      case ODS_HOTLIGHT:    // ODS_HOTLIGHT - Doesn't Work ??!!
        {                   // .. see SubclassprocButton() is OK 
        // ??!! The button is hovered (Mouse - 'case MOUSEHOVER:') DOESN'T WORK ??!!
//ha//          {
//ha//          TRACKMOUSEEVENT ev = {};
//ha//          ev.cbSize = sizeof(TRACKMOUSEEVENT);
//ha//          ev.dwFlags = TME_HOVER | TME_LEAVE;
//ha//          ev.hwndTrack = lpDrawItem->hwndItem;
//ha//          ev.dwHoverTime = 5;//HOVER_DEFAULT;
//ha//          TrackMouseEvent(&ev);
//ha//          }
//ha//
//ha//        // Paint a fancy light blue button when hovered .. see SubclassprocButton() 
//ha//        HBRUSH defaultbrush = CreateSolidBrush(RGB(148, 187, 235));  // Blue background
//ha//        FillRect(lpDrawItem->hDC, &lpDrawItem->rcItem, defaultbrush);
//ha//        SetBkMode(lpDrawItem->hDC, TRANSPARENT);
//ha//
//ha//        // Button edges when released or nothing if button is flat style
//ha//        //DrawEdge(lpDrawItem->hDC, &lpDrawItem->rcItem, EDGE_RAISED, BF_TOPLEFT | BF_BOTTOMRIGHT);
//ha//
//ha//        SelectObject(lpDrawItem->hDC, SetFont(_T("DEFAULT_GUI_FONT"), 16, 6));
//ha//        lpDrawItem->rcItem.top++;     // Adjust text position 1 pixel downwards
//ha//
//ha//        int len;
//ha//        len = GetWindowTextLength(lpDrawItem->hwndItem);
//ha//
//ha//        LPSTR lpBuff;
//ha//        lpBuff = new char[len+1];
//ha//
//ha//        GetWindowTextA(lpDrawItem->hwndItem, lpBuff, len+1);
//ha//        DrawTextA(lpDrawItem->hDC, lpBuff, len, &lpDrawItem->rcItem, DT_CENTER);
        }
        break;

      default:
        {
        // The button is released (Mouse - 'case WM_LBUTTONUP:' and 'case WM_MOUSELEAVE') 
        // Paint the Button with default text color and (default) gray background
        HBRUSH defaultbrush = CreateSolidBrush(BUTTON_BGND_LIGHT_GRAY);  // Gray background
        FillRect(lpDrawItem->hDC, &lpDrawItem->rcItem, defaultbrush);
        SetBkMode(lpDrawItem->hDC, TRANSPARENT);

        // Button edges when released or dark gray if button is flat style
        if (fancyToolbar == MF_CHECKED)
          DrawEdge(lpDrawItem->hDC, &lpDrawItem->rcItem, EDGE_RAISED, BF_TOPLEFT | BF_BOTTOMRIGHT);
        else if (fancyToolbar == MF_UNCHECKED)
          FrameRect(lpDrawItem->hDC, &lpDrawItem->rcItem, CreateSolidBrush(BUTTON_BORDER_DARK_GRAY)); // Border (dark gray)

        SelectObject(lpDrawItem->hDC, SetFont(_T("DEFAULT_GUI_FONT"), 16, 6));
        lpDrawItem->rcItem.top++;     // Adjust text position 1 pixel downwards

        int len;
        len = GetWindowTextLength(lpDrawItem->hwndItem);

        LPSTR lpBuff;
        lpBuff = new char[len+1];

        GetWindowTextA(lpDrawItem->hwndItem, lpBuff, len+1);
        DrawTextA(lpDrawItem->hDC, lpBuff, len, &lpDrawItem->rcItem, DT_CENTER);
        }
        break;
      } // end switch(drawItemState)
    } // end if (hButtonHex)

  return 0;
  } // DrawItemService

//------------------------------------------------------------------------------
//
//            SubclassprocButton  (for fancy dialogboxes & buttons)
//
//                          (via Mouse tracking)
//
//    ... Example usage ...
//    HWND hButtonKey = CreateWindow(
//                        L"BUTTON", 
//                        L"Set Key",
//                        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_OWNERDRAW, 
//                        150, 5, 70, 20,        // x, y, width, height 
//                        hSubCproc,             // _hwnd
//                        (HMENU)ID_BUTTON_EXIT, 
//                        hInst,                 // NULL
//                        NULL);
//
//    ... in WinMain ..
//    SetWindowSubclass(hButtonKey, SubclassprocButton, 101, 0);
//
LRESULT CALLBACK SubclassprocButton(HWND hSubCproc, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
  {
  if (hSubCproc == hButtonKey  ||
      hSubCproc == hButtonIV   ||
      hSubCproc == hKeyTextBox ||
      hSubCproc == hIvTextBox  ||
      (hSubCproc == hButtonHex && IsWindowEnabled(hButtonHex) == TRUE)) // FALSE = 'ButtonHex' disabled (grayed)
    {                             
    switch (uMsg)
      {
      case WM_MOUSEMOVE:
        {
        // Mouse tracking required to resond to WM_MOUSEHOVER
        TRACKMOUSEEVENT ev = {};
        ev.cbSize = sizeof(TRACKMOUSEEVENT);
        ev.dwFlags = TME_HOVER | TME_LEAVE;
        ev.hwndTrack = hSubCproc;
        ev.dwHoverTime = 5;                  // or HOVER_DEFAULT; (slow reaction)
        TrackMouseEvent(&ev);
        }
        break;

      case WM_MOUSEHOVER: 
        {
        if (mouseHover == FALSE) // Mouse just entered the  dialog / button rectangle
          {
          RECT rc = {};

          if (hSubCproc == hKeyTextBox ||    // Dialog fields
              hSubCproc == hIvTextBox)
            {
            // Paint a light blue border when hovered
            GetClientRect(hSubCproc, &rc);
            HDC hdc = GetDC(hSubCproc);
            FrameRect(hdc, &rc, CreateSolidBrush(ICON_BORDER_BLUE));    // Border only
            }

          else                               // Buttons
            {
            GetClientRect(hSubCproc, &rc);   
            HDC hdc = GetDC(hSubCproc);

            // Paint a fancy light blue button when hovered
            HBRUSH blueBrush = CreateSolidBrush(BUTTON_BGND_LIGHT_BLUE);  //158, 217, 235 or 148.187,235 ...
            FillRect(hdc, &rc, blueBrush);
            SetBkMode(hdc, TRANSPARENT);

            // Button edges when released or blue frame if button is flat style
            if (fancyToolbar == MF_CHECKED)
              DrawEdge(hdc, &rc, EDGE_RAISED, BF_TOPLEFT | BF_BOTTOMRIGHT);
            else if (fancyToolbar == MF_UNCHECKED)
              FrameRect(hdc, &rc, CreateSolidBrush(BORDER_BLUE)); // Border (blue)

            SelectObject(hdc, SetFont(_T("DEFAULT_GUI_FONT"), 16, 6));
            rc.top++;   // Adjust text position within button 1 pixel downwards

            int len;
            len = GetWindowTextLength(hSubCproc);

            LPSTR lpBuff;
            lpBuff = new char[len+1];

            GetWindowTextA(hSubCproc, lpBuff, len+1);
            DrawTextA(hdc, lpBuff, len, &rc, DT_CENTER);
            mouseHover = TRUE;              // Mouse within the button rectangle
            } // end if (hSubCproc)
          } // end if (mouseHover)
        } 
        break; // end case WM_MOUSEHOVER

      case WM_LBUTTONDOWN:
        {
        RECT rc = {};

        if (hSubCproc == hKeyTextBox ||    // Dialog fields
            hSubCproc == hIvTextBox)
          {
          // Paint a white border when left mouse button is pressed
          GetClientRect(hSubCproc, &rc);
          HDC hdc = GetDC(hSubCproc);
          FrameRect(hdc, &rc, CreateSolidBrush(BORDER_WHITE));
          }

        else                               // Buttons
          {
          GetClientRect(hSubCproc, &rc);
          HDC hdc = GetDC(hSubCproc);

          // Transparent light orange background when button is pressed
          if (fancyToolbar == MF_CHECKED)
            defaultbrush = CreateSolidBrush(BUTTON_BGND_ORANGE_STD);   // Orange button background
          else if (fancyToolbar == MF_UNCHECKED)
            defaultbrush = CreateSolidBrush(BUTTON_BGND_ORANGE_THEME);   // Orange button background

          FillRect(hdc, &rc, defaultbrush);
          SetBkMode(hdc, TRANSPARENT);

          // Button edges when pressed down or nothing if button is flat style
          if (fancyToolbar == MF_CHECKED)
            DrawEdge(hdc, &rc, EDGE_SUNKEN, BF_TOPRIGHT | BF_BOTTOMLEFT);

          SelectObject(hdc, SetFont(_T("DEFAULT_GUI_FONT"), 16, 6));
          rc.top++;     // Adjust text position within button 1 pixel downwards

          int len;
          len = GetWindowTextLength(hSubCproc);

          LPSTR lpBuff;
          lpBuff = new char[len+1];

          GetWindowTextA(hSubCproc, lpBuff, len+1);
          DrawTextA(hdc, lpBuff, len, &rc, DT_CENTER);
          mouseHover = TRUE;
          } // end if (hSubCproc)
        }
        break; // case WM_LBUTTONDOWN

      case WM_LBUTTONUP:
      case WM_MOUSELEAVE:
        {
        mouseHover = FALSE;    // Mouse just left the dialog / button rectangle
        RECT rc = {};

        if (hSubCproc == hKeyTextBox ||      // Dialog fields
            hSubCproc == hIvTextBox)
          {
          // Paint a white (invisible) border when left mouse button is pressed
          GetClientRect(hSubCproc, &rc);
          HDC hdc = GetDC(hSubCproc);
          FrameRect(hdc, &rc, CreateSolidBrush(BORDER_WHITE));
          }

        else
          {
          GetClientRect(hSubCproc, &rc);     // Buttons
          HDC hdc = GetDC(hSubCproc);
          //SetTextColor(hdc, RGB(0, 0, 0)); // Black text

          // Transparent gray background when button is released
          HBRUSH defaultbrush = CreateSolidBrush(BUTTON_BGND_LIGHT_GRAY);
          FillRect(hdc, &rc, defaultbrush);
          SetBkMode(hdc, TRANSPARENT);

          // Button edges when released or dark gray if button is flat style
          if (fancyToolbar == MF_CHECKED)
             DrawEdge(hdc,  &rc, EDGE_RAISED, BF_TOPLEFT | BF_BOTTOMRIGHT);
          else if (fancyToolbar == MF_UNCHECKED)
            FrameRect(hdc, &rc, CreateSolidBrush(BUTTON_BORDER_DARK_GRAY)); //  (dark grey)

          SelectObject(hdc, SetFont(_T("DEFAULT_GUI_FONT"), 16, 6));
          rc.top++;     // Adjust text position within button 1 pixel downwards

          int len;
          len = GetWindowTextLength(hSubCproc);

          LPSTR lpBuff;
          lpBuff = new char[len+1];

          GetWindowTextA(hSubCproc, lpBuff, len+1);
          DrawTextA(hdc, lpBuff, len, &rc, DT_CENTER);
          }

        // Mouse tracking back to default
        TRACKMOUSEEVENT ev = {};
        ev.cbSize = sizeof(TRACKMOUSEEVENT);
        ev.dwFlags = TME_HOVER | TME_LEAVE | TME_CANCEL;
        ev.hwndTrack = hSubCproc;
        ev.dwHoverTime = HOVER_DEFAULT;
        TrackMouseEvent(&ev);

        return DefSubclassProc(hSubCproc, uMsg, wParam, lParam);
        }
        break;  // end case MOUSELEAVE

      default:
        return DefSubclassProc(hSubCproc, uMsg, wParam, lParam);
      } // end switch (uMsg)
    } // end if (hButtonExit)

  return DefSubclassProc(hSubCproc, uMsg, wParam, lParam);
  }  // SubclassprocButton


//------------------------------------------------------------------------------
//
//                       CreateTBGradientBrush
//
HBRUSH CreateTBGradientBrush(COLORREF top, COLORREF bottom, LPNMTBCUSTOMDRAW item)
  {
  HBRUSH Brush = NULL;
  HDC hdcmem = CreateCompatibleDC(item->nmcd.hdc);
  HBITMAP hbitmap = CreateCompatibleBitmap(item->nmcd.hdc, 
                                           item->nmcd.rc.right  - item->nmcd.rc.left, 
                                           item->nmcd.rc.bottom - item->nmcd.rc.top);
  SelectObject(hdcmem, hbitmap);

  int r1 = GetRValue(top), r2 = GetRValue(bottom);
  int g1 = GetGValue(top), g2 = GetGValue(bottom);
  int b1 = GetBValue(top), b2 = GetBValue(bottom);

  for(int i = 0; i < item->nmcd.rc.bottom-item->nmcd.rc.top; i++)
    { 
    RECT temp;
    int r,g,b;
    r = int(r1 + double(i * (r2-r1) / item->nmcd.rc.bottom-item->nmcd.rc.top));
    g = int(g1 + double(i * (g2-g1) / item->nmcd.rc.bottom-item->nmcd.rc.top));
    b = int(b1 + double(i * (b2-b1) / item->nmcd.rc.bottom-item->nmcd.rc.top));
    Brush = CreateSolidBrush(RGB(r, g, b));
    temp.left = 0;
    temp.top = i;
    temp.right = item->nmcd.rc.right-item->nmcd.rc.left;
    temp.bottom = i + 1; 

    FillRect(hdcmem, &temp, Brush);
    DeleteObject(Brush);
    }

  HBRUSH pattern = CreatePatternBrush(hbitmap);

  DeleteDC(hdcmem);
  DeleteObject(Brush);
  DeleteObject(hbitmap);
  return pattern;
  } // CreateTBGradientBrush
 
//ha////------------------------------------------------------------------------------
//ha////
//ha////                       RedrawButton
//ha////
//ha////   Redraw key and IV dialog boxes (Frame + Contents)
//ha////
//ha//void RedrawButton(HWND _hButton)
//ha//  {
//ha//  RECT rc = {};
//ha//
//ha//  GetClientRect(_hButton, &rc);    // Buttons
//ha//  HDC hdc = GetDC(_hButton);
//ha//  //SetTextColor(hdc, RGB(0, 0, 0)); // Black text
//ha//
//ha//  // Transparent gray background when button is released
//ha//  FillRect(hdc, &rc, CreateSolidBrush(RGB(235, 235, 235)));
//ha//  SetBkMode(hdc, TRANSPARENT);
//ha//
//ha//  // Button edges when released or nothing if button is flat style
//ha//  //DrawEdge(hdc, &rc, EDGE_RAISED, BF_TOPLEFT | BF_BOTTOMRIGHT);
//ha//
//ha//  // Re-paint the button's text string if button is disabled.
//ha//  // Paint the Button with grayed text in this case.
//ha//  if (_hButton == hButtonHex && IsWindowEnabled(hButtonHex) == FALSE)
//ha//    SetTextColor(hdc, RGB(160, 160, 160));  // Grayed text
//ha//    
//ha//  SelectObject(hdc, SetFont(_T("DEFAULT_GUI_FONT"), 16, 6));
//ha//  rc.top++;     // Adjust text position 1 pixel downwards
//ha//
//ha//  int len;
//ha//  len = GetWindowTextLength(_hButton);
//ha//  LPSTR lpBuff;
//ha//  lpBuff = new char[len+1];
//ha//  GetWindowTextA(_hButton, lpBuff, len+1);
//ha//  DrawTextA(hdc, lpBuff, len, &rc, DT_CENTER);
//ha//  } // RedrawButton


//ha////------------------------------------------------------------------------------
//ha////
//ha////                       RedrawTextDialogBox
//ha////
//ha////   Redraw key and IV dialog boxes (Frame + Contents)
//ha////
//ha//void RedrawTextDialogBox(HWND _hDlgTextBox)
//ha//  {
//ha//  RECT rc = {};
//ha//  int i;
//ha//  GetClientRect(_hDlgTextBox, &rc);
//ha//  HDC hdc = GetDC(_hDlgTextBox);
//ha//
//ha//  // Paint a light blue (invisible) border when displayed normally
//ha//  //FrameRect(hdc, &rc, CreateSolidBrush(RGB(148, 187, 235)));  // Frame only
//ha//  pen = CreatePen(PS_INSIDEFRAME, 1, RGB(148, 187, 235));
//ha//  SelectObject(hdc, pen);
//ha//  SetBkMode(hdc, TRANSPARENT);
//ha//  Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
//ha//
//ha//  // Re-paint the dialog's text input string (if any)
//ha//  SelectObject(hdc, SetFont(_T("Courier New"), 16,9));
//ha//  int len;
//ha//  len = GetWindowTextLength(_hDlgTextBox);
//ha//  LPSTR lpBuff;
//ha//  lpBuff = new char[len+1];
//ha//  GetWindowTextA(_hDlgTextBox, lpBuff, len+1);
//ha//
//ha//  // Re-paint '*' if the dialog's text input string is hidden
//ha//  if (keyDisplayMode == FALSE && _hDlgTextBox == hKeyTextBox)
//ha//    {
//ha//    for (i=0; i<len; i++)  lpBuff[i] = '*';
//ha//    }
//ha//
//ha//  DrawTextA(hdc, lpBuff, len, &rc, DT_LEFT);
//ha//  } // RedrawTextDialogBox


//------------------------------------------------------------------------------
//
//                       CustomdDrawService
// 
// Custom Drawing a fancy toolbar
// case WM_NOTIFY:        (see haCrypt.cpp)
//   case NM_CUSTOMDRAW:  (see haCrypt.cpp)
//
//NMCUSTOMDRAW structure that contains general custom draw information.
// Information is specific to an NM_CUSTOMDRAW notification code.
// The uItemState member of this structure can be modified so that a toolbar item
// will be drawn in the specified state without actually changing the item's state.
//
//  LPNMHDR lpHDRCustDraw->xxx
//typedef struct _nmhdr {
//  HWND hwndFrom;
//  UINT idFrom;
//  UINT code;
//} NMHDR, *LPNMHDR;
//
//  LPNMCUSTOMDRAW lpCustDraw->hdr.xxx
//  LPNMCUSTOMDRAW lpCustDraw->xxx
//typedef struct tagNMCUSTOMDRAWINFO {
//  NMHDR     hdr;
//  DWORD     dwDrawStage;
//  HDC       hdc;
//  RECT      rc;
//  DWORD_PTR dwItemSpec;
//  UINT      uItemState;
//  LPARAM    lItemlParam;
//} NMCUSTOMDRAW, *LPNMCUSTOMDRAW;
//
//  LPNMTBCUSTOMDRAW lpTBCustDraw->nmcd.hdr.xxx
//  LPNMTBCUSTOMDRAW lpTBCustDraw->nmcd.xxx
//  LPNMTBCUSTOMDRAW lpTBCustDraw->xxx
//typedef struct _NMTBCUSTOMDRAW {
//  NMCUSTOMDRAW nmcd;
//  HBRUSH       hbrMonoDither;
//  HBRUSH       hbrLines;
//  HPEN         hpenLines;
//  COLORREF     clrText;
//  COLORREF     clrMark;
//  COLORREF     clrTextHighlight;
//  COLORREF     clrBtnFace;
//  COLORREF     clrBtnHighlight;
//  COLORREF     clrHighlightHotTrack;
//  RECT         rcText;
//  int          nStringBkMode;
//  int          nHLStringBkMode;
//  int          iListGap;
//} NMTBCUSTOMDRAW, *LPNMTBCUSTOMDRAW;
//
// Initial toolbar rectangle THEME & TB_STANDARD
//  lpTBCustDraw->nmcd.rc.right  += 899; // 899 
//  lpTBCustDraw->nmcd.rc.left   +=   0; //   0 
//  lpTBCustDraw->nmcd.rc.top    +=   0; //   0   
//  lpTBCustDraw->nmcd.rc.bottom +=  26; //  26
//
int _fancy;

long int CustomdDrawService(LPARAM lParam)
  {
  LPNMTBCUSTOMDRAW lpTBCustDraw = (LPNMTBCUSTOMDRAW)lParam;

  switch (lpTBCustDraw->nmcd.dwDrawStage)
    {
    case CDDS_PREPAINT:
      {
      if (lpTBCustDraw->nmcd.hdr.idFrom == IDC_MAIN_TOOL) // toolbar - IDC_MAIN_TOOL
        {
        // Simulate Mouseclick for button appearance
        if (_fancy != fancyToolbar)
          { 
          ShowWinMouseClick(hButtonDelim, 1, 0, 0); // Normalize any pending button background color 
          _fancy = fancyToolbar;
          }

        if (fancyToolbar == MF_UNCHECKED) // Display the standard grayed toolbar
          {
          // Fill the toolbar area with a light gray background color
          defaultbrush = CreateSolidBrush(BUTTON_BGND_LIGHT_GRAY);
          FillRect(lpTBCustDraw->nmcd.hdc, &lpTBCustDraw->nmcd.rc, defaultbrush);
          // Round the edges of the fancy toolbar (looks ugly..)
          //RoundRect(lpTBCustDraw->nmcd.hdc, 
          //          lpTBCustDraw->nmcd.rc.right 
          //          lpTBCustDraw->nmcd.rc.left  
          //          lpTBCustDraw->nmcd.rc.top   
          //          lpTBCustDraw->nmcd.rc.bottom 
          //          5, 5);
          }
        else // Display a fancy colored toolbar
          {
          // Fill the toolbar area with a fancy background color
          defaultbrush = CreateTBGradientBrush(GRADIENT_LIGHT_BLUE, GRADIENT_GREEN, lpTBCustDraw);          
          FillRect(lpTBCustDraw->nmcd.hdc, &lpTBCustDraw->nmcd.rc, defaultbrush);         
          // Draw a thin light blue border around the toolbar area (looks ugly..)
          //HBRUSH blueBrush = CreateSolidBrush(RGB(0, 170, 255));

          }

//ha//        // Redraw key/IV dialog boxes and buttons residing on the toolbar (IDC_MAIN_TOOL)
//ha//        //  (just in case they were messed up by Windows XP)
//ha//        RedrawTextDialogBox(hKeyTextBox);
//ha//        RedrawTextDialogBox(hIvTextBox);
//ha//        RedrawButton(hButtonHex);
//ha//        RedrawButton(hButtonKey);
//ha//        RedrawButton(hButtonIV);

        // The first NM_CUSTOMDRAW notification will have the dwDrawStage member 
        // of the associated NMCUSTOMDRAW structure set to CDDS_PREPAINT.
        // Return CDRF_NOTIFYITEMDRAW.
        // You will then receive an NM_CUSTOMDRAW notification with 
        // dwDrawStage set to CDDS_ITEMPREPAINT.
        // You can change the fonts or colors of an item 
        // by specifying new fonts and colors and returning CDRF_NEWFONT. 
        // Because these modes do not have subitems, you will not receive 
        // any additional NM_CUSTOMDRAW notifications.
        return CDRF_NOTIFYITEMDRAW;
        } // end if (lpTBCustDraw)
      } 
      break; // end case  CDDS_PREPAINT

    // If your application returns CDRF_NOTIFYITEMDRAW to the initial prepaint 
    // custom draw notification, the control will send notifications 
    // for each item it draws during that paint cycle. 
    // These item-specific notifications will have the CDDS_ITEMPREPAINT value 
    // in the dwDrawStage member of the accompanying NMCUSTOMDRAW structure. 
    // You can request that the control send another notification when it is 
    // finished drawing the item by returning CDRF_NOTIFYPOSTPAINT to these 
    // item-specific notifications. Otherwise, return CDRF_DODEFAULT 
    // and the control will not notify the parent window 
    // until it starts to draw the next item.
    case CDDS_ITEMPREPAINT:
      {
      switch(lpTBCustDraw->nmcd.uItemState)
        {
        case CDIS_DEFAULT:             // (0x00000020) ????
        case 0L:                       // Toolbar icon button (init) released (0x00000000)
        if (fancyToolbar == MF_CHECKED)// Display the standard grayed toolbar
          {
          defaultbrush = CreateTBGradientBrush(GRADIENT_LIGHT_BLUE, GRADIENT_GREEN, lpTBCustDraw);
          FillRect(lpTBCustDraw->nmcd.hdc, &lpTBCustDraw->nmcd.rc, defaultbrush);
          }
          break;

        case CDIS_HOT:                 // Toolbar icon button mouse hover (0x00000040)
          {
          HBRUSH defaultbrush = CreateSolidBrush(ICON_BUTTON_BGND_LIGHT_BLUE);                      // Light blue 
          FillRect(lpTBCustDraw->nmcd.hdc, &lpTBCustDraw->nmcd.rc, defaultbrush);                   // Background
          FrameRect(lpTBCustDraw->nmcd.hdc, &lpTBCustDraw->nmcd.rc, CreateSolidBrush(BORDER_BLUE)); // Border (blue)
          }
          break;

        case CDIS_SELECTED:            // Toolbar icon button pushed down (0x00000001)
        case CDIS_HOT | CDIS_SELECTED: // Toolbar icon button pushed down (0x00000041)
          {
          HBRUSH defaultbrush = CreateSolidBrush(ICON_BGND_LIGHT_ORANGE);                          // Light orange 
          FillRect(lpTBCustDraw->nmcd.hdc, &lpTBCustDraw->nmcd.rc, defaultbrush);                  // Background
          FrameRect(lpTBCustDraw->nmcd.hdc, &lpTBCustDraw->nmcd.rc, CreateSolidBrush(BORDER_RED)); // Border (red)
          }
          break;

        case CDIS_DISABLED:            // Toolbar icon button disabled (0x00000004)
        case CDIS_GRAYED:              // Toolbar icon button grayed   (0x00000002) ???? 
          {
          HBRUSH defaultbrush = CreateSolidBrush(ICON_BORDER_FAINTED_BLUE);         // Fainted blue 100,100,240
          FrameRect(lpTBCustDraw->nmcd.hdc, &lpTBCustDraw->nmcd.rc, defaultbrush);  // Border
          }
          break;

        case CDIS_CHECKED:             // Toolbar icon button is checked (via BTNS_CHECKGROUP) (0x00000008)
        case CDIS_HOT | CDIS_CHECKED:  // Toolbar icon button is checked (via BTNS_CHECKGROUP) (0x00000048)
          {
          HBRUSH defaultbrush = CreateSolidBrush(ICON_BGND_LIGHT_ORANGE);                          // Light orange 
          FillRect(lpTBCustDraw->nmcd.hdc, &lpTBCustDraw->nmcd.rc, defaultbrush);                  // Background
          FrameRect(lpTBCustDraw->nmcd.hdc, &lpTBCustDraw->nmcd.rc, CreateSolidBrush(BORDER_RED)); // Border (red)
          }
          break;

        default:
          break;
        } // end switch (lpTBCustDraw->nmcd.uItemState)
      } 
      break; // case CDDS_ITEMPREPAINT

    default:
      return CDRF_DODEFAULT;
      break;
    } // end switch (lpTBCustDraw->nmcd.dwDrawStage)
  
  return CDRF_DODEFAULT;
  } // CustomdDrawService
    

//-----------------------------------------------------------------------------
//
//        PaintWindowWhite
//
// Paint the window rectangle white to mark it 'active'
//
void PaintWindowWhite(HWND _hwnd)
  {
  RECT rcClient;
  PAINTSTRUCT ps;

  HDC hdc = BeginPaint(_hwnd, &ps);
  HDC hdcMem = CreateCompatibleDC(hdc);
  GetClientRect(_hwnd, &rcClient);
  FillRect(hdc, &rcClient, (HBRUSH)GetStockObject(WHITE_BRUSH));  // WHITE_BRUSH
  DeleteDC(hdcMem);
  EndPaint(_hwnd, &ps);
  } // PaintWindowWhite


//-----------------------------------------------------------------------------
//
//        PaintWindowGray
//
// Paint the window rectangle gray to mark it 'inactive'
//
void PaintWindowGray(HWND _hwnd)
  {
  RECT rcClient;
  PAINTSTRUCT ps;

  HDC hdc = BeginPaint(_hwnd, &ps);
  HDC hdcMem = CreateCompatibleDC(hdc);
  GetClientRect(_hwnd, &rcClient);
  FillRect(hdc, &rcClient, (HBRUSH)GetStockObject(LTGRAY_BRUSH)); // WHITE_BRUSH
  DeleteDC(hdcMem);
  EndPaint(_hwnd, &ps);
  } // PaintWindowGray


//-----------------------------------------------------------------------------
//
//        PaintColoredEscapeMsg  (Deprecated)
//
// Change text and text colors in statusbar
//
void PaintColoredEscapeMsg(TCHAR* szStatusInfo)
  {
//ha//  SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); // 2nd: Make it sensitive for 'paint'
//ha//
//ha//  hdcStatusbar = BeginPaint(hStatusbar, &_ps);                    // Create the device context (DC)
//ha//  SetTextColor(hdcStatusbar, STATUS_FGND);                        // FGND = faded white
//ha//  SetBkColor(hdcStatusbar, STATUS_BGND);                          // BGND = designed w/ paint.exe
//ha//
//ha//  //hFont = SetFont(_T("Consolas"), 16, 8);
//ha//  hFont = SetFont(_T("DEFAULT_GUI_FONT"), 16, 8);                 // <-- Set current hFont
//ha//  SelectObject(hdcStatusbar, hFont);
//ha//
//ha//  //BOOL TextOut(
//ha//  //  HDC    hdc,
//ha//  //  int    x,
//ha//  //  int    y,
//ha//  //  LPCSTR lpString,
//ha//  //  int    length
//ha//  //);
//ha//  //
//ha//  // Display status info
//ha//  TextOut(hdcStatusbar, MAINWINDOW_WIDTH-180, 3, szStatusInfo, wcslen(szStatusInfo)); // UNICODE text only.
//ha//  EndPaint(hStatusbar, &_ps);                                     // Free up HDC created with BeginPaint
  } // PaintColoredEscapeMsg


//-----------------------------------------------------------------------------
//
//                     PaintColoredStatusInfoMsg
//
// Change text and text colors in statusbar
//
void PaintColoredStatusInfoMsg(TCHAR* szStatusInfoMsg)
  {
  statColor = FGNDWHITE_BGNDBLUE;  // White text color on blue background in statusbar

  PTSTR pstr = szStatusInfoMsg;
  SendMessage(hStatusbar, WM_SETFONT, (LPARAM)SetFont(_T("DEFAULT_GUI_FONT"), 16, 8), FALSE);
  SendMessage(hStatusbar, SB_SETPARTS, sizeof(statwidthsAlert)/sizeof(int), (LPARAM)statwidthsAlert);
  SendMessage(hStatusbar, SB_SETTEXT, SBT_OWNERDRAW, (LPARAM)pstr);

  // Last hwndTT (=hIvTextBox): Include Icon & Title in tooltip and activate tooltip display
  SendMessage(hwndTT, TTM_SETTITLE, TTI_INFO, (LPARAM)_T("Text field"));  
  SendMessage(hwndTT, TTM_ACTIVATE, TRUE, 0);  // Enable last hwndTT (=hIvTextBox) 

  ControlFileMenu(MF_GRAYED);
  ControlCryptoMenu(MF_GRAYED);

  EnableWindow(hButtonHex, FALSE);             // Disable Hex/Txt button   
  } // PaintColoredStatusInfoMsg

//-----------------------------------------------------------------------------
//
//        PaintColoredStatusErrorMsg
//
// Change text and text colors in statusbar
//
void PaintColoredStatusErrorMsg(TCHAR* szStatusErrorMsg)
  {
  statColor = FGNDWHITE_BGNDRED;   // White text color on red background in statusbar

  ShowWinMouseClick(hButtonDelim, 1, 0, 0);     // Normalize any pending button background color
  if ((dwCryptFileSize > 0)     && 
      (dwCryptFileSize != _ERR) &&              // (-1) = 0xFFFFFFFF = Invalid dwCryptFileSize
      (pszCryptFileIn != NULL)  &&              // An allocated buffer must exist
      multiFileFlag == FALSE    &&              // No Crypto data displayed if multiple files were processed
      FileProcessingMode != FILEMODE_TEXT &&    // No Crypto data displayed if /TEXT
      FileProcessingMode == CryptoProcessingMode)
    {                                           // There may be data from previous crypto operation
    Bin2Txt();                                  // Display as text again (may have invoked from text mode)
    SetWindowTextA(hEdit, NULL);                // Init-clear the Text Field
    SetWindowTextA(hEdit, pszCryptFileDisplay); // Change text 
    ControlCryptoMenu(MF_ENABLED);
    }
  else
    SetWindowText(hMain, szSignonTitle);        // Display signon-text in mainwindow's title field

  // Change text and text colors in statusbar and prepare paint
  PTSTR pstr = szStatusErrorMsg;
  SendMessage(hStatusbar, WM_SETFONT, (LPARAM)SetFont(_T("DEFAULT_GUI_FONT"), 16, 8), FALSE);
  SendMessage(hStatusbar, SB_SETPARTS, sizeof(statwidthsAlert)/sizeof(int), (LPARAM)statwidthsAlert);
  SendMessage(hStatusbar, SB_SETTEXT, SBT_OWNERDRAW, (LPARAM)pstr);

  // Last hwndTT (=hEdit): Include Icon & Title in tooltip and activate tooltip display
  SendMessage(hwndTT, TTM_SETTITLE, TTI_INFO, (LPARAM)_T("Text field"));    
  SendMessage(hwndTT, TTM_ACTIVATE, TRUE, 0);   // Enable last hwndTT (=hIvTextBox)

  EnableWindow(hButtonHex, FALSE);              // Disable Hex/Txt Button
  activeProgbar = FALSE;                        // Progressbar de-activated
  } // PaintColoredStatusErrorMsg


//-----------------------------------------------------------------------------
//
//                    PaintColoredStatusProgressMsg
//
// Change text and text colors in statusbar
//
void PaintColoredStatusProgressMsg(TCHAR* szStatusProgressMsg)
  {
  statColor = FGNDGREEN_BGNDTRANS; // Green Info text color in statusbar

  PTSTR pstr = szStatusProgressMsg;
  SendMessage(hStatusbar, WM_SETFONT, NULL, FALSE);
  SendMessage(hStatusbar, SB_SETPARTS, sizeof(statwidthsNorm)/sizeof(int), (LPARAM)statwidthsNorm);
  SendMessage(hStatusbar, SB_SETTEXT, SBT_OWNERDRAW, (LPARAM)pstr);
  } // PaintColoredStatusProgressMsg

//-----------------------------------------------------------------------------
//
//                    PaintColoredStatusPercentMsg
//
// Change text and text colors in statusbar
//
void PaintColoredStatusPercentMsg(TCHAR* szStatusMsg)
  {
  statColor = FGNDBLUE_BGNDTRANS;  // Blue copy text color in statusbar

  PTSTR pstr = szStatusMsg;
  SendMessage(hStatusbar, WM_SETFONT, NULL, FALSE);
  SendMessage(hStatusbar, SB_SETPARTS, sizeof(statwidthsNorm)/sizeof(int), (LPARAM)statwidthsNorm);
  SendMessage(hStatusbar, SB_SETTEXT, SBT_OWNERDRAW, (LPARAM)pstr);
  } // PaintColoredStatusPercentMsg

//-----------------------------------------------------------------------------
//
//                    PaintColoredStatusMsg
//
// Change text and text colors in statusbar
//
void PaintColoredStatusMsg(TCHAR* szStatusMsg)
  {
  statColor = FGNDBLACK_BGNDTRANS; // Black standard text color in statusbar

  PTSTR pstr = szStatusMsg;
  SendMessage(hStatusbar, WM_SETFONT, NULL, FALSE);
  SendMessage(hStatusbar, SB_SETPARTS, sizeof(statwidthsNorm)/sizeof(int), (LPARAM)statwidthsNorm);
  SendMessage(hStatusbar, SB_SETTEXT, SBT_OWNERDRAW, (LPARAM)pstr);
  } // PaintColoredStatusMsg

//------------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, 
//ha//               _T("lpDrawItem->itemState = %08X\nODS_DISABLED = %08X\nlpDrawItem->hwndItem = %08X\n
//ha//                lpDrawItem->itemState, ODS_DISABLED, lpDrawItem->hwndItem, hButtonHex);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG STOP 2"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, 
//ha//               _T("lpDrawItem->itemState = %08X\nODS_HOTLIGHT = %08X\nlpDrawItem->hwndItem = %08X\nhButtonKey = %08X"), 
//ha//                lpDrawItem->itemState, ODS_HOTLIGHT, lpDrawItem->hwndItem, hButtonKey);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG STOP 2"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "CursorPos = %d, %d\nx, y = %d, %d",
//ha//        csav.x, csav.y, x,y);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG stop A", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, 
//ha//               _T("lpDrawItem->itemState = %08X\nODS_DEFAULT = %08X\nODS_CHECKED = %08X"), 
//ha//                lpDrawItem->itemState, ODS_DEFAULT, ODS_CHECKED, ODS_COMBOBOXEDIT, ODS_GRAYED);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG STOP Start"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, 
//ha//               _T("uMsg = %08X\nWM_LBUTTONDOWN = %08X\nWM_LBUTTONUP = %08X\nWM_MOUSELEAVE = %08X\nWM_MOUSEHOVER = %08X"), 
//ha//                uMsg, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSELEAVE, WM_MOUSEHOVER);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG STOP SubclassprocButton"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

