// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptFileT.cpp - C++ Developer source file.
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

#include <windows.h>
#include <commctrl.h>  // Library Comctl32.lib
#include <winuser.h>
#include <commdlg.h>
#include <tchar.h>

#include <stdlib.h>
#include <string.h>
#include <string>      // sprintf, etc.
#include <strsafe.h>

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

DWORD dwTxtLen = 0;
DWORD dwTextFileSize = 0;

TCHAR* pszTxtRd = TEXT("%lu byte(s) read.");
TCHAR* pszTxtWr = TEXT("%lu byte(s) written.");
TCHAR* pszTextFileExtensionFilter = _T(" Text & Crypto Files (.txt .d* .a* .3* .m*)\0 \
*.txt;*.d*;*.a*;*.3*;*.b*;*.m*;*.#*\0 \
All files and shortcut targets (*.*)\0*.*\0\0"); //All Files\0*.*\0\0

// Global extern variables
extern TCHAR szCountBuf[];
extern int szCountBufsize;

extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern TCHAR szSignonTitle[];

extern TCHAR* pszCryptA;     // Crypto algo (abused for text)
extern TCHAR* pszCryptM;     // Crypto mode (abused for text) 

extern LPSTR pszCryptFileIn, pszCryptFileDisplay, pszTextFileIn;
extern LPSTR pszHexTxtFileIn;

extern ULONG  dwFileSize, ln;
extern DWORD _lastErr;

extern int _hexMode, _escFlag, _escAbort, textColor, multiFileFlag;

extern HWND hMain;
extern HWND hEdit;
extern HWND hStatusbar;
extern HWND hButtonHex;
 
// External functions
extern void ControlCryptoToolItems(int, int);
extern void CtrlHideShowWindow(HWND, int);
//ha//extern void DestroyProgressbar();
extern void DisplayLastError(int);

extern BOOL CheckBin2Txt(int);
extern BOOL CheckEscapeAbort();
extern BOOL FileBlockText(HANDLE);

//------------------------------------------------------------------------------
//
//                     ParseTextFile
//
// Text file is loaded in chunks (no progressbar is displayed)
//
BOOL ParseTextFile(HWND _hwnd, LPTSTR lpszFileName) 
  { 
  DWORD dwFileSizeHigh, dwFileSizeLow;              // Filesize MOD 4G
  LPDWORD lpFileSizeHigh = (DWORD*)&dwFileSizeHigh; // Filesize > 4 Gbyte

  BOOL bSuccess = FALSE;
  
  // Open the file for reading, and retrieve the size of the file. 
  HANDLE hFile = CreateFile(
    lpszFileName, 
    GENERIC_READ, 
    FILE_SHARE_READ, 
    (LPSECURITY_ATTRIBUTES) NULL, 
    OPEN_EXISTING, 
    FILE_ATTRIBUTE_NORMAL,          
    (HANDLE)NULL); 

  _escFlag = FALSE;   // Reset any pending ESC-Abort condition

  if (hFile != INVALID_HANDLE_VALUE)
    {
    // LPDWORD lpFileSizeHigh (used only if > 4Gbyte should be allowed).
    //  A pointer to the variable where the high-order doubleword
    //  of the file size is returned. This parameter can be NULL
    //  if the application does not require the high-order doubleword.
    //
    //dwTextFileSize = GetFileSize(hFile, NULL);
    dwTextFileSize = GetFileSize(hFile, lpFileSizeHigh);                  

    // Large text files > 1Gbyte are always truncated at 4K.
    // Display 1st chunk of file in text field to allow analyzing of possible crypto data.
    // This is better than to abort with "Insufficient Memory" error.
    if (dwFileSizeHigh != 0 || (dwFileSizeHigh == 0 && dwTextFileSize > FILE_BLOCK_1G))
      dwTextFileSize = CRYPT_TEXT_MAXSIZE;    // Fake size to 4K only.

    if (dwTextFileSize != _ERR)        // File exists
      {
      dwFileSize = dwTextFileSize;     // dwFileSize: Needed for progressbar & Crypto algo  

      // Free possibly occupied /TEXT memory Only if not already freed
      if (pszTextFileIn != NULL) pszTextFileIn = (LPSTR)GlobalFree(pszTextFileIn);
        
      // Free occupied hex/txt display buffer
      if (pszCryptFileDisplay != NULL) pszCryptFileDisplay = (LPSTR)GlobalFree(pszCryptFileDisplay);

      // Free previously allocated buffer to get enough memory intercepting the crypto data
      if (pszCryptFileIn != NULL) pszCryptFileIn = (LPSTR)GlobalFree(pszCryptFileIn);

      // Maximum memory buffer size possible: Windows System dependent ~ 1.6G
      pszTextFileIn =       (LPSTR)GlobalAlloc(GPTR, dwTextFileSize + FILE_BLOCK_SIZE + 1); // Allocate text buffer
      pszCryptFileDisplay = (LPSTR)GlobalAlloc(GPTR, CRYPT_TEXT_MAXSIZE*(3+1) + 1);         // Allocate hex/txt display buffer

      pszHexTxtFileIn = pszTextFileIn; // For hex/text display

      // Check if the necessary allocated buffer is available
      if (pszTextFileIn == NULL || pszCryptFileDisplay == NULL)
        {
        DisplayLastError(HA_ERROR_MEMORY_ALLOC);
        return(bSuccess);
        }

      // Process the input file
      // ----------------------
      if (FileBlockText(hFile) == FALSE) return(bSuccess);    
      else bSuccess = TRUE;                // File has been successfuly processed

      // Note: Big Crypt-Files are only partly displayed in the text window ..!!
      // Crypt data must be modified in order to get it displayed as text
      if (CheckBin2Txt(1) == TRUE)         // Truncated crypto data loaded
        {
        _hexMode = FALSE;                         // Set text display mode
        EnableWindow(hButtonHex, TRUE);           // Enable Hex/Txt Button
        CtrlHideShowWindow(hButtonHex, SW_SHOW);  // Show/Enable Hex/Txt Button

        textColor = T_GREEN;                      // Green text
        SetFocus (hEdit);                         // Set focus to text field
        // Wrte-enable text field
        SendMessage(hEdit, EM_SETREADONLY, FALSE, 0); 
        SetWindowTextA(_hwnd, NULL);              // Init-clear the text field
        // Change text within specified text field
        if (SetWindowTextA(_hwnd, pszCryptFileDisplay)) bSuccess = TRUE; 
        SetFocus (hMain);                         // Deviate focus to hMain
        textColor = FALSE;                        // Black text
        }

      else                                 // Normal (real) text file loaded
        {                                         
        CtrlHideShowWindow(hButtonHex, SW_HIDE);  // Hide/Disable Hex/Txt Button
        SetWindowTextA(_hwnd, NULL);              // Init-clear the Text Field
        // Change text within specified text field
        if (SetWindowTextA(_hwnd, pszTextFileIn)) bSuccess = TRUE; 
        }
      } // end if (dwTextFileSize)

    else DisplayLastError(HA_ERROR_FILE_OPEN);
    } // end if (hfile)                 

  return bSuccess;
  } // ParseTextFile


//-----------------------------------------------------------------------------
//
//                          DoTxtFileOpen
//
OPENFILENAME txtofn={0}; // Global to remember the 'ofn.lpstrInitialDir'

void DoTxtFileOpen(HWND _hwnd)
  {
  TCHAR szFileName[MAX_PATH+1] = _T("");
       
  multiFileFlag = FALSE; // Single file only
  
  // Remove-clear Progressbar 'Loading file'
  // Ensure the correct crypto item remains selected
//ha//  DestroyProgressbar();
  ControlCryptoToolItems(MF_ENABLED, FALSE);  // Keep 'em disabled. 

  ZeroMemory(&txtofn, sizeof(OPENFILENAME));

  txtofn.lStructSize = sizeof(OPENFILENAME);
  txtofn.hwndOwner   = _hwnd;
  txtofn.lpstrFilter = pszTextFileExtensionFilter;
  txtofn.lpstrFile   = szFileName;
  txtofn.nMaxFile    = MAX_PATH;
//  txtofn.lpstrDefExt = _T("");  // This appends .txt (for some obscure reason)
  txtofn.lpstrDefExt = NULL;      // No auto appending any extension
  txtofn.lpstrTitle  = _T(" /TEXT - Open a text file");            //NULL;
  txtofn.Flags       = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
  
  if (GetOpenFileName(&txtofn))
    {
    hEdit = GetDlgItem(_hwnd, IDC_MAIN_EDIT);
    pszCryptA = _T("TXT");
    pszCryptM = _T("/TEXT");
    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)szFileName);
    SetWindowText(_hwnd, szFileName);      // Display filename in mainwindow's title field

    if (ParseTextFile(hEdit, szFileName))  // Read file with Progress Bar 
      {                                     
      StringCbPrintf(szCountBuf, szCountBufsize, pszTxtRd, ln);
      SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)szCountBuf);
      }
    }
  else
    {
    SetWindowText(hMain, szSignonTitle);   // Display signon-text in mainwindow's title field
    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)_T("/TEXT")); // Show string
    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)_T(""));      // Clear string
    }
  } // DoTxtFileOpen


//-----------------------------------------------------------------------------
//
//                     SaveTextFileFromEdit
//
BOOL SaveTextFileFromEdit(HWND _hwnd, LPCTSTR pszFileName)
  {
  BOOL bSuccess = FALSE;
  _lastErr = ERROR_SUCCESS;  // Assume no errors

  HANDLE hFile = CreateFile(
    pszFileName, 
    GENERIC_WRITE, 
    0, 
    NULL,
    CREATE_ALWAYS, 
    FILE_ATTRIBUTE_NORMAL, 
    NULL);

  _escFlag = FALSE;          // Reset any pending ESC-Abort condition

  if (hFile != INVALID_HANDLE_VALUE)
    {
    DWORD dwWritten;

    // Display saving ...
    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)_T("Saving, please wait ..."));

    // If the specified window is an edit control, the function
    //  retrieves the length of the text within the control.
    dwTxtLen = GetWindowTextLength(_hwnd);

    // No need to bother if there's no text.
    if (dwTxtLen > 0)
      {
      LPSTR pszText = (LPSTR) LocalAlloc(LPTR, dwTxtLen + 1);  // +1 for zero terminator          
      if (pszText != NULL)
        {
        // Copy the text of the specified window's title bar (if it has one) into a buffer.
        if (GetWindowTextA(_hwnd, pszText, dwTxtLen + 1))      // +1 Zero-Terminated Text
//ha//        if (GetWindowText(_hwnd, pszText, dwTxtLen + 1))       // +1 Zero-Terminated Text
          {
          // Write dwTxtLen (i.e. w/o zero terminator)
          if (WriteFile(hFile, pszText, dwTxtLen, &dwWritten, NULL)) bSuccess = TRUE;
          else _lastErr = GetLastError();             // Save error code  from 'WriteFile'
          }
        LocalFree(pszText);
        } // end if (pszText)
      } // end if(dwTxtLen)

    CloseHandle(hFile);
    } // end if(hfile)
 
  else _lastErr = GetLastError(); // Save error code  from 'CreateFile()'
  
  return bSuccess;
  } // SaveTextFileFromEdit


//-----------------------------------------------------------------------------
//
//                            DoTxtFileSave
//
//  OPENFILENAME txtofn;   (Global)
//
void DoTxtFileSave(HWND _hwnd)
  {
  TCHAR szFileName[MAX_PATH] = _T("");

  dwTxtLen = GetWindowTextLength(hEdit);
  if (dwTxtLen == 0)  // Data to write
    {
    //MessageBox(NULL, szFileWrite, szError, MB_OK | MB_ICONERROR);
    DisplayLastError(HA_ERROR_FILE_WRITE);
    return;
    }

  ZeroMemory(&txtofn, sizeof(OPENFILENAME));

  txtofn.lStructSize = sizeof(OPENFILENAME);
  txtofn.hwndOwner   = _hwnd;
  txtofn.lpstrFilter = pszTextFileExtensionFilter;
  txtofn.lpstrFile   = szFileName;
  txtofn.nMaxFile    = MAX_PATH;
//  txtofn.lpstrDefExt = _T("");  // This appends .txt (for some obscure reason)
  txtofn.lpstrDefExt = NULL;      // No auto appending any extension
  txtofn.lpstrTitle  = _T(" /TEXT - Save displayed text");            //NULL;
  txtofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;

  // Display saving ...
  SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); // Clean up statusbar part 0 from 'paint' 
  SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("Save displayed text ..."));
  SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)_T(""));         // Clear statusbar part 1

  if (GetSaveFileName(&txtofn))
    {
    hEdit = GetDlgItem(_hwnd, IDC_MAIN_EDIT);
    if (SaveTextFileFromEdit(hEdit, (LPCTSTR)szFileName))
      {
      StringCbPrintf(szCountBuf, szCountBufsize, pszTxtWr, dwTxtLen);
      SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)szCountBuf);
      SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)szFileName);
      }
    else if (_escAbort == FALSE && _lastErr != ERROR_SUCCESS) DisplayLastError(_lastErr);
      
    else DisplayLastError(HA_ERROR_FILE_WRITE);
    }
  else
    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)TEXT("No file(s) saved..."));
  } // DoTxtFileSave

//-----------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{
//ha//sprintf(DebugBuf, "dwTextFileSize = %d\ndwRead=%d", dwTextFileSize,dwRead);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG STOP 1", MB_OK);
//ha//}
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{
//ha//sprintf(DebugBuf, "dwTextFileSize = %d\nMAX_PATH=%d", dwTextFileSize,MAX_PATH);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG STOP 2", MB_OK);
//ha//}
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{
//ha//sprintf(DebugBuf, "dwTxtLen = %d", dwTxtLen);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG STOP 1", MB_OK);
//ha//}
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
