// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCopyFileL.cpp - C++ Developer source file.
// (c)2022 by helmut altmann  (This module has been deprecated.)

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

TCHAR szSrcName[MAX_PATH]  = _T("");
TCHAR szDestName[MAX_PATH] = _T("");

TCHAR* pszCopyFileExtensionFilter = _T(" All Files (*.*)\0*.*\0 All files and shortcut targets (*.*)\0*.*\0\0");
TCHAR* pszLargeTxtCpy = TEXT("%llu byte(s) copied.");

__int64 ddFileSizeLarge, lln;

HANDLE hSrcFile;  // Handle of source file.
HANDLE hDestFile; // Handle of destination file.

// Global extern variables
extern LPSTR pszCryptFileIn, pszTextFileIn;

extern TCHAR szCountBuf[];
extern int szCountBufsize;

extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern int textColor;

extern TCHAR szErrorFileOpen[];
extern TCHAR szErrorMemoryAlloc[];
extern TCHAR szErrorDiskFull[];
extern TCHAR szErrorFileWrite[];
extern TCHAR szSignonTitle[];
extern TCHAR szEscapeAbort[];

extern HWND hMain;
extern HWND hTool;
extern HWND hEdit;
extern HWND hStatusbar;
extern HWND hProgBar;          // Handle of progress bar.

extern ULONG  dwFileSize, dwCryptFileSize, ln;
extern DWORD _lastErr;

extern int _escFlag, _escAbort;
extern int activeProgbar;     // Progressbar activity

extern BOOL CheckEscapeAbort();

extern void InitProgressbar(ULONG);             // Init file dependent stepping
extern void DisplayProgressCount(ULONG, int);
extern void DestroyProgressbar();

extern void InitProgressbarL(ULONG);            // Init large file dependent stepping
extern void DisplayProgressCountL(__int64, int);
extern void DestroyProgressbarL();
//extern void InitLargeFileProgressbar(ULONG);

extern void PaintColoredStatusPercentMsg(TCHAR*);
extern void PaintColoredEscapeMsg(TCHAR*);

extern void DisplayLastError(int);
extern void ControlCryptoToolItems(int, int);

extern void DoEvents();      // Absolutely needed for 'one thread-only' UIs!
extern BOOL FileBlockCopy(DWORD);

//ha////-DEPRECATED------------------------------------------------------------------
//ha////-DEPRECATED------------------------------------------------------------------
//ha////-----------------------------------------------------------------------------
//ha////
//ha////                          LargeFileCopy
//ha////
//ha//BOOL LargeFileCopy(HWND _hwnd, LPTSTR lpszFileName) 
//ha//  {
//ha//  DWORD dwFileSizeHigh, dwFileSizeLow;              // dwFileSizeLow = Filesize MOD 4G
//ha//  LPDWORD lpFileSizeHigh = (DWORD*)&dwFileSizeHigh; // Filesize > 4 Gbyte
//ha//
//ha//  DWORD dwFileSizeBlocks;      // Number of file chunks
//ha//  DWORD dwFileBlock;           // Size of each file chunk to be copied
//ha//  DWORD dwFileBlockRemainder;  // Size of the remaining rest to be copied
//ha//
//ha//  LPSTR pchTmp;   // Pointer to temp buffer of data read from file.
//ha//  LPSTR pszCopyFileIn = NULL;
//ha//
//ha//  int i, j;       // Init bytesrd: Progress-Bar chunks to be read
//ha//  DWORD dwRead;   // bytesrd
//ha//  BOOL bSuccess = FALSE;
//ha//  
//ha//  //-----------------------------------------------------------------
//ha//  // Open source file for reading, and retrieve the size of the file. 
//ha//  //-----------------------------------------------------------------
//ha//  hSrcFile = CreateFile(
//ha//    lpszFileName, 
//ha//    GENERIC_READ, 
//ha//    FILE_SHARE_READ, 
//ha//    (LPSECURITY_ATTRIBUTES) NULL, 
//ha//    OPEN_EXISTING, 
//ha//    FILE_ATTRIBUTE_NORMAL,          
//ha//    (HANDLE)NULL); 
//ha//
//ha//  if (hSrcFile != INVALID_HANDLE_VALUE)
//ha//    {
//ha//    //DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
//ha//    //
//ha//    // lpFileSizeHigh =:
//ha//    //  Pointer where the high-order doubleword of the file size is returned.
//ha//    //  NULL if application does not require high-order doubleword.
//ha//    //  NULL = 4Gbyte (=0x100000000) max
//ha//    //
//ha//    // Example: 00000001.38A41FC0 = 5245247424 Bytes (1Gbyte = 40000000 =1073741824)
//ha//    //          138A41FC0 / 40000000 = 4, 138A41FC0 % 40000000 = 38A41FC0
//ha//    //
//ha//    // DWORD dwFileSizeLow;                                            //  0x38A41FC0 
//ha//    // DWORD dwFileSizeHigh;                                           //  0x00000001
//ha//    // LPDWORD lpFileSizeHigh = (DWORD*)&dwFileSizeHigh;            
//ha//    // dwFileSizeLow = GetFileSize(hFile, lpFileSizeHigh);
//ha//    //
//ha//    // dwFileSizeLow = GetFileSize(hFile, lpFileSizeHigh);             // GetFileSize > 4G
//ha//    //
//ha//    // Build 64bit integer
//ha//    // ddFileSizeLarge = UInt32x32To64(dwFileSizeHigh, 0x80000000L);    // 0x0000000010000000 (* 2G)
//ha//    // ddFileSizeLarge <<= 1;                                           // 0x0000000100000000 (* 2)
//ha//    // ddFileSizeLarge |= dwFileSizeLow;                                // 0x0000000138A41FC0
//ha//    //
//ha//    // Calculate how many blocks of 1G each: Divide Build 64bit integer by 1G
//ha//    // dwFileSizeBlocks = (DWORD)Int64ShrlMod32(ddFileSizeLarge, 30); //         0x00000004 chunks of 1 Gbyte each
//ha//    // Calculate the rest: 64bit integer MOD 1G
//ha//    // dwFileSizeMod4G = (DWORD)(ddFileSizeLarge % 0x40000000LL);       //         0x38A41FC0 Filesize % 0x40000000 (= MOD 1 Gbyte)
//ha//    //
//ha//    //---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//    // {                 
//ha//    // sprintf(DebugBuf, "dwFileSizeLow = %08X\ndwFileSizeHigh = %08X\nddFileSizeLarge = %llX [=%llu]",
//ha//    //                    dwFileSizeLow, dwFileSizeHigh, ddFileSizeLarge, ddFileSizeLarge);
//ha//    // MessageBoxA(NULL, DebugBuf, "DEBUG STOP GetFileSize(..)", MB_OK);
//ha//    // }
//ha//    //---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//
//ha//    dwFileSizeLow = GetFileSize(hSrcFile, lpFileSizeHigh);              // Filesize > 4 Gbyte
//ha//
//ha//    // Build 64bit integer
//ha//    ddFileSizeLarge = UInt32x32To64(dwFileSizeHigh, 0x80000000L);                    // * 2G
//ha//    ddFileSizeLarge <<= 1;                                                           // * 2
//ha//    ddFileSizeLarge |= dwFileSizeLow;                                                // 64bit file size > 4Gbyte
//ha//
//ha//    // Calculate how many blocks of 1G each: ddFileSizeLarge / 1G
//ha//    dwFileSizeBlocks = (DWORD)Int64ShrlMod32(ddFileSizeLarge, BASE2_EXPONENT_64M);   // 4 chunks of 1 Gbyte each
//ha//
//ha//    // ------------------------------------------------------------------------
//ha//#ifdef x64  // 64bit                                                        // |
//ha//    dwFileBlock = FILE_BLOCK_64M;                                           // |
//ha//#else                                                                       // |
//ha//    // Calculate the remainder: ddFileSizeLarge % (2.e[BASE2_EXPONENT_64M]) // |
//ha//    dwFileBlock = 0;                                                        // |
//ha//    __asm                           // Using an assembler CPU Instruction   // |
//ha//      {                                                                     // |
//ha//      bts dwFileBlock, BASE2_EXPONENT_64M      // e.g. Build FILE_BLOCK_64M // |
//ha//      }                                                                     // |
//ha//#endif                                                                      // |
//ha//    dwFileBlockRemainder = (DWORD)(ddFileSizeLarge % (__int64)dwFileBlock); // |
//ha//    // ------------------------------------------------------------------------ 
//ha//
//ha//    if (dwFileSizeLow != _ERR)         // File exists
//ha//      {
//ha//      // Free occupied crypto memory (leaves more memory for /COPY)
//ha//      // (may hang the application if freed more than once)
//ha//      if (pszCryptFileIn != NULL)      // Only if not already freed
//ha//        {                             
//ha//        if (GlobalFree(pszCryptFileIn) == NULL) pszCryptFileIn = NULL;      
//ha//        }
//ha//      if (pszTextFileIn != NULL) GlobalFree(pszTextFileIn);
//ha//        {                             
//ha//        if (GlobalFree(pszTextFileIn) == NULL) pszTextFileIn = NULL;      
//ha//        }
//ha//
//ha//      //----------------------
//ha//      // Open destination file
//ha//      //----------------------
//ha//      hDestFile = CreateFile(
//ha//        szDestName, 
//ha//        GENERIC_WRITE, 
//ha//        0, 
//ha//        NULL,
//ha//        CREATE_ALWAYS, 
//ha//        FILE_ATTRIBUTE_NORMAL, 
//ha//        NULL);
//ha//
//ha//      if (hDestFile == INVALID_HANDLE_VALUE)
//ha//        {
//ha//        DisplayLastError(HA_ERROR_FILE_OPEN);
//ha//        return(FALSE);
//ha//        }
//ha//
//ha//      // Disable all windows while copying lengthy files to prevent lockups
//ha//      // (..the user may be tempted to toy around clicking erratically on 
//ha//      //  windows sections while waiting until the file copy terminates.)
//ha////      EnableWindow(hTool, FALSE);   
//ha//
//ha//      //  'DoEvents': Absolutely needed for 'one thread-only' UIs. 
//ha//      //  !! Without 'DoEvents' lockups will occur on lenghty files !!
//ha//      DoEvents(); // IMPORTANT: 'DoEvents' must stay here in place!
//ha//
//ha//      // 1) Read all 1G blocks if file size > 4G
//ha//      if (dwFileSizeBlocks != 0)
//ha//        {
//ha//        j = 0;
//ha//        InitProgressbarL(dwFileBlock);
//ha//
//ha//        do
//ha//          {
//ha//          if (FileBlockCopy(dwFileBlock) == FALSE) 
//ha//            {
//ha//            DestroyProgressbarL();            // Ensure the correct crypto item remains selected
//ha//            EnableWindow(hTool, TRUE);        // Re-enable everything
//ha//            SetFocus(hEdit);                  // Set cursor into text field
//ha//            SetDlgItemText(_hwnd, IDC_MAIN_EDIT, NULL); // Clear edit field
//ha//            return(FALSE);
//ha//            }
//ha//
//ha//          j++;                                // 1G chunks  counter
//ha//          lln = UInt32x32To64(j, ln);         // Calculate the total bytes read
//ha//          DisplayProgressCountL(lln, 3);      // Display bytes currently read 
//ha//          } while (j < dwFileSizeBlocks);
//ha//
//ha//        DestroyProgressbarL();                  // Ensure the correct crypto item remains selected
//ha//        ControlCryptoToolItems(MF_ENABLED, FALSE);  // Keep 'em disabled. 
//ha//        } // end if (dwFileSizeBlocks)
//ha//
//ha//      // 2) All 1G blocks (if any) have been read, now read the remaining rest (if any)
//ha//      if (dwFileSizeLow > 0)
//ha//        {
//ha//        // Don't accumulate bytes count if file size < 4G
//ha//        if (dwFileSizeBlocks == 0) lln = 0LL;  
//ha//        bSuccess = FileBlockCopy(dwFileBlockRemainder);
//ha//        }
//ha//      lln += (__int64)ln;                     // Calculate the total bytes read
//ha//      } // end if (dwFileSizeLow != ERR)                        
//ha//
//ha//    else DisplayLastError(HA_ERROR_FILE_OPEN);
//ha//    
//ha//    CloseHandle(hSrcFile);                    // Close source file
//ha//    CloseHandle(hDestFile);                   // Close destinaion File
//ha//    } // end if (hSrcFile)                  
//ha//
//ha////  EnableWindow(hTool, TRUE);                  // Re-enable everything
//ha////  SendMessage(hEdit, EM_SETREADONLY, FALSE, 0);
//ha//  SetFocus(hEdit);                            // Set cursor into text field
//ha//  SetDlgItemText(_hwnd, IDC_MAIN_EDIT, NULL); // Clear edit field
//ha//
//ha//  return bSuccess;
//ha//  } //  LargeFileCopy
//ha//
//ha//
//ha////-----------------------------------------------------------------------------
//ha////
//ha////                          DoCopySrcFileOpen
//ha////
//ha//void DoCopySrcFileOpen(HWND _hwnd)
//ha//  {
//ha//  OPENFILENAME s_ofn;
//ha//
//ha//  // Remove-clear Progressbar 'Loading file'
//ha//  // Ensure the correct crypto item remains selected
//ha//  DestroyProgressbar();
//ha//  ControlCryptoToolItems(MF_ENABLED, FALSE);  // Keep 'em disabled. 
//ha//
//ha//  ZeroMemory(&s_ofn, sizeof(OPENFILENAME));
//ha//
//ha//  s_ofn.lStructSize = sizeof(OPENFILENAME);
//ha//  s_ofn.hwndOwner   = _hwnd;
//ha//  s_ofn.lpstrFilter = pszCopyFileExtensionFilter;
//ha//  s_ofn.lpstrFile   = szSrcName;
//ha//  s_ofn.nMaxFile    = MAX_PATH;
//ha//  s_ofn.lpstrDefExt = NULL;     // No auto appending any extension
//ha//  s_ofn.Flags       = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
//ha//  
//ha//  if (GetOpenFileName(&s_ofn))
//ha//    {
//ha//    hEdit = GetDlgItem(_hwnd, IDC_MAIN_EDIT);
//ha//    PaintColoredStatusPercentMsg(_T("Copying ...")); // Just to display it blue colored
//ha//    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)szSrcName);
//ha//    SetWindowText(_hwnd, szSrcName);                 // Display filename in mainwindow's title field
//ha//    }
//ha//  else
//ha//    {
//ha//    SetWindowText(hMain, szSignonTitle);             // Display signon-text in mainwindow's title field
//ha//    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)_T("No file(s) copied..."));  // Show string
//ha//    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)_T(""));      // Clear string
//ha//    }
//ha//  } // DoCopySrcFileOpen
//ha//
//ha//
//ha////-----------------------------------------------------------------------------
//ha////
//ha////                            DoCopyDestFileOpen
//ha////
//ha//void DoCopyDestFileOpen(HWND _hwnd)
//ha//  {
//ha//  OPENFILENAME d_ofn;
//ha//
//ha//  ZeroMemory(&d_ofn, sizeof(OPENFILENAME));
//ha//
//ha//  d_ofn.lStructSize = sizeof(OPENFILENAME);
//ha//  d_ofn.hwndOwner   = _hwnd;
//ha//  d_ofn.lpstrFilter = pszCopyFileExtensionFilter;
//ha//  d_ofn.lpstrFile   = szDestName;
//ha//  d_ofn.nMaxFile    = MAX_PATH;
//ha//  d_ofn.lpstrDefExt = NULL;     // No auto appending any extension
//ha//  d_ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
//ha//
//ha//  if (GetSaveFileName(&d_ofn))
//ha//    {
//ha//    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)szDestName);
//ha//
//ha//    // Write info text with standard color (black) into text edit field
//ha//    int index = GetWindowTextLength(hEdit);
//ha//
//ha//    textColor = 2;                                           // Green text
//ha//    SetFocus (hEdit);                                        // Set focus
//ha//    SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)_T("Large file. Press ESC to abort..."));    
//ha//    SendMessage(hEdit, EM_SETSEL, (WPARAM)index, (LPARAM)index); // Select end of text
//ha//    SetFocus (hMain);                                        // Deviate focus to hMain
//ha//    textColor = FALSE;                                       // Black text
//ha//
//ha//    //SendMessage(hEdit, EM_SETREADONLY, TRUE, 0);           // Lock hEdit text display field
//ha//    //PaintColoredEscapeMsg(_T("Press ESC to abort..."));    // Alternatively use statusbar
//ha//
//ha//    if (LargeFileCopy(hMain, szSrcName))    // Copy file with Progress Bar  
//ha//      {
//ha//      // Display the number of bytes having been copied.                                      
//ha//      StringCbPrintf(szCountBuf, szCountBufsize, pszLargeTxtCpy, lln);
//ha//      SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)szCountBuf);
//ha//      }
//ha//    else if (_escAbort == FALSE && _lastErr != ERROR_SUCCESS) DisplayLastError(_lastErr);
//ha//    } // end if (GetSaveFileName)
//ha//
//ha//  else DisplayLastError(HA_NO_FILE_COPIED);
//ha//  } // DoCopyDestFileOpen
//ha//
//ha////-----------------------------------------------------------------------------

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{                
//ha//sprintf(DebugBuf, "dwFileSizeLow = %08X\ndwFileSizeHigh = %08X\nddFileSizeLarge = %llX [=%llu]\ndwFileSizeBlocks = %i\ndwFileSizeMod4G = %08X [=%lu]",
//ha//                   dwFileSizeLow, dwFileSizeHigh, ddFileSizeLarge, ddFileSizeLarge, dwFileSizeBlocks1G, dwFileSizeMod4G, dwFileSizeMod4G);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG STOP haCryptFileT - DoTxtFileCopy", MB_OK);
//ha//}
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{                
//ha//sprintf(DebugBuf, "ln = %08X\nj = %i [j < %i]\nBytesRd = %llX [=%llu]", ln, j, dwFileSizeBlocks1G, lln, lln);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG STOP 3 haCryptFileT - DoTxtFileCopy", MB_OK);
//ha//}
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//  DWORD __lastErr = GetLastError();
//ha//  DWORD __errNr = CommDlgExtendedError();
//ha//
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("_lastErr = %08X\nGetLastError() = %08X\nCommDlgExtendedError() = %08X"), _lastErr, __lastErr, __errNr);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG STOP 0"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
