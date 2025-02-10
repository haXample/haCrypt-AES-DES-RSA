// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptFileC.cpp - C++ Developer source file.
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
#include <shlwapi.h>   // Library shlwapi.lib for PathFileExistsA
#include <commctrl.h>  // Library Comctl32.lib               
#include <winuser.h>   // contains: #if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP) typedef HANDLE HDWP; #endif                                                                            
#include <commdlg.h>
#include <tchar.h>

#include <stdlib.h>
#include <string.h>
#include <string>      // sprintf, etc.
#include <strsafe.h>

typedef HANDLE HDWP;	 // needed in <shlobj_core.h> for 'x64' ha reduced VC 2019 installation 
#include <shlobj.h>    // Typical Shell header file, for browsing directory info (#include(s) <shlobj_core.h>!)

#include <unknwn.h>    // For browsing directory info

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

TCHAR szCountBuf[2*COUNTBUF_SIZE];       // Temporary buffer for formatted text
int szCountBufsize = sizeof szCountBuf;
TCHAR* pszCountBuf = szCountBuf;

char DebugBuf[2*MAX_PATH+1];             // Temporary buffer for formatted UNICODE text
int DebugbufSize = sizeof(DebugBuf);
char* psz_DebugBuf = DebugBuf;

TCHAR _tDebugBuf[2*MAX_PATH+1];          // Temporary buffer for formatted UNICODE text
int _tDebugbufSize = sizeof(_tDebugBuf);
TCHAR* psz_tDebugBuf = _tDebugBuf;

TCHAR _tTimeBuf[MAX_PATH+1];             // File Time&Date buffer
int _tTimebufSize = sizeof(_tTimeBuf);
TCHAR* psz_tTimeBuf = _tTimeBuf;

DWORD dwFileSizeHigh, dwFileSizeLow;              // Filesize MOD 4Gbyte
LPDWORD lpFileSizeHigh = (DWORD*)&dwFileSizeHigh; // Filesize * 4Gbyte

ULONG dwFileSize, dwCryptFileSize;

LPSTR pszCryptFileIn = NULL, pszCryptFileDisplay = NULL, pszTextFileIn = NULL;
LPSTR pszHexTxtFileIn, pszCryptFileOut;

TCHAR* pszFileExtensionFilter = _T(" Arc Files (.txt .doc .xls .mp3 ..\x20)\0 \
*.a*;*.b*;*.d*;*.f*;*.g*;*.j*;*.l*;*.m*;*.p*;*.r*;*.s*;*.t*;*.w*;*.x*;*.z*;*.3*\0 \
All files and shortcut targets (*.*)\0*.*\0\0");    //All Files\0*.*\0\0

TCHAR _mdfpath[MAX_PATH+1]       = _T(""); // Multifile destination path
TCHAR mdPathSave[MAX_PATH+1];              // Multifile destination path save
TCHAR _msfpath[MAX_PATH+1]       = _T(""); // Multifile source path
TCHAR msPathSave[MAX_PATH+1];              // Multifile source path save
TCHAR szFileNameSav[MAX_PATH+1] = _T("");
TCHAR szNextFile[MAX_PATH+1]    = _T("");  // Global
TCHAR szSrcFileName[MAX_PATH+1];

TCHAR* pszNextFile;
TCHAR* pszNextFileName;
TCHAR* pszSrcName = NULL;

PCTSTR pszLast, pszLastExt;                // Global

int fCount, pCount,_valAQ, _valCK;         // Global
int multiFileFlag = FALSE, largeFileFlag = FALSE, skipFlag, _flag29K;
int _multiFileBrowserFlag = MF_UNCHECKED;  // Initially turned off

DWORD _lastErr, _dlgErr;  // Global storage for 'GetLastError() / CommDlgExtendedError()'
                                                                                                  
// Global extern variables
extern ULONG ln, FileProcessingMode;
extern int _hexMode, _escFlag, _escAbort, textColor, renameFlag;
 
extern TCHAR szFileExtension[]; // = szFileExtensionAe; 
extern TCHAR szSrcName[];
extern TCHAR szDestName[];
extern TCHAR szPathSave[];

extern TCHAR* pszTxtWr;

extern HANDLE hSrcFile;   // Handle of source file.

//extern TCHAR szErrorMemoryAlloc[];
extern TCHAR szErrorFileSizeAES[];
extern TCHAR szErrorFileSizeDES[];
extern TCHAR szStatusClear[];

extern TCHAR szCryptAlgoTitle_DECIPHER[];
extern TCHAR szCryptAlgoTitle_ENCRYPT[];
extern TCHAR szCryptAlgo_SAVE[];

extern HINSTANCE g_hInst; // Main hInstance

extern HWND hMain;
extern HWND hTool;
extern HWND hEdit;
extern HWND hStatusbar;
extern HWND hButtonHex;
extern HWND hButtonDelim; // Dummy Button (invisible)

extern BROWSEINFO bi;
extern LPITEMIDLIST pidlPathSave;  

// External functions declaration
extern void InitProgressbar(ULONG);
extern void DisplayProgressCount(ULONG, int); // Progressbar and numeric count display
extern void DestroyProgressbar();

extern void PaintColoredStatusMsg(TCHAR*);
extern void DisplayLastError(int);

extern void GetCryptoModeText(int);
extern void Bin2Txt(); 
extern void Bin2Hex(int); 

extern void ControlCryptoToolItems(int, int);
extern void ControlToolWindow(int);
extern void ControlCryptoMenu(const int);
extern void ControlFileMenu(const int);
extern void CtrlHideShowWindow(HWND, int);
extern void ShowWinMouseClick(HWND, int, int, int); 
extern BOOL CheckEscapeAbort();

extern BOOL DoLargeBinFileCrypto(HWND, int);
extern BOOL FileBlockCrypto(HANDLE, int);

extern BOOL MfSaveBrowserDialog();

extern INT_PTR CALLBACK DialogProcMultiFile(HWND, UINT, WPARAM, LPARAM); 

// Forward declaration of functions included in this code module:
void DoBinFileCrypto(HWND, int);
BOOL LoadBinFileCrypto(int);
BOOL SaveBinFile(TCHAR*);

//-----------------------------------------------------------------------------
//
//                      GetGetLastWriteTime
//
//typedef struct _FILETIME {
//  DWORD dwLowDateTime;
//  DWORD dwHighDateTime;
//} FILETIME, *PFILETIME, *LPFILETIME;
//
//typedef struct _SYSTEMTIME {
//  WORD wYear;
//  WORD wMonth;
//  WORD wDayOfWeek;
//  WORD wDay;
//  WORD wHour;
//  WORD wMinute;
//  WORD wSecond;
//  WORD wMilliseconds;
//} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;
//
// Usage
//    HANDLE hFile;
//    TCHAR szBuf[MAX_PATH];
//
//    if (GetLastWriteTime( hFile, szBuf, MAX_PATH ))
//        _tprintf(TEXT("Last write time is: %s\n"), szBuf);
//
// GetLastWriteTime - Retrieves the last-write date/time and converts
//                    the date/time to a string
//
// hFile      - Valid file handle
// lpszString - Pointer to buffer to receive string
//
void GetLastWriteTime(TCHAR* szFileName, LPTSTR lpszString, DWORD lpszStringSize)
  {
  FILETIME ftCreate, ftAccess, ftWrite;
  SYSTEMTIME stUTC, stLocal;
  DWORD dwRet;

  HANDLE hFile = CreateFile(
    szFileName,
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    0,
    NULL);

  // Retrieve time & Date of the file.
  GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite);
  CloseHandle(hFile); 
  
  // Convert the last-write time to local time.
  FileTimeToSystemTime(&ftWrite, &stUTC);
  SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

  // Build a string (lpszString) showing the date and time.
  StringCchPrintf(lpszString, lpszStringSize, TEXT("%02d.%02d.%d %02d:%02d:%02d"),
                          stLocal.wDay, stLocal.wMonth, stLocal.wYear,
                          stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
  } // GetLastWriteTime

//-----------------------------------------------------------------------------
//
//                      TruncateFilePath
//
// TCHAR szNextFile[MAX_PATH+1] = _T("");
// TruncateFilePath((PWSTR)szNextFile);
//
TCHAR szDots[] =_T("...");
TCHAR szTruncPath0[MAX_PATH+1];
TCHAR szTruncPath1[MAX_PATH+1];
TCHAR szTruncPath2[MAX_PATH+1];
PWSTR szTruncPath = szTruncPath1;

void TruncateFilePath(PWSTR szLongPath, int _slenMAX, int _mode)  
  {                                     
  int _slenP, _slenF, _slenTP, i;
  
  _slenP = lstrlen(szLongPath);  // _slenP does not include 0-terminator
  for (i=0; i<=_slenP; i++)      // Also copy the 0-terminator (i<=_slenP) 
   {
   szTruncPath0[i] = szLongPath[i]; 
   szTruncPath1[i] = szLongPath[i]; 
   szTruncPath2[i] = szLongPath[i]; 
   }

  if (_mode == 0)  // File mode
    {
    PathStripPathW(szTruncPath0);      // Build filename only
    _slenF = lstrlen(szTruncPath0);    // Length of filename

    szTruncPath1[_slenP -_slenF] = 0;  // Build path w/o filename
    }

  if (_slenP > _slenMAX)               // String is to long to fit into window
    {
    szTruncPath2[20] = 0;              // Truncate path+filename
    lstrcat(szTruncPath2, szDots);     // Build 1st part of truncated path
  
    // Build a truncated path of calculated length
    //  in order to keep some distance to the window's border.
    if (_mode == 0)  // File mode
      {
      _slenTP = _slenMAX - (20 + 3 +_slenF);
      lstrcat(szTruncPath2, &szTruncPath1[_slenP -_slenF - _slenTP]); 
      lstrcat(szTruncPath2, szTruncPath0); // Build truncated file path
      }
    else // Directory mode = 1
      {
      _slenTP = _slenP - _slenMAX + 20 + 3;// + _slenMAX + (20 + 3 +_slenP);
      lstrcat(szTruncPath2, &szTruncPath1[_slenTP]); 
      }
    }

  szTruncPath = szTruncPath2;              // szTruncPath (global used outside)
  } // TruncateFilePath


//-----------------------------------------------------------------------------
//
//                      CheckInvalidFileName
//
BOOL CheckInvalidFileName(TCHAR* pszSrcName, TCHAR* pszDestName)
  {
  TCHAR* pszLast;
  int i;
  
  // Stop 'StrRStrI()' at '.' of last extension
  pszLast = (TCHAR*)&pszDestName[lstrlen(pszDestName)-lstrlen(szFileExtension)];    
  
  // Get filename only
  for (i=0; i<=lstrlen(pszDestName); i++) szTruncPath0[i] = pszDestName[i]; 
  PathStripPathW(szTruncPath0);      

  // Build save-filename
  skipFlag = FALSE;
  if (StrStrI(pszLast, szFileExtension) == NULL)
    lstrcat(pszDestName, szFileExtension);       
  else if (lstrcmp(szTruncPath0, pszSrcName) == 0) skipFlag = TRUE;

  return(skipFlag);
  } // CheckInvalidFileName


//-----------------------------------------------------------------------------
//
//                      DisplayListMultipleFiles
//
BOOL DisplayListMultipleFiles(TCHAR* _fName)
  {
  // List the files in edit window
  int index = GetWindowTextLength(hEdit);
   
  if (index < ((28*1024)+300) && _flag29K == FALSE)              // ~29K
    {
    SetFocus (hEdit);                                            // Set focus
    SendMessage(hEdit, EM_SETSEL, (WPARAM)index, (LPARAM)index); // Select end of text
    if (skipFlag == FALSE)
      SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)_fName);      // Append.
    else
      {
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("%s (skipped)"), _fName); 
      SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)_tDebugBuf);  // Append.
      }
    index = GetWindowTextLength(hEdit);
    SendMessage(hEdit, EM_SETSEL, (WPARAM)index, (LPARAM)index); // Again: Select end of text
    SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)(LPARAM)_T("\x0D\x0A")); // Append "\n"
    }

  else if (_flag29K == FALSE)
    {
    SetFocus (hEdit);                                             // Set focus
    SendMessage(hEdit, EM_SETSEL, (WPARAM)index, (LPARAM)index);  // Select end of text
    StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("---The displayed text is truncated at about 29K---")); 
    SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)_tDebugBuf);     // Append.
    _flag29K = TRUE;
    } 

  return(TRUE);
  } // DisplayListMultipleFiles

//-----------------------------------------------------------------------------
//
//                           LoadBinFileCrypto
//
BOOL LoadBinFileCrypto(int cryptMode)
  {
  BOOL bSuccess = FALSE;
  
  dwCryptFileSize = dwFileSizeLow;
  dwFileSize = dwCryptFileSize; // dwFileSize: Needed for progressbar & Crypto algo, 

  if ((dwCryptFileSize < DES_BLOCK_SIZE)                       &&
      (((FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_DES)   ||
       ((FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_TDES))
      )
    {
    dwCryptFileSize = _ERR;     // (-1) = 0xFFFFFFFF = Invalidate dwCryptFileSize
    StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%s - %s"), pszNextFileName, szErrorFileSizeDES); 
    DisplayLastError(_ERR);     // Display formatted _tDebugBuf contents
    CloseHandle(hSrcFile);
    return(bSuccess);
    }

  if ((dwCryptFileSize < AES_BLOCK_SIZE) &&
      ((FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_AES))
    {
    dwCryptFileSize = _ERR;     // Invalidate dwCryptFileSize
    StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%s - %s"), pszNextFileName, szErrorFileSizeAES); 
    DisplayLastError(_ERR);     // Display formatted _tDebugBuf contents
    CloseHandle(hSrcFile);
    return(bSuccess);
    }

  // -----------------------
  // Allocate global buffers
  //                                
  // Free possibly occupied /TEXT memory Only if not already freed
  if (pszTextFileIn != NULL) pszTextFileIn = (LPSTR)GlobalFree(pszTextFileIn);
    
  // Free occupied hex/txt display buffer
  if (pszCryptFileDisplay != NULL) pszCryptFileDisplay = (LPSTR)GlobalFree(pszCryptFileDisplay);

  // Free previously allocated buffer to get enough memory intercepting the crypto data
  if (pszCryptFileIn != NULL) pszCryptFileIn = (LPSTR)GlobalFree(pszCryptFileIn);

  pszCryptFileIn      = (LPSTR)GlobalAlloc(GPTR, dwCryptFileSize + AES_BLOCK_SIZE + 1); // +ISO BLOCK PAD (AES,DES,3DES)
  pszCryptFileDisplay = (LPSTR)GlobalAlloc(GPTR, CRYPT_TEXT_MAXSIZE*(3+1) + 1);         // Allocate hex/txt display buffer

  pszCryptFileOut = pszCryptFileIn;  // Dummy, but still needed. Used by most Crypto functions (except DES-ECB)
  pszHexTxtFileIn = pszCryptFileIn;  // For hex/text display

  // Check if the necessary allocated buffer is available
  if (pszCryptFileIn == NULL || pszCryptFileDisplay == NULL)
    {
    dwCryptFileSize = _ERR;          // Invalidate dwCryptFileSize
    DisplayLastError(HA_ERROR_MEMORY_ALLOC);
    CloseHandle(hSrcFile);
    return(bSuccess);
    }

  // Process the input file
  // ----------------------
  // Skip FileBlockCrypto(..) if skipFlag == TRUE
  if (CheckInvalidFileName(pszSrcName, mdPathSave) == FALSE)  
    {
    EnableWindow(hButtonHex, FALSE);  // Disable Hex/Txt Button
    if (FileBlockCrypto(hSrcFile, cryptMode) == FALSE) bSuccess = FALSE;    
    else bSuccess = TRUE;             // File has been successfuly processed
    }
  else bSuccess = TRUE;

  CloseHandle(hSrcFile);
  return bSuccess;                    // Return status of operation
  } // LoadBinFileCrypto


//-----------------------------------------------------------------------------
//
//                           LoadBinFile
//
BOOL LoadBinFile(TCHAR* pszFileName, int cryptMode)
  {
  BOOL bSuccess = FALSE;
  
  hSrcFile = CreateFile(
    pszFileName,
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL,              
    OPEN_EXISTING,
    0,
    NULL);

  pszSrcName = pszFileName; // Init globals

  _escFlag = FALSE;         // Reset any pending ESC-Abort condition

  // ... ?? Put in here, if needed: Request ownership of the critical section ... ??
  if (hSrcFile != INVALID_HANDLE_VALUE)
    {
    // LPDWORD lpFileSizeHigh (used only if > 4Gbyte should be allowed).
    //  A pointer to the variable where the high-order doubleword
    //  of the file size is returned. This parameter can be NULL
    //  if the application does not require the high-order doubleword.
    //
    //dwFileSizeLow = GetFileSize(hSrcFile, NULL);          // <   4Gbyte only
    dwFileSizeLow = GetFileSize(hSrcFile, lpFileSizeHigh);  // >= 4Gbyte allowed.               


    // Check filesize (minimum and maximum)
    // ------------------------------------
    // Maximum memory buffer size possible (average):
    //  2 * (800*1024*1024) --> dwCryptFileSize ~ 2*3200000h (~ 1600Mbyte)
    // Thus here we'll do large file processing if filesize > 1Gbyte
    // This prevents the "Insufficient Memory" error, as 1G is mostly available.
    //
    if (dwFileSizeHigh != 0 || dwFileSizeLow > FILE_BLOCK_1G)   
      {
      // If large files are not supported: Abort with "Insufficient Memory" error
      //StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%s - %s"), pszNextFileName, szErrorMemoryAlloc); 
      //DisplayLastError(_ERR);   // Display formatted _tDebugBuf contents
      //CloseHandle(hSrcFile);
      //return(bSuccess);         

      // Large files are supported. Process large files > 1Gbyte
      largeFileFlag = TRUE;       // TRUE = Multifile processing for large files
      bSuccess = DoLargeBinFileCrypto(hMain, cryptMode);
      }

    else // Process files <= 1Gbyte
      {
      largeFileFlag = FALSE;      // FALSE = Standard multifile processing
      bSuccess = LoadBinFileCrypto(cryptMode);
      }
    CloseHandle(hSrcFile);        // Release file handle
    } // end if (hSrcFile)

  else
    {                             // Invalid Handle = 0xFFFFFFFF
    _lastErr = GetLastError();    // = ERROR_SHARING_VIOLATION
    DisplayLastError(_lastErr);   // Display error message
    }
  return bSuccess;                // Return status of operation
  } // LoadBinFile


//-----------------------------------------------------------------------------
//
//                      SaveMultiBinFile
//
BOOL SaveMultiBinFile(HWND _hwnd)
  {
  BOOL bSuccess = FALSE;
  int i, index=0;

  //struct _stat fstatBuf;      // Size <  4Gbyte
  struct __stat64 fstatBuf64;   // Size >= 4Gbyte
  __int64 fsize64;

  skipFlag = CheckInvalidFileName(pszSrcName, pszNextFile);

  // Copy (re-format) TCHAR* pszNextFile  --> TCHAR pszNextFile[]
  for (i=0; i<=lstrlen(pszNextFile); i++) szNextFile[i] = pszNextFile[i];

  if (PathFileExists(szNextFile) && skipFlag == FALSE)  // Checking for file existence
    {                                  
    GetLastWriteTime(szNextFile, _tTimeBuf, MAX_PATH);

    //int _wstat(
    //   const wchar_t *path,
    //   struct _stat *buffer
    //);
    //_wstat(szCryptoDestName, &fstatBuf);
    //fsize64 = (__int64)fstatBuf.st_size;       // Only size < 4Gbyte

    //int _wstat64(
    //   const wchar_t *path,
    //   struct __stat64 *buffer
    //);
    _wstat64(szNextFile, &fstatBuf64);           // Size >= 4Gbyte
    fsize64 = fstatBuf64.st_size;

    // Calculate [KB] like WINDOWS-Explorer
    int fsRounding = 1;                          // Round to next higher KB value
    if ((fsize64 % 1024LL) == 0) fsRounding = 0; // Don't round exact values

    TruncateFilePath((PWSTR)szNextFile, 55, 0);  // Should fit nicely into dialogbox
    StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT(" \
%s\n \
Size: %lld KB\n \
Change Date: %s"), szTruncPath, //szNextFile, //szTruncPath
                   (fsize64==0LL ? 0LL : (fsize64/1024LL)+(__int64)fsRounding),
                   _tTimeBuf);
    
    // Multifile selection Modal DialogBox "Confirm overwriting file(s)"
    // "[Yes]" "[Yes to all]" "[No]" "[No to all]" "[Cancel]"
    if (_valAQ == 0 || (_valAQ == A_YES) || (_valAQ == A_NO))
      DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_FILEC), hMain,
                     DialogProcMultiFile, IDD_HACRYPT_FILEC);

    // Skip saving file and keep the existing file(s) untouched
    if ((_valAQ == A_NOALL) || (_valAQ == A_NO) || (_valAQ == A_CANCEL))
      {
      CloseHandle(hSrcFile);              // Release file handle
      return(TRUE); 
      }
    } // end if (PathFileExists)

  // Display file to be saved in status area (1) 
  SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)pszNextFile);

  if (skipFlag == FALSE)                  // File is valid
    {
    //-----------
    // Write file
    //
    // Ensure the character case sensitivity is the same as shown in edit field,
    // e.g. may be "*.d_d" --> should be "*.D_d", etc.. System is case insensitive.
    // We possibly rename the extension without actually changing the filename.
    // Ensure the correct look of the file extension before the file is re-created.
    if (PathFileExists(szNextFile)) _wrename(szNextFile, szNextFile);             

    if (SaveBinFile(szNextFile))
      {
      pCount++;                           // Count the files being saved
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("File %i saved..."), pCount); 
      SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)_tDebugBuf);
      SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)szNextFile);
      bSuccess = DisplayListMultipleFiles(szTruncPath0);
      }

    // SaveBinFile() failure
    else if (_escAbort == FALSE && _lastErr != ERROR_SUCCESS)
      {
      DisplayLastError(_lastErr);
      return(bSuccess);
      }
    else if (_escAbort == FALSE)
      {
      DisplayLastError(HA_ERROR_FILE_WRITE);
      return(bSuccess);
      }
    } // end if (skipFlag == FALSE)

  else // skipFlag == TRUE                // Invalid file extension
    bSuccess = DisplayListMultipleFiles(szTruncPath0);

  return(bSuccess);
  } // SaveMultiBinFile


//-----------------------------------------------------------------------------
//
//                      MultiBinFileOpen
//
OPENFILENAME ofn={0};                         // Global
// Enough to multiselect about 2000 short filenames (DOS Convention 8.3 assumed)
TCHAR ofnFileName[100*MAX_PATH+1] = _T("");   // Global to remember the 'ofn.lpstrInitialDir' 
                                              // Bufsize = 100*MAX_PATH ~ 26K (should be enough)
//ha//void MultiBinFileOpen(HWND _hwnd, int cryptMode)
BOOL MultiBinFileOpen(HWND _hwnd, int cryptMode)
  {
  int i, bSuccess = TRUE;
  TCHAR* ptr;
  LPCWSTR szOpenTitle = _T(""); 
  
  // Set the title of open dialog box
  if (cryptMode == ENCRYPT) szOpenTitle = szCryptAlgoTitle_ENCRYPT; //_T(" /Encrypt - Open file(s)");
  else szOpenTitle = szCryptAlgoTitle_DECIPHER;                     //_T(" /Decipher - Open encrypted file(s)");

  ZeroMemory(&ofn, sizeof(OPENFILENAME));

//ha//  // ---------------------------------- !!!! wont remember last loaded path if placed here !!!!
//ha//  // IMPORTANT!  IMPORTANT!  IMPORTANT!
//ha//  // Necessary to prevent CommDlgExtendedError() = 0x3002 on next invocation.
//ha//  // (only if multiple files are selected, ...won't occur if single file).
//ha//  ofnFileName[0] = 0; // IMPORTANT! - Initialization.
//ha//  // ----------------------------------

  ofn.lStructSize       = sizeof(OPENFILENAME);
  ofn.hwndOwner         = _hwnd;   
  ofn.lpstrFilter       = pszFileExtensionFilter;
  ofn.lpstrFile         = ofnFileName;
  ofn.nMaxFile          = 100*MAX_PATH+1;         // Bufsize = 100*MAX_PATH ~ 26K 
  ofn.lpstrDefExt       = _T("");                 // NULL; // No auto appending any extension
  ofn.lpstrInitialDir   = ofnFileName;
  ofn.lpstrTitle        = szOpenTitle;            //NULL;
  ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_ALLOWMULTISELECT; // | OFN_NOCHANGEDIR;

  // Determine how many files are selected
  if (GetOpenFileName(&ofn)) 
    {
    ptr = ofn.lpstrFile;          // Init ptr to multifile array

    // Init multifile source path
    for (i=0; i<=lstrlen(ptr); i++) _msfpath[i] = ptr[i];  
    _msfpath[ofn.nFileOffset-1] = 0; // Terminate path (there is no '\' at end of pathname (except drive letters))

    if (!(lstrlen(_msfpath) == 3 && _msfpath[1] == L':')) // Drive letter already comes with '\'
      lstrcat(_msfpath, TEXT("\\")); // Append '\' only if not a drive letter, e.g. 'H:\'

    pszNextFile = ptr;            // Save the first path & filename for later
    ptr += ofn.nFileOffset;       // Skip path

    fCount=0;
    while (*ptr)                  // Any file present?
      {
      fCount++;                   // Count the files
      ptr += (lstrlen(ptr)+1);    // Advance to next file
      } // end while

    //----------------------------------------------------------------------
    // If a single file is selected do the standard GetSaveFileName() dialog
    //
    if (fCount == 1)
      {
      // Single file: Display CryptMode loading ...
      GetCryptoModeText(cryptMode);
      SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)pszNextFile);

      pszNextFileName = pszNextFile + ofn.nFileOffset;
      
      // Display filename in mainwindow's title field
      SetWindowText(_hwnd, pszNextFile);  

      // Init "Save as .." path for later (appended with appropriate file extension)
      StringCbCopyW(szFileNameSav, sizeof(szFileNameSav), pszNextFile); 
      lstrcat(szFileNameSav, szFileExtension); // Append the initial crypto extension

      multiFileFlag = FALSE;                    // Display crypto text
      _hexMode = FALSE;                         // Set Text display, i.e. reset hex mode

      //--------------------------
      // Process the file contents
      //
      if (LoadBinFile(pszNextFile, cryptMode) == FALSE) return(FALSE);

      ControlCryptoMenu(MF_ENABLED);            // Allow saving crypto file
      CtrlHideShowWindow(hButtonHex,  SW_SHOW); // Allow Hex/Text toggle

      return(bSuccess);
      } // end if (fCount==1)      

    //-----------------------------------------------------------------------
    // If multiple files are selected
    //  open a dialog box to choose a folder where to save the selected files
    //

    // ---------------------------------- !!!! must be placed here !!!! ------
    // IMPORTANT!  IMPORTANT!  IMPORTANT!
    // Necessary to prevent CommDlgExtendedError() = 0x3002 on next invocation.
    // (only if multiple files are selected, ...won't occur if single file).
    ofnFileName[0] = 0; // IMPORTANT! - Initialization.
    // ---------------------------------- !!!! must be placed here !!!! ------

    if (MfSaveBrowserDialog() == FALSE)  // See 'haCryptBrowse.cpp'
      {
      pCount=0;
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("%i File(s) saved."), pCount); 
      SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_tDebugBuf);
      SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)_mdfpath);
      return(FALSE);
      }
    //
    // End of dialog box to choose a folder where to save the selected files
    //----------------------------------------------------------------------

    SetFocus(hEdit);               // Set cursor into text field
    SetWindowText(hEdit, NULL);    // Init-clear the Text Field
    //-------------------------------
    // 'Rename file extension' dialog
    //
    GetCryptoModeText(cryptMode);  // Set file extension string and crypt mode text
    // Modal DialogBox to rename the file extension (Multiple files)
    DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_FILEX), hMain,
                   DialogProcMultiFile, (LPARAM)IDD_HACRYPT_FILEX);
    if (_valAQ == A_CANCEL) return(FALSE);

    //----------------------------------------------------------- 
    // Continue multiple files (without GetSaveFileName() dialog)
    //
    multiFileFlag = TRUE;            // Don't display any crypto text
    _flag29K = FALSE;                // Flag an empty text field buffer


    ptr = ofn.lpstrFile;             // Init ptr to multifile array
    ptr[ofn.nFileOffset-1] = 0;      // Terminate source path (there is no '\' at end of pathname)

    SetWindowText(_hwnd, _msfpath);  // Display source path in mainwindow's title field

    ptr += ofn.nFileOffset;          // Skip source path and point to 1st filename

    ControlCryptoToolItems(MF_ENABLED, FALSE);   
    ControlToolWindow(FALSE);
    //EnableWindow(hTool, FALSE);   
    SendMessage(hEdit, EM_SETREADONLY, TRUE, 0);  // Disable text field for crypto data edit

    pCount=0; _valAQ=0;
    while (*ptr)
      {
      // Stop multifile processing if cancelled and keep file(s) untouched
      if (_valAQ == A_CANCEL) break;

      //hEdit = GetDlgItem(_hwnd, IDC_MAIN_EDIT);
      pszNextFile = ptr;             // Save next filename
      ptr += (lstrlen(ptr)+1);       // Advance ptr (+ 0-terminator)

      // Multiple files: Display CryptMode loading ...

      pszNextFileName = pszNextFile;
  
      // Re-build selected paths  (copy inclusive 0-terminator)
      for (i=0; i<=lstrlen(_mdfpath); i++)  mdPathSave[i] = _mdfpath[i];     
      for (i=0; i<=lstrlen(_msfpath); i++)  msPathSave[i] = _msfpath[i];     
      lstrcat(mdPathSave, pszNextFile);  // Concatenate dest path & filename
      lstrcat(msPathSave, pszNextFile);  // Concatenate src path & filename

      // At this point:
      // _mdfpath = Pointer to dest folder path (without filename)
      // _msfpath = Pointer to src folder path (without filename)
      // mdPathSave = pointer to complete destination filepath  (folder+filename)
      // msPathSave = pointer to complete source filepath (folder+filename)
      // pszNextFile = pointer to filename (without folder path)
      // pszNextFileName = pointer to filename
      //
      SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)msPathSave);

      //-------------------------------------------
      // Process next file contents, abort on error
      //
      if ((bSuccess = LoadBinFile(pszNextFile, cryptMode)) == FALSE) break;  

      // Re-init selected path (Add the path to pszNextFile again)
      pszNextFile = mdPathSave; // Init 'pszNextFile' for 'SaveMultiBinFile()'

      EnableWindow(hButtonHex, FALSE); // Disable Hex/Txt button

      // Save each file directly without any dialog (Display saving ...)
      if (largeFileFlag == FALSE)
        {
        if (SaveMultiBinFile(_hwnd) == FALSE) break;  // return;
        }
      } // end while

    SetWindowText(_hwnd, _mdfpath); // Display path in mainwindow's title field

    if (bSuccess == TRUE)
      {
      // Programmatically send the 'F5' (refresh command) to Windows Explorer
      if (pCount > 0)
        SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATH, _mdfpath, NULL); // "F5"-key simulation

      StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("%i File(s) processed."), pCount); 
      SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_tDebugBuf);
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("%s*%s"), _mdfpath, szFileExtension); 
      SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)_tDebugBuf);
      ControlCryptoMenu(MF_GRAYED);

      //---------------------------------------------------------------
      // Show a browser dialog with the processed files filtered     //|
      renameFlag = FALSE;                                            //|
      extern int BrowserFilterFileType(LPWSTR, LPWSTR);              //|
      if (_multiFileBrowserFlag == MF_CHECKED)                       //|
        BrowserFilterFileType(szFileExtension, _mdfpath);            //|
      //---------------------------------------------------------------
      }
    } // end if (GetOpenFile())

  else // else (Getopenfilename())
    {
    // "CommDlgExtendedError() 12290=0x00003002"  USB SD Folder
    // Error code 12290=0x3002 (CommDlgExtendedError) when running a
    //  "Save [...]" command and the latest path was a network path containing a dot
    //    ----------------------------------
    //    IMPORTANT!  IMPORTANT!  IMPORTANT!
    //    Necessary to prevent CommDlgExtendedError() = 0x3002  on next invocation.
    //    (only if multiple files are selected, ...won't occur if single file).
    // ofnFileName[0] = 0; // IMPORTANT! - Initialization.
    //    ----------------------------------
    // DWORD _dlgErr = CommDlgExtendedError();
    // Error codes can be returned for GetOpenFileName and GetSaveFileName:
    //  0x00003003 = FNERR_BUFFERTOOSMALL (too many file selected)
    //   The first two bytes of the lpstrFile buffer contain an integer value 
    //   specifying the size required to receive the full name, in characters.
    //   [sizeRequired = (int)ofnFileName[0];  // not implemented.]
    //  0x00003002 = FNERR_INVALIDFILENAME (Invalid filename) 
    //
    bSuccess = FALSE;

    _dlgErr = CommDlgExtendedError();  

    // Display filename in mainwindow's title field
    if (lstrlen(pszNextFile) > sizeof(void*) &&
        multiFileFlag == FALSE               &&
        pszCryptFileIn != NULL)
      {
      ControlFileMenu(MF_ENABLED);
      SetWindowText(_hwnd, pszNextFile);
      }   
    else ControlCryptoMenu(MF_GRAYED);

    if (_dlgErr == FNERR_INVALIDFILENAME)
      {
      //DisplayLastError(_dlgErr);
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("FNERR_INVALIDFILENAME - 0x%04X  [%i]"), _dlgErr, _dlgErr); 
      DisplayLastError(_ERR);     // Display formatted _tDebugBuf contents
      }
    else if (_dlgErr == FNERR_BUFFERTOOSMALL) DisplayLastError(HA_TOO_MANY_FILES);
    else DisplayLastError(HA_NO_FILE_SELECTED);

    if (pszCryptFileIn != NULL      &&
        pszCryptFileDisplay != NULL &&
        multiFileFlag == FALSE)
      {
      _hexMode = FALSE;               // Set text display
      EnableWindow(hButtonHex, TRUE); // Enable Hex/Txt Button
      }
    }

  SendMessage(hEdit, EM_SETREADONLY, FALSE, 0); // Disable text field for crypto data edit
  return(bSuccess);
  } // MultiBinFileOpen


//-----------------------------------------------------------------------------
//
//               DoBinFileOpen (invoke explorer Dialog: "Open")
//
//ha//void DoBinFileOpen(HWND _hwnd, int cryptMode)
BOOL DoBinFileOpen(HWND _hwnd, int cryptMode)
  {
  int bSuccess = TRUE;

  // Remove-clear Progressbar 'Loading file'
  // Ensure the correct crypto item remains selected
  DestroyProgressbar();
  bSuccess = MultiBinFileOpen(_hwnd, cryptMode); // Open and process the file(s)

  ControlToolWindow(TRUE);
  ControlCryptoToolItems(MF_ENABLED, TRUE);   
  //EnableWindow(hTool, TRUE);    

  if (largeFileFlag == TRUE) ControlCryptoMenu(MF_GRAYED);
  else ControlCryptoMenu(MF_ENABLED);
      
  // If no crypto data in text field or if text filed is empty:
  // - Hide Hex/Txt Button
  // - Disable "Save as .." in crypto menus
  // - Multiple files: Invalidate last file's crypto data   
  if (multiFileFlag == TRUE || GetWindowTextLength(hEdit) == 0)
    {
    dwCryptFileSize = 0;                      // Invalidate last file's crypto data
    CtrlHideShowWindow(hButtonHex,  SW_HIDE); // Hide Hex/Txt Button
    ControlCryptoMenu(MF_GRAYED);             // Disable "Save as .." in crypto menu
    }
  multiFileFlag = FALSE;                      // Ensure normal handling

  // Simulate Mouseclick to make buttons re-appear
  ShowWinMouseClick(hButtonDelim, 1, 0, 0);  
  return(bSuccess);  
  } // DoBinFileOpen


//-----------------------------------------------------------------------------
//
//                           SaveBinFile
//
BOOL SaveBinFile(TCHAR* pszFileName)    // =(LPCTSTR pszFileName)
  {
  BOOL bSuccess = FALSE;
  int i, byteswr;
  DWORD dwWritten;
  _escFlag = FALSE;

  LPSTR pszFileOutbuf = pszCryptFileIn;

  _lastErr = ERROR_SUCCESS;             // Assume no errors

  HANDLE hFile = CreateFile(
    pszFileName, 
    GENERIC_WRITE, 
    0, 
    NULL,
    CREATE_ALWAYS, 
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, // | FILE_FLAG_NO_BUFFERING;
    NULL);

  if (hFile != INVALID_HANDLE_VALUE)
    {
    InitProgressbar(0L);     // Initialize the Progressbar (% counter only)
    ln = 0;
    do
      {
      if ((dwCryptFileSize-ln) < FILE_BLOCK_SIZE) byteswr = dwCryptFileSize % (FILE_BLOCK_SIZE);   // % 1M
      else byteswr = FILE_BLOCK_SIZE;                                                              // = 1M

      if (WriteFile(hFile, pszFileOutbuf, byteswr, &dwWritten, NULL)) bSuccess = TRUE;
      else 
        {
        _lastErr = GetLastError();
        DestroyProgressbar();
        CloseHandle(hFile);
        bSuccess = FALSE;
        break;
        }

      // Begin: --ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort
      // Here we allow to abort reading very lengthy files by pressing the ESC key
      if (CheckEscapeAbort() == TRUE)
        {
        DestroyProgressbar();
        CloseHandle(hFile);
        bSuccess = FALSE;
        break;
        }
      // End: --ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort

      for (i=0; i<dwWritten; i++) pszFileOutbuf++;   // Transfer / append the block read
      ln += byteswr; //dwWritten;                    // Update counter total bytes read
      DisplayProgressCount(ln, 2);                   // Display ln counter in KB on statusbar
      } while (ln < dwCryptFileSize);                // end do while

    // Remove-clear Progressbar 'Saving file'
    // Ensure the correct crypto item remains selected
    DestroyProgressbar();
    
    // Display saving ...  CloseHandle(hFile) sometimes produces delay
    if (bSuccess == TRUE)
      SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("Saving, please wait ..."));

    MSG msg;                                    // Dummy for PeekMessage()
    PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE); // Prevent "Not responding" system msg
                                                
    CloseHandle(hFile);                         // 'CloseHandle(hFile)' sometimes takes too long
    } // end if (hfile)                 
  
  else _lastErr = GetLastError();               // Save error code from 'CreateFile()'

  return bSuccess;
  } // SaveBinFile


//-----------------------------------------------------------------------------
//
//            DoBinFileSave (invoke explorer Dialog: "Save as..")
//
OPENFILENAME osfn;                         // Open save file (Global)
TCHAR osfnFileName[MAX_PATH+1] = _T("");   // Global to remember the 'osfn.lpstrInitialDir' 

void DoBinFileSave(HWND _hwnd)
  {
  if (dwCryptFileSize == 0)                // No data to write?
    {
    DisplayLastError(HA_ERROR_FILE_WRITE);
    return;
    }

  ZeroMemory(&osfn, sizeof(OPENFILENAME));

  // Remember the current paths (open file) (save file) for convenience
  if (osfnFileName[0] == 0) lstrcpy(osfnFileName, szFileNameSav); // Initial path
  else                                                            // All other paths
    {
    TCHAR szFileNameSav2[MAX_PATH+1] = _T("");             // Temporary filname buffer
    lstrcpy(szFileNameSav2, szFileNameSav);                // Save incoming path (MAX_PATH+1)
    PathRemoveFileSpec(osfnFileName);                      // Build pathname only
    PathStripPathW(szFileNameSav2);                        // Build filename only

    // Append '\' (has been stripped off by PathRemoveFileSpec)
    // However, '\' is not stripped off at drive letters like 'H:\' (appending '\' not required) 
    if (lstrlen(osfnFileName) > 3) StringCbCat(osfnFileName, MAX_PATH+1, _T("\\"));

    StringCbCat(osfnFileName, MAX_PATH+1, szFileNameSav2); // Build Last path + actual filename
    }
     
  osfn.lStructSize    = sizeof(OPENFILENAME);
  osfn.hwndOwner      = _hwnd;
  osfn.lpstrFilter    = pszFileExtensionFilter;
  osfn.lpstrFile      = osfnFileName; //szFileNameSav;
  osfn.nMaxFile       = MAX_PATH+1;
  osfn.lpstrDefExt    = _T("");   //NULL; // No auto appending any extension
  ofn.lpstrInitialDir = osfnFileName;
  osfn.lpstrTitle     = szCryptAlgo_SAVE; //_T(" Save encrypted/deciphered data");   //NULL;
  osfn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;

  // ATTENTION! - Needed for XP: Touch text field to clear graphic mode
  // Otherwise the text window will not update (XP is still in graphic mode),
  //  which causes a messy text field when moving or aborting the browser dialog.
  SendMessage(hEdit, EM_SETREADONLY, FALSE, 0);  // XP workaround !

  if (GetSaveFileName(&osfn))
    {
    // Explorer dialog: Display saving ...
    PaintColoredStatusMsg(szStatusClear);
    SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); // Clean up statusbar from 'paint' 
    SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)osfnFileName);

    if (SaveBinFile(osfnFileName))  // ((LPCTSTR)osfnFileName)) // Write crypto data to file
      {
      StringCbPrintf(szCountBuf, sizeof szCountBuf, pszTxtWr, ln);
      SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)szCountBuf);
      }
    else if (_escAbort == FALSE && _lastErr != ERROR_SUCCESS) DisplayLastError(_lastErr);
      
    else if (_escAbort == FALSE) DisplayLastError(HA_ERROR_FILE_WRITE);
    } // end if

  else SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)TEXT("No Files saved..."));
  ShowWinMouseClick(hButtonHex, 1, 0, 0);  // Simulate Mouseclick to make button appear
  } // DoBinFileSave


//ha////--DEPRECATED-----------------------------------------------------------------
//ha////
//ha////                            DoBinFileCrypto
//ha////
//ha//// Called from 'haCryptFileC.cpp[LoadBinFile]'
//ha////  (only if (dwFileSizeHigh != 0 || dwFileSizeLow > FILE_BLOCK_1G))    
//ha////
//ha//void DoBinFileCrypto(HWND _hwnd, int cryptMode)
//ha//  {
//ha//  TCHAR szCryptoDestName[MAX_PATH];
//ha//  PTSTR pszCryptoDestName = szCryptoDestName;
//ha//  PTSTR ppszExt = NULL;
//ha//  
//ha//  //struct _stat fstatBuf;      // Size <  4Gbyte
//ha//  struct __stat64 fstatBuf64;   // Size >= 4Gbyte
//ha//  __int64 fsize64;
//ha//
//ha//  int i, _slenP, _slenF;
//ha//
//ha//  // Remove-clear Progressbar 'Loading file'
//ha//  // Ensure the correct crypto item remains selected
//ha//  DestroyProgressbar();
//ha//
//ha//  // Duplicate the external source filename for local usage
//ha//  for (i=0; i<MAX_PATH; i++) pszCryptoDestName[i] = pszSrcName[i];
//ha//
//ha//  // Set proposed file extension and allow the user
//ha//  //  to Rename the file extension (Modal DialogBox Rename)
//ha//  GetCryptoModeText(cryptMode);
//ha//
//ha//  if (multiFileFlag == FALSE)  // Already done in 'haCryptFileC.cpp[SaveMultiBinFile]'
//ha//    DialogBox(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_FILEX), NULL, DialogProcMultiFile);   
//ha//
//ha//  // At this point:
//ha//  // szFileExtension  = Pointer to the file extension string returned by the user
//ha//
//ha//  // Find the source filename's file extension (if any)
//ha//  ppszExt = PathFindExtension(pszCryptoDestName);
//ha//
//ha//  // Possible Buffer Overflow: _slenP + _slenF may not exceed MAX_PATH
//ha//  _slenF = lstrlen(ppszExt);                  
//ha//  _slenP = lstrlen(pszCryptoDestName);
//ha//
//ha//  //szCryptoDestName[_slenP - _slenF] = 0;         // Discard original file extension
//ha//  // Build save-filename (keep org file extension)
//ha//  pszLast = (PCTSTR)&pszCryptoDestName[_slenP-5];  // Stop 'StrRStrI()' at '.' of last extension
//ha//  if ((pszLastExt = StrStrI(pszLast, szFileExtension)) == NULL)
//ha//    //for (i=0; i<_slenF; i++) pszCryptoDestName[i+_slenP] = szFileExtension[i];
//ha//    lstrcat(pszCryptoDestName, szFileExtension);    // Build save-filename, append crypto extension
//ha//
//ha//  // At this point:
//ha//  // PTSTR pszCryptoDestName = File to be written. 
//ha//  //  if (multiFileFlag == FALSE)
//ha//  //    PTSTR pszCryptoDestName ==> Original filePATH with crypto extension (e.g. c:\test\abc.txt.A~e).
//ha//  //  if (multiFileFlag == TRUE) 
//ha//  //    PTSTR pszCryptoDestName ==> Original fileNAME with crypto extension (e.g. abc.txt.A~e).
//ha//  //
//ha//  if (multiFileFlag == FALSE) // Already done in 'haCryptFileC.cpp[SaveMultiBinFile]'
//ha//    {
//ha//    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)szCryptoDestName);
//ha//
//ha//    // Write colored info text into edit field
//ha//    int index = GetWindowTextLength(hEdit);
//ha//
//ha//    textColor = T_GREEN;                                         // Green
//ha//    SetFocus (hEdit);                                            // Set focus
//ha//    //PaintColoredStatusPercentMsg(_T("Press ESC to abort...")); // Alternatively use statusbar
//ha//    SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)_T("Large file. Press ESC to abort..."));    
//ha//    SendMessage(hEdit, EM_SETSEL, (WPARAM)index, (LPARAM)index); // Select end of text
//ha//    SetFocus (hMain);                                            // Deviate focus to hMain
//ha//    textColor = FALSE;                                           // Black
//ha//
//ha//    // Check file existence
//ha//    if (PathFileExists(szCryptoDestName))        // Checking for file existence
//ha//      {                                  
//ha//      GetLastWriteTime(szCryptoDestName, _tTimeBuf, MAX_PATH);
//ha//
//ha//      //int _wstat(
//ha//      //   const wchar_t *path,
//ha//      //   struct _stat *buffer
//ha//      //);
//ha//      //_wstat(szCryptoDestName, &fstatBuf);
//ha//      //fsize64 = (__int64)fstatBuf.st_size;       // Only size < 4gByte
//ha//
//ha//      //int _wstat64(
//ha//      //   const wchar_t *path,
//ha//      //   struct __stat64 *buffer
//ha//      //);
//ha//      _wstat64(szCryptoDestName, &fstatBuf64);     // Size >= 4Gbyte
//ha//      fsize64 = fstatBuf64.st_size;
//ha//
//ha//      // Calculate [KB] like WINDOWS-Explorer
//ha//      int fsRounding = 1;                          // Round to next higher KB value
//ha//      if ((fsize64 % 1024LL) == 0) fsRounding = 0; // Don't round exact values
//ha//
//ha//      TruncateFilePath((PWSTR)szCryptoDestName);   // Should fit nicely into dialogbox
//ha//      StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT(" \
//ha//%s\n \
//ha//Size: %lld KB\n \
//ha//Change Date: %s"), szTruncPath, //szCryptoDestName, 
//ha//                   (fsize64==0LL ? 0LL : (fsize64/1024LL)+(__int64)fsRounding),
//ha//                   _tTimeBuf);
//ha//    
//ha//      // Single file Modal DialogBox "Confirm overwriting file"
//ha//      if (_valAQ == 0 || (_valAQ == A_YES) || (_valAQ == A_NO))
//ha//        DialogBox(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_FILECL), NULL, DialogProcMultiFile);
//ha//
//ha//      // Skip saving file and keep the existing file(s) untouched
//ha//      if ((_valAQ == A_NOALL) || (_valAQ == A_NO) || (_valAQ == A_CANCEL))
//ha//        {
//ha//        DisplayLastError(HA_NO_FILE_SELECTED); // No files processed
//ha//        SetFocus (hEdit);                      // Set focus to hEdit
//ha//        SetWindowTextA(hEdit, NULL);           // Init-clear the Editor text Field
//ha//        return; 
//ha//        }
//ha//      } // end if (PathFileExists)
//ha//    } // end if (multiFileFlag == FALSE)
//ha//
//ha//  // Load Binfile
//ha//
//ha//  if (LoadBinFileCrypto((LPCTSTR)szSrcName, (LPCTSTR)szCryptoDestName, cryptMode)) // Crypto file with Progress Bar 
//ha//    {
//ha//    // Display the number of bytes having been copied.                                      
//ha//    StringCbPrintf(szCountBuf, szCountBufsize, pszTxtWr, ln);
//ha//    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)szCountBuf);
//ha//    }
//ha//  else if (_escAbort == FALSE && _lastErr != ERROR_SUCCESS) DisplayLastError(_lastErr);
//ha//
//ha//  if (multiFileFlag == TRUE && skipFlag == FALSE) // Not done in 'haCryptFileC.cpp[SaveMultiBinFile]'
//ha//    {
//ha//    fCount++;
//ha//    // List the files in edit window
//ha//    int index = GetWindowTextLength(hEdit);
//ha//    SetFocus (hEdit);                                             // Set focus
//ha//    SendMessage(hEdit, EM_SETSEL, (WPARAM)index, (LPARAM)index);  // Select end of text
//ha//    StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("%s%s"), _mdfpath, szCryptoDestName); 
//ha//    SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)_tDebugBuf);     // Append.
//ha//
//ha//    index = GetWindowTextLength(hEdit);
//ha//    SendMessage(hEdit, EM_SETSEL, (WPARAM)index, (LPARAM)index);  // Again: Select end of text
//ha//    SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)_T("\x0D\x0A")); // Append "\n"
//ha//    }
//ha//  else
//ha//    {
//ha//    // List the files in edit window
//ha//    int index = GetWindowTextLength(hEdit);
//ha//    SetFocus (hEdit);                                             // Set focus
//ha//    SendMessage(hEdit, EM_SETSEL, (WPARAM)index, (LPARAM)index);  // Select end of text
//ha//    StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("%s%s (skipped)"), _mdfpath, szCryptoDestName); 
//ha//    SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)_tDebugBuf);     // Append.
//ha//
//ha//    index = GetWindowTextLength(hEdit);
//ha//    SendMessage(hEdit, EM_SETSEL, (WPARAM)index, (LPARAM)index);  // Again: Select end of text
//ha//    SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)_T("\x0D\x0A")); // Append "\n"
//ha//    }
//ha//
//ha//  // Simulate Mouseclick to make buttons re-appear
//ha//  ShowWinMouseClick(hButtonDelim, 1, 0, 0);  
//ha//  } // DoBinFileCrypto


//--------------------------------------------------------------------------------------------


//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{
//--- Large Integers ---                 
//ha//long long num2 = 0x1234567890ABCDEFLL;
//ha//long long num3 = 0x100000000000LL;
//ha//sprintf(DebugBuf, "dwCryptFileSize = %08X\ndwFileSizeHigh = %08X\nnum2 = %llX\nnum3 = %llX", dwCryptFileSize, dwFileSizeHigh, num2, num3);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG STOP haCryptFileC", MB_OK);
//ha//}
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//    if (pCount > 1940)
//ha//    {
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("szNextFile = %s\npCount = %i"), szNextFile, pCount);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG STOP 0"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//    }
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{ 
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("ptr =%s\n")
//ha//                                           _T("_mdfpath = %s\n")
//ha//                                           _T("_msfpath = %s\n")
//ha//                                           _T("mdPathSave = %s\n")
//ha//                                           _T("msPathSave = %s\n")
//ha//                                           _T("pszNextFile = %s\n")
//ha//                                           _T("pszNextFileName = %s"),
//ha//                                           ptr, 
//ha//                                           _mdfpath,
//ha//                                           _msfpath,
//ha//                                           mdPathSave,
//ha//                                           msPathSave,
//ha//                                           pszNextFile, 
//ha//                                           pszNextFileName); 
//ha//MessageBox(NULL, _tDebugBuf, _T("MultiBinFileOpen 2"), MB_ICONINFORMATION | MB_OK);
//ha//}
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---


