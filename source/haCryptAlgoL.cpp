// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptAlgoL.cpp - C++ Developer source file.
// (c)2022 by helmut altmann

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
#include <shlwapi.h>   // Library shlwapi.lib for PathFileExistsA, PathFindExtension
#include <commctrl.h>  // Library Comctl32.lib
#include <winuser.h>
#include <commdlg.h>
#include <tchar.h>

#include <sys\stat.h>  // For _open( , , S_IWRITE) needed for VC 2010
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

TCHAR* pszTxtWrL = TEXT("%llu byte(s) written.");
TCHAR szCryptoDestName[MAX_PATH];

int minutesDES, minutesAES, minutes3DES;
int _largeFileLastBlock;

// Global extern variables
extern int _hexMode, multiFileFlag, largeFileFlag;

extern LPSTR pszCryptFileOut, pszCryptFileDisplay, pszHexTxtFileIn;

extern TCHAR szSrcName[];
extern TCHAR szDestName[];
extern TCHAR _mdfpath[];   // Multifile destination path
extern TCHAR mdPathSave[]; // Multifile destination path+filename save
extern TCHAR msPathSave[]; // Multifile source path save

extern PCTSTR pszLast, pszLastExt;

//extern LPCTSTR pszSrcName;
extern TCHAR* pszSrcName;

extern PTSTR szTruncPath;

extern TCHAR* pszCopyFileExtensionFilter;
extern TCHAR* pszLargeTxtCpy;

extern TCHAR szFileExtension[];

extern __int64 ddFileSizeLarge, lln;

extern HANDLE hSrcFile;    // Handle of source file.
extern HANDLE hDestFile;   // Handle of destination file.

extern LPSTR pszCryptFileIn, pszTextFileIn;

extern TCHAR szCountBuf[];
extern int szCountBufsize;

extern TCHAR _tTimeBuf[];  // File Time&Date buffer
extern int _tTimebufSize;
extern TCHAR* psz_tTimeBuf;

extern char DebugBuf[];    // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[]; // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern char* pszIcvBuffer; // Large file intermediate MAC for each 64M block

extern int textColor, _ProgressbarLL;
extern int pCount, _valAQ;

extern HINSTANCE g_hInst;  // Main hInstance

extern HWND hMain;
extern HWND hTool;
extern HWND hEdit;
extern HWND hStatusbar;
extern HWND hButtonHex;
extern HWND hButtonDelim;

extern ULONG  dwFileSize, dwCryptFileSize, ln;
extern ULONG FileProcessingMode;
extern DWORD _lastErr;     // Global storage for 'GetLastError()

extern int skipFlag, _escFlag, _escAbort;

extern DWORD dwFileSizeHigh, dwFileSizeLow;       // Filesize MOD 4Gbyte
extern LPDWORD lpFileSizeHigh;                    // Filesize * 4Gbyte

extern void InitProgressbarL(ULONG);              // Init file dependent stepping
extern void DisplayProgressCountL(__int64, int);  // ProgressbarL and ln count display
extern void DestroyProgressbarL();                // Destroy progressbarL, update toolbar icons

extern void DisplayMacStatusbar();
extern void DisplayLastError(int);
extern void GetLastWriteTime(TCHAR*, LPTSTR, DWORD);
extern void TruncateFilePath(LPWSTR, int, int);
extern void GetCryptoModeText(int);
extern void Bin2Txt(); 
extern void Bin2Hex(int); 

extern void ControlCryptoToolItems(int, int);
extern void ControlToolWindow(int);

extern void ShowWinMouseClick(HWND, int, int, int);
extern BOOL CryptoAlgorithmFunctions(int);

extern BOOL CheckEscapeAbort();
extern BOOL FileBlockCryptoL(HANDLE, HANDLE, int);
extern BOOL CheckInvalidFileName(TCHAR*, TCHAR*);
extern BOOL DisplayListMultipleFiles(TCHAR*);

extern INT_PTR CALLBACK DialogProcMultiFile(HWND, UINT, WPARAM, LPARAM); 

//-------------------------------------------------------------------------------
//
//                           LoadBinFileCryptoL
//
// The following global variables must be supplied:
//
//  HANDLE hSrcFile         // Handle of file being read
//
BOOL LoadBinFileCryptoL(LPCTSTR pszFileNameRd, LPCTSTR pszFileNameWr, int cryptMode)
  {
  BOOL bSuccess = FALSE;

//ha//  DWORD dwFileSizeHigh, dwFileSizeLow;              // dwFileSizeLow = Filesize MOD 4G
//ha//  LPDWORD lpFileSizeHigh = (DWORD*)&dwFileSizeHigh; // Filesize > 4Gbyte

  DWORD dwFileSizeBlocks;      // Number of file chunks
  DWORD dwFileBlock;           // Size of each file chunk to be copied
  DWORD dwFileBlockRemainder;  // Size of the remaining rest to be copied

//ha//  HANDLE hFileRd = CreateFile( // Open file for read
//ha//    pszFileNameRd,
//ha//    GENERIC_READ,
//ha//    FILE_SHARE_READ,
//ha//    NULL,              
//ha//    OPEN_EXISTING,
//ha//    0,
//ha//    NULL);
  HANDLE hFileRd = hSrcFile;   // File already open for read

  HANDLE hFileWr = CreateFile( // Open file for write
    pszFileNameWr, 
    GENERIC_WRITE, 
    0, 
    NULL,
    CREATE_ALWAYS, 
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, // | FILE_FLAG_NO_BUFFERING;
    NULL);

  _escFlag = FALSE;   // Reset any pending ESC-Abort condition

  // ... ?? Put in here, if needed: Request ownership of the critical section ... ??
  if (hFileRd != INVALID_HANDLE_VALUE && hFileWr != INVALID_HANDLE_VALUE)
    {
    // LPDWORD lpFileSizeHigh (used only if > 4Gbyte should be allowed).
    //  A pointer to the variable where the high-order doubleword
    //  of the file size is returned. This parameter can be NULL
    //  if the application does not require the high-order doubleword.
    // DWORD dwFileSizeLow = GetFileSize(hFileRd, NULL);
    // DWORD dwFileSizeLow = GetFileSize(HANDLE hFileRd, LPDWORD lpFileSizeHigh);
    //
    // lpFileSizeHigh =:
    //  Pointer where the high-order doubleword of the file size is returned.
    //  NULL if application does not require high-order doubleword.
    //  NULL = 4Gbyte (=0x100000000) max
    //
    // Example: 00000001.38A41FC0 = 5245247424 Bytes (1Gbyte = 40000000 =1073741824)
    //          138A41FC0 / 40000000 = 4, 138A41FC0 % 40000000 = 38A41FC0
    //
    // DWORD dwFileSizeLow;                                            //  0x38A41FC0 
    // DWORD dwFileSizeHigh;                                           //  0x00000001
    // LPDWORD lpFileSizeHigh = (DWORD*)&dwFileSizeHigh;            
    // dwFileSizeLow = GetFileSize(hFile, lpFileSizeHigh);
    //
    // dwFileSizeLow = GetFileSize(hFile, lpFileSizeHigh);             // GetFileSize > 4G
    //
    // Build 64bit integer
    // ddFileSizeLarge = UInt32x32To64(dwFileSizeHigh, 0x80000000L);    // 0x0000000010000000 (* 2G)
    // ddFileSizeLarge <<= 1;                                           // 0x0000000100000000 (* 2)
    // ddFileSizeLarge |= dwFileSizeLow;                                // 0x0000000138A41FC0
    //
    // Calculate how many blocks of 1G each: Divide Build 64bit integer by 1G
    // dwFileSizeBlocks = (DWORD)Int64ShrlMod32(ddFileSizeLarge, 30); //         0x00000004 chunks of 1 Gbyte each
    // Calculate the rest: 64bit integer MOD 1G
    // dwFileSizeMod4G = (DWORD)(ddFileSizeLarge % 0x40000000LL);       //         0x38A41FC0 Filesize % 0x40000000 (= MOD 1 Gbyte)
    //
    //---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
    // {                 
    // sprintf(DebugBuf, "dwFileSizeLow = %08X\ndwFileSizeHigh = %08X\nddFileSizeLarge = %llX [=%llu]",
    //                    dwFileSizeLow, dwFileSizeHigh, ddFileSizeLarge, ddFileSizeLarge);
    // MessageBoxA(NULL, DebugBuf, "DEBUG STOP GetFileSize(..)", MB_OK);
    // }
    //---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

    //dwFileSizeLow = GetFileSize(hFileRd, lpFileSizeHigh);         // Filesize > 4 Gbyte

    // Build 64bit integer
    ddFileSizeLarge = UInt32x32To64(dwFileSizeHigh, 0x80000000L);   // * 2G
    ddFileSizeLarge <<= 1;                                          // * 2   = dwFileSizeHigh * 4G
    ddFileSizeLarge |= dwFileSizeLow;                               // 64bit file size > 4Gbyte

    // Calculate how many blocks of 64M each: ddFileSizeLarge / 64M
    dwFileSizeBlocks = (DWORD)Int64ShrlMod32(ddFileSizeLarge, BASE2_EXPONENT_64M);

    // ------------------------------------------------------------------------
#ifdef x64  // 64bit                                                        // |
    dwFileBlock = FILE_BLOCK_64M;     // __asm not supported in CL64        // |
#else                                                                       // |
    // Calculate the remainder: ddFileSizeLarge % (2.e[BASE2_EXPONENT_64M]) // |
    dwFileBlock = 0;                                                        // |
    __asm                             // Using an assembler CPU Instruction // |
      {                                                                     // |
      bts dwFileBlock, BASE2_EXPONENT_64M      // e.g. Build FILE_BLOCK_64M // |
      }                                                                     // |
#endif                                                                      // |
    dwFileBlockRemainder = (DWORD)(ddFileSizeLarge % (__int64)dwFileBlock); // |
    // ------------------------------------------------------------------------ 

    // The predicted average time wasted by the process (storage device dependend)
    // Example:
    // 5245247424 / 64M ~ 79
    //  minutesDES  ~  7min  (~ 5s / 64M)
    //  minutesAES  ~  3min  (~ 2s / 64M)
    //  minutes3DES ~ 18min  (~13s / 64M)
    //  
    minutesDES  = ((dwFileSizeBlocks+1) *  5) / 60; // Rounded up
    minutesAES  = ((dwFileSizeBlocks+1) *  2) / 60; // Rounded up
    minutes3DES = ((dwFileSizeBlocks+1) * 13) / 60; // Rounded up

    // At this point:
    // ddFileSizeLarge = (dwFileSizeBlocks * 64M) + dwFileBlockRemainder
    //
    dwCryptFileSize = dwFileBlock;   // Initialize dwCryptFileSize for alloc & algo
    dwFileSize = dwCryptFileSize;    // dwFileSize: Needed for progressbar & Crypto algo, 

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
      dwCryptFileSize = _ERR;         // Invalidate dwCryptFileSize
      DisplayLastError(HA_ERROR_MEMORY_ALLOC);
      CloseHandle(hFileRd);
      CloseHandle(hFileWr);
      return(bSuccess);
      }

    // Disable all windows while copying lengthy files to prevent lockups
    // (..the user may be tempted to toy around clicking erratically on 
    //  windows sections while waiting until the file copy terminates.)
    ControlToolWindow(FALSE);
    //EnableWindow(hTool, FALSE);   

    // 1) If file size > 4Gbyte: Read all 64M blocks
    int i;
    if ((FileProcessingMode & CRYPT_MODE_MASK) == CRYPT_MAC)
      {
      for (i=0; i<AES_BLOCK_SIZE; i++) pszIcvBuffer[i] = 0;                       
      }

    ln = 0LL;
    if (dwFileSizeBlocks != 0)
      {
      EnableWindow(hButtonHex, FALSE);      // Disable Hex/Txt Button
      InitProgressbarL(dwFileBlock);

      dwCryptFileSize = dwFileBlock;        // =64M: Needed for DES, AES, 3DES modules
      int j = 0;  _largeFileLastBlock = FALSE; // Reset block counter and last block flag
      do
        {
        if ((j + 1) == dwFileSizeBlocks && dwFileBlockRemainder == 0)
         _largeFileLastBlock = TRUE;        // Set - Processing the last block

        if (FileBlockCryptoL(hFileRd, hFileWr, cryptMode) == FALSE) 
          {
          DestroyProgressbarL();            // Ensure the correct crypto item remains selected
          ControlToolWindow(TRUE);          // Re-enable everything
          //EnableWindow(hTool, TRUE);        // Re-enable everything
          SetFocus(hEdit);                  // Set cursor into text field
          SetDlgItemText(hMain, IDC_MAIN_EDIT, NULL); // Clear edit field

          pszCryptFileIn =      (LPSTR)GlobalFree(pszCryptFileIn);      // result = NULL
          pszCryptFileDisplay = (LPSTR)GlobalFree(pszCryptFileDisplay); // result = NULL

          CloseHandle(hFileRd);             // Close source file
          CloseHandle(hFileWr);             // Close destinaion File
          return(FALSE);
          }

        //------------------------------------------------
        // Store 1st 4K in 'pszCryptFileDisplay' for later
        if (j == 0) Bin2Txt();              
        //------------------------------------------------

        // NOT IMPLEMENTED: SEPARATE MACs 64M-BLOCKWISE ARE WRITTEN. ONLY THE LAST MAC IS DISPLAYED. 
        if ((FileProcessingMode & CRYPT_MODE_MASK) == CRYPT_MAC)
          {
          dwCryptFileSize = dwFileBlock;    // =64M: Reset: Needed for DES, AES, 3DES modules
          for (i=0; i<AES_BLOCK_SIZE; i++) pszIcvBuffer[i] = pszCryptFileOut[i]; 
          }

        j++;                                // 1G chunks  counter
        lln = UInt32x32To64(j, ln);         // Calculate the total bytes read

        // Display progressbar + crypto bytes processed (%)
        DisplayProgressCountL(lln, PROGRESS_CRYPT_BAR);     
        } while (j < dwFileSizeBlocks);
      } // end if (dwFileSizeBlocks)

    // 2) All 64M blocks have been read, now read the remaining rest (if any)
    if (dwFileBlockRemainder > 0)           // Crypt processing the rest
      {
      EnableWindow(hButtonHex, FALSE);      // Disable Hex/Txt Button
      dwCryptFileSize = dwFileBlockRemainder;
      _largeFileLastBlock = TRUE;           // Set - Processing the last block
      bSuccess = FileBlockCryptoL(hFileRd, hFileWr, cryptMode);
      lln += (__int64)ln;                   // Calculate the total bytes read
      }
    
    _largeFileLastBlock = FALSE;            // Reset - Last block has been processed

    DWORD dwWritten;
    if (FileProcessingMode == (CRYPT_AES | CRYPT_MAC))
      {
      lln = AES_BLOCK_SIZE;
      dwFileSize = AES_BLOCK_SIZE;
      WriteFile(hFileWr, pszCryptFileOut, AES_BLOCK_SIZE, &dwWritten, NULL);
      for (i=0; i<AES_BLOCK_SIZE; i++) pszHexTxtFileIn[i] = pszCryptFileOut[i];
      Bin2Hex(TRUE);                             // Spaced
      pszCryptFileDisplay[3*AES_BLOCK_SIZE] = 0; // Terminate spaced ascii hex string
      }
    else if (FileProcessingMode == (CRYPT_DES  | CRYPT_MAC) ||
             FileProcessingMode == (CRYPT_TDES | CRYPT_MAC))
      {
      lln = DES_BLOCK_SIZE;
      dwFileSize = DES_BLOCK_SIZE;
      WriteFile(hFileWr, pszCryptFileOut, DES_BLOCK_SIZE, &dwWritten, NULL);
      for (i=0; i<DES_BLOCK_SIZE; i++) pszHexTxtFileIn[i] = pszCryptFileOut[i];
      Bin2Hex(TRUE);                             // Spaced
      pszCryptFileDisplay[3*DES_BLOCK_SIZE] = 0; // Terminate spaced ascii hex string
      }

    DestroyProgressbarL();                  // Ensure the correct crypto item remains selected

    StringCbPrintf(_tDebugBuf, _tDebugbufSize, pszTxtWrL, lln); // Emit number of bytes written
    SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)_tDebugBuf);

    if ((FileProcessingMode & CRYPT_MODE_MASK) == CRYPT_MAC)    // Large file: Display MAC instead of filename
      DisplayMacStatusbar();

    SetWindowText(hMain, szCryptoDestName); // Always display destination path in mainwindow's title field
    
    //-------------------------------------------------------------------------
    // Note: Big Crypto-Files are only partly displayed in the text window ..!!
    // Display truncated crypto data only if edit field
    //  is not occupied (Multifile list, _ProgressbarLL)
    //
    if (_hexMode == 0) Bin2Txt();           // Display crypto data as text
    if (multiFileFlag == FALSE) 
      {
      SetFocus (hMain);                     // Set focus to hEdit
      SetDlgItemText(hMain, IDC_MAIN_EDIT, NULL); // Clear edit field
      SetFocus (hEdit);                     // Set focus to hEdit
      textColor = T_GREEN;                  // Green text color in textfield
      SetWindowTextA(hEdit, NULL);          // Init-clear the Editor text Field
      SetWindowTextA(hEdit, pszCryptFileDisplay); // Load pszCryptFileDisplay (4K) into edit field
      SetFocus (hMain);                     // Deviate focus to hMain
      textColor = FALSE;                    // Reset to black text color
      }
    EnableWindow(hButtonHex, FALSE);        // Disable Hex/Txt Button ('pszHexTxtFileIn' not valid)
    //-------------------------------------------------------------------------
                                                                        //ha//            Hex/Txt Button:
//ha//    pszCryptFileIn =      (LPSTR)GlobalFree(pszCryptFileIn);      // result = NULL 'pszHexTxtFileIn' not valid
//ha//    pszCryptFileDisplay = (LPSTR)GlobalFree(pszCryptFileDisplay); // result = NULL 'pszCryptFileDisplay' not valid

    CloseHandle(hFileRd);                   // Close source file
    CloseHandle(hFileWr);                   // Close destinaion File
    } // end if (hFileRd && hFileWR)                  

  else DisplayLastError(HA_ERROR_FILE_OPEN);
  
  // Re-enable everything
  ControlToolWindow(TRUE);          // Re-enable everything
  //EnableWindow(hTool, TRUE);

//ha//------------------------------- Begin
//ha//  if (multiFileFlag == FALSE)
//ha//    {                   
//ha//    SendMessage(hEdit, EM_SETREADONLY, FALSE, 0);
//ha//    SetFocus(hEdit);                            // Set cursor into text field
//ha//    SetDlgItemText(hMain, IDC_MAIN_EDIT, NULL); // Clear edit field
//ha//    }
//ha//------------------------------- End

  CloseHandle(hFileRd);                     // Close source file
  CloseHandle(hFileWr);                     // Close destinaion File
  return bSuccess;
  } //  LoadBinFileCryptoL

//-----------------------------------------------------------------------------
//
//                            DoLargeBinFileCrypto
//
// Called from 'haCryptFileC.cpp[LoadBinFile]'
//  (only if (dwFileSizeHigh != 0 || dwFileSizeLow > FILE_BLOCK_1G))    
//
BOOL DoLargeBinFileCrypto(HWND _hwnd, int cryptMode)
  {
  TCHAR szCryptoDestNameSave[MAX_PATH];
  PTSTR pszCryptoDestName = szCryptoDestName;
  PTSTR ppszExt = NULL;
  
  struct __stat64 fstatBuf64;   // Size >= 4Gbyte
  __int64 fsize64;

  int i, _slenP, _slenF;

  // Remove-clear Progressbar 'Loading file'
  // Ensure the correct crypto item remains selected
  DestroyProgressbarL();

  // Set proposed file extension and allow the user
  //  to Rename the file extension (Modal DialogBox Rename)
  GetCryptoModeText(cryptMode);

  if (multiFileFlag == FALSE)  // Already done in 'haCryptFileC.cpp[SaveMultiBinFile]'
    {
    //DialogBox(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_FILEX), hMain, DialogProcMultiFile);  
    DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_FILEX), hMain, DialogProcMultiFile, IDD_HACRYPT_FILEX);  
    if (_valAQ == A_CANCEL)
      {
      DisplayLastError(HA_NO_FILE_SELECTED);
      return(FALSE);
      }
    }

  // At this point:
  // szFileExtension  = Pointer to the file extension string returned by the user

  // Duplicate the external source filename for local usage
  for (i=0; i<MAX_PATH; i++) pszCryptoDestName[i] = pszSrcName[i];

  skipFlag = CheckInvalidFileName(pszSrcName, pszCryptoDestName);

  if (multiFileFlag == TRUE)   // Build destination path for multiple large files
    {
    // Duplicate destination filename+crypto-extension
    for (i=0; i<MAX_PATH; i++) szCryptoDestNameSave[i] = pszCryptoDestName[i];  
    // Build destination path: Concatenate path+filename+crypto-extension
    for (i=0; i<=lstrlen(_mdfpath); i++) pszCryptoDestName[i] = _mdfpath[i];
    lstrcat(pszCryptoDestName, szCryptoDestNameSave);     
    }

  // At this point:
  // PTSTR pszCryptoDestName = path+Filename+crypto-extension to be written. 
  //  if (multiFileFlag == FALSE)
  //    PTSTR pszCryptoDestName ==> Single file processing:
  //                                 Original source filePATH with crypto-extension (e.g. c:\src\abc.txt.A~e).
  //  if (multiFileFlag == TRUE) 
  //    PTSTR pszCryptoDestName ==> Multiple file processing: 
  //                                 Destination filePATH with crypto-extension (e.g. d:\dest\abc.txt.A~e).
  //
  if (multiFileFlag == FALSE) // Already done in 'haCryptFileC.cpp[SaveMultiBinFile]'
    {
    // Single large file:
    // Check if srcfile path and destfile path are identical
    // Large files are loaded and saved immediately.
    // It is not possible to load/save a file onto itself.
    // The user could for example choose a different file extension
    // and thus save the file under another name.  
    while (_valAQ == A_CONTINUE && wcscmp(pszSrcName, pszCryptoDestName) == S_OK)
      {
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("ERROR: Cannot save large source file onto itself. ")
                                                 _T("Please modify the file extension."));
      DisplayLastError(_ERR);
      //DialogBox(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_FILEX), hMain, DialogProcMultiFile);  
      DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_FILEX), hMain, DialogProcMultiFile, IDD_HACRYPT_FILEX);  
      if (_valAQ == A_CANCEL)
        {
        DisplayLastError(HA_NO_FILE_SELECTED);
        return(FALSE);
        }

      // Duplicate the external source filename for local usage
      for (i=0; i<MAX_PATH; i++) pszCryptoDestName[i] = pszSrcName[i];
      skipFlag = CheckInvalidFileName(pszSrcName, pszCryptoDestName);
      } // end while

    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)szCryptoDestName);

    // Write colored info text into edit field
    int index = GetWindowTextLength(hEdit);

    textColor = T_GREEN;                                         // Green
    SetFocus (hEdit);                                            // Set focus
    SendMessage(hEdit, EM_SETREADONLY, TRUE, 0);                 // Disable text field for crypto data edit
    //PaintColoredStatusPercentMsg(_T("Press ESC to abort...")); // Alternatively use statusbar
    SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)_T("Large file. Press ESC to abort..."));    
    SendMessage(hEdit, EM_SETSEL, (WPARAM)index, (LPARAM)index); // Select end of text
    SetFocus (hMain);                                            // Deviate focus to hMain
    textColor = FALSE;                                           // Black
    } // end if (multiFileFlag == FALSE)

  // Check file existence
  if (PathFileExists(szCryptoDestName) && skipFlag == FALSE)     // Checking for file existence
    {                                  
    GetLastWriteTime(szCryptoDestName, _tTimeBuf, MAX_PATH);

    //int _wstat64(
    //   const wchar_t *path,
    //   struct __stat64 *buffer
    //);
    _wstat64(szCryptoDestName, &fstatBuf64);     // Size >= 4Gbyte
    fsize64 = fstatBuf64.st_size;

    // Calculate [KB] like WINDOWS-Explorer
    int fsRounding = 1;                          // Round to next higher KB value
    if ((fsize64 % 1024LL) == 0) fsRounding = 0; // Don't round exact values

    TruncateFilePath((PWSTR)szCryptoDestName, 55, 0);   // Should fit nicely into dialogbox
    StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT(" \
%s\n \
Size: %lld KB\n \
Change Date: %s"), szTruncPath, //szCryptoDestName, 
                 (fsize64==0LL ? 0LL : (fsize64/1024LL)+(__int64)fsRounding),
                 _tTimeBuf);
  
    // Single file Modal DialogBox "Confirm overwriting file" "[Yes]" "[No]"
    //DialogBox(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_FILECL), hMain, DialogProcMultiFile);
    DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_FILECL), hMain, DialogProcMultiFile, IDD_HACRYPT_FILECL);

    // Skip saving file and keep the existing file(s) untouched
    if (_valAQ == A_NO && multiFileFlag == FALSE) // Already done in 'haCryptFileC.cpp[SaveMultiBinFile]' ????
      {
      DisplayLastError(HA_NO_FILE_SELECTED); // No files processed
      SetFocus (hEdit);                      // Set focus to hEdit
      SetWindowTextA(hEdit, NULL);           // Init-clear the Editor text Field
      return(FALSE);
      }
    } // end if (PathFileExists)

  // Load Binfile
  //-------------
  if (_valAQ != A_NO)
    {
    // Crypto file with Progress Bar
    if (LoadBinFileCryptoL((LPCTSTR)szSrcName, (LPCTSTR)szCryptoDestName, cryptMode))   
      {
      // Display the number of bytes having been written.                                     
      StringCbPrintf(szCountBuf, szCountBufsize, pszTxtWrL, lln);
      SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)szCountBuf);
      }
    else if (_escAbort == FALSE && _lastErr != ERROR_SUCCESS) DisplayLastError(_lastErr);

    // List the files in edit window
    if (multiFileFlag == TRUE && skipFlag == FALSE) // Not done in 'haCryptFileC.cpp[SaveMultiBinFile]'
      {
      pCount++;                                     // Increment file count
      DisplayListMultipleFiles(szCryptoDestNameSave);
      }
    else if (skipFlag == TRUE)
      DisplayListMultipleFiles(szCryptoDestNameSave);
    } // end if (_valAQ != A_NO)

  // Simulate Mouseclick to make buttons re-appear
  ShowWinMouseClick(hButtonDelim, 1, 0, 0);
  return(TRUE); 
  } // DoLargeBinFileCrypto

//-----------------------------------------------------------------------------

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{                
//ha//sprintf(DebugBuf, "dwFileSizeLow = %08X\ndwFileSizeHigh = %08X\nddFileSizeLarge = %llX [=%llu]\ndwFileSizeBlocks = %i\ndwFileSizeMod4G = %08X [=%lu]",
//ha//                   dwFileSizeLow, dwFileSizeHigh, ddFileSizeLarge, ddFileSizeLarge, dwFileSizeBlocks1G, dwFileSizeMod4G, dwFileSizeMod4G);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG STOP haCryptFileT - DoTxtFileCopy", MB_OK);
//ha//}
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("szFileExtension = %s\n
//ha//                                               szFileExtension, pszSrcName, ppszExt, szCryptoDestName, _slenF);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG STOP 0"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
