// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptFileB.cpp - C++ Developer source file.
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

int GlobalCryptMode;        // Publish 'cryptMode'

// Global extern variables
extern char DebugBuf[];     // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];  // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;
extern TCHAR* psz_tDebugBuf;

extern LPSTR pszCryptFileIn, pszCryptFileOut, pszTextFileIn;                  

extern ULONG ln, dwFileSize, dwCryptFileSize, dwTextFileSize;
extern ULONG FileProcessingMode;
extern DWORD _lastErr;      // Global for 'GetLastError()'

extern int _escFlag, _escAbort;

extern HANDLE hSrcFile;     // Handle of source file.
extern HANDLE hDestFile;    // Handle of destination file.

// External functions declaration
extern void DisplayLastError(int);
extern void InitProgressbar(ULONG);
extern void DisplayProgressCount(ULONG, int);    // Progressbar / Numeric count display (%)
extern void DestroyProgressbar();                // Destroy progressbar, update toolbar icons

extern BOOL CryptoAlgorithmFunctions(int);
extern BOOL CheckEscapeAbort();

//ha////-----------------------------------------------------------------------------
//ha////
//ha////                          FileBlockCopy  (deprecated)
//ha////
//ha////   HANDLE hSrcFile;  // Handle of source file.
//ha////   HANDLE hDestFile; // Handle of destination file.
//ha////
//ha//BOOL FileBlockCopy(DWORD _blkSize)
//ha//  {
//ha//  LPSTR pchTmp;               // Pointer to temp buffer of data read from file.
//ha//  LPSTR pszCopyFileIn = NULL;
//ha//
//ha//  ULONG i;                    // Init bytesrd: Progress-Bar chunks to be read
//ha//  DWORD dwRead;               // bytesrd
//ha//  DWORD dwWritten;            // byteswr
//ha//  BOOL bSuccess = FALSE;      // Return value
//ha//
//ha//  if (pszCopyFileIn != NULL) GlobalFree(pszCopyFileIn);
//ha//  // Maximum memory buffer size possible: Windows System dependent ~ 2G
//ha//  pszCopyFileIn = (LPSTR)LocalAlloc(LPTR, FILE_BLOCK_1G + FILE_BLOCK_SIZE + 1);
//ha//
//ha//  pchTmp = (LPSTR)LocalAlloc(LPTR, FILE_BLOCK_SIZE + 1); // Provide temporary memory
//ha//  if (pszCopyFileIn == NULL || pchTmp == NULL)           // (inner loop1)
//ha//    {
//ha//    //_lastErr = GetLastError();
//ha//    DisplayLastError(HA_ERROR_MEMORY_ALLOC);
//ha//    return(bSuccess);
//ha//    }
//ha//
//ha//  // Parse the file. Process chunks of FILE_BLOCK_SIZE to allow a progressbar 
//ha//  dwFileSize = _blkSize;         // dwFileSize: Needed for progressbar 
//ha//  dwCryptFileSize = _blkSize;    // dwCryptFileSize:  Needed for Crypto algo
//ha//
//ha//  ln = 0; 
//ha//  do
//ha//    { 
//ha//    ReadFile(hSrcFile, pchTmp, FILE_BLOCK_SIZE, &dwRead, NULL);  // Read a block
//ha//    if (WriteFile(hDestFile, pchTmp, dwRead, &dwWritten, NULL)) bSuccess = TRUE;
//ha//    else
//ha//      {
//ha//      _lastErr = GetLastError();
//ha//      CloseHandle(hSrcFile);     // Close source file
//ha//      CloseHandle(hDestFile);    // Close destinaion File
//ha//      return(FALSE);
//ha//      }
//ha//
//ha//    for (i=0; i<dwRead; i++) pszCopyFileIn[ln+i] = pchTmp[i];  // Transfer / append the block read
//ha//
//ha//    // Begin: --ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort
//ha//    // Here we allow to abort reading very lengthy files by pressing the ESC key
//ha//    if ((_escAbort = CheckEscapeAbort()) == TRUE)
//ha//      {
//ha//      LocalFree(pchTmp);         // Discard temporary memory
//ha//      LocalFree(pszCopyFileIn);  // Discard temporary buffer
//ha//      CloseHandle(hSrcFile);     // Close source file
//ha//      CloseHandle(hDestFile);    // Close destinaion File
//ha//      return(FALSE);             // Abort function
//ha//      }
//ha//    // End:   --ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort
//ha//
//ha//    ln += dwRead;                // Update counter total bytes read
//ha//    } while (ln < _blkSize);     // end do while
//ha//
//ha//  bSuccess = TRUE;
//ha//  LocalFree(pchTmp);             // Discard temporary memory
//ha//  LocalFree(pszCopyFileIn);      // Discard temporary buffer
//ha//
//ha//  return(bSuccess);                  
//ha//  } // FileBlockCopy


//-----------------------------------------------------------------------------
//
//                      FileBlockText
//
// The following global variables must be supplied:
//
//  ULONG ln              // Byte counter
//  ULONG dwTextFileSize  // Total size of input file
//
//  HANDLE hFile          // Handle of file being read
//
BOOL FileBlockText(HANDLE hFile)
  {
  LPSTR pchTmp;   // Pointer to temp buffer of data read from file.
  int i;          // Init bytesrd: Progress-Bar chunks to be read
  DWORD dwRead;   // bytesrd

  pchTmp = (LPSTR)LocalAlloc(LPTR, FILE_BLOCK_SIZE + 1); // Provide temporary memory

  // Parse the file. Process chunks of FILE_BLOCK_SIZE to allow a progressbar 
  InitProgressbar(0L);     // Initialize the Progressbar (% counter only)

  ln = 0;
  do
    { 
    ReadFile(hFile, pchTmp, FILE_BLOCK_SIZE, &dwRead, NULL);   // Read a block
    for (i=0; i<dwRead; i++) pszTextFileIn[ln+i] = pchTmp[i];  // Transfer / append the block read

    // Begin: --ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort
    // Here we allow to abort reading very lengthy files by pressing the ESC key
    if (CheckEscapeAbort() == TRUE)
      {
      LocalFree(pchTmp);               // Discard temporary memory
      CloseHandle(hFile);              // Close file
      DestroyProgressbar();
      return(FALSE);
      }
    // End:   --ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort

    ln += dwRead;                      // Update counter total bytes read

    // Loading File: Display ln counter in KB on statusbar
    DisplayProgressCount(ln, PROGRESS_LOAD_PCENT);       
    } while (ln < dwTextFileSize);     // end do while

  LocalFree(pchTmp);                   // Discard temporary memory
  CloseHandle(hFile);

  // Remove-clear Progressbar 'Loading file'
  // Ensure the correct crypto item remains selected
  DestroyProgressbar();

  pszTextFileIn[dwTextFileSize] = 0;   // Add null terminator
  return(TRUE);
  } // FileBlockText


//-----------------------------------------------------------------------------
//
//                      FileBlockCryptoL
//
// The following global variables must be supplied:
//
//  LPSTR pszCryptFileIn  // Allocated global buffer to intercept the whole file
//                          (bufsize is restricted by the system memory available)
//  LPSTR pszCryptFileOut // pszCryptFileIn
//
//  char * pszKeyBuffer   // Key buffer (max key length for AES = 256 bits)
//  char * pszIcvBuffer   // IV buffer (max key length for AES = 256 bits)
//
//  ULONG ln              // Byte counter
//  ULONG dwCryptFileSize // Total size of input file
//
//  int cryptMode         // Mode ENCRYPT / DECIPHER
//  HANDLE hFile          // Handle of file being read
//
BOOL FileBlockCryptoL(HANDLE hFileRd, HANDLE hFileWr, int cryptMode)
  {
  LPSTR pchTmp;   // Pointer to temp buffer of data read from file.
  int i;          // Init bytesrd: Progress-Bar chunks to be read
  DWORD dwRead;   // Bytesrd

  BOOL bSuccess = FALSE;
  int byteswr;
  DWORD dwWritten;

  _escFlag = FALSE;
  GlobalCryptMode = cryptMode; // Just in case if needed elsewhere

  // In order to allow a progressbar (or percetage display) the complete file
  //  is read in chunks (blockwise) into a locally allocated buffer (pchTmp)
  pchTmp = (LPSTR)LocalAlloc(LPTR, (sizeof(char) * FILE_BLOCK_SIZE) + 1); 

  ln = 0;
  do
    { 
    ReadFile(hFileRd, pchTmp, FILE_BLOCK_SIZE, &dwRead, NULL);   // Read a block
    for (i=0; i<dwRead; i++) pszCryptFileIn[ln+i] = pchTmp[i];   // Transfer / append the block read

    // Begin: --ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort
    // Here we allow to abort reading very lengthy files by pressing the ESC key
    if (CheckEscapeAbort() == TRUE)
      {
      LocalFree(pchTmp);                // Discard temporary memory
      CloseHandle(hFileRd);             // Close files
      CloseHandle(hFileWr);
      return(bSuccess);
      }
    // End:   --ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort

    ln += dwRead;                       // Update counter total bytes read
    } while (ln < dwCryptFileSize);     // end do while

  pchTmp = (LPSTR)LocalFree(pchTmp);

  if (CryptoAlgorithmFunctions(cryptMode) == FALSE) return(bSuccess);
  
  if ((FileProcessingMode & CRYPT_MODE_MASK) == CRYPT_MAC) bSuccess = TRUE;
  else
    {
    if (WriteFile(hFileWr, pszCryptFileOut, ln, &dwWritten, NULL)) bSuccess = TRUE;
    else _lastErr = GetLastError();
    }

  return(bSuccess);    
  } // FileBlockCryptoL


//-----------------------------------------------------------------------------
//
//                      FileBlockCrypto
//
// The following global variables must be supplied:
//
//  LPSTR pszCryptFileIn  // Allocated global buffer to intercept the whole file
//  LPSTR pszCryptFileOut // pszCryptFileIn
//                          (bufsize is restricted by the system memory available)
//
//  char * pszKeyBuffer   // Key buffer (max key length for AES = 256 bits)
//  char * pszIcvBuffer   // IV buffer (max key length for AES = 256 bits)
//
//  ULONG ln              // Byte counter
//  ULONG dwCryptFileSize // Total size of input file
//  ULONG dwFileSize      // dwFileSize: Needed for progressbar & Crypto algo, 
//
//  int cryptMode         // Mode ENCRYPT / DECIPHER
//  HANDLE hFile          // Handle of file being read
//
BOOL FileBlockCrypto(HANDLE hFile, int cryptMode)
  {
  LPSTR pchTmp;   // Pointer to temp buffer of data read from file.
  int i;          // Init bytesrd: Progress-Bar chunks to be read
  DWORD dwRead;   // Bytesrd

  GlobalCryptMode = cryptMode; // Just in case if needed elsewhere

  InitProgressbar(0L);     // Initialize the Progressbar (% counter only)

  // In order to allow a progressbar (or percetage display) the complete file
  //  is read in chunks (blockwise) into a locally allocated buffer (pchTmp)
  pchTmp = (LPSTR)LocalAlloc(LPTR, (sizeof(char) * FILE_BLOCK_SIZE) + 1); 

  ln = 0;
  do
    { 
    ReadFile(hFile, pchTmp, FILE_BLOCK_SIZE, &dwRead, NULL);     // Read a block
    for (i=0; i<dwRead; i++) pszCryptFileIn[ln+i] = pchTmp[i];   // Transfer / append the block read

    // Begin: --ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort
    // Here we allow to abort reading very lengthy files by pressing the ESC key
    if (CheckEscapeAbort() == TRUE)
      {
      LocalFree(pchTmp);                // Discard temporary memory
      CloseHandle(hFile);               // Close file
      DestroyProgressbar();
      return(FALSE);
      }
    // End:   --ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort

    ln += dwRead;                       // Update counter total bytes read

    // Progressbar + ln count + percentage
    //DisplayProgressCount(ln, PROGRESS_CRYPT_BAR);
      
    // No progressbar, only ln count + percentage
    DisplayProgressCount(ln, PROGRESS_LOAD_PCENT);
    } while (ln < dwCryptFileSize);     // end do while

  pszCryptFileIn[dwCryptFileSize]  = 0; // Add null terminator
  LocalFree(pchTmp);
  CloseHandle(hFile);

  // Remove-clear Progressbar 'Loading file'
  // Ensure the correct crypto item remains selected
  DestroyProgressbar();
  
  // Crypto Algorithm functions: DES, 3DES, AES, MAC
  if (CryptoAlgorithmFunctions(cryptMode) == FALSE) return(FALSE);
  else return(TRUE);    
  } // FileBlockCrypto

//------------------------------------------------------------------------------

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{                
//ha//sprintf(DebugBuf, "ln = %08X\nj = %i [j < %i]\nBytesRd = %llX [=%llu]", ln, j, dwFileSizeBlocks1G, lln, lln);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG STOP 3 haCryptFileT - DoTxtFileCopy", MB_OK);
//ha//}
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

