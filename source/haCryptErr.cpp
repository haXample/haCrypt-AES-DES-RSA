// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptErr.cpp - C++ Developer source file.
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
TCHAR szErrorFileIsUsed[]       = _T("Error: File is being used by another process.");
TCHAR szErrorFileWrite[]        = _T("Error: File write failed.");
TCHAR szErrorFileOpen[]         = _T("Error: File open failed.");
TCHAR szErrorDiskFull[]         = _T("Error: Disk full.");
TCHAR szErrorFileSizeRSA[]      = _T("/RSA Large files > %i bytes should be processed with DES/AES/3DES");
TCHAR szErrorFileSizeDES[]      = _T("Incorrect data size < 8");
TCHAR szErrorFileSizeAES[]      = _T("Incorrect data size < 16");
TCHAR szErrorMemoryAlloc[]      = _T("Error: File size. Insufficient memory.");
TCHAR szErrorInvalidFilename[]  = _T("Invalid filename");
TCHAR szErrorSharingViolation[] = _T("File sharing violation");
TCHAR szErrorAccessDenied[]     = _T("Access denied");          
TCHAR szErrorFileNotFound[]     = _T("File not found");
TCHAR szErrorNotReady[]         = _T("Device not ready");

TCHAR szPathNotFound[]          = _T("Path not found");
TCHAR szInvalidDirectoryName[]  = _T("Invalid directory name");
TCHAR szTooManyFiles[]          = _T("Too many files selected.");
TCHAR szNoFileSelected[]        = _T("No File(s) selected...");
TCHAR szNoFileCopied[]          = _T("No file(s) copied...");
                                
TCHAR szKeyFileError[]          = _T("Incorrect Key size > 32");
TCHAR szIvFileError[]           = _T("Incorrect IV size > 16");
TCHAR szKeyGenErrorRSA[]        = _T("/RSA This generated key has not been saved. Import/load another appropriate key.");
TCHAR szKeyFileErrorRSA[]       = _T("/RSA Incorrect key");
TCHAR szNoPubKeyErrorRSA[]      = _T("RSA /Encrypt: Please import a desired public key.");
TCHAR szNoPrvKeyErrorRSA[]      = _T("RSA /Decipher: Please load your private key.");

// Extern variables
extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern int _escAbort;

extern void PaintColoredStatusErrorMsg(TCHAR*);

//-----------------------------------------------------------------------------
//
//                      DisplayLastError
//
void DisplayLastError(int _lastError)
  {
  _escAbort = FALSE;

  switch(_lastError)
    {
    case _ERR:
      PaintColoredStatusErrorMsg(_tDebugBuf);       // Composed error message
      break;
    case ERROR_DIRECTORY:
      PaintColoredStatusErrorMsg(szInvalidDirectoryName);
      break;                                                                                                 
    case ERROR_PATH_NOT_FOUND:   
      PaintColoredStatusErrorMsg(szPathNotFound);
      break;                                                                                                 
    case ERROR_NOT_READY:
      PaintColoredStatusErrorMsg(szErrorNotReady);
      break;                                                                                                 
    case ERROR_FILE_NOT_FOUND:
      PaintColoredStatusErrorMsg(szErrorFileNotFound);
      break;                                                                                                 
    case FNERR_INVALIDFILENAME:
    case ERROR_INVALID_NAME:
      PaintColoredStatusErrorMsg(szErrorInvalidFilename);
      break; 
    case ERROR_SHARING_VIOLATION:
      PaintColoredStatusErrorMsg(szErrorFileIsUsed);
      break; 
    case ERROR_ACCESS_DENIED:
      PaintColoredStatusErrorMsg(szErrorAccessDenied);
      break;
    case ERROR_DISK_FULL:
      PaintColoredStatusErrorMsg(szErrorDiskFull);
      break;
    case HA_TOO_MANY_FILES:
      PaintColoredStatusErrorMsg(szTooManyFiles);
      break;
    case HA_ERROR_FILE_WRITE:
      PaintColoredStatusErrorMsg(szErrorFileWrite);
      break;
    case HA_ERROR_FILE_OPEN:
      PaintColoredStatusErrorMsg(szErrorFileOpen);
      break;
    case HA_NO_FILE_SELECTED:
      PaintColoredStatusErrorMsg(szNoFileSelected);
      break;
    case HA_NO_FILE_COPIED:
      PaintColoredStatusErrorMsg(szNoFileCopied);
      break;
    case HA_ERROR_KEY_SIZE_RSA:
      PaintColoredStatusErrorMsg(szKeyFileErrorRSA);
      break;
    case HA_ERROR_NOPUBKEY_RSA:
      PaintColoredStatusErrorMsg(szNoPubKeyErrorRSA);
      break;
    case HA_ERROR_NOPRVKEY_RSA:
      PaintColoredStatusErrorMsg(szNoPrvKeyErrorRSA);
      break;
    case HA_ERROR_KEY_GEN_RSA:
      PaintColoredStatusErrorMsg(szKeyGenErrorRSA);
      break;
    case HA_ERROR_FILESIZE_RSA:
      PaintColoredStatusErrorMsg(szErrorFileSizeRSA);
      break;
    case HA_ERROR_FILESIZE_DES:
      PaintColoredStatusErrorMsg(szErrorFileSizeDES);
      break;
    case HA_ERROR_FILESIZE_AES:
      PaintColoredStatusErrorMsg(szErrorFileSizeAES);
      break;
    case HA_ERROR_MEMORY_ALLOC:
      PaintColoredStatusErrorMsg(szErrorMemoryAlloc);
      break;
    case HA_ERROR_KEY_FILESIZE:
      PaintColoredStatusErrorMsg(szKeyFileError);
      break;
    case HA_ERROR_IV_FILESIZE:
      PaintColoredStatusErrorMsg(szIvFileError);
      break;
    default:
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("ERROR: LastErrorode = 0x%08X [%i]"), _lastError, _lastError);
      PaintColoredStatusErrorMsg(_tDebugBuf);
      break;
    } // end switch
  } // DisplayLastError

//------------------------------------------------------------------------------
