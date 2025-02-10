// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptFileR.cpp - C++ Developer source file.
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

TCHAR szFileName[2*MAX_PATH+1];
TCHAR szFileNameNew[2*MAX_PATH+1];
TCHAR szFilePathNew[2*MAX_PATH+1];
TCHAR szFilePathOld[2*MAX_PATH+1];
TCHAR szExtensionSave[20];
TCHAR szPathSave[MAX_PATH+1];
TCHAR* pszPathSave = NULL;

WIN32_FIND_DATA FindFileData;
int _cancel, renameFlag=FALSE;

// Extern variables
extern TCHAR szSignonTitle[];
extern TCHAR oldFileExtension[];
extern TCHAR newFileExtension[];
extern TCHAR szStatusClear[];

extern int _valAQ, multiFileFlag, _escFlag;
extern DWORD _lastErr;

extern char DebugBuf[];     // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];  // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern HINSTANCE g_hInst;

extern HWND hMain;
extern HWND hEdit;
extern HWND hStatusbar;

extern void ControlRenameDialog(int);
extern void DisplayLastError(int);
extern void PaintColoredStatusMsg(TCHAR*);
extern void PaintColoredStatusInfoMsg(TCHAR*);
extern void PaintColoredStatusPercentMsg(TCHAR*);
extern int CBTCustomMessageBox(HWND, LPCTSTR, LPCTSTR, UINT, UINT);
extern BOOL CheckEscapeAbort();

extern INT_PTR CALLBACK DialogProcMultiFile(HWND, UINT, WPARAM, LPARAM); 

extern int CALLBACK BrowseCallbackProc(HWND, UINT, LPARAM, LPARAM);
extern BOOL DoRootFolder(WCHAR *);
extern BOOL DoCurrentFolder(TCHAR *);
extern BOOL OpenBrowserDialog();

//------------------------------------------------------------------------------
//
//                      MessageBoxLastError
//
// GetLastError():
//  ERROR_ALREADY_EXISTS    = 0x0B7 [183]  _T("File already exists")
//  ERROR_INVALID_NAME      = 0x07B [123]  _T("Invalid filename")
//  ERROR_FILE_NOT_FOUND    = 0x002 [002]  _T("File not found")
//  ERROR_SHARING_VIOLATION = 0x020 [032]  _T("File sharing violation")
//  ERROR_ACCESS_DENIED     = 0x005 [005]  _T("Access denied")
//  ERROR_PATH_NOT_FOUND    = 0x003 [003]  _T("File not found")
//  ERROR_DIRECTORY         = 0x10B [267]  _T("Invalid directory name")
//
// Example (affecting directories)
// ren *. *.txt
// ------------
// t1.txt
// t1
// __ (c:\temp600\__ = Subdir)
// .  (c:\temp600\.  = Actual Dir)
// .. (c:\           = Root Dir)
//
// ERRORS (Messagebox output):
// c:\temp600\.  c:\temp600\..txt   [0x20]
// c:\temp600\.. c:\temp600\...txt  [0x05]
// c:\temp600\t1 c:\temp600\t1.txt  [0xB7]
// c:\temp600\__ c:\temp600\__.txt  [0x20]
//
TCHAR szRenFileType[] = _T("Rename file extensions.");

void MessageBoxLastError(DWORD _lastError)
  {
  switch(_lastError)
    {
    // Pop-up a detailed description why rename is not possible
    case ERROR_ALREADY_EXISTS:
      PaintColoredStatusMsg(szStatusClear);
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("Path = %s\nCmd = REN  %s  *.%s\n\n")
                                                 _T("%s - Not renamed\n%s - File already exists.\n\n")
                                                 _T("Press [ESC] to abort or [OK] to continue."),
                                                 szPathSave, oldFileExtension, newFileExtension,
                                                 FindFileData.cFileName, szFileName);
      CBTCustomMessageBox(NULL, _tDebugBuf, szRenFileType, MB_OK, IDI_HACRYPT_ICON);
      break;

    // These errors are displayed on the statusbar
    case ERROR_PATH_NOT_FOUND:   
    case ERROR_FILE_NOT_FOUND:
    case ERROR_INVALID_NAME:
    case ERROR_SHARING_VIOLATION:
    case ERROR_ACCESS_DENIED:
    case ERROR_DIRECTORY:
      DisplayLastError(_lastError);
      break;

    case HA_ERROR_REN_WILDCARD:
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("WILDCARDS   * ?   NOT SUPPORTED IN FILE TYPE  '.Old'")); 
      DisplayLastError(_ERR);     // Display formatted _tDebugBuf contents
      break;

    case HA_ERROR_REN_FILETYPE:
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("ERROR:    \\ / : * ? \x22 < > |   NOT ALLOWED IN FILE EXTENSION")); 
      DisplayLastError(_ERR);     // Display formatted _tDebugBuf contents
      break;

    case HA_ERROR_REN_ZIPFILE:
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("ERROR: RENAMING ZIP-FILE NOT ALLOWED")); 
      DisplayLastError(_ERR);     // Display formatted _tDebugBuf contents
      break;
    
    // Pop-up the error number issued by the system
    default:
      PaintColoredStatusMsg(szStatusClear);
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("Path = %s\nCmd = REN  %s  *.%s\n\n")
                                                 _T("%s - Not renamed\nERROR: LastErrorode = 0x%08X [%i]\n\n")
                                                 _T("Press [ESC] to abort or [OK] to continue."),
                                                 szPathSave, oldFileExtension, newFileExtension,
                                                 FindFileData.cFileName, _lastError, _lastError);  //, EACCES);
      CBTCustomMessageBox(NULL, _tDebugBuf, szRenFileType, MB_OK, IDI_HACRYPT_ICON);
      break;   
    } // snd switch
  } // MessageBoxLastError


//------------------------------------------------------------------------------
//
//                             ZipFileContainer
//
// Don't allow to either rename a zip-file, or to create one just by renaming.
// Note: Zip files are monitored by the system, and may provoke annyoing pop-ups.
//
//  Return: FALSE = Not a zip-file, rename is allowed
//          TRUE  = Rename forbidden ('Old' = .zip or 'New' will become a .zip)
//
BOOL ZipFileContainer(TCHAR _szFileName[], TCHAR _newFileExtension[])
  {
  TCHAR* _strZip = _T(".zip");
  PTSTR _pstr;
  BOOL _zipResult = FALSE;

  if (wcscmp(PathFindExtension(_szFileName), _strZip) == 0)
    _zipResult = TRUE;   // 'Old' = ".zip": Not trying a zip-file

  if ((_pstr = StrRChrW(_newFileExtension, NULL, _T('.'))) != NULL)  
    {
    if (lstrlen(_pstr) == lstrlen(_strZip) &&                   // Found last '.'
        wcsstr(_newFileExtension, _strZip) != NULL)
      _zipResult = TRUE; // 'New' = ".zip": Trying to rename a zip-file
    }

  else if (lstrlen(_newFileExtension) == lstrlen(_strZip)-1 &&  // "zip"
           wcsstr(_newFileExtension, &_strZip[1]) != NULL)
    _zipResult = TRUE;   // 'New' = "zip": Trying to rename a zip-file

  return(_zipResult);
  } // ZipFileContainer 

//------------------------------------------------------------------------------
//
//                             DoFileRename
//
void DoFileRename()
  {
  TCHAR* pszLast;
  int i, _fCount, _errCount, result;

  SendMessage(hEdit, EM_SETREADONLY, FALSE, 0); // Enable rd/wr in edit field 
  SetDlgItemText(hMain, IDC_MAIN_EDIT, NULL);   // Clear text edit field
  PaintColoredStatusMsg(szStatusClear);         // Clear status part 0 & part 1
  SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("")); 
  SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)_T("")); 

  //-----------------------------------------------------------
  // Select a Folder (szPathSave[] = ...)
  //  and (optionally) get a fileType (szExtensionSave[] = ...)
  if (OpenBrowserDialog() == FALSE)
    {
    DoRootFolder(NULL);             // Reset to the very system root 
    szExtensionSave[0] = 0;         // Clear string
    return;
    }

  // Get 'oldFileExtension[]' and 'newFileExtension[]'
  // Stick DialogBox(...) to 'hMain' not to 'NULL' so it stays visible and forces user to respond.
  ControlRenameDialog(MF_GRAYED);   // Disable file menue item 'Rename' - Don't allow recoursion
  DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_FILEXR), hMain,
                 DialogProcMultiFile, (LPARAM)IDD_HACRYPT_FILEXR);
  ControlRenameDialog(MF_ENABLED);  // Re-enable for another usage                       

  // Abort if cancelled and keep file(s) untouched
  if (_valAQ == A_CANCEL)
    {
    DoRootFolder(NULL);             // Reset to the very system root 
    szExtensionSave[0] = 0;         // Clear string
    SetWindowText(hMain, szSignonTitle);  // Display signon-text in mainwindow's title field
    return;                         // Abort return
    }

  for (i=0; i<=lstrlen(szPathSave); i++) szFileName[i] = szPathSave[i];
  // szFileName = old filename + wildcard extension
  lstrcat(szFileName, oldFileExtension); 

  _lastErr = 0; _escFlag = FALSE;

  // Dont allow '?' or '*' in oldFileExtension of szFileName (prevent x64 system hang)
  //  (all other illegal chars are handled correctly by 'FindFirstFile(..)')
  PTSTR _pstr;
  if ((_pstr = StrRChrW(szFileName, NULL, _T('.'))) != NULL) // skip *.
    {
    if (StrChrW(_pstr, _T('*')) != NULL ||
        StrChrW(szFileName, _T('?')) != NULL)
      {
      MessageBoxLastError(HA_ERROR_REN_WILDCARD);
      return;
      }
    }

  // Check for illegal characters in newFileExtension
  if (StrChrW(newFileExtension, _T('\\')) != NULL || 
      StrChrW(newFileExtension, _T('/')) != NULL  ||
      StrChrW(newFileExtension, _T(':')) != NULL  ||
      StrChrW(newFileExtension, _T('*')) != NULL  ||
      StrChrW(newFileExtension, _T('?')) != NULL  ||
      StrChrW(newFileExtension, _T('"')) != NULL  ||
      StrChrW(newFileExtension, _T('<')) != NULL  ||
      StrChrW(newFileExtension, _T('>')) != NULL  ||
      StrChrW(newFileExtension, _T('|')) != NULL) 
    {
    MessageBoxLastError(HA_ERROR_REN_FILETYPE);
    return;
    }

  // Check if current szFileName is a zip-file or newFileExtension is "zip"
  // Don't allow renaming zip files (these are monitored by the system)
  if (ZipFileContainer(szFileName, newFileExtension))
    {
    MessageBoxLastError(HA_ERROR_REN_ZIPFILE);
    return;
    }

  HANDLE hFind = FindFirstFile(szFileName, &FindFileData);
  if (hFind == INVALID_HANDLE_VALUE)   
    {
    _lastErr = GetLastError();
    MessageBoxLastError(_lastErr);
    return;
    } 
  else 
    {
    SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); 
    //SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("Renaming..."));
    PaintColoredStatusPercentMsg(_T("Renaming..."));
    multiFileFlag = TRUE;                              // Disable 'case WM_DRAWITEM:'
      
    _fCount = 0; _errCount = 0;
    do
      {
      // Re-init all strings
      for (i=0; i<=lstrlen(FindFileData.cFileName); i++)
        szFileName[i] = FindFileData.cFileName[i];

      for (i=0; i<=lstrlen(&szPathSave[0]); i++)
        {
        szFilePathNew[i] = szPathSave[i];              // Prepare path for new file name
        szFilePathOld[i] = szPathSave[i];              // Prepare path old filename
        }

      // +2: skip '*.' of oldFileExtension (was needed to find the first file)
      szFileName[lstrlen(FindFileData.cFileName)-lstrlen(oldFileExtension)+2] = 0;  

      // Duplicate szFileName (New filename = Old filename)
      for (i=0; i<=lstrlen(szFileName); i++) szFileNameNew[i] = szFileName[i];

      lstrcat(szFileNameNew, _T("."));                 // New filename + "."
      lstrcat(szFileNameNew, newFileExtension);        // New filename + new file extension

      // oldFileExtension = '*.' means no extension. 
      // So adding '.' plus newFileExtension was obviously intended by the user.
      // (Otherwise lengthen the filename makes no sense. We're dealing with file extensions here!) 
      //
      if (lstrlen(oldFileExtension) == 2) lstrcat(szFileName, _T("."));  

      lstrcat(szFileName, newFileExtension);           // New filename = old filename + new file extension
      lstrcat(szFilePathNew, szFileName);              // path + new filename
      lstrcat(szFilePathOld, FindFileData.cFileName);  // path + old filename

      // Check if path is a directory (Folders should not be renamed).
      if (!(GetFileAttributes(szFilePathOld) & FILE_ATTRIBUTE_DIRECTORY))
        {
        // Try to rename the file
        if (_wrename(szFilePathOld, szFilePathNew) != 0)   // File rename
          {
          _lastErr = GetLastError();
          MessageBoxLastError(_lastErr);
          if (_errCount++ > 100)
            {
            DoRootFolder(NULL);
            szExtensionSave[0] = 0; // Clear string
            break;                  // Stop and return
            }
          }
        else _fCount++;  // File has been renamed.
        } // end if (!FILE_ATTRIBUTE_DIRECTORY)

      MSG msg;                                    // Dummy for PeekMessage()
      PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE); // Prevent "Not responding" system msg
      
      // Display the file just having been renamed
      SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)szFilePathNew);  

      // Begin: --ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort
      // Here we allow to abort renaming huge amounts of files by pressing the ESC key
      if (CheckEscapeAbort() == TRUE) break;
      // End: --ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort

      } while (FindNextFile(hFind, &FindFileData));
    } // end if - else (hFind == INVALID_HANDLE_VALUE)

  // Display renamepath\*.newExtension in mainwindow's title field
  StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%s*.%s"), szPathSave, newFileExtension);
  SetWindowText(hMain, _tDebugBuf);
  
  // Must stay here, because of repaint behaviour of Windows XP at BFFM_INITIALIZED.
  //  (XP will take the last contents of _tDebugBuf if extensions are equal ?!)       
  StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%i file(s) renamed."), _fCount);
  PaintColoredStatusInfoMsg(_tDebugBuf); // Change text and text colors in statusbar

  // Suppress a possible last '.' ("filename.E." should become "filename.E")
  if (szFilePathNew[lstrlen(szFilePathNew)-1 ] == L'.')
    szFilePathNew[lstrlen(szFilePathNew)-1 ] = 0; 
  PTSTR _szExtensionSave = PathFindExtension(szFilePathNew);                                          

  //---------------------------------------------------------------------------------------
  // Show a browser dialog with the processed file type filtered (Don't use _tDebugBuf!) //|
  renameFlag = TRUE;                                                                     //|
  extern int BrowserFilterFileType(LPWSTR, LPWSTR);                                      //|
  if (_fCount > 0) BrowserFilterFileType(_szExtensionSave, szPathSave);                  //|
  renameFlag = FALSE;                                                                    //|
  //---------------------------------------------------------------------------------------

//ha//  FindClose(hFind);
  multiFileFlag = FALSE;  // Enable 'case WM_DRAWITEM:' see 'haCryptMain.cpp'

  // Preselect current folder for next rename
  //  (also free used memory  allocated by SH...() functions)
  DoCurrentFolder(szPathSave);
  szExtensionSave[0] = 0; // Invalidate to allow next run with defaults  
//ha//  DoRootFolder(szPathSave);
  } // DoFileRename
   
//------------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//  StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("szFilePathNew = %s\nszPathSave = %s\n_szExtensionSave = %s"),
//ha//                                                   szFilePathNew, szPathSave, _szExtensionSave);
//ha//  MessageBox(NULL, _tDebugBuf, _T("DEBUG 1 haWintest - DoFileRename"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("oldFileExtension = %s\nnewFileExtension = %s"), oldFileExtension, newFileExtension);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG 0 haWintest - DoFileRename"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
