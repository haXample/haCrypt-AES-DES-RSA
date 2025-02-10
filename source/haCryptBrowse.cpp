// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptBrowse.cpp - C++ Developer source file.
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

int _cbtFolderFlag = FALSE; // CBT Hook title/button string control

TCHAR pathDisplay[MAX_PATH+1] = _T("");
TCHAR MfpathDisplay[MAX_PATH+1] = _T("");

TCHAR szPathSaveCpy[MAX_PATH+1];
TCHAR szMfPathSaveCpy[MAX_PATH+1];

BROWSEINFO bi = {0};                  // Global
LPITEMIDLIST pidl = NULL;             // Global
LPITEMIDLIST pidlPathSave = NULL;     // Global
PCUIDLIST_ABSOLUTE pidlSave = NULL;   // Global

BROWSEINFO Mfbi = {0};                // Global
LPITEMIDLIST Mfpidl = NULL;           // Global
PCUIDLIST_ABSOLUTE MfpidlSave = NULL; // Global

extern char DebugBuf[];     // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];  // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern TCHAR _mdfpath[1];   // Multifile destination path
extern TCHAR mdPathSave[];  // Multifile destination path save
extern TCHAR szPathSave[];
extern TCHAR szExtensionSave[];
extern TCHAR oldFileExtension[];

extern HWND hMain;
extern HWND hStatusbar;

extern PIDLIST_ABSOLUTE CBTSHBrowseForFolder(BROWSEINFO);

//-----------------------------------------------------------------------------
//                  Dual: haCryptR.cpp / haCryptC.cpp

//-----------------------------------------------------------------------------
//
//                  RepositionBrowseWindow
//
void RepositionBrowseWindow(HWND _hwnd)
      {
      RECT DesktopRect;
      RECT MainRect;
      RECT BrowserRect;   // Always the same values ??!!
      RECT StatusRect;
      POINT BrowserStart; // Browser upper left edge x, y coordinates

      HWND hDesktop = GetDesktopWindow();       // Get handle to desktop

      ::GetWindowRect(hDesktop, &DesktopRect);  // The desktop window
      ::GetWindowRect(hMain, &MainRect);        // The main window position
      ::GetWindowRect(_hwnd, &BrowserRect);     // The browser window

      ::GetWindowRect(hStatusbar, &StatusRect); // The statusbar window
      int StatusHeight = StatusRect.bottom - StatusRect.top; // Fix value

      // This is the browser window's upper top left (ha design)
      BrowserStart.x = MainRect.left +7;       
      BrowserStart.y = MainRect.top +27;

      if (MainRect.left < DesktopRect.left)  // Keep it visible
        {
        BrowserStart.x = MainRect.right/2;
        BrowserStart.y = MainRect.top +27;
        }
      // Adjust if browser window is off desktop - "Taskleiste"
      if (DesktopRect.bottom < MainRect.bottom+27) BrowserStart.y = MainRect.top/2;

      // Re-position the Browser window at UPPER left of Text-field: +7, +27, 0 ,0
      // 0,0 - Resizing doesn't work with SHBrowseForFolder()                                   
      ::SetWindowPos(_hwnd, NULL,         
                     BrowserStart.x, BrowserStart.y, 0, 0, 
                     SWP_NOZORDER | SWP_NOSIZE); // | SWP_SHOWWINDOW | SWP_NOACTIVATE);

      UpdateWindow(_hwnd);
      } // RepositionBrowseWindow

//-----------------------------------------------------------------------------
//                           haCryptR.cpp

//-----------------------------------------------------------------------------
//
//                           BrowseCallbackProc
//
// bi.lParam = LPARAM lpData 
//
int CALLBACK BrowseCallbackProc(HWND _hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData)
  {
  switch (uMsg)
    {
    case BFFM_INITIALIZED:
      RepositionBrowseWindow(_hwnd);
      SendMessage(_hwnd, BFFM_SETEXPANDED, TRUE, lpData); // Select path and show files
      break;

    case BFFM_SELCHANGED:
      //SendMessage(_hwnd, BFFM_SETSTATUSTEXT, TRUE, (LPARAM)_T(""));                              // Doesn't have any effect
      //SendMessage(_hwnd, BFFM_SETSELECTION, TRUE, (LPARAM)_T("H:\\TEMP600\\__\\_\\_\\123.txt")); // works, but not useful
      //SendMessage(_hwnd, BFFM_SETEXPANDED, TRUE, (LPARAM)_T("H:\\TEMP600\\__\\_\\_\\"));         // Doesn't expand
      break;
    } // end switch
  return 0;
  } // BrowseCallbackProc

//-----------------------------------------------------------------------------
//
//                           DoCurrentFolder
//
// Views can use this method to force Windows Explorer to browse
// to a specific place in the namespace.
// Typically, these are folders contained in the view
//
// LWSTDAPI IUnknown_QueryService(
//   [in]  IUnknown *punk,
//   [in]  REFGUID  guidService,
//   [in]  REFIID   riid,
//   [out] void     **ppvOut
// );
//
// [in] punk -  Type: IUnknown*
//   A pointer to the IUnknown instance of the COM object that supports the service.
//
// HRESULT BrowseObject(
//  PCUIDLIST_RELATIVE pidl,
//  UINT wFlags
//  )
//
BOOL DoCurrentFolder(TCHAR *curFolder)
  {
  int i;

  // Copy the current path (also copying the 0-terminator)
  for (i=0; i<=lstrlen(curFolder); i++)
    szPathSaveCpy[i] = curFolder[i];

  SHGetPathFromIDList(pidlSave, szPathSaveCpy);       // Search in clone pidlSave

  bi.lParam = (LPARAM)szPathSaveCpy;   // Depend on original pidl

  // Free used memory allocated by SH...() functions
  IMalloc* imalloc = 0;
  if (SUCCEEDED(SHGetMalloc(&imalloc)))
    {
    imalloc->Free(pidl);
    imalloc->Release();
    }
  return TRUE;
  } // DoCurrentFolder


//-----------------------------------------------------------------------------
//
//                           DoRootFolder
//
BOOL DoRootFolder(WCHAR *rootFolder)
  {
  ULONG         chEaten;  
  ULONG         dwAttributes;  
  IShellFolder* pDesktopFolder;
    
  if (SUCCEEDED(SHGetDesktopFolder(&pDesktopFolder)))  
    {  
    // Get PIDL for root folder  
    pDesktopFolder->ParseDisplayName(NULL, NULL, rootFolder, &chEaten, &pidlPathSave, &dwAttributes);  
    pDesktopFolder->Release();  
    }  

  // Store PIDL for root folder in BROWSEINFO  
  bi.pidlRoot = pidlPathSave;  
  //bi.lParam = NULL;  
  return TRUE;  
  } // DoRootFolder  
 

//------------------------------------------------------------------------------
//
//                      OpenBrowserDialog - Rename
//
// Unfortunately, 'ShBrowseForFolder()' does not allow you to specify 
//  different text for the window title.
//
// typedef struct _browseinfoW {
//   HWND              hwndOwner;
//   PCIDLIST_ABSOLUTE pidlRoot;   // Root folder from which to start browsing
//   LPWSTR            &pszDisplayName;
//   LPCWSTR           lpszTitle;
//   UINT              ulFlags;
//   BFFCALLBACK       lpfn;
//   LPARAM            lParam;
//   int               iImage;
// } BROWSEINFOW, *PBROWSEINFOW, *LPBROWSEINFOW;
//
// PIDLIST_ABSOLUTE ILCloneFull(
//   [in] PCUIDLIST_ABSOLUTE pidl
// );
//
BOOL OpenBrowserDialog()
  {
  //-----------------------------------------------------------------------
  // If multiple files are selected
  //  open a dialog box to choose a folder where to save the selected files
  //
  int i;
  BOOL bSuccess = FALSE;
  IMalloc* imalloc = 0;

  //BROWSEINFO bi = {0};            // Global, see above
                                   
  bi.hwndOwner      = hMain;
  bi.pidlRoot       = pidlPathSave; // NULL;       
  bi.pszDisplayName = pathDisplay;
  bi.lpszTitle      = _T("Choose a folder, and select anyone of the files\n")
                      _T("with an extension that should be renamed on\n")
                      _T("all files of that type in the chosen folder.");
  bi.ulFlags        = BIF_NEWDIALOGSTYLE | BIF_NONEWFOLDERBUTTON | BIF_BROWSEINCLUDEFILES;// | BIF_NOTRANSLATETARGETS; // | BIF_UAHINT;
  bi.lpfn           = BrowseCallbackProc;
  bi.lParam         = (LPARAM)szPathSave;
  bi.iImage         = 0;

  //pidl = SHBrowseForFolder(&bi);  // Get current LPITEMIDLIST
  _cbtFolderFlag = MULTIFILE_BROWSER_RENAME; // CBT Hook title "Select a Folder" & "Cancel" 
  pidl = CBTSHBrowseForFolder(bi);           // Get current LPITEMIDLIST
  _cbtFolderFlag = FALSE;                    // CBT Hook default 

  pidlSave = ILCloneFull(pidl);   // Clone the LPITEMIDLIST for convenient usage

  if (pidl != NULL)
    {
    // Get the name of the folder into 'szPathSave[]'
    //  and concatenate a backslash
    if (SHGetPathFromIDList(pidl, szPathSave))
      {
      if (GetFileAttributes(szPathSave) & FILE_ATTRIBUTE_DIRECTORY)
        {
        lstrcat(szPathSave, _T("\\"));  // It's a folder, so append it with '\'
        oldFileExtension[0] = 0;        // Clear file extension pattern
        } 

      else                              // It's path + filename
        {
        for (i=lstrlen(szPathSave); i>0; i--)  // Search start-of-filename
          {                                    //  (which is end-of-path)
          if (szPathSave[i] == (WCHAR)'.') break;
          }

        oldFileExtension[0] = L'*';     // Set file extension empty pattern
        oldFileExtension[1] = L'.';
        oldFileExtension[2] = 0;

        szExtensionSave[0] = 0;         // Empty string
        if (i > 0)  
          { 
          szExtensionSave[0] = (WCHAR)'*';     // Save file extension from browser dialog
          szExtensionSave[1] = 0;              // Make it a terminatedt string
          lstrcat(szExtensionSave, &szPathSave[i]);
          szExtensionSave[12+1] = 0;           // Truncate string at length of 10 UCHARS
          }

        for (i=lstrlen(szPathSave); i>0; i--)  // Search start-of-filename
          {                                    //  (which is end-of-path)
          if (szPathSave[i] == (WCHAR)'\\') break;
          } 
        szPathSave[i+1] = 0;            // Append folder with '\' and discard filename
        } // end else
      }

    bSuccess = TRUE;
    } // end if (pidl)

  return(bSuccess);
  } // OpenBrowserDialog


//-----------------------------------------------------------------------------
//                           haCryptC.cpp

//-----------------------------------------------------------------------------
//
//                           MfBrowseCallbackProc
//
// Mfbi.lParam = LPARAM lpData 
//
int CALLBACK MfBrowseCallbackProc(HWND _hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData)
  {
  switch (uMsg)
    {
    case BFFM_INITIALIZED:
      RepositionBrowseWindow(_hwnd);
      SendMessage(_hwnd, BFFM_SETEXPANDED, TRUE, lpData); // Select path and show files
      break;

    case BFFM_SELCHANGED:
      break;
    } // end switch

  return 0;
  } // MfBrowseCallbackProc

//-----------------------------------------------------------------------------
//
//                           MfDoCurrentFolder
//
// Views can use this method to force Windows Explorer to browse
// to a specific place in the namespace.
// Typically, these are folders contained in the view
//
// LWSTDAPI IUnknown_QueryService(
//   [in]  IUnknown *punk,
//   [in]  REFGUID  guidService,
//   [in]  REFIID   riid,
//   [out] void     **ppvOut
// );
//
// [in] punk -  Type: IUnknown*
//   A pointer to the IUnknown instance of the COM object that supports the service.
//
// HRESULT BrowseObject(
//  PCUIDLIST_RELATIVE pidl,
//  UINT wFlags
//  )
//
BOOL MfDoCurrentFolder(TCHAR *curFolder)
  {
  int i;

  // Copy the current path (also copying the 0-terminator)
  for (i=0; i<=lstrlen(curFolder); i++)
    szMfPathSaveCpy[i] = curFolder[i];

  SHGetPathFromIDList(MfpidlSave, szMfPathSaveCpy);     // Search in clone MfpidlSave

  Mfbi.lParam = (LPARAM)szMfPathSaveCpy; // Depend on original Mfpidl

  // Free used memory allocated by SH...() functions
  IMalloc* imalloc = 0;
  if (SUCCEEDED(SHGetMalloc(&imalloc)))
    {
    imalloc->Free(Mfpidl);
    imalloc->Release();
    }
  return TRUE;
  } // MfDoCurrentFolder


//------------------------------------------------------------------------------
//
//                      MfOpenBrowserDialog
//
// If multiple files are selected
//  open a dialog box to choose a folder where to save the selected files
//
// Unfortunately, 'ShBrowseForFolder()' does not allow you to specify 
//  different text for the window title.
//
// typedef struct _browseinfoW {
//   HWND              hwndOwner;
//   PCIDLIST_ABSOLUTE pidlRoot;   // Root folder from which to start browsing
//   LPWSTR            &pszDisplayName;
//   LPCWSTR           lpszTitle;
//   UINT              ulFlags;
//   BFFCALLBACK       lpfn;
//   LPARAM            lParam;
//   int               iImage;
// } BROWSEINFOW, *PBROWSEINFOW, *LPBROWSEINFOW;
//
// PIDLIST_ABSOLUTE ILCloneFull(
//   [in] PCUIDLIST_ABSOLUTE pidl
// );
//
BOOL MfSaveBrowserDialog()
  {
  int bSuccess = FALSE;
  int i;

  //BROWSEINFO Mfbi = {0};                       // Global, see above

  Mfbi.hwndOwner      = hMain;
  Mfbi.pidlRoot       = NULL;                    // = MfpidlSave;
  Mfbi.pszDisplayName = MfpathDisplay;
  Mfbi.lpszTitle      = _T("Choose a folder where the files should be saved.");
  Mfbi.ulFlags        = BIF_NEWDIALOGSTYLE;      // | BIF_NONEWFOLDERBUTTON;
  Mfbi.lpfn           = MfBrowseCallbackProc;    // = NULL
  Mfbi.lParam         = (LPARAM)szMfPathSaveCpy; // = (LPARAM)_T("H:\\");
  Mfbi.iImage         = 0;

  //Mfpidl = SHBrowseForFolder(&Mfbi); // Get the LPITEMIDLIST
  _cbtFolderFlag = MULTIFILE_BROWSER_CRYPTO; // CBT Hook title "File(s) processed" "Close" 
  Mfpidl = CBTSHBrowseForFolder(Mfbi);      // Get the LPITEMIDLIST
  _cbtFolderFlag = FALSE;                   // CBT Hook default

  MfpidlSave = ILCloneFull(Mfpidl);    // Clone the LPITEMIDLIST for convenience

  if (Mfpidl != NULL)
    {
    // Get the name of the folder
    if (SHGetPathFromIDList(Mfpidl, _mdfpath))
      {
      // Add a backslash and make a backup copy, needed later
      if (_mdfpath[wcslen(_mdfpath)-1] != '\\') lstrcat(_mdfpath, _T("\\"));
      for (i=0; i<=MAX_PATH; i++) mdPathSave[i] = _mdfpath[i];  
      }
    // Preselect current folder for next rename
    //  (also free used memory  allocated by SH...() functions)
    //DoCurrentFolder(MfpathDisplay);  // Alternatively working
    // Free used memory allocated by SH...() functions
    MfDoCurrentFolder(mdPathSave);
    bSuccess = TRUE;
    } // end if (Mfpidl)
  
  return(bSuccess);
  } // MfSaveBrowserDialog

//--------------------------------------------------------------------------------------------

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{
//ha//sprintf(DebugBuf, "FileProcessingMode = %08X\nCRYPT_MAC= %08X", FileProcessingMode, CRYPT_MAC);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG STOP 0", MB_OK);
//ha//}
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{ 
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("pszNextFile: %s\nmdPathSave=%s"), pszNextFile, mdPathSave); 
//ha//MessageBox(NULL, _tDebugBuf, _T("STOP 3"), MB_ICONINFORMATION | MB_OK);
//ha//}
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---


