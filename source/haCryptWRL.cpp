// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptWRL.cpp - C++ Developer source file.
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

// Filtering the folders that appear in the Browse for Folder dialog

// With thanks and regrds to:
// The Old New Thing: Practical Development Throughout the Evolution of Windows
// Book from Raymond Chen

#include <shlwapi.h>  // Library shlwapi.lib for PathFileExistsA, PathFindExtensionW

typedef HANDLE HDWP;	// needed in <shlobj_core.h> for 'x64' ha reduced VC 2019 installation 
#include <shlobj.h>   // Typical Shell header file, for browsing directory info (#include(s) <shlobj_core.h>!)
#include <shobjidl.h>

#include <winuser.h>  // contains: #if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP) typedef HANDLE HDWP; #endif                                                                            
#include <windows.h>
#include <commctrl.h> // Library Comctl32.lib
#include <commdlg.h>

#include <string.h>                                                  
#include <string>     // sprintf, etc.                                   
#include <tchar.h>     
#include <strsafe.h>  // <strsafe.h> must be included after <tchar.h>

#include <propkey.h>
#include <propvarutil.h>

#include <objbase.h>
#include <windowsx.h> // For Edit_GetLine

#include "haCrypt.h"

// Global variables
TCHAR* pszFileType;           // File extension to be filtered
TCHAR* pszFolder;
TCHAR pszShowFolder[MAX_PATH+1];

TCHAR _tEditLine[MAX_PATH+1]; // Temporary buffer for formatted UNICODE text
int _i,_j, _k;

// External variables
extern char DebugBuf[];       // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];    // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern int renameFlag, _flag29K, _cbtFolderFlag;

extern HWND hMain;
extern HWND hEdit;
extern HWND hStatusbar;

extern PIDLIST_ABSOLUTE CBTSHBrowseForFolder(BROWSEINFO);
extern void RepositionBrowseWindow(HWND);

// Forward declaration of functions included in this code module:
BOOL IsMyComputerFolder(IUnknown *);
HRESULT GetObjectCLSID(IUnknown *, CLSID *);

#define FILE_TYPE           //ha3// Used by 'haCryptFileC.cpp'&'haCryptFileR.cpp'
//ha2//#define DRIVE_LETTER //ha2// Just for demo & test only
//ha1//#define DRIVE_SIZE   //ha1// Just for demo & test only

//ha1ha2////------------------------------------------------------------------------
//ha1ha2//                //*****************************************************************
//ha1ha2//_MSC_VER > 1600 // _MSC_VER (Visual Studio 2019) - Smart pointer class library WRL |
//ha1ha2//                //*****************************************************************
//ha1ha2//
//ha1//#ifdef DRIVE_SIZE
//ha1////---------------------------------------------------------------------------
//ha1//// WRL does not come with a "smart VARIANT" class analogous to ATL’s CComVariant,
//ha1////  so we provide our own very simple one.
//ha1////
//ha1//// Keyword "this":
//ha1//// ---------------
//ha1//// The keyword "this" is a pointer accessible only within the
//ha1//// nonstatic member functions of a class, struct, or union type. 
//ha1//// It points to the object for which the member function is called.
//ha1//// Static member functions don't have a  "this" pointer.
//ha1////
//ha1//// Syntax
//ha1////   this
//ha1////   this->member-identifier
//ha1////
//ha1//struct ComVariant : public VARIANT
//ha1//  {
//ha1//  ComVariant() { VariantInit(this); }       // Keyword "this"
//ha1//  ~ComVariant() { VariantClear(this); }     // Keyword "this"
//ha1//  };
//ha1//
//ha1////---------------------------------------------------------------------------
//ha1////
//ha1////                   class CFunnyFilter - DRIVE_SIZE
//ha1////
//ha1////Today’s Little Program applies an arbitrary filter to the Browse for Folder dialog:
//ha1//// We will filter out drives smaller than 8GB.
//ha1//// Customize the Browse for Folder dialog so it shows only drives > 8G 
//ha1////                                                                    
//ha1//// WinAPI 32/64bit code for Windows 10 (Visual Studio 2019 Syntax).
//ha1////
//ha1//#define STRICT_TYPED_ITEMIDS
//ha1//
//ha1//// Smart pointer class library is "Rolls Dice" WRL !! (Woodoo Code)
//ha1//#include <wrl\client.h>                                   
//ha1//#include <wrl\implements.h>  
//ha1//using namespace Microsoft::WRL;                                        
//ha1//
//ha1//class CFunnyFilter : public RuntimeClass <
//ha1//                              RuntimeClassFlags<RuntimeClassType::ClassicCom>,
//ha1//                              IFolderFilter
//ha1//                              >
//ha1//  {
//ha1//  public:
//ha1//
//ha1// //--------------------------------------------------------------------------
//ha1// //
//ha1// //                     ShouldShow - DRIVE_SIZE
//ha1// //
//ha1// //Our custom Should­Show method first checks if we are showing children of My Computer.
//ha1// // If not, then we allow the item to pass through the filter.
//ha1// //
//ha1// //Next, we convert the folder to IShell­Folder2.
//ha1// // If we can’t, then we allow the item to pass through the filter. (Arbitrary choice.)
//ha1// //
//ha1// //Next, we ask for the capacity of the item.
//ha1// // If we can’t (no media in drive, or it’s not a drive in the first place),
//ha1// // then we allow the item to pass through the filter. (Arbitrary choice.)
//ha1// //
//ha1// //Next, we look at the capacity, and if it’s at least 512GB,
//ha1// // then we allow the item to pass through the filter.
//ha1// // Otherwise, we have a drive smaller than 512GB, so we filter it out.
//ha1// //
//ha1// // *** IFolderFilter ***
//ha1// //
//ha1//  IFACEMETHODIMP ShouldShow(IShellFolder* psf,
//ha1//                            PCIDLIST_ABSOLUTE pidlFolder,
//ha1//                            PCUITEMID_CHILD pidlItem)
//ha1//    {
//ha1//    if (!IsMyComputerFolder(psf))                                         
//ha1//      return S_OK;                                                        
//ha1//                                                                          
//ha1//    ComPtr<IShellFolder2> spsf2;                                          
//ha1//                                                                          
//ha1//    if (FAILED(ComPtr<IUnknown>(psf).As(&spsf2)))                         
//ha1//      return S_OK;                                                        
//ha1//                                                                          
//ha1//    ComVariant svt;                                                       
//ha1//                                                                              
//ha1//    if (FAILED(spsf2->GetDetailsEx(pidlItem, &PKEY_Capacity, &svt)))      
//ha1//      return S_OK;                                                        
//ha1//                                                                          
//ha1//    // Dont show < 8G                                                       
//ha1//    if (VariantToUInt64WithDefault(svt, 0) < 8ULL*1024ULL*1024ULL*1024ULL)
//ha1//      return S_FALSE;    // Don't show                                    
//ha1//                                                                          
//ha1//    return S_OK;         // Show                                            
//ha1//   } // ShouldShow
//ha1//
//ha1//  //-------------------------------------------------------------------------
//ha1//  //
//ha1// //                         GetEnumFlags - DRIVE_SIZE
//ha1// //
//ha1// // Okay, working upward, the next method is Get­Enum­Flags.
//ha1// //  This is called when the Browse for Folder dialog wants to enumerate the children of a folder,
//ha1// //  and it’s our chance to influence what gets enumerated.
//ha1// //  We don’t want to expand the drives themselves, so if we have something that is a child
//ha1// //  of My Computer, we set the enumeration flags to zero, which means that nothing gets enumerated.
//ha1// //
//ha1//  IFACEMETHODIMP GetEnumFlags(IShellFolder* psf,
//ha1//                              PCIDLIST_ABSOLUTE pidlFolder,
//ha1//                              HWND *phwnd,
//ha1//                              DWORD *pgrfFlags)   // =A0 (SHCONTF_FOLDERS | SHCONTF_INCLUDEHIDDEN)
//ha1//    {
//ha1//    return S_OK;
//ha1//    } // GetEnumFlags
//ha1//
//ha1//  }; // end class CFunnyFilter
//ha1//
//ha1//-----------------------------------------------------------------------------
//ha1//
//ha1//                        BrowserFilterFileType
//ha1//
//ha1//int BrowserFilterFileType(LPWSTR szStrFileType, LPWSTR szStrFolder)
//ha1//  {
//ha1//  //CoInitialize init; // Using CoInitializeEx(..)
//ha1//  HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
//ha1//
//ha1//  MessageBox(NULL, _T("Show drives > 8G only"), _T("--Explorer Browser Filter--"), MB_ICONINFORMATION | MB_OK);
//ha1//
//ha1//  BROWSEINFO bi = { };
//ha1//
//ha1//  bi.pszDisplayName = NULL; // szDisplayName;                              
//ha1//  bi.lpfn           = WRLBrowseCallbackProc;                             
//ha1//  bi.ulFlags        = BIF_NEWDIALOGSTYLE | BIF_BROWSEINCLUDEFILES;         
//ha1//
//ha1//  PIDLIST_ABSOLUTE pidl = SHBrowseForFolder(&bi);
//ha1//  CoTaskMemFree(pidl);
//ha1//  return 0;
//ha1//  }  // BrowserFilterFileType
//ha1//#endif // DRIVE_SIZE

//ha2//#ifdef DRIVE_LETTER
//ha2////-----------------------------------------------------------------------------
//ha2////
//ha2////                   class CFunnyFilter - DRIVE_LETTER 
//ha2////
//ha2//// Customize the Browse for Folder dialog so it shows only drive letters.
//ha2//// First, we declare a global variable to remember the location of what was once called My Computer
//ha2////  but nowadays goes by the name This PC. Whatever it is, it’s the thing that contains
//ha2////  your drive letters.
//ha2//// The real work happens in the filter. Starting at the bottom, we have a method called Check­Depth
//ha2////  which determines whether the passed-in folder is an ancestor of, equal to,
//ha2////  or a descendant of My Computer. Actually, we treat anything that isn’t a parent
//ha2////  or equal to My Computer as if it were a descendant.
//ha2//// The Check­Depth method is method is a bit tricky for a few reasons.
//ha2////  First, it treats the null pointer as equivalent to the desktop, so that it is the ancestor
//ha2////  of everything. For whatever reason, that’s what IFolder­Filter gives you, so we accommodate it.
//ha2//// Second, if you pass FALSE to ILIs­Parent, it means that the function will return a nonzero value
//ha2////  if the first ID list is an ancestor of or is equal to the second ID list.
//ha2////  Therefore, we have to do the equality test first.
//ha2//// Okay, working upward, the next method is Get­Enum­Flags.
//ha2////  This is called when the Browse for Folder dialog wants to enumerate the children of a folder,
//ha2////  and it’s our chance to influence what gets enumerated.
//ha2////  We don’t want to expand the drives themselves, so if we have something that is a child
//ha2////  of My Computer, we set the enumeration flags to zero, which means that nothing gets enumerated.
//ha2////
//ha2//PIDLIST_ABSOLUTE g_pidlMyComputer;
//ha2////
//ha2//#define STRICT_TYPED_ITEMIDS
//ha2//
//ha2//// Smart pointer class library is "Rolls Dice" WRL !! (Woodoo Code)
//ha2//#include <wrl\client.h>                                   
//ha2//#include <wrl\implements.h>  
//ha2//using namespace Microsoft::WRL;                                        
//ha2/
//ha2//class CFunnyFilter : public RuntimeClass <
//ha2//                              RuntimeClassFlags<RuntimeClassType::ClassicCom>,
//ha2//                              IFolderFilter
//ha2//                              >
//ha2//  {
//ha2//  public:
//ha2//
//ha2// //-----------------------------------------------------------------------------
//ha2// //
//ha2// //                     ShouldShow - DRIVE_LETTER
//ha2// //
//ha2// // Customize the Browse for Folder dialog so it shows only drive letters.
//ha2// //
//ha2// // The first method is Should­Show. This is where most of the excitement is.
//ha2// //  You are given a folder and an item in that folder, and your job is to decide
//ha2// //  whether that item should be shown in the Browse for Folder dialog.
//ha2// // First, we say that folders which are ancestors of My Computer can show all of their children.
//ha2// //  This ensures that the Browse for Folder dialog can reach My Computer in the first place.
//ha2// // Second, we say that descendants of My Computer do not show any children.
//ha2// //  This is technically redundant because our Get­Enum­Flags prevented those children
//ha2// //  from being enumerated, but we’ll block them here just to be sure they don’t show up.
//ha2// // Finally, if we are showing children of My Computer itself,
//ha2// //  we ask for the parsing name of the item and see if a drive root comes back.
//ha2// //  If the parsing name is longer than four characters, then the Str­Ret­To­Buf function
//ha2// //  will fail with an insufficient-buffer error, in which case we know that we don’t have a drive root.
//ha2// // The handy Str­Ret­To­Buf function deals with the kooky STRRET structure so we don’t have to.
//ha2// // So that’s the filtering.
//ha2// //
//ha2// // *** IFolderFilter ***
//ha2// //
//ha2//  IFACEMETHODIMP ShouldShow(IShellFolder* psf,
//ha2//                            PCIDLIST_ABSOLUTE pidlFolder,
//ha2//                            PCUITEMID_CHILD pidlItem)
//ha2//    {
//ha2//   int compare = CompareDepth(pidlFolder);                                
//ha2//   if (compare < 0) return S_OK;                                          
//ha2//   if (compare > 0) return S_FALSE;                                       
//ha2//                                                                          
//ha2//   STRRET str;                                                            
//ha2//   psf->GetDisplayNameOf(pidlItem, SHGDN_FORPARSING, &str);               
//ha2//                                                                          
//ha2//   wchar_t buf[4];                                                        
//ha2//   if (SUCCEEDED(StrRetToBuf(&str, pidlItem, buf, ARRAYSIZE(buf))) &&     
//ha2//       PathIsRoot(buf))                                         
//ha2//     return S_OK;                                                         
//ha2//                                                                          
//ha2//   return S_FALSE;                                                        
//ha2//   } // ShouldShow
//ha2//
//ha2//  //-----------------------------------------------------------------------------
//ha2//  //
//ha2// //                         GetEnumFlags - DRIVE_LETTER
//ha2// //
//ha2// // Okay, working upward, the next method is Get­Enum­Flags.
//ha2// //  This is called when the Browse for Folder dialog wants to enumerate the children of a folder,
//ha2// //  and it’s our chance to influence what gets enumerated.
//ha2// //  We don’t want to expand the drives themselves, so if we have something that is a child
//ha2// //  of My Computer, we set the enumeration flags to zero, which means that nothing gets enumerated.
//ha2// //
//ha2//  IFACEMETHODIMP GetEnumFlags(IShellFolder* psf,
//ha2//                              PCIDLIST_ABSOLUTE pidlFolder,
//ha2//                              HWND *phwnd,
//ha2//                              DWORD *pgrfFlags)   // =A0 (SHCONTF_FOLDERS | SHCONTF_INCLUDEHIDDEN)
//ha2//   {
//ha2//   if (CompareDepth(pidlFolder) > 0) *pgrfFlags = 0;                       
//ha2//                                                                          
//ha2//   return S_OK;
//ha2//   } // GetEnumFlags
//ha2// 
//ha2// //----------------------------------------------------------------------- 
//ha2// // Customize the Browse for Folder dialog so it shows only drive letters. 
//ha2// //                                                                        
//ha2//  private:                                                                 
//ha2//  static int CompareDepth(PCIDLIST_ABSOLUTE pidl)                            
//ha2//    {                                                                        
//ha2//    if (pidl == nullptr) return -1;                                          
//ha2//    if (ILIsEqual(pidl, g_pidlMyComputer)) return 0;                       
//ha2//    if (ILIsParent(pidl, g_pidlMyComputer, FALSE)) return -1;                
//ha2//    return 1;                                                                
//ha2//    }
//ha2//                                                                           
//ha2//  }; // end class CFunnyFilter
//ha2//
//ha2//-----------------------------------------------------------------------------
//ha2//
//ha2//                        BrowserFilterFileType
//ha2//
//ha2//int BrowserFilterFileType(LPWSTR szStrFileType, LPWSTR szStrFolder)
//ha2//  {
//ha2//  //CoInitialize init; // Using CoInitializeEx(..)
//ha2//  HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
//ha2//
//ha2//  MessageBox(NULL, _T("Show drive letters only"), _T("--Explorer Browser Filter--"), MB_ICONINFORMATION | MB_OK);
//ha2//  SHGetSpecialFolderLocation(nullptr, CSIDL_DRIVES, &g_pidlMyComputer);
//ha2//
//ha2//  BROWSEINFO bi = { };
//ha2//
//ha2//  bi.pidlRoot       = g_pidlMyComputer;                                   
//ha2//  bi.pszDisplayName = NULL; //szDisplayName;                              
//ha2//  bi.lpfn           = WRLBrowseCallbackProc;                            
//ha2//  bi.ulFlags        = BIF_NEWDIALOGSTYLE | BIF_RETURNONLYFSDIRS;          
//ha2//
//ha2//  PIDLIST_ABSOLUTE pidl = SHBrowseForFolder(&bi);
//ha2//  CoTaskMemFree(pidl);
//ha2//  CoTaskMemFree(g_pidlMyComputer)
//ha2//  return 0;
//ha2//  }  // BrowserFilterFileType
//ha2//#endif // DRIVE_LETTER


//-----------------------------------------------------------------------------
//
//                    IsMyComputerFolder - XP and W10
//
//  (Example: Could also be used for FILE_TYPE, but it is not mandatory)
//
BOOL IsMyComputerFolder(IUnknown *punk)
  {
  CLSID clsid;
  GetObjectCLSID(punk, &clsid);
  return clsid == CLSID_MyComputer;
  } // IsMyComputerFolder

HRESULT GetObjectCLSID(IUnknown *punk, CLSID *pclsid)
  {
  *pclsid = CLSID_NULL;
  IPersist *pp;
  HRESULT hr = punk->QueryInterface(IID_PPV_ARGS(&pp));
  if (SUCCEEDED(hr))
    {
    hr = pp->GetClassID(pclsid);
    pp->Release();
    }
  return hr;
  } // GetObjectCLSID

#ifdef FILE_TYPE // haCrypt - Multifile result browser
//-----------------------------------------------------------------------------
//
//                         EvaluateFileType - XP and W10
//
// Common for XP and Windows XP (Visual Studio 2010 and 2019 Syntax).
// Determine if file should be shown or supressed in the multifile browser result.
// Minimum supported client: Windows XP with SP3 [desktop apps only]
//
// Return: S_FALSE = File should be supressed (not shown)
//         S_OK    = File should be listed (shown) in browser result
//
// Note: S_OK, S_FALSE, TRUE, FALSE
//  S_FALSE=1, (whereas FALSE=0)
//  S_OK   =0, (whereas TRUE =1)
//
BOOL EvaluateFileType(LPWSTR _pszName)
  {
  BOOL _fShow = S_FALSE;     // Initially don't show

  // -------------------------------------------------------------------
  // Feed in and show the file system path and drive letter separately. |
  // This prevents ERROR message "Folder cannot be used.....            |
  // -------------------------------------------------------------------
  if (wcsicmp(_pszName, pszShowFolder) == 0) _fShow = S_OK;

  //-------------------------------------------------
  // Rename: Show file(s) not displayed in text field
  //
  if (renameFlag) 
    {
    if (lstrlen(pszFileType) > 1)
      {
      // Hide all file types, only show files with 'pszFileType' extension
      // _pszFileType: Determine last extension, e.g. 'abc.def.kk' = .kk))
      PTSTR _pszFileType = PathFindExtension(pszFileType);           
      _fShow = wcsicmp(PathFindExtension(_pszName), _pszFileType) == S_OK; //L".txt.G.k", //L".A~d" //L".D~d"
      }

    // pszFileType = L"." - Any file extension?
    else if (StrRChrW(_pszName, NULL, L'.') == NULL)
      _fShow = S_FALSE;      // Supress all files with extension

    else _fShow = S_OK;      // Show all files without extension
    } // end if (renameFlag)

  //--------------------------------------------------------
  // Crypto: Optionally show file(s) displayed in text field
  //
  else if (!_flag29K) 
    {
    int _i, _j, _k;

    _j = SendMessage(hEdit, EM_GETLINECOUNT, 0, 0);
    for (_i=0; _i<(_j-1); _i++)
      {
      for (_k=0; _k<MAX_PATH; _k++) _tEditLine[_k] = 0; // Init clear
      Edit_GetLine(hEdit, _i, _tEditLine, MAX_PATH);

      // Hide all files, only show files processed previously in 'MultiBinFileOpen()'
      // Suppress a possible last '.' (e.g. "filename.E." should become "filename.E") 
      if (_tEditLine[lstrlen(_tEditLine)-1 ] == L'.')
        _tEditLine[lstrlen(_tEditLine)-1 ] = 0;        // Suppress if last is '.'

      _fShow = wcsicmp(PathFindFileName(_pszName), _tEditLine) == S_OK;  // (ignore case)
      if (_fShow != S_OK) break;                       // Don't show this file
      } // end for
    } // end else if

  else // Crypto: Displayed text is truncated at 29K, so show all files with pszFileType (XP, W10)
    {
    // Hide all file types, only show files with 'pszFileType' extension
    _fShow = wcsicmp(PathFindExtension(_pszName), pszFileType) == S_OK; // Weird, but works (ignore case)
    } // end if (_flag29K) 
  
  return(_fShow);  // S_FALSE=Don't show, S_OK=Show
  } // EvaluateFileType

//-----------------------------------------------------------------------------
//
//                     EvaluateShouldShow - XP and W10
//
// Common for XP and Windows XP (Visual Studio 2010 and 2019 Syntax).
// Minimum supported client: Windows XP with SP1 [desktop apps only]
// The Should­Show evaluation method.
//  Create an IShellItem because it’s more convenient.
//  Query the SFGAO_FILE­SYSTEM and SFGAO_FOLDER attributes.
// 
//  If the attributes say "Yes, it’s a file system object, and no, it’s not a folder"
//   Get the display name.
//   For example: If the display name ends in .txt, then SHOW the item. 
//
// SHSTDAPI SHCreateShellItem (
//  [in, optional] PCIDLIST_ABSOLUTE pidlParent,
//  [in, optional] IShellFolder *psfParent,
//  [in]           PCUITEMID_CHILD pidl,
//  [out]          IShellItem **ppsi
//  );
//
BOOL EvaluateShouldShow(IShellFolder *_psf,            // IFACEMETHODIMP ShouldShow(..
                        PCIDLIST_ABSOLUTE _pidlFolder,
                        PCUITEMID_CHILD _pidlItem)
  {
  BOOL fShow = S_FALSE;    // Initially don't show
  IShellItem* spsi;

  HRESULT hr = SHCreateShellItem(_pidlFolder,
                                 _psf, _pidlItem,
                                 &spsi);
  if (SUCCEEDED(hr))
    {                                                                         
    SFGAOF sfgaof;

    // Rename - Only show the processed files
    if (renameFlag)                                        
      hr = spsi->GetAttributes(SFGAO_FILESYSTEM, &sfgaof);

    // Crypto - Show the processed files and folders and zip-files
    else                                                                  
      hr = spsi->GetAttributes(SFGAO_FILESYSTEM | SFGAO_FOLDER, &sfgaof);

    if (SUCCEEDED(hr) && sfgaof == SFGAO_FILESYSTEM)      // if (SUCCEEDED(hr))
      {
      LPWSTR pszName;
      //hr = spsi->GetDisplayName(SIGDN_PARENTRELATIVEPARSING, &pszName); // Returns the path relative to parent folder
      hr = spsi->GetDisplayName(SIGDN_FILESYSPATH, &pszName);  // Returns the item's file system path
      if (wcsicmp(pszName, pszShowFolder) == S_OK)  return(hr);  // Show the file system path (This finally works)
 
      if ((GetFileAttributes(pszName) & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
        fShow = S_OK;

      if (SUCCEEDED(hr))
        {
        fShow = EvaluateFileType(pszName);         // Determine if file should be shown
        CoTaskMemFree(pszName);
        } // end if (hr)
      }
    } // end if (hr)
                                                   // Note: S_OK, S_FALSE, TRUE, FALSE
  if (SUCCEEDED(hr)) hr = fShow ? S_OK : S_FALSE;  //  S_FALSE=1, (whereas FALSE=0)
  return(hr);                                      // S_FALSE=Don't show, S_OK=Show
  } // EvaluateShouldShow()


//-----------------------------------------------------------------------------
                     //******************************************
#if _MSC_VER == 1600 // (1600 = Visual Studio 2010 version 10.0) |
                     //******************************************
//  ---------------------------------------------------------------------------
// |                                                                           |
// |                    class XP_FolderFilterFileType                          |
// |                                                                           |
//  ---------------------------------------------------------------------------
// WinAPI 32bit code for Windows XP (Visual Studio 2010 Syntax).
//
class XP_FolderFilterFileType : public IFolderFilter
  {
  private:
  ULONG mRef;
  
  public:
  XP_FolderFilterFileType() : mRef(0)
    {
    } // XP_FolderFilterFileType

  //---------------------------------------------------------------------------
  //
  //                         AddRef - XP
  //
  // WinAPI 32bit code for Windows XP (Visual Studio 2010 Syntax).
  //
  ULONG __stdcall AddRef()
    {  
    return ++mRef;
    } // AddRef

  //---------------------------------------------------------------------------
  //
  //                         Release - XP
  //
  // WinAPI 32bit code for Windows XP (Visual Studio 2010 Syntax).
  //
  ULONG __stdcall Release()
    {
    if (--mRef > 0) return mRef;

    delete this;                          // Keyword "this"
    return 0;
    } // Release

  //-----------------------------------------------------------------------------
  //
  //                         QueryInterface - XP
  //
  // WinAPI 32bit code for Windows XP (Visual Studio 2010 Syntax).
  //
  // Keyword "this":
  // ---------------
  // The keyword "this" is a pointer accessible only within the
  // nonstatic member functions of a class, struct, or union type. 
  // It points to the object for which the member function is called.
  // Static member functions don't have a "this" pointer.
  //
  // Syntax
  //   this
  //   this->member-identifier
  //
  HRESULT __stdcall QueryInterface(REFIID riid, void**ppv)
    {
    if (!ppv) return E_POINTER;

    *ppv = NULL;

    if (riid == IID_IUnknown)
      *ppv = (IUnknown*) this;            // Keyword "this"

    else if (riid == IID_IFolderFilter)
      *ppv = (IFolderFilter*) this;       // Keyword "this"

    if (*ppv == NULL) return E_NOINTERFACE;

    AddRef();
    return S_OK;
    } // QueryInterface


      //*****************************************************************
#else // _MSC_VER (Visual Studio 2019) - Smart pointer class library WRL |
      //*****************************************************************
//  ---------------------------------------------------------------------------
// |                                                                           |
// |                    class W10_FolderFilterFileType                         |
// |                                                                           |
//  ---------------------------------------------------------------------------
// WinAPI 32/64bit code for Windows 10 (Visual Studio 2019 Syntax).
//
#define STRICT_TYPED_ITEMIDS

// Smart pointer class library is "Rolls Dice" WRL !! (Woodoo Code)
#include <wrl\client.h>                                  
#include <wrl\implements.h> 
using namespace Microsoft::WRL;                                       

class W10_FolderFilterFileType : public RuntimeClass<RuntimeClassFlags<ClassicCom>,
                                                     IFolderFilter>
  {
  public:

       //************************************
#endif // _MSC_VER (Visual Studio 2010/2019) |
       //************************************

  //-----------------------------------------------------------------------------
  //
  //                         GetEnumFlags - XP and W10
  //
  // Common for XP and Windows XP (Visual Studio 2010 and 2019 Syntax).
  //
  HRESULT __stdcall GetEnumFlags(IShellFolder *psf,            // IFACEMETHODIMP GetEnumFlags(..
                                 PCIDLIST_ABSOLUTE pidlFolder,
                                 HWND *phwnd,
                                 DWORD *pgrfFlags)
    {
    //if (CompareDepth(pidlFolder) > 0) *pgrfFlags = 0;  // Not for XP
    //if (*pgrfFlags == SHCONTF_FOLDERS) return S_FALSE; 
    //*pgrfFlags = SHCONTF_FOLDERS;   // Makes no difference
    //*pgrfFlags = 0;                 // Makes no difference
    *pgrfFlags = SHCONTF_NONFOLDERS;  // Makes no difference
    return S_OK;
    //return S_FALSE;                 // Makes no difference
    } // GetEnumFlags

  //-----------------------------------------------------------------------------
  //
  //                     ShouldShow - XP and W10
  //
  // Common for XP and Windows XP (Visual Studio 2010 and 2019 Syntax).
  //
  // *** IFolderFilter ***
  // The real work happens in the Should­Show evaluation method.
  //
  HRESULT __stdcall ShouldShow(IShellFolder *psf,              // IFACEMETHODIMP ShouldShow(..
                               PCIDLIST_ABSOLUTE pidlFolder,
                               PCUITEMID_CHILD pidlItem)
    {
    return(EvaluateShouldShow(psf, pidlFolder, pidlItem));  // S_FALSE=Don't show, S_OK=Show
    } // ShouldShow                                
                                                     
  }; // end class XP_FolderFilterFileType and W10_FolderFilterFileType


//-----------------------------------------------------------------------------
//
//                         WRLBrowseCallbackProc
//
// WinAPI 32/64bit code for Windows 10 (Visual Studio 2019 Syntax).
// WinAPI 32bit code for Windows XP (Visual Studio 2010 Syntax).
//
// lpData Type: LPARAM
//  An application-defined value that was specified in the lParam member
//  of the BROWSEINFO structure used in the call to SHBrowseForFolder.
//
// That's it! Let's install this filter in the callback function:
//
// When we get the BFFM_IUNKNOWN message, we convert the IUnknown (cast to LPARAM)
//  to a IFolder-Filter-Site and tell it to apply our custom filter.
//
int CALLBACK WRLBrowseCallbackProc(HWND _hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData)
  {
  switch (uMsg)
    {
    case BFFM_INITIALIZED:
      RepositionBrowseWindow(_hwnd);
      SendMessage(_hwnd, BFFM_SETEXPANDED, TRUE, lpData); // Select path and show files
      break;
                     //----------------------------------
#if _MSC_VER == 1600 // _MSC_VER (Visual Studio 2010) XP |
                     //----------------------------------
    case BFFM_IUNKNOWN:
      if (lParam)
        {
        IUnknown *punk = (IUnknown *)lParam;
        IFolderFilterSite *spFilterSite = NULL;

        punk->QueryInterface(IID_IFolderFilterSite, (void**)&spFilterSite);
        XP_FolderFilterFileType *filter = new XP_FolderFilterFileType;

        if (SUCCEEDED(spFilterSite->SetFilter(filter)))
          spFilterSite->Release();
        } // end if (lParam)
      break;

      //----------------------------------------
#else // _MSC_VER (Visual Studio 2010/2019) W10 | - Smart pointer class library WRL
      //----------------------------------------
    case BFFM_IUNKNOWN:
      if (lParam)
        {
        //IUnknown *punk = reinterpret_cast<IUnknown*>(lParam);
        IUnknown *punk = (IUnknown *)lParam;
        ComPtr<IFolderFilterSite> spFilterSite;

        if (SUCCEEDED(ComPtr<IUnknown>(punk).As(&spFilterSite)))     
          {
 #ifdef FILE_TYPE // haCrypt -  Multifile result browser
          spFilterSite->SetFilter(Make<W10_FolderFilterFileType>().Get());
//ha1ha2//#else // Examples - DRIVE_SIZE, DRIVE_LETTER
//ha1ha2//          spFilterSite->SetFilter(Make<CFunnyFilter>().Get());
 #endif // FILE_TYPE
          }
        } // end if (lParam)
      break;
       //------------------------------------
#endif // _MSC_VER (Visual Studio 2010/2019) |
       //------------------------------------

    case BFFM_SELCHANGED:
//ha//      if (renameFlag)     // Disable OK-Button in browser dialog
//ha//      SendMessage(_hwnd, BFFM_ENABLEOK, TRUE, 0); // Works, but makes no sense! 
//ha//      //SendMessage(hwnd, BFFM_SETEXPANDED, 1, lpData); // Doesn't work
      break;
    } // end switch

  return 0;
  } // WRLBrowseCallbackProc

//-----------------------------------------------------------------------------
//
//                         BrowserFilterFileType
//
// Thanks to Raymond Chen
//  Applying a filter to the contents of an Explorer Browser
//  https://devblogs.microsoft.com/oldnewthing/
//
// "Okay, let’s plug it in and see if smoke comes out.
//
// The tricky part here is that we have to pass the BIF_NEWDIALOGSTYLE flag,
//  because it's the new Browse for Folder dialog that sends the BFFM_IUNKNOWN message.
//
// The last changes are to Win­Main: We obtain the item ID list for My Computer 
//  and set it as the root for the Browse for Folder dialog.
//  (Remember that Little Programs do little to no error checking.)
//  We also tell the Browse for Folder dialog that we require the user
//  to select a file system object.
//  That ensures that the OK button is disabled when the user is sitting at My Computer.
//  And after the excitement is done, we clean up.
// There you have it. A Browse for Folder dialog that shows only drive letters.
// I’m not sure how useful this is, but I never claimed that this was useful."
//
int BrowserFilterFileType(LPWSTR szStrFileType, LPWSTR szStrFolder)
  {
  // 'SHBrowseForFolder()' may not expand, if too many files reside in the directory.
  // Due to a MS-Design flaw since Windows 95, always showing all files doesn't work.
  // Here we guide the user what to do in this case:
  // He/she must click on the folder in order to see the files processed. 
//ha//  TCHAR szStrFolderInfo[] = _T("Click on the folder to show the resulting files.");
//ha//  StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("%s\n%s"), szStrFolder, szStrFolderInfo);

  // Browserfiletr hangs the application if window is minimized.
  if (IsIconic(hMain) != 0) return 0;  // Skip if haCrypt window is iconic

  // Init global pointers
  pszFileType = szStrFileType;   // File extension to be filtered
  pszFolder = szStrFolder;       // Folder

  // --------------------------------------------------------------------------------------
  // Needed in 'EvaluateShouldShow()' to prevent ERROR message "Folder cannot be used...." |
  // Build pszShowFolder out of pszFolder omitting the ending '\'.                         |
  // However DO NOT omit the ending '\' if pszFolder is a drive letter only, e.g. "H:\"    |
  // Leave any plain drive letter untounched, so it shows up in EvaluateShouldShow().      |
  // --------------------------------------------------------------------------------------
  if (lstrlen(pszFolder) == 4 && pszFolder[3] == (WCHAR)'\\') // Adjust if drive letter ending ':\\'
    szStrFolder[3] = 0;                                       // Force drive letter format ':\'

  for (int i=0; i<MAX_PATH; i++) pszShowFolder[i] = pszFolder[i];
  if (lstrlen(pszFolder) > 3)                 // SIGDN_FILESYSPATH delivers drive letter ending ':\'
    pszShowFolder[lstrlen(pszFolder)-1] = 0;  // SIGDN_FILESYSPATH delivers not ending '\'

  //CoInitialize init;  // Using CoInitializeEx(..)
  HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

  // Set the initial RootFolder (szStrFolder)
  PIDLIST_ABSOLUTE pidlPathSave = NULL;
  ULONG chEaten;  
  ULONG dwAttributes;  
  IShellFolder* pDesktopFolder;
    
  if (SUCCEEDED(SHGetDesktopFolder(&pDesktopFolder)))  
    {  
    // Get PIDL for root folder  
    pDesktopFolder->ParseDisplayName(NULL, NULL, szStrFolder, &chEaten, &pidlPathSave, &dwAttributes);  
    pDesktopFolder->Release();  
    }  

  //ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("%s\nClick on a folder to show subfolders."), szStrFolder); 

  BROWSEINFO bi = {0};

  bi.hwndOwner      = hMain;
  bi.pidlRoot       = pidlPathSave;                                       
  bi.pszDisplayName = NULL;
  bi.lpszTitle      = szStrFolder;  //ha//_tDebugBuf;                                       
  bi.lpfn           = WRLBrowseCallbackProc;                                  
  bi.ulFlags        = BIF_NEWDIALOGSTYLE | BIF_NONEWFOLDERBUTTON | BIF_BROWSEINCLUDEFILES;//ha// | BIF_UAHINT;        
  bi.lParam         = (LPARAM)pszFolder; //NULL;
  bi.iImage         = 0;

  // Unfortunately, with SHBrowseForFolder() there's NOT a lot of control
  // over its appearance and usage:
  // No multiple file selection, no changing button-text, etc.
  //PIDLIST_ABSOLUTE pidl = SHBrowseForFolder(&bi);
  _cbtFolderFlag = MULTIFILE_BROWSER_RENAME | MULTIFILE_BROWSER_CRYPTO; 
  PIDLIST_ABSOLUTE pidl = CBTSHBrowseForFolder(bi);  //ha// Rename text on button 'CANCEL'
  _cbtFolderFlag = FALSE; 

  CoTaskMemFree(pidl);
  return 0;
  } // BrowserFilterFileType
#endif // FILE_TYPE

//------------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("DesktopRect.bottom=%i\nMainRect.bottom=%i\nMainRect.left=%i\nDesktopRect.left=%i"),
//ha//                                                 DesktopRect.bottom, MainRect.bottom, MainRect.left, DesktopRect.left);
//ha//MessageBox(NULL, _tDebugBuf, _T("XP_FolderFilterFileType1"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("hr=%i [S_FALSE=%i]\nfShow=%i\nsfgaof=08X\npszShowFolder=%s\npszFolder=%s\npszName=%s"),
//ha//                                                 hr, S_FALSE, fShow, sfgaof, pszShowFolder, pszFolder, pszName);
//ha//MessageBox(NULL, _tDebugBuf, _T("XP_FolderFilterFileType0"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//int res = (GetFileAttributes(pszName) & FILE_ATTRIBUTE_DIRECTORY);
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("res = %08X [FILE_ATTRIBUTE_DIRECTORY=%08X]\nsfgaof=%08X\npszShowFolder=%s\npszFolder=%s\npszName=%s"),
//ha//                                                 res, FILE_ATTRIBUTE_DIRECTORY, sfgaof, pszShowFolder, pszFolder, pszName);
//ha//MessageBox(NULL, _tDebugBuf, _T("XP_FolderFilterFileType1"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{ 
//ha//BrowserRect.bottom = 300; BrowserRect.top =600; BrowserRect.left =800; BrowserRect.right =1000; // Cant be cahnged ??!!
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("BrowserHeight=%i\nBrowserRect.bottom = %i\nBrowserRect.top=%i\nBrowserRect.left = %i\nBrowserRect.right = %i"),
//ha//                                                 BrowserHeight, DesktopRect.bottom, BrowserRect.top, BrowserRect.left, BrowserRect. right); 
//ha//MessageBox(NULL, _tDebugBuf, _T("2"), MB_ICONINFORMATION | MB_OK);
//ha//}
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

