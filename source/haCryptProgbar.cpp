// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptProgbar.cpp - C++ Developer source file.
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

#ifndef x64  // 64 bit
 #include <uxtheme.h> // Allow theme styling progress bar (XP / Vista or greater)
#endif

#include "haCrypt.h"

// Global variables
int _Pcent, _PcentL;               // Percentage 
int _PcentSav = 0, _PcentSavL = 0; // Performance optimization
int _ProgressbarLL = FALSE;
__int64 llmstep, llistep;
 
HWND hProgBar;               // Handle for progress bar
HWND hProgBarL;              // Large files handled separately

// Extern variables
extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern int activeProgbar, multiFileFlag, _escFlag;  // Progressbar activity
extern int GlobalCryptMode;
extern DWORD dwFileSize;

extern __int64 ddFileSizeLarge, lln;

extern ULONG FileProcessingMode;

extern TCHAR* pszTxtE;
extern TCHAR* pszTxtD;
extern TCHAR* pszCryptL;
extern TCHAR* pszCryptS;
extern TCHAR* pszCryptA;       // Crypto algo text
extern TCHAR* pszCryptM;       // Crypto mode text 

extern HWND hEdit;
extern HWND hButtonDelim;

// Extern functions
extern void DoEvents();        // Absolutely needed for 'one thread-only' UIs!
extern void ControlToolWindow(int);
extern void ControlCryptoToolItems(int, int);
extern void ShowWinMouseClick(HWND, int, int, int); // Simulate Mouseclick

extern void PaintColoredStatusMsg(TCHAR*);
extern void PaintColoredStatusProgressMsg(TCHAR*);
extern void PaintColoredStatusPercentMsg(TCHAR*);

//-----------------------------------------------------------------------------
//
//                       CreateProgressBar
//
// Ensure that the common control DLL is loaded, and create a progress bar 
//  along the bottom of the client area of the parent window. 
//   InitCommonControls(); 
//
// Base the height of the progress bar on the height of a scroll bar arrow.
//
HWND CreateProgressBar(HWND _hwndParent)
  {
  RECT rcClient;             // Client area of parent window.
  int cxHScroll, cyVScroll;  // Height / Length of scroll bar arrow.

  GetClientRect(_hwndParent, &rcClient); 
  
  cyVScroll = GetSystemMetrics(SM_CYVSCROLL); 
  cxHScroll = GetSystemMetrics(SM_CXHSCROLL);  // = 17px + Shade + Frame

  DWORD dwVersion = GetVersion();      // XP: Compiled with VS 2010
  if ((dwVersion & 0xFF) == 5)         // Windows system version
    rcClient.top = cyVScroll;          // Standard frame XP (Windows 5)
  else
    rcClient.top = rcClient.top + 14;  // Running on Vista (Windows 6) or greater

  // Create Progress Bar
  hProgBar = CreateWindowEx(
    0, 
    PROGRESS_CLASS, 
    (LPTSTR) NULL, 
    WS_CHILD | WS_VISIBLE | PBS_SMOOTH,//  | WS_BORDER, 
    rcClient.left,
    rcClient.bottom - cyVScroll,
    rcClient.right + cxHScroll,   // Adjustment to span the full width
    rcClient.top,
    _hwndParent, 
    (HMENU) 0, 
    NULL,       //g_hinst, 
    NULL);

  return(hProgBar);
  } // CreateProgressBar

//------------------------------------------------------------------------------
//
//                          InitProgressbar
//
// Create, set Range and Increment of the progress bar. 
// This function is called by file processing routines to display a progressbar.
//
ULONG lmstep, listep;     

void InitProgressbar(ULONG blockSize)
  {
  if (_ProgressbarLL == TRUE) return; // Turn off cryptoalgorithm progressbar

  // Disable relevant toobar buttons
  ControlToolWindow(FALSE);
  //EnableWindow(hTool, FALSE);   
  SendMessage(hEdit, EM_SETREADONLY, TRUE, 0);  // Disable text field for crypto data edit
    
  if (blockSize == 0L || dwFileSize < 8*FILE_BLOCK_SIZE)
    { 
    activeProgbar = TRUE; // Progressbar activated
    return;               // Dummy init just disable toolbar buttons
    }

  // Here we suppress an empty progressbar area, because
  // multiple files < 1G are processed without progressbar.
  // Note: Files >= 1G are handled in 'InitProgressbarL' with a progressbar.
  if (multiFileFlag == FALSE)  
    {                           
    hProgBar = CreateProgressBar(hEdit);

#ifndef x64  // 64 bit (SetWindowTheme not supported)
    // Running on XP (Windows 5) we want a standard fancy smooth blue progressbar
    DWORD dwVersion = GetVersion();  // Equal or greater than Vista (Windows 6)
    if ((dwVersion & 0xFF) == 5) SetWindowTheme(hProgBar, L"", L""); // Standard theme
#endif

    SendMessage(hProgBar, PBM_SETRANGE32, 0, 100);    // 0 - 100%
    SendMessage(hProgBar, PBM_SETSTEP, (WPARAM)1, 0); // One-by-one
    SendMessage(hProgBar, PBM_SETPOS, 0, 0);          // Begin at left corner
    } // end if (multiFileFlag)

  // lmstep: Normalized file- or crypto-blocks, 100 File chunks max
  lmstep = (dwFileSize/blockSize)/100;
  // ! No progressbar for small files !
  if (lmstep == 0) lmstep = dwFileSize; // Prevent divide by zero
  // listep: 100 incremental steps max (dwFileSize/listep = 100 steps)                            
  listep = ((dwFileSize/blockSize)*blockSize)/100;
  _Pcent = 0;
  _escFlag = FALSE;                     // Reset any pending ESC-Abort condition 
  activeProgbar = TRUE;                 // Progressbar activated

  ShowWinMouseClick(hButtonDelim, 1, 0, 0); // Simulate Mouseclick (button appearance)
  } // InitProgressbar

//-----------------------------------------------------------------------------
//
//                           DisplayProgressCount
//
// This procedure is called by file processing routines to display
//  a progressbar and a bytecounter at the leftmost field of the statusbar.
// The global counter variable 'ln' controls the steps of processing.  
//
void DisplayProgressCount(ULONG _ln, int _PbMode)
  {
  TCHAR* pszTextCount = TEXT(" %lu KB (%d%%)");  // ln / 1024L);  // Echo per COUNT_RATE
  TCHAR* pszTextCountL = TEXT(" %lu");           // ln / 1024L);  // Echo per COUNT_RATE
  TCHAR _pszAsciiBuf[COUNTBUF_SIZE];             // Temporary buffer for formatted text
  int iStep, i;

  if (dwFileSize < 8*FILE_BLOCK_SIZE) // No progress bar on small files (<=8M)
    {
    activeProgbar = FALSE;            // Progressbar de-activated
    return; 
    }

  // Calculate percentage of progress
  _Pcent = (int)((_ln * 100LL) / dwFileSize);   
  if (_Pcent == 0) _PcentSav = _Pcent;  // Initial condition 
  iStep = _Pcent - _PcentSav;           // Next progbar step condition

  // Turn of progressbar from crypto functions for normal files < 1Gbyte
  if (multiFileFlag == TRUE &&
      _PbMode == 1          &&
    // Force 'case 4:' green text color      
    _ProgressbarLL == FALSE) _PbMode = PROGRESS_CRYPT_PCENT; 

  switch(_PbMode)
    {
    case PROGRESS_CRYPT_BAR:      // 1: Crypting process
      // Large file >= 1Gbyte: Handled in 'haCryptAlgoL.cpp'
      // Large file special processing - break;
      if (_ProgressbarLL == TRUE) 
        {
        // Special Handling for the rather slow DES crypto algorithms
        // Remember: 3DES performes three complete DES algorithm steps,
        //           thus lasting 3 times as long as the standard DES.
        // Best for 3DES and DES as well (on slower old computers)
        //  
        if ((FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_TDES || 
            (FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_DES
           )
          {                                                           
          // The triple DES algorithm is busy for more than 5 seconds
          // when encrypting a 64Mbyte block of data.
          // So most likely Windows quite soon shows a message "seems to hang..."
          // and/or appends "Not responding" to our window title bar.
          // Although the process resumes after the 3DES block is finished
          // the "Not responding" message looks ugly and may irritate the user.
          // The following prevents the "(not responding)" state while executing 
          // a long lasting (blocking) task in the main thread:
          //
          // Just call PeekMessage().
          //
          // You don't even have to remove anything from the queue or process it.
          // As long as it is called every 5 seconds, or so,
          // it will cause windows to think the process is still responsive.
          // Do NOT use DisableProcessWindowsGhosting() - not recommended.
          //
          MSG msg;                                      // Dummy for PeekMessage()
          if ((_ln % FILE_BLOCK_16M) == 0)              // Every 16Mbyte step, or so,
            PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE); //  seems to solve the issue
          } // end if (CRYPT_TDES)

        if (_ln / lmstep)   // Only display detailed 1st block (to show the speed)
          {
          lmstep += 2*1024*1024;         // Increment next 2Mbyte step
          //if (lmstep >= FILE_BLOCK_64M) lmstep = 1; // Reset for next 64Mbyte block 
          // Display 'ln' bytes counter in KB and progress in % on statusbar

          if (GlobalCryptMode == ENCRYPT)
            StringCbPrintf(_pszAsciiBuf, sizeof _pszAsciiBuf, pszTxtE, _ln);   // Emit bytes encrypted
          else if (GlobalCryptMode == DECIPHER)
            StringCbPrintf(_pszAsciiBuf, sizeof _pszAsciiBuf, pszTxtD, _ln);   // Emit bytes deciphered
          //SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_pszAsciiBuf);
          PaintColoredStatusProgressMsg(_pszAsciiBuf); // Green color
          }

        break; // Turn off cryptoalgorithm progressbar anyway on large files
        } // end if (_ProgressbarLL)

      // Normal file < 1Gbyte: Green progress bar, KB counter and %
      if (_ln / lmstep)   // lmstep = strange, but works very fast
        {
        lmstep += listep; // Increment next step

        // Next step progressbar only if percentage incremented
        if (_Pcent > _PcentSav)
          {
          // Ensure progressbar and byte counter are always served in message queue
          //  'DoEvents': Absolutely needed for 'one thread-only' UIs. 
          //  !! Without 'DoEvents' lockups will occur on lenghty files !!
          DoEvents(); // IMPORTANT: 'DoEvents' must stay here in place!

          for (i=0; i<iStep; i++) SendMessage(hProgBar, PBM_STEPIT, 0, 0);
 
          DWORD dwVersion = GetVersion();      // XP: Compiled with VS 2010
          if ((dwVersion & 0xFF) > 5)          // Running on Vista or greater (PB sync Problem)
            //Sleep(20); // Must wait some 20ms for the progressbar to get its work done
            Sleep(2);    // Must wait some 20ms for the progressbar to get its work done

          // Display 'ln' bytes counter in KB and progress in % on statusbar
          StringCbPrintf(_pszAsciiBuf, sizeof _pszAsciiBuf, pszTextCount, _ln/1024, _Pcent);
          //SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_pszAsciiBuf);
          PaintColoredStatusProgressMsg(_pszAsciiBuf); // Green color
          _PcentSav = _Pcent;
          }
        } // end if
      break; // end case 1:

    case PROGRESS_LOAD_PCENT:  // 0: Loading File
      if (_Pcent > _PcentSav)  // Blue KB counter and %
        {
        // Ensure progressbar and byte counter are always served in message queue
        //  'DoEvents': Absolutely needed for 'one thread-only' UIs. 
        //  !! Without 'DoEvents' lockups will occur on lenghty files !!
        DoEvents(); // IMPORTANT: 'DoEvents' must stay here in place!
        StringCbPrintf(_pszAsciiBuf, sizeof _pszAsciiBuf, pszCryptL, pszCryptA, pszCryptM, _Pcent);
        //SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_pszAsciiBuf);
        PaintColoredStatusPercentMsg(_pszAsciiBuf);  // Blue color
        _PcentSav = _Pcent;
        }
      break; // end case 0:
  
    case PROGRESS_SAVE_PCENT:  // 2: Saving file
    case PROGRESS_COPY_PCENT:  // 3: Copying file
      if (_Pcent > _PcentSav)  // Blue KB counter and %
        {
        // Ensure progressbar and byte counter are always served in message queue
        //  'DoEvents': Absolutely needed for 'one thread-only' UIs. 
        //  !! Without 'DoEvents' lockups will occur on lenghty files !!
        DoEvents(); // IMPORTANT: 'DoEvents' must stay here in place!
        StringCbPrintf(_pszAsciiBuf, sizeof _pszAsciiBuf, pszCryptS, pszCryptA, pszCryptM, _Pcent);
        //SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_pszAsciiBuf);
        PaintColoredStatusPercentMsg(_pszAsciiBuf);  // Blue color
        _PcentSav = _Pcent;
        }
      break; // end case 2: case 3:

    case PROGRESS_CRYPT_PCENT: // 4: Crypting multifile file
      if (_Pcent > _PcentSav)  // Green KB counter and %
        {
        // Ensure progressbar and byte counter are always served in message queue
        //  'DoEvents': Absolutely needed for 'one thread-only' UIs. 
        //  !! Without 'DoEvents' lockups will occur on lenghty files !!
        DoEvents(); // IMPORTANT: 'DoEvents' must stay here in place!
        StringCbPrintf(_pszAsciiBuf, sizeof _pszAsciiBuf, pszTextCount, _ln/1024, _Pcent);
        //SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_pszAsciiBuf);
        PaintColoredStatusProgressMsg(_pszAsciiBuf); // Green color
        _PcentSav = _Pcent;
        }
      break; // end case 4:
    } // end switch
  } // DisplayProgressCount              

//-----------------------------------------------------------------------------
//
//                           DestroyProgressbar
//
//  Ensure the correct crypto item remains selected.
//  (somebody may have been toying around clicking the toolbar's
//   algo item buttons while the progressbar was processed)
//
void DestroyProgressbar()
  {
  if (_ProgressbarLL == TRUE) return; // Turn off cryptoalgorithm progressbar

  DestroyWindow(hProgBar);                         
  //PaintColoredStatusMsg(szStatusClear);
  activeProgbar = FALSE;  // Indicate de-activated progressbar 
  _PcentSav = 0;
  // Ensure the correct crypto item remains selected
  if (multiFileFlag == FALSE)
    {
//ha//activeProgbar = FALSE;  // Indicate de-activated progressbar  //ha//
    ControlToolWindow(TRUE);
    //EnableWindow(hTool, TRUE);    
    SendMessage(hEdit, EM_SETREADONLY, FALSE, 0); // Disable text field for crypto data edit
    ControlCryptoToolItems(MF_ENABLED, TRUE);
    }   
  } // DestroyProgressbar


//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//
//                       CreateProgressBarL
//
// Large files > 1Gbyte
// Ensure that the common control DLL is loaded, and create a progress bar 
//  along the bottom of the client area of the parent window. 
//   InitCommonControls(); 
//
// Base the height of the progress bar on the height of a scroll bar arrow.
//
HWND CreateProgressBarL(HWND _hwndParent)
  {
  RECT rcClient;             // Client area of parent window.
  int cxHScroll, cyVScroll;  // Height / Length of scroll bar arrow.

  GetClientRect(_hwndParent, &rcClient); 
  
  cyVScroll = GetSystemMetrics(SM_CYVSCROLL); 
  cxHScroll = GetSystemMetrics(SM_CXHSCROLL);  // = 17px + Shade + Frame

  DWORD dwVersion = GetVersion();      // XP: Compiled with VS 2010
  if ((dwVersion & 0xFF) == 5)         // Windows system version
    rcClient.top = cyVScroll;          // Standard frame XP (Windows 5)
  else
    rcClient.top = rcClient.top + 14;  // Running on Vista (Windows 6) or greater

  // Create Progress Bar
  hProgBarL = CreateWindowEx(
    0, 
    PROGRESS_CLASS, 
    (LPTSTR) NULL, 
    WS_CHILD | WS_VISIBLE | PBS_SMOOTH,//  | WS_BORDER, 
    rcClient.left,
    rcClient.bottom - cyVScroll,
    rcClient.right + cxHScroll,   // Adjustment to span the full width
    rcClient.top,
    _hwndParent, 
    (HMENU) 0, 
    NULL,       //g_hinst, 
    NULL);

  return(hProgBarL);
  } // CreateProgressBarL

//------------------------------------------------------------------------------
//
//                    InitProgressbarL
//
// Large files > 1Gbyte
// This function is called by file processing routines.
//
void InitProgressbarL(ULONG blockSize)
  {
  // Disable relevant toobar buttons
  ControlToolWindow(FALSE);
  //EnableWindow(hTool, FALSE);   
  //SendMessage(hEdit, EM_SETREADONLY, TRUE, 0);  // Disable text field for crypto data edit
    
  if (blockSize == 0L)
    { 
    activeProgbar = TRUE; // Progressbar activated
    return;               // Dummy init just disable toolbar buttons
    }

  hProgBarL = CreateProgressBarL(hEdit);

#ifndef x64  // 64 bit (SetWindowTheme not supported)
  // Running on XP (Windows 5) we want a standard fancy smooth blue progressbar
  DWORD dwVersion = GetVersion();  // Equal or greater than Vista (Windows 6)
  if ((dwVersion & 0xFF) == 5) SetWindowTheme(hProgBarL, L"", L""); // Standard theme
#endif

  SendMessage(hProgBarL, PBM_SETRANGE32, 0, 100);   // 0 - 100%
  SendMessage(hProgBarL, PBM_SETSTEP, (WPARAM)1, 0); // One-by-one
  SendMessage(hProgBarL, PBM_SETPOS, 0, 0);           // Begin at left corner

  // llmstep: Normalized file- or crypto-blocks, 100 File chunks max
  lmstep = 1;                  // For Crypto algo functions (large file init)
  llmstep = (ddFileSizeLarge/(__int64)blockSize)/100LL;
  // ! No progressbar for small files !
  if (llmstep == 0) llmstep = ddFileSizeLarge; // Prevent divide by zero
  // llistep: 100 incremental steps max (ddFileSizeLarge/llistep = 100 steps)                           
  llistep = ((ddFileSizeLarge/(__int64)blockSize)*(__int64)blockSize)/100LL;
  _PcentL = 0;
  _escFlag = FALSE;            // Reset any pending ESC-Abort condition 
  activeProgbar = TRUE;        // Progressbar activated
  _ProgressbarLL = TRUE;       // Turn off crypto algorithm progressbar

  ShowWinMouseClick(hButtonDelim, 1, 0, 0); // Simulate Mouseclick (button appearance)
  } // InitProgressbarL

//-----------------------------------------------------------------------------
//
//                           DisplayProgressCountL
//
// Large files > 1Gbyte
// This procedure is called by file processing routines to display
//  a percentage and a bytecounter at the leftmost field of the statusbar.
// The global counter variable 'lln' controls the steps of processing.  
// 
void DisplayProgressCountL(__int64 _lln, int _PbMode)
  {
  TCHAR* pszPercentCount = TEXT(" %llu (%d%%)\r"); // Echo bytes and percentage
  TCHAR _pszAsciiBuf[COUNTBUF_SIZE];               // Temporary buffer for formatted text
  int iStepL, i;

  // Calculate percentage (%) of progress
  _PcentL = (int)((_lln * 100LL) / ddFileSizeLarge);   
  if (_PcentL == 0) _PcentSavL = _PcentL;          // Initial condition 
  iStepL = _PcentL - _PcentSavL;                   // Next progbar step condition

  switch(_PbMode)
    {
    case PROGRESS_CRYPT_BAR:      // 1: Crypting process  with progressbar
      // Next step progressbar only if percentage incremented
      if (_PcentL > _PcentSavL)
        { 
        // Ensure progressbar and byte counter are always served in message queue
        //  'DoEvents': Absolutely needed for 'one thread-only' UIs. 
        //  !! Without 'DoEvents' lockups will occur on lenghty files !!
        DoEvents(); // IMPORTANT: 'DoEvents' must stay here in place!

        for (i=0; i<iStepL; i++) SendMessage(hProgBarL, PBM_STEPIT, 0, 0);

        StringCbPrintf(_pszAsciiBuf, sizeof _pszAsciiBuf, pszCryptS, pszCryptA, pszCryptM, _PcentL);
        PaintColoredStatusPercentMsg(_pszAsciiBuf);  // Blue color
        _PcentSavL = _PcentL;
        }
      break;

    case PROGRESS_SAVE_PCENT:    // 2: Saving crypto file (without progressbar)
      if (_PcentL > _PcentSavL)
        {
        // Ensure progressbar and byte counter are always served in message queue
        //  'DoEvents': Absolutely needed for 'one thread-only' UIs. 
        //  !! Without 'DoEvents' lockups will occur on lenghty files !!
        DoEvents(); // IMPORTANT: 'DoEvents' must stay here in place!
        StringCbPrintf(_pszAsciiBuf, sizeof _pszAsciiBuf, pszCryptS, pszCryptA, pszCryptM, _PcentL);
        PaintColoredStatusPercentMsg(_pszAsciiBuf);  // Blue color
        _PcentSavL = _PcentL;
        }
      break;

    case PROGRESS_COPY_PCENT:    // 3: Copying file (without progressbar)
      if (_PcentL > _PcentSavL)
        {
        // Ensure progressbar and byte counter are always served in message queue
        //  'DoEvents': Absolutely needed for 'one thread-only' UIs. 
        //  !! Without 'DoEvents' lockups will occur on lenghty files !!
        DoEvents(); // IMPORTANT: 'DoEvents' must stay here in place!
        StringCbPrintf(_pszAsciiBuf, sizeof _pszAsciiBuf, pszPercentCount, _lln, _PcentL);
        //SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_pszAsciiBuf);
        PaintColoredStatusPercentMsg(_pszAsciiBuf);  // Blue color
        _PcentSavL = _PcentL;
        }
      break;
    } // end switch
  } // DisplayProgressCountL               


//-----------------------------------------------------------------------------
//
//                           DestroyProgressbarL
//
// Large files > 1Gbyte
//  Ensure the correct crypto item remains selected.
//  (somebody may have been toying around clicking the toolbar's
//   algo item buttons while the progressbar was processed)
//
void DestroyProgressbarL()
  {
  DestroyWindow(hProgBarL);                        
  //PaintColoredStatusMsg(szStatusClear);
  activeProgbar = FALSE;  // Indicate de-activated progressbar 
  _ProgressbarLL = FALSE; // Turn on cryptoalgorithm progressbar
  _PcentSavL = 0;
  // Ensure the correct crypto item remains selected
  ControlToolWindow(TRUE);
  //EnableWindow(hTool, TRUE);    
  SendMessage(hEdit, EM_SETREADONLY, FALSE, 0); // Enable text field for crypto data edit
  ControlCryptoToolItems(MF_ENABLED, TRUE);   
  } // DestroyProgressbarL

//------------------------------------------------------------------------------

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{                
//ha//sprintf(DebugBuf, "ln = %08X\nj = %i [j < %i]\nBytesRd = %llX [=%llu]", ln, j, dwFileSizeBlocks1G, lln, lln);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG STOP 3 haCryptFileT - DoTxtFileCopy", MB_OK);
//ha//}
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "lmstep=%d  [_ln=%d]\nlistep = %i", lmstep, _ln, listep);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG stop A", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%s\ndwFileSize = %i\n_ln = %08X\n_Pcent = %d%%"),
//ha//                                               szCryptModeBuf, dwFileSize, _ln,  _Pcent);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG STOP 0"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, pszCryptL, pszCryptA, pszCryptM, _Pcent);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG STOP 0"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
