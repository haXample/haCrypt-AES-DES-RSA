// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptConsole.cpp - C++ Developer source file.
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

#include <sys\stat.h> // For _stat(char*, struct _stat *) needed for VC 2010
#include <string.h>
#include <string>     // sprintf, etc.
#include <tchar.h>     
#include <strsafe.h>  // <strsafe.h> must be included after <tchar.h>

#include "haCrypt.h"

// Global variables
TCHAR _cmdExample[] = _T("ECHO EXAMPLE: for \x25i in (*.txt) do hedit \x25i F:\\tmp\\\x25~ni.enc /1234 /encrypt /aes")
                      _T("&&ECHO NOTE:    Pathnames \x25i - may not contain spaces.")
                      _T("&&ECHO          Filename extensions (\x25i.*) - 3 characters max. (DOS convention)");

TCHAR _sys32path[MAX_PATH+1] = _T("c:\\windows\\system32;");
TCHAR _cmdlineBuf[MAX_PATH+1]; // Console commandline buffer
TCHAR _curDir[MAX_PATH+1];     // Current EXE directory
TCHAR heditExe[MAX_PATH+1];    // HEDIT.EXE path
TCHAR heditTmp[MAX_PATH+1];    // HEDIT.TMP path

// Extern variables
extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern char* pszKeyBuffer;   // Key buffer (max key length for AES = 256 bits)
extern char* pszIcvBuffer;   // IV buffer (max key length for AES = 256 bits)

extern ULONG FileProcessingMode, dwFileSize, dwCryptFileSize;

extern HWND hMain;

extern void DisplayLastError(int);
extern void WindowsDoAlgorithmMac(LPSTR, LPSTR, LPSTR, LPSTR);

// Forward declaration of functions included in this code module:
void DoConsoleFileOpen(HWND);

//---------------------------------------------------------------------
//
//                    ConsoleHeditExeVerify
//
// Verfication of HEDIT.EXE is necessary to protect us against Trojan Horses
// (a malware console program could be executed under the name "HEDIT.EXE").
//
BOOL ConsoleHeditExeVerify()
  {
  // MACs for an invariant 16K Block (0x0200..0x41FF) of Hedit.EXE
  // Note: Can't build the Mac over copmlete Hedit.exe, because data 
  //       in EXE-Header changes for every build also if source is unchanged.
  // Functionally identical Hedit V1.5 builds are supported:
  // Expected result for HEDIT_XP.EXE V1.5 build 29.05.2023:
  //  DES MAC = 4F 3A 88 88 7A DB 99 5C 
  char DesMacHeditExe[] =  {(char)0x4F, (char)0x3A, (char)0x88, (char)0x88,
                            (char)0x7A, (char)0xDB, (char)0x99, (char)0x5C};
  // Expected result for HEDIT_XP.EXE V1.5 build 23.12.2023:
  //  DES MAC = 71 8F 1E 65 3B FC 8E C5 
  char DesMacHeditExe1[] = {(char)0x71, (char)0x8F, (char)0x1E, (char)0x65,
                            (char)0x3B, (char)0xFC, (char)0x8E, (char)0xC5};
  // Expected result for HEDIT64.EXE V1.5 build 23.12.2023:
  //  DES MAC = 0B 1B 46 D8 F8 3E 36 DD 
  char DesMacHeditExe2[] = {(char)0x0B, (char)0x1B, (char)0x46, (char)0xD8,
                            (char)0xF8, (char)0x3E, (char)0x36, (char)0xDD};
  BOOL bSuccess = FALSE;

  LPSTR pchTmp;   // Pointer to temp buffer of data read from file.
  int i, fsize;
  DWORD dwRead;   // Bytesrd
  
  struct _stat fstatBuf; // Size < 4Gbyte
  
  HANDLE hHeditExe = CreateFile(
    heditExe,
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL,              
    OPEN_EXISTING,
    0,
    NULL);

  if (hHeditExe != INVALID_HANDLE_VALUE)
    {
    //int _wstat(
    //  TCHAR *path,
    //  struct _stat *buffer
    //  );
    _wstat(heditExe, &fstatBuf);   // Input file status (no UNICODE)
    fsize = fstatBuf.st_size;      // Only size < 4GByte

    if (fsize < HEDIT_MAC_END-HEDIT_MAC_START)
      {                                                          
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("HEDIT.EXE - Recognition failed.")); 
      DisplayLastError(_ERR);     // Display formatted _tDebugBuf contents
      }

    pchTmp = (LPSTR)LocalAlloc(LPTR, fsize); 

    // Read Hedit.exe image
    ReadFile(hHeditExe, pchTmp, fsize, &dwRead, NULL);        
    //dwCryptFileSize = dwRead;

    // Restrict mMAC to invariant hedit.exe  binary block
    dwCryptFileSize = HEDIT_MAC_END-HEDIT_MAC_START;   
    LPSTR _pchTmp = &pchTmp[HEDIT_MAC_START];

    dwFileSize = dwCryptFileSize; // dwFileSize: Needed for progressbar & Crypto algo, 
    for (i=0; i<DES_BLOCK_SIZE; i++)
      {
      pszKeyBuffer[i] = 0;  // DES Key = 0
      pszIcvBuffer[i] = 0;  // DES IV  = 0
      }
    FileProcessingMode = CRYPT_DES | CRYPT_MAC;  // DES MAC is sufficient

    WindowsDoAlgorithmMac(_pchTmp, _pchTmp, pszIcvBuffer, pszKeyBuffer);


    // Check MAC for HEDIT.EXE
    for (i=0; i<DES_BLOCK_SIZE; i++)
      {
      if (_pchTmp[i] != DesMacHeditExe[i]   &&   // Hedit build  29.05.2023
          _pchTmp[i] != DesMacHeditExe1[i]  &&   // Hedit build  23.12.2023
          _pchTmp[i] != DesMacHeditExe2[i])      // Hedit build  23.12.2023
       break; // MAC incorrect (no match)
      }
    if (i == DES_BLOCK_SIZE) bSuccess = TRUE;    // MAC matches the HEDIT.EXE V1.5
                                                 // (executing HEDIT.EXE aloowed)
    pchTmp = (LPSTR)LocalFree(pchTmp);
    } // end if (hHeditExe)

  else bSuccess = FALSE;

  CloseHandle(hHeditExe);
  if (bSuccess == FALSE)
    {                                                          
    StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("HEDIT.EXE - Recognition failed.")); 
    DisplayLastError(_ERR);     // Display formatted _tDebugBuf contents
    }
  return(bSuccess);
  } // ConsoleHeditExeVerify


//-----------------------------------------------------------------------------
//
//                                CreateConsole
//
void CreateConsole(int _wParam)
  {
  // Before showing the console window prepare the requested commads.
  switch(_wParam)
    {
    case ID_CONSOLE_HEDIT_FILEOPEN:
      DoConsoleFileOpen(hMain);
      break;
    case ID_CONSOLE_HEDIT:
//ha//      StringCbPrintf(_cmdlineBuf, sizeof(_cmdlineBuf),_T("%s /?"), heditExe); //ha// problem: path w/ spaces
      StringCbPrintf(_cmdlineBuf, sizeof(_cmdlineBuf),_T("HEDIT.EXE /?"));
      break;
    case ID_CONSOLE_HEDIT_CRYPT:
      StringCbPrintf(_cmdlineBuf, sizeof(_cmdlineBuf),_T("%s"), _cmdExample);
      break;
    } // end switch
  
  // Create and initialize the console window
  FILE* conin  = stdin;                       // setup console I/O streams
  FILE* conout = stdout;
  FILE* conerr = stderr;
  AllocConsole();                             // Create a console
  AttachConsole(GetCurrentProcessId());
  freopen_s(&conin,  "CONIN$",  "r", stdin);  // Provide console I/O
  freopen_s(&conout, "CONOUT$", "w", stdout);
  freopen_s(&conerr, "CONOUT$", "w", stderr);

  // Hide the main window application,
  //  since it's of no use when the console is running.
  ShowWindow(hMain, SW_HIDE);        
  ShowScrollBar(GetConsoleWindow(), SB_BOTH, 0);  // Console without scroll bars 
  
  // Resizing or Maximizing console window is not allowed (avoids messy screen)
  //
  // IMPORTANT NOTE: 'SetWindowLong' is not working on some computers:
  // It is also the case that this fails with out-of-date copies of XP
  //  (even SP3, and perhaps others). I have confirmed on over a dozen workstations
  //  that installing recommended updates resolves this issue.
  //  There were an average of updates needed on each, 
  //  so it's hard to say which one did the trick, but apparently one of them did.
  //  Yet another reason to keep updates enabled.
  //
  HWND hConsoleWindow = GetConsoleWindow();
  SetWindowLong(
    hConsoleWindow, 
    GWL_STYLE, 
    GetWindowLong(hConsoleWindow, GWL_STYLE) & ~WS_MAXIMIZEBOX ^ WS_THICKFRAME);

  // Show Console 80x25 for hedit.exe
  //system("cmd /c MODE CON COLS=80 LINES=25");      // ANSI:    Restrict console window to 80x25
  _wsystem(_T("cmd /c MODE CON COLS=80 LINES=25"));  // UNICODE: Restrict console window to 80x25

  // At this point:
  // We are running in the Console. All Console-Commands are allowed from here on 
  // Set minimal environment such that "cmd" and "Hedit.exe" can be invoked
  StringCbCat(_sys32path, MAX_PATH, _curDir);
  SetEnvironmentVariable(_T("path"), _sys32path);    // PATH=..

  _wsystem(_cmdlineBuf);                             // UNICODE: Launch Hedit.exe

  // Stay within console after leaving Hedit.exe
  printf("\nConsole application: HEDIT.EXE\n");      // Console function: printf(..)

  // Launch a 2nd instance of cmd prompt to provide full editing features
  system("cmd");                                     // ANSI: Command CMD

  // At this point: Console prompt >
  // Only typing "EXIT" will terminate at the console window.
  // EXIT: Some User Guidance before exiting
  system("cls");
  printf("\n     -----------------------------");
  printf("\n    | haCrypt console terminated. |");
  printf("\n     -----------------------------");
  Sleep(1500);   // Wait some 1..2s before leaving

  FreeConsole(); // Discard console and exit
  } // CreateConsole

//-----------------------------------------------------------------------------
//
//                      GetHomeDirectory
//
void GetHomeDirectory()
  {
  int i;
  DWORD  _curDirBufLength;
  LPWSTR _curDirBuf;

  _curDirBufLength = GetCurrentDirectory(NULL, 0);                // Get length of current directory-string
  _curDirBuf = (LPWSTR)LocalAlloc(LPTR, 2*_curDirBufLength + 16); // At least *2 +16 (XP - sporadic failures otherwise ???)   
  _curDirBuf[_curDirBufLength] = 0;                               // Terminate directory-string

  GetCurrentDirectory(_curDirBufLength, _curDirBuf);              // Get the folder where we reside
  for (i=0; i<=_curDirBufLength; i++)
    {
    _cmdlineBuf[i] = _curDirBuf[i];  // Init cmdline
    _curDir[i]     = _curDirBuf[i];  // Init current path
    heditExe[i]    = _curDirBuf[i];  // Init HEDIT.EXE path
    heditTmp[i]    = _curDirBuf[i];  // Init HEDIT.TMP path
    }

  // UNICODE: Initialize heditExe and heditTmp
  StringCbCat(heditExe, MAX_PATH, _T("\\HEDIT.EXE"));     // Init 'heditExe' 'HEDIT.EXE'
  StringCbCat(heditTmp, MAX_PATH, _T("\\HEDIT.TMP"));     // Init 'heditTmp' 'HEDIT.TMP'
  StringCbCat(_cmdlineBuf, MAX_PATH, _T("\\Hedit.exe "));
  LocalFree(_curDirBuf);             // Discard the allocated buffer
  } // GetHomeDirectory

//-----------------------------------------------------------------------------
//
//                      DoConsoleFileOpen
//
void DoConsoleFileOpen(HWND _hwnd)
  {
  OPENFILENAME ofn={0};                      // OPENFILENAMEA won't work on Windows XP
  TCHAR szFileName[MAX_PATH] = _T("");
  char * tempBuf;
  int k;

  ZeroMemory(&ofn, sizeof(OPENFILENAME));

  ofn.lStructSize = sizeof(OPENFILENAME);
  ofn.hwndOwner   = _hwnd;
  ofn.lpstrFilter = _T(" haCrypt Files (.a~e .a_e .a°e .a~m .. .k .iv .bin .txt\x20)\0 \
  *.a~*;*.a_*;*.a°*;*.d~*;*.d_*;*.d°*;*.3~*;*.3_*;*.3°*;*.k;*.iv;*.#*;*.e*;*.bin;*.txt\0 \
  All Files (*.*)\0*.*\0\0");
  ofn.lpstrFile   = szFileName;
  ofn.nMaxFile    = MAX_PATH;
  ofn.lpstrDefExt = _T("txt");
  ofn.Flags       = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
  
  // Build console commandline "folder\HEDIT folder\filename"
  if (GetOpenFileName(&ofn)) StringCbCat(_cmdlineBuf, MAX_PATH, szFileName);
  } // DoConsoleFileOpen

//------------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha////--CONSOLE----CONSOLE----CONSOLE----CONSOLE----CONSOLE----CONSOLE----CONSOLE----CONSOLE--
//ha//printf("\n******** DEBUG STOP 1 ********\n");
//ha//printf("curDir = %s", curDir);
//ha//while (_kbhit() != 0) _getch();   // flush key-buffer 
//ha//printf("\n***** press 'q' for exit *****\n");
//ha//if (_getch() == 'q') exit(0);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha////--CONSOLE----CONSOLE----CONSOLE----CONSOLE----CONSOLE----CONSOLE----CONSOLE----CONSOLE--

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "cmdlineBuf=%s\ncurDir=%s\nhomeDir=%s\ncurDirBuf=%s\ncurDirBufLength=%d", 
//ha//                   cmdlineBuf,    curDir,    homeDir,    curDirBuf,    curDirBufLength);
//ha//MessageBoxA(NULL, DebugBuf, "ANSI stop2--------------------------------------", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize,
//ha//               _T("_cmdlineBuf=%s\n_curDir=%s\n_homeDir=%s\n_curDirBuf=%s\n_curDirBufLength=%d"), 
//ha//                   _cmdlineBuf,    _curDir,    _homeDir,    _curDirBuf,    _curDirBufLength);
//ha//MessageBox(NULL, _tDebugBuf, _T("UNICODE stop2--------------------------------------"), MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "dwCryptFileSize=%08X\n_pchTmp=%08X\n_pchTmp[0..7]=%02X %02X %02X %02X %02X %02X %02X %02X",
//ha//                   dwCryptFileSize, pchTmp,
//ha//                     (UCHAR)_pchTmp[0], (UCHAR)_pchTmp[1], 
//ha//                     (UCHAR)_pchTmp[2], (UCHAR)_pchTmp[3],
//ha//                     (UCHAR)_pchTmp[4], (UCHAR)_pchTmp[5], 
//ha//                     (UCHAR)_pchTmp[6], (UCHAR)_pchTmp[7]);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG 2 Hedit MAC", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
