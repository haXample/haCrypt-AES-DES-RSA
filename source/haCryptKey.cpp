// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptKey.cpp - C++ Developer source file.
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

#include <uxtheme.h>  // Allow theme styling progress bar (XP / Vista or greater

#include "haCrypt.h"                  

// Global variables
TCHAR _tKeyIcvBuf[2*KEY_SIZE_MAX]; // Temporary buffer for formatted UNICODE text
int _tKeyIcvBufSize = sizeof(_tKeyIcvBuf);

TCHAR szKeyIcvBuf[KEY_SIZE_MAX+1]; // (UNICODE) Key buffer (max key length for AES = 256 bits)

TCHAR szKeyHidden[]    = _T("Key is hidden.");
TCHAR szKeySavedDES[]  = _T("DES: Key saved.");
TCHAR szKeySaved3DES[] = _T("3DES: Key saved.");
TCHAR szKeySaved128[]  = _T("AES: 128bit Key saved.");
TCHAR szKeySaved192[]  = _T("AES: 192bit Key saved.");
TCHAR szKeySaved256[]  = _T("AES: 256bit Key saved.");

TCHAR* pszTextDesKeyIV = TEXT("={%02X %02X %02X %02X %02X %02X %02X %02X}");
TCHAR* pszTextAesKeyIV = TEXT("={%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X}");
TCHAR* pszTextTdesKey  = TEXT("={%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X}");
TCHAR* pszTextAesKey   = TEXT("={%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X \
%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X}");

TCHAR* pszKeyIcvInfo = _T("%s = %s");
TCHAR* pszTextTdesIV = pszTextDesKeyIV;  // 3DES-IV (i.e. TDES or TDEA) = DES-IV

int _keylength = 128;                   // AES default keysize = 128 bits

// External variables
extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern int k, gwtstat, keyDisplayMode;
extern ULONG FileProcessingMode;

extern DWORD dwFileSize, dwCryptFileSize;
extern DWORD dwKeyFileSize, dwIvFileSize;

extern TCHAR szStatusClear[];
extern TCHAR szKeyNull[];
extern TCHAR szKeyFileName[];  // Keyfile
extern TCHAR szIcvFileName[];  // IV-file

extern TCHAR* pszTextKeySaved;
extern TCHAR* pszKeyIcvFileName;

extern HWND hTool;
extern HWND hKeyTextBox;           
extern HWND hIvTextBox;          
extern HWND hButtonIV;
extern HWND hStatusbar;

extern LPSTR szKeyDialogIn[]; // (Unicode)=char* szKeyDialogInKey[..] buffer (max key length for AES=256 bits)  
extern LPSTR szIcvDialogIn[]; // (Unicode)=char* szIcvDialogInIV[..] buffer (max IV length for AES=128 bits)      
extern char* pszKeyBuffer;    // (ANSI,Ascii) Default: Dialog-key pointer for Crypto functions
extern char* pszIcvBuffer;    // (ANSI,Ascii) Default: Dialog-IV pointer for Crypto functions

extern char KeyDialog_In[];   // (ANSI,Ascii) Key buffer (max key length for AES = 256 bits)
extern char IcvDialog_In[];   // (ANSI,Ascii) IV buffer (max key length for AES = 128 bits)

extern void PaintColoredStatusMsg(TCHAR*);

//-----------------------------------------------------------------------------
//
//                        ClearKeyDialog
//
void ClearKeyDialog()
  {
  // Init clear key buffer for crypto functions
  for (k=0; k<KEY_SIZE_MAX; k++)
    szKeyDialogIn[k] = 0;                       
  // Clear Toolbar's key edit field
  SetDlgItemText(hTool, ID_TOOLBAR_KEYEDIT, NULL);
  } // ClearKeyDialog

//-----------------------------------------------------------------------------
//
//                        ClearIcvDialog
//
void ClearIcvDialog()
  {
  // Init clear IV
  for (k=0; k<AES_BLOCK_SIZE; k++)  // AES-IV = max size
    szIcvDialogIn[k] = 0;                       
  // Clear Toolbar's IV edit field
  SetDlgItemText(hTool, ID_TOOLBAR_IVEDIT, NULL); 
  } // ClearIcvDialog

//-----------------------------------------------------------------------------
//
//                        ShowActualKeyIv
//
void ShowActualKeyIv(int _mode)             
  {
  int dwKeyIvFileSize = 0;
  HWND hKeyIvTextBox;

  TCHAR* pszKeyIvfileStr  = NULL;
  TCHAR* pszKeyIvStr      = NULL;
  TCHAR* pszKeyIvTestStr  = NULL;
  TCHAR* pszKeyIvNull     = NULL;
  TCHAR* pszKeyIvFileName = NULL;

  if (_mode == 0)       // Key
    {
    hKeyIvTextBox    = hKeyTextBox;  
    dwKeyIvFileSize  = dwKeyFileSize;
    pszKeyIvfileStr  = _T("Keyfile");
    pszKeyIvStr      = _T("Key");
    pszKeyIvTestStr  = _T("TEST-KEY");
    pszKeyIvNull     = szKeyNull;     // Display default key warning message instead of 0s 
    pszKeyIvFileName = szKeyFileName;
    }
  else if (_mode == 1)  // IV
    {
    hKeyIvTextBox    = hIvTextBox;  
    dwKeyIvFileSize  = dwIvFileSize;
    pszKeyIvfileStr  = _T("IV-file");
    pszKeyIvStr      = _T("IV    ");
    pszKeyIvTestStr  = _T("TEST-IV");
    pszKeyIvNull     = _T("NULL");    // Display NULL instead of hex 0s
    pszKeyIvFileName = szIcvFileName;
    }

  if (dwKeyIvFileSize > 0)            // Key loaded from file?
    {
    //extern PWSTR szTruncPath;                                                                 // Deprecated.
    //TruncateFilePath(szKeyFileName, 20, 0);                                                   // Deprecated.
    //StringCbPrintf(_tKeyIcvBuf, _tKeyIcvBufSize, szKeyInfo, _T("Keyfile"), szTruncPath);      // Deprecated.
    PathStripPathW(pszKeyIvFileName); // Build filename only
    if (pszKeyIvFileName[0] != 0)     // Key/IV loaded from file?
      StringCbPrintf(_tKeyIcvBuf, _tKeyIcvBufSize, pszKeyIcvInfo, pszKeyIvfileStr, pszKeyIvFileName); // filename
    else
      StringCbPrintf(_tKeyIcvBuf, _tKeyIcvBufSize, pszKeyIcvInfo, pszKeyIvStr, pszKeyIvTestStr);      // TEST-KEY/IV
    return; 
    }

  // No need to bother if there's no text.
  if (GetWindowTextLength(hKeyIvTextBox) > 0) // Any Text at all?
    {
    pszKeyIvFileName[0] = 0;    // Clear KeyIvFileName, since the key/IV has been entered on keyboard
    gwtstat = GetWindowText(hKeyIvTextBox, szKeyIcvBuf, TYPED_KEY_SIZE_MAX+1); // +1 = NULL-Terminator
    if (keyDisplayMode == MF_UNCHECKED)
      StringCbPrintf(_tKeyIcvBuf, _tKeyIcvBufSize, pszKeyIcvInfo, pszKeyIvStr, szKeyHidden);
    else
      StringCbPrintf(_tKeyIcvBuf, _tKeyIcvBufSize, pszKeyIcvInfo, pszKeyIvStr, szKeyIcvBuf);
    }
  else 
    StringCbPrintf(_tKeyIcvBuf, _tKeyIcvBufSize, pszKeyIcvInfo, pszKeyIvStr, pszKeyIvNull);
  } // ShowActualKeyIv


//-----------------------------------------------------------------------------
//
//                        InitCryptoKeyFromDialog
//
//  This conversion UNICODE -> ANSI relies on 'sprintf' function formatting!
//  The reason is that this technique works fro 32bit and 64bit.
//
void InitCryptoKeyFromDialog(int _mode)
  {
  char AlgoKeyBuf[KEY_SIZE_MAX+1];       // Key / Icv only, buffer for formatted ANSI text

  for (k=0; k<KEY_SIZE_MAX+1; k++) AlgoKeyBuf[k] = 0;

  if (_mode == 0)
    {
    for (k=0; k<KEY_SIZE_MAX; k++) KeyDialog_In[k] = 0;
    sprintf(AlgoKeyBuf,"%s", (char *)&szKeyDialogIn[0]);  // = sprintf(AlgoKeyBuf,"%s", (LPSTR)&szKeyDialogIn[0]);

    // Special key manipulation (_mode = 0) for ALL crypto modes!
    if (_mode == 0 && AlgoKeyBuf[6] == 0xA0) AlgoKeyBuf[6] = 0xFF; // Adjust for Alt+<255> keypad, 
    if (_mode == 0 && AlgoKeyBuf[7] == 0xA0) AlgoKeyBuf[7] = 0xFF; //  simulate keypad entry  0xFF

    KeyDialog_In[0]  = AlgoKeyBuf[0];   
    KeyDialog_In[1]  = AlgoKeyBuf[1]; 
    KeyDialog_In[2]  = AlgoKeyBuf[2];
    KeyDialog_In[3]  = AlgoKeyBuf[3];
    KeyDialog_In[4]  = AlgoKeyBuf[4];
    KeyDialog_In[5]  = AlgoKeyBuf[5];
    KeyDialog_In[6]  = AlgoKeyBuf[6]; 
    KeyDialog_In[7]  = AlgoKeyBuf[7];   // 64bit

    KeyDialog_In[8]  = AlgoKeyBuf[8];   
    KeyDialog_In[9]  = AlgoKeyBuf[9]; 
    KeyDialog_In[10] = AlgoKeyBuf[10];
    KeyDialog_In[11] = AlgoKeyBuf[11];
    KeyDialog_In[12] = AlgoKeyBuf[12];
    KeyDialog_In[13] = AlgoKeyBuf[13]; 
    KeyDialog_In[14] = AlgoKeyBuf[14];
    KeyDialog_In[15] = AlgoKeyBuf[15];  // 128bit

    KeyDialog_In[16] = AlgoKeyBuf[16];  
    KeyDialog_In[17] = AlgoKeyBuf[17]; 
    KeyDialog_In[18] = AlgoKeyBuf[18];
    KeyDialog_In[19] = AlgoKeyBuf[19];
    KeyDialog_In[20] = AlgoKeyBuf[20];
    KeyDialog_In[21] = AlgoKeyBuf[21];
    KeyDialog_In[22] = AlgoKeyBuf[22]; 
    KeyDialog_In[23] = AlgoKeyBuf[23];  // 192bit
//  -------------------------------------------------------------------------------------
    KeyDialog_In[24] = AlgoKeyBuf[24];  // 256bit key not supported with Keyboard dialog  
    KeyDialog_In[25] = AlgoKeyBuf[25];  //  (see key loading via file)  
    KeyDialog_In[26] = AlgoKeyBuf[26];
    KeyDialog_In[27] = AlgoKeyBuf[27];  
    KeyDialog_In[28] = AlgoKeyBuf[28];
    KeyDialog_In[29] = AlgoKeyBuf[29];
    KeyDialog_In[30] = AlgoKeyBuf[30];  
    KeyDialog_In[31] = AlgoKeyBuf[31];  

    // Set key pointer for crypto functions
    if (dwKeyFileSize == 0) pszKeyBuffer = KeyDialog_In;  
    } // end if (_mode == 0)

  else
    {
    for (k=0; k<AES_BLOCK_SIZE; k++) IcvDialog_In[k] = 0;
    sprintf(AlgoKeyBuf,"%s", (char *)&szIcvDialogIn[0]);  // = sprintf(AlgoKeyBuf,"%s", (LPSTR)&szIcvDialogIn[0]);

    IcvDialog_In[0]  = AlgoKeyBuf[0];
    IcvDialog_In[1]  = AlgoKeyBuf[1]; 
    IcvDialog_In[2]  = AlgoKeyBuf[2];
    IcvDialog_In[3]  = AlgoKeyBuf[3];
    IcvDialog_In[4]  = AlgoKeyBuf[4];
    IcvDialog_In[5]  = AlgoKeyBuf[5];
    IcvDialog_In[6]  = AlgoKeyBuf[6]; 
    IcvDialog_In[7]  = AlgoKeyBuf[7];  // 64bit (DES, 3DES)

    IcvDialog_In[8]  = AlgoKeyBuf[8];
    IcvDialog_In[9]  = AlgoKeyBuf[9]; 
    IcvDialog_In[10] = AlgoKeyBuf[10];
    IcvDialog_In[11] = AlgoKeyBuf[11];
    IcvDialog_In[12] = AlgoKeyBuf[12];
    IcvDialog_In[13] = AlgoKeyBuf[13]; 
    IcvDialog_In[14] = AlgoKeyBuf[14];
    IcvDialog_In[15] = AlgoKeyBuf[15]; // 128bit  (AES)

    // Set IV pointer for crypto functions
    if (dwKeyFileSize == 0) pszIcvBuffer = IcvDialog_In;
    } // end else if (_mode == 1)

  } // InitCryptoKeyFromDialog               

//-----------------------------------------------------------------------------
//
//                              DispayKeyDialogHex
//
//  Converts the UNICODE into ANSI characters: _mode=0 (Key), _mode=1 (IV)
//
void DispayKeyDialogHex(HWND _hwnd, char _uniBlock[], int _mode)
  {
  TCHAR _szAsciiBuf[COUNTBUF_SIZE];         // Temporary buffer for formatted text
  UCHAR aeskeySizeDetect = 0x00;            // Initially clear

  if (dwKeyFileSize > 0 && _mode == 0) return;     // Key already loaded from file - return.
  else if (dwIvFileSize > 0 && _mode == 1) return; // IV already loaded from file - return.

  // Special key manipulation (_mode = 0) for ALL crypto modes!
  if (_mode == 0 && (UCHAR)_uniBlock[6] == 0xA0) _uniBlock[6] = 0xFF; // Adjust for Alt+<255> keypad, 
  if (_mode == 0 && (UCHAR)_uniBlock[7] == 0xA0) _uniBlock[7] = 0xFF; //  simulate keypad entry 0xFF

  if (_mode == 0) _keylength = 256;               // AES keylength = 256 bits (assumed)
                                                  
  for (k=24; k<32; k++)
    aeskeySizeDetect |= (UCHAR)_uniBlock[k];      // AES/TDES keylength = 192/168 bits
  if (_mode == 0 && aeskeySizeDetect == 0x00) _keylength = 192;  

  for (k=16; k<32; k++)
    aeskeySizeDetect |= (UCHAR)_uniBlock[k];      // AES default keylength = 128 bits
  if (aeskeySizeDetect == 0x00) _keylength = 128; 
  
  // Clean up statusbar from 'paint'
  PaintColoredStatusMsg(szStatusClear);
  SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); 
  // Display key and IV in hexadecimal notaion

  switch(FileProcessingMode & CRYPT_ALGO_MASK)
    {
    case CRYPT_AES:
      if (_keylength == 128 && _mode == 0) // Mode 0 = Key
        // AES128 key and IV 16 bytes
        StringCbPrintf(_szAsciiBuf, sizeof _szAsciiBuf, pszTextAesKeyIV,    
                       (UCHAR)_uniBlock[0], (UCHAR)_uniBlock[1], 
                       (UCHAR)_uniBlock[2], (UCHAR)_uniBlock[3],
                       (UCHAR)_uniBlock[4], (UCHAR)_uniBlock[5], 
                       (UCHAR)_uniBlock[6], (UCHAR)_uniBlock[7],
                       (UCHAR)_uniBlock[8], (UCHAR)_uniBlock[9], 
                       (UCHAR)_uniBlock[10],(UCHAR)_uniBlock[11],
                       (UCHAR)_uniBlock[12],(UCHAR)_uniBlock[13],
                       (UCHAR)_uniBlock[14],(UCHAR)_uniBlock[15]);
      else if (_keylength == 192 && _mode == 0)
        // AES192 key 24 bytes (sharing buffer with 3DES)
        StringCbPrintf(_szAsciiBuf, sizeof _szAsciiBuf, pszTextTdesKey, 
                       (UCHAR)_uniBlock[0], (UCHAR)_uniBlock[1], 
                       (UCHAR)_uniBlock[2], (UCHAR)_uniBlock[3],
                       (UCHAR)_uniBlock[4], (UCHAR)_uniBlock[5], 
                       (UCHAR)_uniBlock[6], (UCHAR)_uniBlock[7],
                       (UCHAR)_uniBlock[8], (UCHAR)_uniBlock[9], 
                       (UCHAR)_uniBlock[10],(UCHAR)_uniBlock[11],
                       (UCHAR)_uniBlock[12],(UCHAR)_uniBlock[13],
                       (UCHAR)_uniBlock[14],(UCHAR)_uniBlock[15],
                       (UCHAR)_uniBlock[16],(UCHAR)_uniBlock[17],
                       (UCHAR)_uniBlock[18],(UCHAR)_uniBlock[19],
                       (UCHAR)_uniBlock[20],(UCHAR)_uniBlock[21],
                       (UCHAR)_uniBlock[22],(UCHAR)_uniBlock[23]);
      else if (_keylength == 256 && _mode == 0)
        // AES256 key 32 bytes
        StringCbPrintf(_szAsciiBuf, sizeof _szAsciiBuf, pszTextAesKey, 
                       (UCHAR)_uniBlock[0], (UCHAR)_uniBlock[1], 
                       (UCHAR)_uniBlock[2], (UCHAR)_uniBlock[3],
                       (UCHAR)_uniBlock[4], (UCHAR)_uniBlock[5], 
                       (UCHAR)_uniBlock[6], (UCHAR)_uniBlock[7],
                       (UCHAR)_uniBlock[8], (UCHAR)_uniBlock[9], 
                       (UCHAR)_uniBlock[10],(UCHAR)_uniBlock[11],
                       (UCHAR)_uniBlock[12],(UCHAR)_uniBlock[13],
                       (UCHAR)_uniBlock[14],(UCHAR)_uniBlock[15],
                       (UCHAR)_uniBlock[16],(UCHAR)_uniBlock[17],
                       (UCHAR)_uniBlock[18],(UCHAR)_uniBlock[19],
                       (UCHAR)_uniBlock[20],(UCHAR)_uniBlock[21],
                       (UCHAR)_uniBlock[22],(UCHAR)_uniBlock[23],
                       (UCHAR)_uniBlock[24],(UCHAR)_uniBlock[25], 
                       (UCHAR)_uniBlock[26],(UCHAR)_uniBlock[27],
                       (UCHAR)_uniBlock[28],(UCHAR)_uniBlock[29],
                       (UCHAR)_uniBlock[30],(UCHAR)_uniBlock[31]);
      else if (_mode == 1)                 // Mode 1 = IV
        // AES IV 16 bytes                                                                  
        StringCbPrintf(_szAsciiBuf, sizeof _szAsciiBuf, pszTextAesKeyIV,  
                       (UCHAR)_uniBlock[0], (UCHAR)_uniBlock[1], 
                       (UCHAR)_uniBlock[2], (UCHAR)_uniBlock[3],
                       (UCHAR)_uniBlock[4], (UCHAR)_uniBlock[5], 
                       (UCHAR)_uniBlock[6], (UCHAR)_uniBlock[7],
                       (UCHAR)_uniBlock[8], (UCHAR)_uniBlock[9], 
                       (UCHAR)_uniBlock[10],(UCHAR)_uniBlock[11],
                       (UCHAR)_uniBlock[12],(UCHAR)_uniBlock[13],
                       (UCHAR)_uniBlock[14],(UCHAR)_uniBlock[15]);

      if (_keylength == 128)      pszTextKeySaved = szKeySaved128;  // 128bit
      else if (_keylength == 192) pszTextKeySaved = szKeySaved192;  // 192bit
      else if (_keylength == 256) pszTextKeySaved = szKeySaved256;  // 256bit not implemented
      break;  // end case CRYPT_AES

    case CRYPT_DES:                        // Mode 0 and 1 = Key/IV
      // DES key and IV 8 bytes
      StringCbPrintf(_szAsciiBuf, sizeof _szAsciiBuf, pszTextDesKeyIV,    
                     (UCHAR)_uniBlock[0],(UCHAR)_uniBlock[1],
                     (UCHAR)_uniBlock[2],(UCHAR)_uniBlock[3],
                     (UCHAR)_uniBlock[4],(UCHAR)_uniBlock[5],
                     (UCHAR)_uniBlock[6],(UCHAR)_uniBlock[7]);
      pszTextKeySaved = szKeySavedDES;     // DES standard keylength
      break;

    case CRYPT_TDES:
      if (_mode == 0)
        {                                  // Mode 0 = Key                                     
        // TDES key 24 bytes
        StringCbPrintf(_szAsciiBuf, sizeof _szAsciiBuf, pszTextTdesKey,  
                       (UCHAR)_uniBlock[0], (UCHAR)_uniBlock[1], 
                       (UCHAR)_uniBlock[2], (UCHAR)_uniBlock[3],
                       (UCHAR)_uniBlock[4], (UCHAR)_uniBlock[5], 
                       (UCHAR)_uniBlock[6], (UCHAR)_uniBlock[7],
                       (UCHAR)_uniBlock[8], (UCHAR)_uniBlock[9], 
                       (UCHAR)_uniBlock[10],(UCHAR)_uniBlock[11],
                       (UCHAR)_uniBlock[12],(UCHAR)_uniBlock[13],
                       (UCHAR)_uniBlock[14],(UCHAR)_uniBlock[15],
                       (UCHAR)_uniBlock[16],(UCHAR)_uniBlock[17],
                       (UCHAR)_uniBlock[18],(UCHAR)_uniBlock[19],
                       (UCHAR)_uniBlock[20],(UCHAR)_uniBlock[21],
                       (UCHAR)_uniBlock[22],(UCHAR)_uniBlock[23]);
        pszTextKeySaved = szKeySaved3DES;  // 3DES standard keylength
        }
      else                                 // Mode 1 = IV
        // TDES IV 8 bytes (sharing IV buffer with DES)                                                                 
        StringCbPrintf(_szAsciiBuf, sizeof _szAsciiBuf, pszTextDesKeyIV,  
                       (UCHAR)_uniBlock[0],(UCHAR)_uniBlock[1],
                       (UCHAR)_uniBlock[2],(UCHAR)_uniBlock[3],
                       (UCHAR)_uniBlock[4],(UCHAR)_uniBlock[5],
                       (UCHAR)_uniBlock[6],(UCHAR)_uniBlock[7]);
      break;

    default:
      return;
      break;
    } // end switch
  
  //  Clear status field IF key display is hidden
  if (_mode == 0 && keyDisplayMode == MF_UNCHECKED)
    {
    PaintColoredStatusMsg(szStatusClear);
    SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); 
    SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)_T("")); 
    return;
    }

  // Display key / IV in hexadecimal rendition
  SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)_szAsciiBuf);  
  } // DispayKeyDialogHex              

//-----------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "FileProcessingMode = %08X\n_keylength = %i\n_mode = %i", FileProcessingMode, _keylength, _mode);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG DispayKeyDialogHex", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, 
//ha//               _T("szKeyFileName = %s\nszTestKey = %s"), szKeyFileName, szTestKey);
//ha//MessageBox(NULL, _tDebugBuf, _T("ryptoToggleEditedText STOP 1"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, 
//ha//               _T("dwKeyIvFileSize=%i\npszKeyIvFileName=%s\nszKeyFileName[0]=%02X\npszKeyIvfileStr=%s\npszKeyIvStr=%s\npszKeyIvTestStr=%s\npszKeyIvNull=%s"),
//ha//               dwKeyIvFileSize, pszKeyIvFileName, szKeyFileName[0], pszKeyIvfileStr, pszKeyIvStr, pszKeyIvTestStr, pszKeyIvNull);
//ha//MessageBox(NULL, _tDebugBuf, _T("ShowActualKeyIv STOP 1"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

