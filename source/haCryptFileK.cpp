// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptFileK.cpp - C++ Developer source file.
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
TCHAR* pszKeyRd        = TEXT("%lu Key-byte(s) read.");
TCHAR* pszIvRd         = TEXT("%lu IV-byte(s) read.");
TCHAR* pszKeyFileSaved = TEXT("%ibit %s");  // %i (for integer)

TCHAR szStatusClear[];

char szKeyFileIn[2*KEY_SIZE_MAX+1];
char szIvFileIn[2*AES_BLOCK_SIZE+1];

char KeyFile_In[KEY_SIZE_MAX+1];  // (Ascii, ANSI) Key buffer (max key length for AES = 256 bits)
char IcvFile_In[KEY_SIZE_MAX+1];  // (Ascii, ANSI) IV buffer (max key length for AES = 256 bits)

TCHAR szKeyFileName[MAX_PATH] = _T("");
TCHAR szIcvFileName[MAX_PATH] = _T("");
TCHAR* pszKeyIcvFileName;

DWORD dwKeyFileSize = 0;
DWORD dwIvFileSize = 0;                           

// Global extern variables
extern TCHAR szCountBuf[];  // Temporary buffer for formatted UNICODE text
extern int szCountBufsize;                                                                                  

extern char DebugBuf[];     // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];  // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern ULONG FileProcessingMode, ActiveProcessingMode;

extern int _keylength, keyDisplayMode;  // Key control for AES Algorthm functions

extern char* pszKeyBuffer;  // (Ascii, ANSI) key pointer for Crypto functions
extern char* pszIcvBuffer;  // (Ascii, ANSI) IV pointer for Crypto functions

extern TCHAR szIvSaved[];     
extern TCHAR szKeySaved[];

extern TCHAR* pszTextKeySaved;
extern TCHAR* pszTextAesKey;
extern TCHAR* pszTextTdesKey;
extern TCHAR* pszTextDesKeyIV;
extern TCHAR* pszTextAesKeyIV;

extern HWND hEdit;
extern HWND hStatusbar;
extern HWND hButtonKey;
extern HWND hButtonIV;
extern HWND hButtonHex;
 
// External functions
extern void ShowWinMouseClick(HWND, int, int, int);
extern void DisplayLastError(int);
extern void PaintColoredStatusMsg(TCHAR*);

extern void ClearKeyDialog();
extern void ClearIcvDialog();

//-----------------------------------------------------------------------------
//
//                              DispayKeyFileHex
//
//  Converts the UNICODE into ANSI characters: _mode=0 (Key), _mode=1 (IV)
//
void DispayKeyFileHex(HWND _hwnd, char _uniBlock[], int _mode)
  {
  TCHAR* _pszAsciiBuf = szCountBuf;   // Temporary buffer for formatted text
  int _asciiBufSize = szCountBufsize;
  UCHAR aeskeySizeDetect = 0x00;                  // Initially clear
  int k;

  if (_mode == 0) _keylength = KEY_LENGTH_256;    // Init AES keylength = 256 bits
                                                  
  for (k=KEY_SIZE_24; k<KEY_SIZE_MAX; k++)
    aeskeySizeDetect |= (UCHAR)_uniBlock[k];      // AES/TDES keylength = 192/168 bits
  if (_mode == 0 && aeskeySizeDetect == 0x00) _keylength = KEY_LENGTH_192;   

  for (k=KEY_SIZE_16; k<KEY_SIZE_MAX; k++)
    aeskeySizeDetect |= (UCHAR)_uniBlock[k];      // AES default keylength = 128 bits
  if (aeskeySizeDetect == 0x00) _keylength = KEY_LENGTH_128;  

  for (k=KEY_SIZE_8; k<KEY_SIZE_MAX; k++)
    aeskeySizeDetect |= (UCHAR)_uniBlock[k];      // DES default keylength = 64 (56) bits
  if (aeskeySizeDetect == 0x00) _keylength = KEY_LENGTH_64;  

  // Don't truncate/expand the key if keyfile matches exactly any blocksize
  // This allows testing 0-keys and 0-expanded keys when using a keyfile. 
  if (_mode == 0 && (((dwKeyFileSize * 8) % KEY_LENGTH_64) == 0))
    _keylength = (dwKeyFileSize * 8);

  // Zero-expand IVs for AES CBC modes if necessary
  if (_mode == 1 && (FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_AES)
    _keylength = KEY_LENGTH_128;
  
  // Truncate IVs for DES/3DES CBC modes if necessary
  else if (_mode == 1 && (FileProcessingMode & CRYPT_ALGO_MASK) != CRYPT_AES)
    _keylength = KEY_LENGTH_64;
  
  // Truncate/zero-expand Keys for DES/3DES/AES modes if necessary
  else if (_mode == 0 && (FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_DES)
    _keylength = KEY_LENGTH_64;
  
  else if (_mode == 0 && (FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_TDES)
    _keylength = KEY_LENGTH_192;
  
  else if (_mode == 0 && (FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_AES && _keylength < KEY_LENGTH_128)
    _keylength = KEY_LENGTH_128;
       
  SetWindowTextA(_hwnd, NULL);                    // Init-clear the Text Field
  // Clean up statusbar from 'paint'
  SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); 

  // Display key and IV in hexadecimal notation
  switch(_keylength)
    {
    case KEY_LENGTH_64:
      StringCbPrintf(_pszAsciiBuf, _asciiBufSize, pszTextDesKeyIV,    
                     (UCHAR)_uniBlock[0],(UCHAR)_uniBlock[1],
                     (UCHAR)_uniBlock[2],(UCHAR)_uniBlock[3],
                     (UCHAR)_uniBlock[4],(UCHAR)_uniBlock[5],
                     (UCHAR)_uniBlock[6],(UCHAR)_uniBlock[7]);
      break;

    case KEY_LENGTH_128:
      StringCbPrintf(_pszAsciiBuf, _asciiBufSize, pszTextAesKeyIV,  
                     (UCHAR)_uniBlock[0], (UCHAR)_uniBlock[1], 
                     (UCHAR)_uniBlock[2], (UCHAR)_uniBlock[3],
                     (UCHAR)_uniBlock[4], (UCHAR)_uniBlock[5], 
                     (UCHAR)_uniBlock[6], (UCHAR)_uniBlock[7],
                     (UCHAR)_uniBlock[8], (UCHAR)_uniBlock[9], 
                     (UCHAR)_uniBlock[10],(UCHAR)_uniBlock[11],
                     (UCHAR)_uniBlock[12],(UCHAR)_uniBlock[13],
                     (UCHAR)_uniBlock[14],(UCHAR)_uniBlock[15]);

      break;

    case KEY_LENGTH_192:
      if (_mode == 0)
        StringCbPrintf(_pszAsciiBuf, _asciiBufSize, pszTextTdesKey, 
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
      break;

    case KEY_LENGTH_256:
      if (_mode == 0)
        StringCbPrintf(_pszAsciiBuf, _asciiBufSize, pszTextAesKey,   
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
      break;

    default:
      return;
      break;
    } // end switch
  
  // Clean up statusbar from 'paint'
  PaintColoredStatusMsg(szStatusClear);
  SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); 
  // Display key / IV in hexadecimal rendition
  SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)_pszAsciiBuf); 

  if (_mode == 0)
    { 
    StringCbPrintf(_tDebugBuf, _tDebugbufSize, pszKeyFileSaved, _keylength, szKeySaved);
    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)_tDebugBuf);
    ClearKeyDialog();
    }
  else if (_mode == 1)
    {
    SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)szIvSaved);
    ClearIcvDialog();
    } 

  //  Clear status field IF key display is hidden
  if (_mode == 0 && keyDisplayMode == MF_UNCHECKED)
    SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)_T(""));
  pszTextKeySaved = szKeySaved;     // Default  
  } // DispayKeyFileHex              


//-----------------------------------------------------------------------------
//
//                        InitCryptoKeyFromFile
//
//  _mode=0 (Key), _mode=1 (IV)
//
void InitCryptoKeyFromFile(HWND _hwnd, int _mode)
  {
  int i;

  if (_mode == 0)      // Transfer Key to crypto functions
    {
    // Key File
    for (i=0; i<KEY_SIZE_MAX; i++) KeyFile_In[i] = 0;
    for (i=0; i<KEY_SIZE_MAX; i++) KeyFile_In[i] = szKeyFileIn[i];
    if (dwKeyFileSize > 0) pszKeyBuffer = KeyFile_In;
    }

  else if (_mode == 1) // Transfer IV to crypto functions
    {
    // IvFile 
    for (i=0; i<KEY_SIZE_MAX; i++) IcvFile_In[i] = 0;
    for (i=0; i<KEY_SIZE_MAX; i++) IcvFile_In[i] = szIvFileIn[i];
    if (dwIvFileSize > 0) pszIcvBuffer = IcvFile_In;
    } // end if (_mode)
  } //  InitCryptoKeyFromFile


//------------------------------------------------------------------------------
//
//                     ReadKeyFile
//
// _mode=0 (Key), _mode=1 (IV)
//
BOOL ReadKeyFile(HWND _hwnd, LPTSTR lpszFileName, int _mode) 
  { 
  HANDLE hFile;     // Handle of file.

  int i;            // Init bytesrd: Progress-Bar chunks to be read
  DWORD dwRead;     // bytesrd
  BOOL bSuccess = FALSE;
  
  // Open the file for reading, and retrieve the size of the file. 
  hFile = CreateFile(
    lpszFileName, 
    GENERIC_READ, 
    FILE_SHARE_READ, 
    (LPSECURITY_ATTRIBUTES) NULL, 
    OPEN_EXISTING, 
    FILE_ATTRIBUTE_NORMAL,          
    (HANDLE)NULL); 

  if (hFile != INVALID_HANDLE_VALUE)
    {
    if (_mode == 0) // key-file
      {
      dwKeyFileSize = GetFileSize(hFile, NULL);
      if ((dwKeyFileSize != 0xFFFFFFFF) && (dwKeyFileSize <= KEY_SIZE_MAX) && (_mode ==0)) 
        {
        for (i=0; i<sizeof(szKeyFileIn); i++) // cLear buffer
          szKeyFileIn[i] = 0;

        if (ReadFile(hFile, szKeyFileIn, dwKeyFileSize, &dwRead, NULL))
        szKeyFileIn[dwKeyFileSize+1] = 0;     // Add null terminator

        bSuccess = TRUE;
        SetWindowTextA(_hwnd, NULL);          // Init-clear the Text Field
        } // end if (filesize)
      else
        {
        //PaintColoredStatusErrorMsg(szKeyFileError);
        DisplayLastError(HA_ERROR_KEY_FILESIZE);
        return bSuccess;
        }
      } // end if (_mode==0)

    else if (_mode == 1) // IV-file
      {
      dwIvFileSize = GetFileSize(hFile, NULL);
      if ((dwIvFileSize != 0xFFFFFFFF) && (dwIvFileSize <= AES_BLOCK_SIZE) && (_mode ==1))
        {
        for (i=0; i<sizeof(szIvFileIn); i++) // cLear buffer
          szIvFileIn[i] = 0;

        if (ReadFile(hFile, szIvFileIn, dwIvFileSize, &dwRead, NULL))
        szKeyFileIn[dwIvFileSize+1] = 0;     // Add null terminator

        bSuccess = TRUE;
        SetWindowTextA(_hwnd, NULL);         // Init-clear the Text Field
        } // end if (filesize)
      else
        {
        //PaintColoredStatusErrorMsg(szIvFileError);
        DisplayLastError(HA_ERROR_IV_FILESIZE);
        return bSuccess;
        }
      } // end if (_mode==1)
     
    CloseHandle(hFile);
    } // end if (hfile)                 
  
  //else _lastErr = GetLastError(); // Error code from 'CreateFile()' handled by System dialog

  // Store and display key/IV read from file
  InitCryptoKeyFromFile(_hwnd, _mode);
  
  // Display file contents hex
  if (_mode == 0) DispayKeyFileHex(_hwnd, szKeyFileIn, _mode);
  else if (_mode == 1) DispayKeyFileHex(_hwnd, szIvFileIn, _mode);

  return bSuccess;
  } // ReadKeyFile


//-----------------------------------------------------------------------------
//
//                DoKeyFileOpen  (invoke explorer Dialog: "Open")
//
// _mode=0 (Key), _mode=1 (IV)
//
void DoKeyFileOpen(HWND _hwnd, int _mode)
  {
  OPENFILENAME ofn;

  if (_mode == 0) pszKeyIcvFileName = szKeyFileName;
  else if (_mode == 1)  pszKeyIcvFileName = szIcvFileName;

  ZeroMemory(&ofn, sizeof(OPENFILENAME));

  ofn.lStructSize = sizeof(OPENFILENAME);
  ofn.hwndOwner   = _hwnd;
  ofn.lpstrFilter = _T("Key Files (*.#k*, *.#i*)\0*.#k*;#*.*;*.#i*;*.b*;*.i*;*.k*;*.t*\0All Files (*.*)\0*.*\0");
//ha//  ofn.lpstrFile   = szKeyFileName;
  ofn.lpstrFile   = pszKeyIcvFileName;
  ofn.nMaxFile    = MAX_PATH;
  ofn.lpstrDefExt = _T("#");
  ofn.Flags       = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
  
  if (GetOpenFileName(&ofn))
    {
    hEdit = GetDlgItem(_hwnd, IDC_MAIN_EDIT);
    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)_T("Keyfile Loading ..."));
    SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)szKeyFileName);
    SetWindowText(_hwnd, pszKeyIcvFileName);      // Display filename in mainwindow's title field

    if (ReadKeyFile(hEdit, pszKeyIcvFileName, _mode))
      {
      if (_mode == 0)
        StringCbPrintf(szCountBuf, szCountBufsize, pszKeyRd, dwKeyFileSize);
      else if (_mode == 1)
        {
        lstrcpy(szIcvFileName, pszKeyIcvFileName);
        StringCbPrintf(szCountBuf, szCountBufsize, pszIvRd, dwIvFileSize);
        }
      SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)szCountBuf);
      }
    }
  else
    DisplayLastError(HA_NO_FILE_SELECTED);

  // Simulate Mouseclick to make button & dialog appear (XP Problem)
  ShowWinMouseClick(hButtonHex, 1, 0, 0); 
  ShowWinMouseClick(hButtonKey, 1, 0, 0); 
  if (ActiveProcessingMode == CRYPT_CBC) 
    ShowWinMouseClick(hButtonIV, 1, 0, 0);    
  } // DoKeyFileOpen


//-----------------------------------------------------------------------------

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(_KeyDebugBuf, "Key= [%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X]\n"
//ha//"         [%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X]\n\nKeyStr=%s\ndwKeyFileSize = %i",
//ha//                 (UCHAR)szKeyFileIn[0],  (UCHAR)szKeyFileIn[1], 
//ha//                 (UCHAR)szKeyFileIn[2],  (UCHAR)szKeyFileIn[3],
//ha//                 (UCHAR)szKeyFileIn[4],  (UCHAR)szKeyFileIn[5], 
//ha//                 (UCHAR)szKeyFileIn[6],  (UCHAR)szKeyFileIn[7],
//ha//                 (UCHAR)szKeyFileIn[8],  (UCHAR)szKeyFileIn[9], 
//ha//                 (UCHAR)szKeyFileIn[10], (UCHAR)szKeyFileIn[11],
//ha//                 (UCHAR)szKeyFileIn[12], (UCHAR)szKeyFileIn[13],
//ha//                 (UCHAR)szKeyFileIn[14], (UCHAR)szKeyFileIn[15],
//ha//                 (UCHAR)szKeyFileIn[16], (UCHAR)szKeyFileIn[17], 
//ha//                 (UCHAR)szKeyFileIn[18], (UCHAR)szKeyFileIn[19],
//ha//                 (UCHAR)szKeyFileIn[20], (UCHAR)szKeyFileIn[21], 
//ha//                 (UCHAR)szKeyFileIn[22], (UCHAR)szKeyFileIn[23],
//ha//                 (UCHAR)szKeyFileIn[24], (UCHAR)szKeyFileIn[25], 
//ha//                 (UCHAR)szKeyFileIn[26], (UCHAR)szKeyFileIn[27],
//ha//                 (UCHAR)szKeyFileIn[28], (UCHAR)szKeyFileIn[29],
//ha//                 (UCHAR)szKeyFileIn[30], (UCHAR)szKeyFileIn[31], szKeyFileIn, dwKeyFileSize);
//ha//MessageBoxA(NULL, _KeyDebugBuf, "STOP 1", MB_OK); // Show MAC bytes
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(szCountBuf, sizeof szCountBuf, pszTxtAesMAC,
//ha//                     pszCryptFileIn[0],  pszCryptFileIn[1], 
//ha//                     pszCryptFileIn[2],  pszCryptFileIn[3],
//ha//                     pszCryptFileIn[4],  pszCryptFileIn[5], 
//ha//                     pszCryptFileIn[6],  pszCryptFileIn[7],
//ha//                     pszCryptFileIn[8],  pszCryptFileIn[9], 
//ha//                     pszCryptFileIn[10], pszCryptFileIn[11],
//ha//                     pszCryptFileIn[12], pszCryptFileIn[13],
//ha//                     pszCryptFileIn[14], pszCryptFileIn[15],
//ha//                     pszCryptFileIn[16], pszCryptFileIn[17], 
//ha//                     pszCryptFileIn[18], pszCryptFileIn[19],
//ha//                     pszCryptFileIn[20], pszCryptFileIn[21], 
//ha//                     pszCryptFileIn[22], pszCryptFileIn[23],
//ha//                     pszCryptFileIn[24], pszCryptFileIn[25], 
//ha//                     pszCryptFileIn[26], pszCryptFileIn[27],
//ha//                     pszCryptFileIn[28], pszCryptFileIn[29],
//ha//                     pszCryptFileIn[30], pszCryptFileIn[31]);
//ha// SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)szCountBuf); // Show MAC bytes
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(_KeyDebugBuf, "dwKeyFileSize = %i\n_keylength = %i\n((dwKeyFileSize*8) %% 64) = %i", dwKeyFileSize, _keylength, ((dwKeyFileSize*8) % 64));
//ha//MessageBoxA(NULL, _KeyDebugBuf, "DispayKeyFileHex STOP 1", MB_OK); // Show MAC bytes
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "KeyFile_In[ 0]= %08X %08X %08X %08X\nKeyFile_In[ 4]= %08X %08X %08X %08X\n"
//ha//                  "KeyFile_In[ 8]= %08X %08X %08X %08X\nKeyFile_In[12]= %08X %08X %08X %08X\n"
//ha//                  "KeyFile_In[16]= %08X %08X %08X %08X\nKeyFile_In[20]= %08X %08X %08X %08X\n"
//ha//                  "KeyFile_In[23]= %08X %08X %08X %08X\nKeyFile_In[28]= %08X %08X %08X %08X\n"
//ha//                  "KeyFile_In=%s\nszKeyFileIn=%s\ndwKeyFileSize=%i",
//ha//                 KeyFile_In[0],  KeyFile_In[1], 
//ha//                 KeyFile_In[2],  KeyFile_In[3],
//ha//                 KeyFile_In[4],  KeyFile_In[5], 
//ha//                 KeyFile_In[6],  KeyFile_In[7],
//ha//                 KeyFile_In[8],  KeyFile_In[9], 
//ha//                 KeyFile_In[10], KeyFile_In[11],
//ha//                 KeyFile_In[12], KeyFile_In[13],
//ha//                 KeyFile_In[14], KeyFile_In[15],
//ha//                 KeyFile_In[16], KeyFile_In[17], 
//ha//                 KeyFile_In[18], KeyFile_In[19],
//ha//                 KeyFile_In[20], KeyFile_In[21], 
//ha//                 KeyFile_In[22], KeyFile_In[23],
//ha//                 KeyFile_In[24], KeyFile_In[25], 
//ha//                 KeyFile_In[26], KeyFile_In[27],
//ha//                 KeyFile_In[28], KeyFile_In[29],
//ha//                 KeyFile_In[30], KeyFile_In[31], KeyFile_In, szKeyFileIn, dwKeyFileSize);
//ha//MessageBoxA(NULL, DebugBuf, "haCryptFileK", MB_OK); // Show MAC bytes
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "KeyFile[ 0]= [%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X]\n"
//ha//                  "KeyFile[16]= [%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X]\n\nszKeyFileIn=%s\ndwKeyFileSize = %i",
//ha//                 (UCHAR)KeyFile[0],  (UCHAR)KeyFile[1], 
//ha//                 (UCHAR)KeyFile[2],  (UCHAR)KeyFile[3],
//ha//                 (UCHAR)KeyFile[4],  (UCHAR)KeyFile[5], 
//ha//                 (UCHAR)KeyFile[6],  (UCHAR)KeyFile[7],
//ha//                 (UCHAR)KeyFile[8],  (UCHAR)KeyFile[9], 
//ha//                 (UCHAR)KeyFile[10], (UCHAR)KeyFile[11],
//ha//                 (UCHAR)KeyFile[12], (UCHAR)KeyFile[13],
//ha//                 (UCHAR)KeyFile[14], (UCHAR)KeyFile[15],
//ha//                 (UCHAR)KeyFile[16], (UCHAR)KeyFile[17], 
//ha//                 (UCHAR)KeyFile[18], (UCHAR)KeyFile[19],
//ha//                 (UCHAR)KeyFile[20], (UCHAR)KeyFile[21], 
//ha//                 (UCHAR)KeyFile[22], (UCHAR)KeyFile[23],
//ha//                 (UCHAR)KeyFile[24], (UCHAR)KeyFile[25], 
//ha//                 (UCHAR)KeyFile[26], (UCHAR)KeyFile[27],
//ha//                 (UCHAR)KeyFile[28], (UCHAR)KeyFile[29],
//ha//                 (UCHAR)KeyFile[30], (UCHAR)KeyFile[31], szKeyFileIn, dwKeyFileSize);
//ha//MessageBoxA(NULL, DebugBuf, "STOP 1", MB_OK); // Show MAC bytes
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

