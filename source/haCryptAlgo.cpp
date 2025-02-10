// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptAlgo.cpp - C++ Developer source file.
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

char szCryptDisplayInfo[] = "\r\n---The displayed text is truncated.---";

                                          // Default file extensions for multiple file mode
TCHAR szFileExtensionAe[20] = _T(".A_e"); // (".A_d") (".A~e")(".A~d") (".A°e")(".A°d") (".A~m")
TCHAR szFileExtensionDe[20] = _T(".D_e"); // (".D_d") (".D~e")(".D~d") (".D°e")(".D°d") (".D~m")
TCHAR szFileExtension3e[20] = _T(".3_e"); // (".3_d") (".3~e")(".3~d") (".3°e")(".3°d") (".3~m")
TCHAR szFileExtension[20];                // Must init 'szFileExtension' (re-loading later)

TCHAR* pszTxtAesMAC = TEXT("MAC = [%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c]"); // Rendered as 16 bytes Hex "Text"
TCHAR* pszTxtDesMAC = TEXT("MAC = [%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c]");                                 // Rendered as  8 bytes Hex "Text"

TCHAR* pszTxtE = TEXT("%lu bytes encrypted.");
TCHAR* pszTxtD = TEXT("%lu bytes deciphered.");

TCHAR* pszCryptL = TEXT("%s %s loading... (%d%%)");
TCHAR* pszCryptS = TEXT("%s %s saving... (%d%%)");
TCHAR* pszCryptA;            // Crypto algo text (DES, AES, 3DES)
TCHAR* pszCryptAM;           // Crypto algo mode text (ECB, CBC)
TCHAR* pszCryptM;            // Crypto mode text (/ENCRYPT, /DECIPHER, /MAC, ...)

int dfltFlag;

// External variables
extern TCHAR* pszCountBuf;   // Temporary buffer for formatted text
extern int szCountBufsize;

extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern WPARAM gwCryptContinue;

extern int multiFileFlag, _ProgressbarLL, largeFileFlag, GlobalCryptMode;
extern int _hexMode, _escFlag, _escAbort, textColor;
 
extern ULONG ln, dwFileSize, dwCryptFileSize;
extern ULONG FileProcessingMode, CryptoProcessingMode, FileProcessingModeContinue;

extern LPSTR pszCryptFileIn, pszCryptFileOut, pszCryptFileDisplay;
extern LPSTR pszHexTxtFileIn;

extern char* pszKeyBuffer;   // Key buffer (max key length for AES = 256 bits)
extern char* pszIcvBuffer;   // IV buffer (max key length for AES = 256 bits)

extern HWND hStatusbar;
extern HWND hButtonHex;
extern HWND hEdit;
extern HWND hMain;

// External functions declaration
extern void WindowsDoAlgorithmStealECB(LPSTR, LPSTR, int); // Single ioblock method
extern void WindowsDoAlgorithmStealCBCE(LPSTR, LPSTR, LPSTR, LPSTR);
extern void WindowsDoAlgorithmStealCBCD(LPSTR, LPSTR, LPSTR, LPSTR);
extern void WindowsDoAlgorithmIsoECB(LPSTR, LPSTR, LPSTR, int);
extern void WindowsDoAlgorithmIsoCBCE(LPSTR, LPSTR, LPSTR, LPSTR);
extern void WindowsDoAlgorithmIsoCBCD(LPSTR, LPSTR, LPSTR, LPSTR);
extern void WindowsDoAlgorithmMac(LPSTR, LPSTR, LPSTR, LPSTR);

extern void InitProgressbar(ULONG);
extern void DestroyProgressbar();
extern void PaintColoredStatusProgressMsg(TCHAR*);
extern void CtrlHideShowWindow(HWND, int);

// Forward declarations
void DisplayMacStatusbar();

//--------------------------------------------------------------------------
//
//                              asc2hex
//
unsigned char asc2hex(unsigned char *asc_str)
  {
  unsigned char _c;

  _c = toupper(*asc_str);
  if (_c >= '0' && _c <= '9') _c = _c - '0';
  else if (_c >= 'A' && _c <= 'F') _c = _c - '7';
  else _c = 0xFF;
  return (_c);
  }  // asc2hex

//---------------------------------------------------------------------------
//
//                      AscHex2Bin
//
// Example: Converts  "KY RM 33 34 62 61 45 46 35 34"
//          to binary "00 00 03 04 0B 0A 0E 0D 05 04"
//
int AscHex2Bin(char *_inbuf, char *_outbuf, int _bytesrd) 
  {
  char _tmpbuf[2];
  int i, _byteswr =0, j = 0;

  for (i=0; i < _bytesrd; i++)
    {
    if (!j && (_inbuf[i] != ' ')     &&   // Allow SPACE
              (_inbuf[i] != '\x09')  &&   // Allow TAB
              (_inbuf[i] != '\x0D')  &&   // Allow CR
              (_inbuf[i] != '\x0A'))      // Allow LF
      {
      _tmpbuf[0] = (char)asc2hex((unsigned char *)&_inbuf[i]);
      _tmpbuf[1] = (char)asc2hex((unsigned char *)&_inbuf[i+1]);

      if (((unsigned char)_tmpbuf[0] == 0xFF) ||
          ((unsigned char)_tmpbuf[1] == 0xFF))
        return(_ERR);                                      // Indicate illegal char(s)
      else
        _outbuf[_byteswr] = (_tmpbuf[0] <<4) | _tmpbuf[1]; // Build binary

      j = 1;             // OK, set next
      _byteswr++;        // Advance _byteswr
      }
    else j = 0;          // Set skipped
    } // end for
  return (_byteswr); // Adjust _byteswr (advanced one too many)
  } // AscHex2Bin


//-----------------------------------------------------------------------------
//
//                        Bin2Txt
//
// Big Crypt-Files are only partly displayed in the text window ..!
//
void Bin2Txt() 
  {
  DWORD lk, li;

  if (dwFileSize > CRYPT_TEXT_MAXSIZE) lk = CRYPT_TEXT_MAXSIZE; 
  else lk = dwFileSize;

  for (li=0; li<lk; li++)   
    {
    if (pszHexTxtFileIn[li] == 0) pszCryptFileDisplay[li] = ' ';  // Change any 0s into spaces (forces Text Display)
    else pszCryptFileDisplay[li] = pszHexTxtFileIn[li];           // Show part of crypt-algo output
    }
  if (dwFileSize > CRYPT_TEXT_MAXSIZE)
    {   
    // fill in the info text    
    for (li=0; li<sizeof szCryptDisplayInfo; li++)
      pszCryptFileDisplay[lk - sizeof szCryptDisplayInfo+1 + li] = szCryptDisplayInfo[li];
    }
  pszCryptFileDisplay[lk] = 0; // Add null terminator
  } // Bin2Txt


//-----------------------------------------------------------------------------
//
//                        Bin2Hex
//
// Big Crypt-Files are only partly displayed in the text window ..!
//
static const TCHAR HexChars[] = TEXT("0123456789ABCDEF");

void Bin2Hex(int _spaced) 
  {
  DWORD li, lk, dwOffset = 0;
  int i;
  
  if (dwFileSize > CRYPT_TEXT_MAXSIZE) lk = CRYPT_TEXT_MAXSIZE; 
  else lk = dwFileSize;

  for (li = 0; li < lk; li++)
    {
    for (i = 0; ((i<16) && (li<lk)); i++)
      {
      pszCryptFileDisplay[dwOffset++] = HexChars[(pszHexTxtFileIn[li] & 0xF0) >> 4];
      pszCryptFileDisplay[dwOffset++] = HexChars[pszHexTxtFileIn[li] & 0x0F];
      if (_spaced == TRUE) pszCryptFileDisplay[dwOffset++] = TEXT(' ');
      li++;  // Advance index
      }
    li--;    // Adjust index
    pszCryptFileDisplay[dwOffset++] = TEXT('\r');
    pszCryptFileDisplay[dwOffset++] = TEXT('\n');
    }
  if (dwFileSize > CRYPT_TEXT_MAXSIZE)
    {
    // fill in the info text    
    for (li=0; li<sizeof szCryptDisplayInfo; li++)
      pszCryptFileDisplay[dwOffset - sizeof szCryptDisplayInfo+1 + li] = szCryptDisplayInfo[li]; 
    }
  pszCryptFileDisplay[dwOffset] = 0; // Add null terminator 
  } // Bin2Hex


//-----------------------------------------------------------------------------
//
//                        CheckBin2Txt
//
// Check for non-ascii chars in the text field (dectect potential crypto data)
// Checking only the first 4K (= CRYPT_TEXT_MAXSIZE) will do.
//
BOOL CheckBin2Txt(int _mode)
  {
  DWORD lk, li;
  int j = FALSE;

  // Only 1st 256 bytes are tested. Ensures no colored ANSI text display if DECIPHER //ha//
  // (a junk text line appars when scolling into in progbar area,                    //ha//
  //   which will not be recoknized if encryptted (ENCRYPT) data is displayed)       //ha//
  //HA//if (dwFileSize > CRYPT_TEXT_MAXSIZE) lk = CRYPT_TEXT_MAXSIZE;                                                    //ha//
  if (dwFileSize > 256) lk = 256;                                                    //ha//
  else lk = dwFileSize;

  for (li=0; li<lk; li++)   
    {
    //_mode == 1:  Changing any 0s into spaces forces Text Display
    if (_mode == 1)
      {
      if (pszHexTxtFileIn[li] == 0) pszCryptFileDisplay[li] = ' '; 
      else pszCryptFileDisplay[li] = pszHexTxtFileIn[li];
      }

    // Chars < 0x20 and > 0x7F are considered crypto data
    //  (except FF, CR, LF, TAB)
    pszHexTxtFileIn[li] &= 0xFF;
    if (pszHexTxtFileIn[li] < ' '     && 
        (pszHexTxtFileIn[li]  != 0x0C && 
         pszHexTxtFileIn[li]  != 0x0D &&
         pszHexTxtFileIn[li]  != 0x0A &&
         pszHexTxtFileIn[li]  != 0x09 &&
         pszHexTxtFileIn[li]  != 0x19 &&

         // Some pseudo ANSI codes (supporting German keyboard)
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0x80 && // € EUR    
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0xDC && // Ü
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0xFC && // ü    
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0xD6 && // Ö    
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0xF6 && // ö    
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0xC4 && // Ä    
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0xE4 && // ä  
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0xDF && // ß    
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0xA7 && // §    
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0xB0 && // °    
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0xB2 && // ²    
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0xB3 && // ³    
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0xB4 && // ´    
         (UCHAR)pszHexTxtFileIn[li] != (UCHAR)0xB5)   // µ    
       )
      j = TRUE;                        //  Set flag "crypto data" 
    } // end for

  return(j);
  } // CheckBin2Txt


//-----------------------------------------------------------------------------
//
//                           GetCryptoModeText
//
void GetCryptoModeText(int cryptMode)
  {
  int i;

  switch(FileProcessingMode & CRYPT_ALGO_MASK)
    {
    case CRYPT_DES:
      pszCryptA = _T("DES");
      for (i=0; i<=lstrlen(szFileExtensionDe); i++) szFileExtension[i] = szFileExtensionDe[i];
      break;

    case CRYPT_TDES:
      pszCryptA = _T("3DES");
      for (i=0; i<=lstrlen(szFileExtension3e); i++) szFileExtension[i] = szFileExtension3e[i];
      break;

    case CRYPT_AES:
      pszCryptA = _T("AES");
      for (i=0; i<=lstrlen(szFileExtensionAe); i++) szFileExtension[i] = szFileExtensionAe[i];
      break;
    } // end switch

  if ((FileProcessingMode & CRYPT_CBCECB_MASK) == CRYPT_ECB) pszCryptAM = _T("ECB");
  else pszCryptAM = _T("CBC");

  // Preset szFileExtension[3], may be altered depending on 'cryptMode'
  // (just to simplify the cases below)
  szFileExtension[3] = _T('e');
                    
  switch(FileProcessingMode & CRYPT_MODE_MASK)
    {
    case CRYPT_ECB:
      if (cryptMode == DECIPHER)
        {
        pszCryptM = _T("/ECBDECIPHER");
        szFileExtension[3] = _T('d');
        }
      else pszCryptM = _T("/ECBENCRYPT");
      break;

    case CRYPT_CBC:
      szFileExtension[2] = _T('~');
      if (cryptMode == DECIPHER)
        { 
        pszCryptM = _T("/DECIPHER");
        szFileExtension[3] = _T('d');
        }
      else pszCryptM = _T("/ENCRYPT");
      break;

    case CRYPT_ECB | CRYPT_ISO:
    case CRYPT_ECB | CRYPT_PKCS:
      szFileExtension[2] = _T('°');
      if (cryptMode == DECIPHER)
        {
        pszCryptM = _T("/ECBD");
        szFileExtension[3] = _T('d');
        }
      else pszCryptM = _T("/ECBE");
      break;

    case CRYPT_CBC | CRYPT_ISO:
    case CRYPT_CBC | CRYPT_PKCS:
      szFileExtension[2] = _T('°');
      if (cryptMode == DECIPHER)
        {
        pszCryptM = _T("/CBCD");
        szFileExtension[3] = _T('d');
        }
      else pszCryptM = _T("/CBCE");
      break;

    case CRYPT_MAC:
      szFileExtension[2] = _T('~');
      szFileExtension[3] = _T('m');
      pszCryptM = _T("/MAC");
      pszCryptAM = pszCryptM;
      break;

    case FILEMODE_TEXT:
    case FILEMODE_TEXTNEW:
      break;
    } // end switch
  } // GetCryptoModeText


//---------------------------------------------------------------------
//
//                    CryptoAlgorithmfunctions
//
BOOL CryptoAlgorithmFunctions(int cryptMode)
  {
  if ((FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_DES   ||
      (FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_TDES)
    InitProgressbar(DES_BLOCK_SIZE);  // Initialize Progressbar: DES, 3DES
  else
    InitProgressbar(AES_BLOCK_SIZE);  // Initialize Progressbar: AES

  switch(FileProcessingMode)
    {
    // CRYPTO
    case CRYPT_DES  | CRYPT_ECB:              
    case CRYPT_AES  | CRYPT_ECB:              
    case CRYPT_TDES | CRYPT_ECB:              
      WindowsDoAlgorithmStealECB(pszCryptFileIn, pszKeyBuffer, cryptMode); // Single ioblock method
      break;

    case CRYPT_DES  | CRYPT_CBC:
    case CRYPT_AES  | CRYPT_CBC:
    case CRYPT_TDES | CRYPT_CBC:
      if (cryptMode == ENCRYPT)
        WindowsDoAlgorithmStealCBCE(pszCryptFileIn, pszCryptFileOut, pszIcvBuffer, pszKeyBuffer);
      else if (cryptMode == DECIPHER)
        WindowsDoAlgorithmStealCBCD(pszCryptFileIn, pszCryptFileOut, pszIcvBuffer, pszKeyBuffer);
      break;

    case CRYPT_DES  | CRYPT_ECB | CRYPT_ISO:  
    case CRYPT_DES  | CRYPT_ECB | CRYPT_PKCS:
    case CRYPT_AES  | CRYPT_ECB | CRYPT_ISO:  
    case CRYPT_AES  | CRYPT_ECB | CRYPT_PKCS:
    case CRYPT_TDES | CRYPT_ECB | CRYPT_ISO:  
    case CRYPT_TDES | CRYPT_ECB | CRYPT_PKCS:
      WindowsDoAlgorithmIsoECB(pszCryptFileIn, pszCryptFileOut, pszKeyBuffer, cryptMode);
      break;

    case CRYPT_DES  | CRYPT_CBC | CRYPT_ISO:  
    case CRYPT_DES  | CRYPT_CBC | CRYPT_PKCS:
    case CRYPT_AES  | CRYPT_CBC | CRYPT_ISO:  
    case CRYPT_AES  | CRYPT_CBC | CRYPT_PKCS:
    case CRYPT_TDES | CRYPT_CBC | CRYPT_ISO:  
    case CRYPT_TDES | CRYPT_CBC | CRYPT_PKCS:
      if (cryptMode == ENCRYPT)
        WindowsDoAlgorithmIsoCBCE(pszCryptFileIn, pszCryptFileOut, pszIcvBuffer, pszKeyBuffer);
      else if (cryptMode == DECIPHER)
        WindowsDoAlgorithmIsoCBCD(pszCryptFileIn, pszCryptFileOut, pszIcvBuffer, pszKeyBuffer);
      break;

    case CRYPT_AES  | CRYPT_MAC:
      WindowsDoAlgorithmMac(pszCryptFileIn, pszCryptFileOut, pszIcvBuffer, pszKeyBuffer);
      _hexMode = TRUE;                         // Force hex display for MAC
      if (!largeFileFlag) ln = AES_BLOCK_SIZE; // Set MAC size = 1 AES Block
      break;
    case CRYPT_DES  | CRYPT_MAC:
    case CRYPT_TDES | CRYPT_MAC:
      WindowsDoAlgorithmMac(pszCryptFileIn, pszCryptFileOut, pszIcvBuffer, pszKeyBuffer);
      _hexMode = TRUE;                         // Force hex display for MAC
      if (!largeFileFlag) ln = DES_BLOCK_SIZE; // Set MAC size = 1 DES, 3DES Block
      break;

    // TEXT
    case FILEMODE_TEXT:
    case FILEMODE_TEXTNEW:
      break;
    } // end switch(FileProcessingMode)

  // Remove-clear Progressbar 'Loading file'
  // Ensure the correct crypto item remains selected
  DestroyProgressbar();

  // Set the real file size according the crypto functions' output
  // 1) Cipher text stealing: dwfilesize = unchanged
  // 2) ISO Padding:          dwFilesize += additional ISO Padding bytes
  // 3) MAC:                  dwfilesize = 8 bytes DES, 3DES or 16 bytes AES 
  dwFileSize = ln;          // Set the correct dwFileSize = dwCryptFileSize = ln

  if (_escFlag == TRUE)     // Handle ESC-Abort from crypto functions
    {
    DestroyProgressbar();
    return(FALSE);
    }

  if (cryptMode == ENCRYPT)
    StringCbPrintf(pszCountBuf, szCountBufsize, pszTxtE, ln);  // Emit bytes encrypted
  else if (cryptMode == DECIPHER)
    StringCbPrintf(pszCountBuf, szCountBufsize, pszTxtD, ln);  // Emit bytes deciphered

  if (largeFileFlag == TRUE)                    // Green color
    PaintColoredStatusProgressMsg(pszCountBuf); 
  else                                          // Black Color
    SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)pszCountBuf);  

  CryptoProcessingMode = FileProcessingMode;    // Save the currently processed crypto mode

  //--MAC BEGIN----------------------------------------------------------------
  //--MAC BEGIN----------------------------------------------------------------
  if ((FileProcessingMode & CRYPT_MODE_MASK) == CRYPT_MAC && !largeFileFlag)
    DisplayMacStatusbar(); // Display MAC as AsciiHex (non-spaced) on statusbar
  //--MAC END------------------------------------------------------------------
  //--MAC END------------------------------------------------------------------

  // Note: Big Crypto-Files are only partly displayed in the text window ..!!
  if (_hexMode == FALSE) Bin2Txt();            // Display text

  // Display truncated crypto data only if edit field is not occupied (Multifile list, _ProgressbarLL)
  if (multiFileFlag == FALSE && largeFileFlag == FALSE) 
    {
//ha//    textColor = T_GREEN;                   // Green text color in textfield
//ha//    SetFocus (hEdit);                      // Set focus to hEdit
//ha//    SendMessage(hEdit, EM_SETREADONLY, TRUE, 0);  // Disable text field for crypto data edit
    SetWindowTextA(hEdit, NULL);           // Init-clear the Editor text Field

    if ((FileProcessingMode & CRYPT_MODE_MASK) == CRYPT_MAC || (CheckBin2Txt(0) == TRUE))
      {
      textColor = T_GREEN;                   // Green text color in textfield                  //ha//
      SetFocus (hEdit);                      // Set focus to hEdit                             //ha//
      SendMessage(hEdit, EM_SETREADONLY, TRUE, 0);  // Disable text field for crypto data edit //ha//
      SetWindowTextA(hEdit, pszCryptFileDisplay); // Display crypto text or CMAC
      SetFocus (hMain);                      // Deviate focus to hMain                         //ha//
      textColor = FALSE;                     // Reset to black text color                      //ha//
      }
    else
      {
      pszCryptFileIn[dwCryptFileSize] = 0;        // Set zero terminator at end of file
      SetWindowTextA(hEdit, pszCryptFileIn);      // Display plain ascii text
      CtrlHideShowWindow(hButtonHex, SW_HIDE);    // Hide/Disable Hex/Txt Button
      }

//ha//    SetFocus (hMain);                      // Deviate focus to hMain
//ha//    textColor = FALSE;                     // Reset to black text color
    //EnableWindow(hEdit, FALSE); // !!! Not usable. Clears the text field !!!
    //BlockInput(TRUE);           // !!! Not usable. Blocks keyboard & mouse totally !!!
    }

  if (largeFileFlag == FALSE && (CheckBin2Txt(0) == TRUE))
    EnableWindow(hButtonHex, TRUE); // Enable Hex/Txt Button   //_ProgressbarLL

  return(TRUE);
  } // CryptoAlgorithmFunctions


//---------------------------------------------------------------------
//
//                    DisplayMacStatusbar
//
void DisplayMacStatusbar()
  {
  Bin2Hex(FALSE);                          // MAC: 1st - Display hex non-spaced (MAC only)                            
                                           //  (changed again after MAC has been shown)
  // DES & TDES MAC                                  
  if ((FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_DES || // Show 8 bytes MAC (Hex non spaced)
      (FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_TDES)
    {
    dwCryptFileSize = DES_BLOCK_SIZE;      // Force Mac HEX display in text field to DES_BLOCK_SIZE
    StringCbPrintf(pszCountBuf, szCountBufsize, pszTxtDesMAC,            // Hex means 2 chars per byt
                         pszCryptFileDisplay[0], pszCryptFileDisplay[1],   // Byte 1
                         pszCryptFileDisplay[2], pszCryptFileDisplay[3],   // Byte 2
                         pszCryptFileDisplay[4], pszCryptFileDisplay[5],   // Byte 3
                         pszCryptFileDisplay[6], pszCryptFileDisplay[7],   // ...
                         pszCryptFileDisplay[8], pszCryptFileDisplay[9], 
                         pszCryptFileDisplay[10],pszCryptFileDisplay[11],
                         pszCryptFileDisplay[12],pszCryptFileDisplay[13],  // ...
                         pszCryptFileDisplay[14],pszCryptFileDisplay[15]); // Byte 8
    }
  // AES MAC
  else if ((FileProcessingMode & CRYPT_ALGO_MASK) == CRYPT_AES)
    {
    dwCryptFileSize = AES_BLOCK_SIZE;      // Force Mac HEX display in text field to AES_BLOCK_SIZE
    StringCbPrintf(pszCountBuf, szCountBufsize, pszTxtAesMAC,            // Hex means 2 chars per byte
                         pszCryptFileDisplay[0], pszCryptFileDisplay[1],   // Byte 1
                         pszCryptFileDisplay[2], pszCryptFileDisplay[3],   // Byte 2
                         pszCryptFileDisplay[4], pszCryptFileDisplay[5],   // Byte 3
                         pszCryptFileDisplay[6], pszCryptFileDisplay[7],   // ...
                         pszCryptFileDisplay[8], pszCryptFileDisplay[9], 
                         pszCryptFileDisplay[10],pszCryptFileDisplay[11],
                         pszCryptFileDisplay[12],pszCryptFileDisplay[13],
                         pszCryptFileDisplay[14],pszCryptFileDisplay[15],
                         pszCryptFileDisplay[16],pszCryptFileDisplay[17], 
                         pszCryptFileDisplay[18],pszCryptFileDisplay[19],
                         pszCryptFileDisplay[20],pszCryptFileDisplay[21], 
                         pszCryptFileDisplay[22],pszCryptFileDisplay[23],
                         pszCryptFileDisplay[24],pszCryptFileDisplay[25], 
                         pszCryptFileDisplay[26],pszCryptFileDisplay[27],
                         pszCryptFileDisplay[28],pszCryptFileDisplay[29],  // ...
                         pszCryptFileDisplay[30],pszCryptFileDisplay[31]); // Byte 16
    }
  // Show MAC bytes (non-spaced)
  SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)pszCountBuf); 

  Bin2Hex(TRUE);                                // MAC: 2nd - Display hex spaced (default)
  if (multiFileFlag == FALSE && !largeFileFlag) // Display only if Edit field not occupied
    {
    SetWindowTextA(hEdit, NULL);                // Init-clear the Text Field
    SetWindowTextA(hEdit, pszCryptFileDisplay); // Change text (after MAC has been shown)
    }
  } // DisplayMacStatusbar()


//---------------------------------------------------------------------
//
//                    DispatchCryptoAlgofunction
//
// Input:  WPARAM gwCryptContinue
//
void DispatchCryptoAlgofunction(LPSTR _iBuf, LPSTR _oBuf, LPSTR _ivBuf, LPSTR _kyBuf)
  {
  dfltFlag = FALSE;

  switch((int)gwCryptContinue)
    {
    // Crypto Menu: DES
    case ID_CRYPTO_DES_ECBENCRYPT:      
      FileProcessingMode = CRYPT_DES | CRYPT_ECB;
      WindowsDoAlgorithmStealECB(_iBuf, _kyBuf, ENCRYPT);  // Single ioblock method
      break;                          
    case ID_CRYPTO_DES_ECBDECIPHER:     
      FileProcessingMode = CRYPT_DES | CRYPT_ECB;
      WindowsDoAlgorithmStealECB(_iBuf, _kyBuf, DECIPHER); // Single ioblock method
      break;                          
    case ID_CRYPTO_DES_ENCRYPT:         
      FileProcessingMode = CRYPT_DES | CRYPT_CBC;
      WindowsDoAlgorithmStealCBCE(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_DES_DECIPHER:        
      FileProcessingMode = CRYPT_DES | CRYPT_CBC;
      WindowsDoAlgorithmStealCBCD(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_DES_ECBE:      
      FileProcessingMode = CRYPT_DES | CRYPT_ECB | CRYPT_ISO;
      WindowsDoAlgorithmIsoECB(_iBuf, _oBuf, _kyBuf, ENCRYPT);
      break;                          
    case ID_CRYPTO_DES_ECBD:      
      FileProcessingMode = CRYPT_DES | CRYPT_ECB | CRYPT_ISO;
      WindowsDoAlgorithmIsoECB(_iBuf, _oBuf, _kyBuf, DECIPHER);
      break;                          
    case ID_CRYPTO_DES_CBCE:      
      FileProcessingMode = CRYPT_DES | CRYPT_CBC | CRYPT_ISO;
      WindowsDoAlgorithmIsoCBCE(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_DES_CBCD:      
      FileProcessingMode = CRYPT_DES | CRYPT_CBC | CRYPT_ISO;
      WindowsDoAlgorithmIsoCBCD(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_DES_ECBE_PKCS:     
      FileProcessingMode = CRYPT_DES | CRYPT_ECB | CRYPT_PKCS;
      WindowsDoAlgorithmIsoECB(_iBuf, _oBuf, _kyBuf, ENCRYPT);
      break;                          
    case ID_CRYPTO_DES_ECBD_PKCS:     
      FileProcessingMode = CRYPT_DES | CRYPT_ECB | CRYPT_PKCS;
      WindowsDoAlgorithmIsoECB(_iBuf, _oBuf, _kyBuf, DECIPHER);
      break;                          
    case ID_CRYPTO_DES_CBCE_PKCS:     
      FileProcessingMode = CRYPT_DES | CRYPT_CBC | CRYPT_PKCS;
      WindowsDoAlgorithmIsoCBCE(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_DES_CBCD_PKCS:     
      FileProcessingMode = CRYPT_DES | CRYPT_CBC | CRYPT_PKCS;
      WindowsDoAlgorithmIsoCBCD(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_DES_MAC:     
      FileProcessingMode = CRYPT_DES | CRYPT_MAC;
      WindowsDoAlgorithmMac(_iBuf, _oBuf, _ivBuf, _kyBuf);
      if (!largeFileFlag) ln = DES_BLOCK_SIZE; // Set MAC size = 1 Block
      break;                          

    // Crypto Menu: 3DES
    case ID_CRYPTO_TDES_ECBENCRYPT:     
      FileProcessingMode = CRYPT_TDES | CRYPT_ECB;
      WindowsDoAlgorithmStealECB(_iBuf, _kyBuf, ENCRYPT);  // Single ioblock method
      break;                          
    case ID_CRYPTO_TDES_ECBDECIPHER:      
      FileProcessingMode = CRYPT_TDES | CRYPT_ECB;
      WindowsDoAlgorithmStealECB(_iBuf, _kyBuf, DECIPHER); // Single ioblock method
      break;                          
    case ID_CRYPTO_TDES_ENCRYPT:          
      FileProcessingMode = CRYPT_TDES | CRYPT_CBC;
      WindowsDoAlgorithmStealCBCE(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_TDES_DECIPHER:       
      FileProcessingMode = CRYPT_TDES | CRYPT_CBC;
      WindowsDoAlgorithmStealCBCD(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_TDES_ECBE:     
      FileProcessingMode = CRYPT_TDES | CRYPT_ECB | CRYPT_ISO;
      WindowsDoAlgorithmIsoECB(_iBuf, _oBuf, _kyBuf, ENCRYPT);
      break;                          
    case ID_CRYPTO_TDES_ECBD:     
      FileProcessingMode = CRYPT_TDES | CRYPT_ECB | CRYPT_ISO;
      WindowsDoAlgorithmIsoECB(_iBuf, _oBuf, _kyBuf, DECIPHER);
      break;                          
    case ID_CRYPTO_TDES_CBCE:     
      FileProcessingMode = CRYPT_TDES | CRYPT_CBC | CRYPT_ISO;
      WindowsDoAlgorithmIsoCBCE(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_TDES_CBCD:     
      FileProcessingMode = CRYPT_TDES | CRYPT_CBC | CRYPT_ISO;
      WindowsDoAlgorithmIsoCBCD(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_TDES_ECBE_PKCS:      
      FileProcessingMode = CRYPT_TDES | CRYPT_ECB | CRYPT_PKCS;
      WindowsDoAlgorithmIsoECB(_iBuf, _oBuf, _kyBuf, ENCRYPT);
      break;                          
    case ID_CRYPTO_TDES_ECBD_PKCS:      
      FileProcessingMode = CRYPT_TDES | CRYPT_ECB | CRYPT_PKCS;
      WindowsDoAlgorithmIsoECB(_iBuf, _oBuf, _kyBuf, DECIPHER);
      break;                          
    case ID_CRYPTO_TDES_CBCE_PKCS:      
      FileProcessingMode = CRYPT_TDES | CRYPT_CBC | CRYPT_PKCS;
      WindowsDoAlgorithmIsoCBCE(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_TDES_CBCD_PKCS:      
      FileProcessingMode = CRYPT_TDES | CRYPT_CBC | CRYPT_PKCS;
      WindowsDoAlgorithmIsoCBCD(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_TDES_MAC:      
      FileProcessingMode = CRYPT_TDES | CRYPT_MAC;
      WindowsDoAlgorithmMac(_iBuf, _oBuf, _ivBuf, _kyBuf);
      if (!largeFileFlag) ln = TDES_BLOCK_SIZE; // Set MAC size = 1 Block
      break;                          

    // Crypto Menu: AES
    case ID_CRYPTO_AES_ECBENCRYPT:          
      FileProcessingMode = CRYPT_AES | CRYPT_ECB;
      WindowsDoAlgorithmStealECB(_iBuf, _kyBuf, ENCRYPT);   // Single ioblock method
      break;                          
    case ID_CRYPTO_AES_ECBDECIPHER:       
      FileProcessingMode = CRYPT_AES | CRYPT_ECB;
      WindowsDoAlgorithmStealECB(_iBuf, _kyBuf, DECIPHER);  // Single ioblock method
      break;                          
    case ID_CRYPTO_AES_ENCRYPT:         
      FileProcessingMode = CRYPT_AES | CRYPT_CBC;
      WindowsDoAlgorithmStealCBCE(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_AES_DECIPHER:        
      FileProcessingMode = CRYPT_AES | CRYPT_CBC;
      WindowsDoAlgorithmStealCBCD(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_AES_ECBE:      
      FileProcessingMode = CRYPT_AES | CRYPT_ECB | CRYPT_ISO;
      WindowsDoAlgorithmIsoECB(_iBuf, _oBuf, _kyBuf, ENCRYPT);
      break;                          
    case ID_CRYPTO_AES_ECBD:      
      FileProcessingMode = CRYPT_AES | CRYPT_ECB | CRYPT_ISO;
      WindowsDoAlgorithmIsoECB(_iBuf, _oBuf, _kyBuf, DECIPHER);
      break;                          
    case ID_CRYPTO_AES_CBCE:      
      FileProcessingMode = CRYPT_AES | CRYPT_CBC | CRYPT_ISO;
      WindowsDoAlgorithmIsoCBCE(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_AES_CBCD:      
      FileProcessingMode = CRYPT_AES | CRYPT_CBC | CRYPT_ISO;
      WindowsDoAlgorithmIsoCBCD(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_AES_ECBE_PKCS:     
      FileProcessingMode = CRYPT_AES | CRYPT_ECB | CRYPT_PKCS;
      WindowsDoAlgorithmIsoECB(_iBuf, _oBuf, _kyBuf, ENCRYPT);
      break;                          
    case ID_CRYPTO_AES_ECBD_PKCS:     
      FileProcessingMode = CRYPT_AES | CRYPT_ECB | CRYPT_PKCS;
      WindowsDoAlgorithmIsoECB(_iBuf, _oBuf, _kyBuf, DECIPHER);
      break;                          
    case ID_CRYPTO_AES_CBCE_PKCS:     
      FileProcessingMode = CRYPT_AES | CRYPT_CBC | CRYPT_PKCS;
      WindowsDoAlgorithmIsoCBCE(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_AES_CBCD_PKCS:     
      FileProcessingMode = CRYPT_AES | CRYPT_CBC | CRYPT_PKCS;
      WindowsDoAlgorithmIsoCBCD(_iBuf, _oBuf, _ivBuf, _kyBuf);
      break;                          
    case ID_CRYPTO_AES_MAC:     
      FileProcessingMode = CRYPT_AES | CRYPT_MAC;
      WindowsDoAlgorithmMac(_iBuf, _oBuf, _ivBuf, _kyBuf);
      if (!largeFileFlag) ln = AES_BLOCK_SIZE; // Set MAC size = 1 Block
      break;
    default:
      dfltFlag = TRUE;
      break;
    } // end switch

  } // DispatchCryptoAlgofunction


//--------------------------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "inblock = %02X %02X %02X %02X %02X %02X %02X %02X\noutblock = %02X %02X %02X %02X %02X %02X %02X %02X ",
//ha//                  (UCHAR)pszCryptFileIn[0],(UCHAR)pszCryptFileIn[1],(UCHAR)pszCryptFileIn[2],(UCHAR)pszCryptFileIn[3],
//ha//                  (UCHAR)pszCryptFileIn[4],(UCHAR)pszCryptFileIn[5],(UCHAR)pszCryptFileIn[6],(UCHAR)pszCryptFileIn[7], 
//ha//                  (UCHAR)pszCryptFileOut[0],(UCHAR)pszCryptFileOut[1],(UCHAR)pszCryptFileOut[2],(UCHAR)pszCryptFileOut[+3],
//ha//                  (UCHAR)pszCryptFileOut[4],(UCHAR)pszCryptFileOut[5],(UCHAR)pszCryptFileOut[6],(UCHAR)pszCryptFileOut[+7]); 
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG DES MAC ioblock[i]", MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------Dlk+i+EBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("FileProcessingMode = %08X\ncryptMode = %i\n(ENCRYPT=%i, DECIPHER=%i)\nszFileExtension = %s"), 
//ha//               FileProcessingMode, cryptMode, ENCRYPT, DECIPHER, szFileExtension);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG 2 haCryptAlgo GetCryptoModeText"), MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

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

