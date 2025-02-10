// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptAlgoRsa.cpp - C++ Developer source file.
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

// RSA Algorithm provided to securely sending symmetric keys for DES/AES/3DES 
//
//  ---------------------------------------------------------------------------
// |                Copyright (c)2022  Helmut Altmann                          |
//  ---------------------------------------------------------------------------
//  
//******************************************************************************

#include <string>      // sprintf, etc.

#include <windows.h>
#include <shlwapi.h>   // Library shlwapi.lib for PathFileExistsA
#include <commctrl.h>  // Library Comctl32.lib
#include <winuser.h>
#include <commdlg.h>
#include <tchar.h>

#include <sys\stat.h>  // For _open( , , S_IWRITE) needed for VC 2010
#include <stdlib.h>
#include <strsafe.h>   // <strsafe.h> must be included after <tchar.h>
#include <time.h>
//#include <shlobj.h>

#ifdef x64 // 64 bit (Visual Studio 2019)
  #include <Stringapiset.h>  // Winnls.h
#else      // 32 bit (Visual Studio 2010)
  #include <Winnls.h>        // Stringapiset.h
#endif
      
#include "haCrypt.h"
#include "RSAbigIntegerC.h"
#include "RSAfuncC.h"

using namespace std;

//-----------------------------------------------------------------------------
//
#define UCHAR unsigned char
#define UINT unsigned int
#define ULONG unsigned long int

extern BOOL CheckEscapeAbort();
extern void PaintColoredStatusMsg(TCHAR*);

extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern HWND hMain;
extern HWND hEdit;
extern HWND hStatusbar;
extern TCHAR szStatusClear[];

extern int i, j, bytesrd;
extern unsigned long lk, ln;

//-------------------------------------------------------------------------------
//
//                                RSA
//
TCHAR* pszRsaFileExtensionFilter = _T(" Text & Crypto Files (.txt .d* .a* .3* .m*)\0 \
*.txt;*.d*;*.a*;*.3*;*.b*;*.m*;*.#*\0 \
All files and shortcut targets (*.*)\0*.*\0\0"); //All Files\0*.*\0\0

unsigned __int64 recoursionCnt;

int rsaWordCount;
int pubKeyFlag=FALSE, prvKeyFlag=FALSE, keypairGenFlag=FALSE;   // Must stay here in place (64 bit buffer overrun ???) 

char szRsaPubbufN[2*RSA_BLOCK_SIZE];      // 32 bytes (8 dwords, 8*sizeof(int))
int szRsaPubbufNSize = sizeof szRsaPubbufN;

char szRsaPubbufE[2*RSA_BLOCK_SIZE];      // Using 32 bytes (actually only 1 word, sizeof(int))
int szRsaPubbufESize = sizeof szRsaPubbufE;

char szRsaPubKey[sizeof(szRsaPubbufN) + sizeof(int)]; 
int szRsaPubKeySize = sizeof szRsaPubKey; // Actually 36 bytes (9 dwords, 9*sizeof(int))
char* pszRsaPubKey = szRsaPubKey;

char szRsaPrvbufN[2*RSA_BLOCK_SIZE];      // 32 bytes (8 dwords, 8*sizeof(int))
int szRsaPrvbufNSize = sizeof szRsaPrvbufN;

char szRsaPrvbufD[2*RSA_BLOCK_SIZE];      // 32 bytes (8 dwords, 8*sizeof(int))
int szRsaPrvbufDSize = sizeof szRsaPrvbufD;

char szRsaPrvKey[sizeof(szRsaPrvbufN) + sizeof(szRsaPrvbufD)];  
int szRsaPrvKeySize = sizeof szRsaPrvKey; // 64 bytes (16 dwords, 16*sizeof(int))
char* pszRsaPrvKey = szRsaPrvKey;
//
char szRsaPadbuf[RSA_BUFFER_SIZE];        // 512 bytes (128 dwords, 128*sizeof(int))
int szRsaPadbufSize = sizeof szRsaPadbuf;
char* pszRsaPadbuf = szRsaPadbuf;

int szRsaTempbuf[2*RSA_BUFFER_SIZE];      // For temporary usage

char szRsaDatabuf[2*RSA_BUFFER_SIZE];     // 1024 bytes (256 dwords, 256*sizeof(int))
int szRsaDatabufSize = sizeof szRsaDatabuf;
char* pszRsaDatabuf = szRsaDatabuf;

char szRsaData[2*RSA_BUFFER_SIZE];        // 1024 bytes (256 dwords, 256*sizeof(int))
int szRsaDataSize = sizeof szRsaData;
char* pszRsaData = szRsaData;

char szRsabuf[2*RSA_BUFFER_SIZE];         // 1024 bytes (256 dwords, 256*sizeof(int))
int szRsabufSize = sizeof szRsabuf;
char* pszRsabuf = szRsabuf;               // Publicly used in 'rsabiginteger.cpp'

TCHAR szFileNamePub[MAX_PATH+1] = _T(""); // Recently imported public key file
TCHAR szFileNamePrv[MAX_PATH+1] = _T(""); // Recently loaded private key file

// Externals
extern TCHAR szErrorFileSizeRSA[];

extern int CBTMessageBox(HWND, LPCTSTR, LPCTSTR, UINT);             // Centered Messagebox within parent window
extern int CBTCustomMessageBox(HWND, LPCTSTR, LPCTSTR, UINT, UINT); // Centered CustomMessagebox within parent window
//ha//extern int CustomMessageBox(HWND, LPCTSTR, LPCTSTR, UINT, UINT);    // Normal CustomMessagebox

extern void DisplayLastError(int);
extern void GetHomeDirectory();
extern void PaddingRsaData(char*, int);
extern BOOL ReadRsaData(HWND, LPTSTR, int); 

void DoRsaSave(HWND, char*, int, int);

RSAfunc rsa(RSA_BUFFER_SIZE);          // Global class object (single instance)
BigInteger inblock(RSA_BUFFER_SIZE);   // Global class object (single instance)
BigInteger outblock(RSA_BUFFER_SIZE);  // Global class object (single instance)


//-----------------------------------------------------------------------------
//
//                    AnsiToUnicode
//
// Windows Western European codepage = 1252 (instead of CP_UTF8)
//
TCHAR lpUnicode[8*RSA_BUFFER_SIZE];

TCHAR* AnsiToUnicode(char* lpszStr, int _szStrSize)
  {
  char _sztempStr[2*RSA_BUFFER_SIZE];
  int i, nLen;
  
  for (i=0; i<8*RSA_BUFFER_SIZE; i++) lpUnicode[i] = 0;     // Init clear

  // Init non-destructive temporary buffer
  for (i=0; i<_szStrSize; i++) _sztempStr[i] = lpszStr[i];  
  
  // Just to make it displayable
  for (i=0; i<_szStrSize; i++)
    {
    if (_sztempStr[i] == 0) _sztempStr[i] = ' ';
    }

  // Windows Western European codepage = 1252 (instead of CP_UTF8)
  nLen = MultiByteToWideChar(1252, MB_PRECOMPOSED, _sztempStr, _szStrSize, NULL, 0);
  if (nLen == 0) return NULL;

  nLen = MultiByteToWideChar(1252, MB_PRECOMPOSED, _sztempStr, _szStrSize, lpUnicode, nLen);
  if (nLen == 0) return NULL;

  return lpUnicode;
  } // AnsiToUnicode

//-----------------------------------------------------------------------------
//
//                    editTextField()
//
void editTextField(TCHAR* _string)
  {
  SetFocus (hEdit);                                             // Set focus
  int index = GetWindowTextLength(hEdit);
  SendMessage(hEdit, EM_SETSEL, (WPARAM)index, (LPARAM)index);  // Select end of text
  SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)_string);        // Append.
  } // editTextField(TCHAR* _string)

//------------------------------------------------------------------------------
//
//                     PaddingRsaData
//
//  When you use textbook RSA, the public key is (e,N)
//   and the ciphertext of a message m is c = m**e mod N
//  
//  The encryption process of textbook RSA involves no randomness;
//   this causes the problem. It is easy to see that when having
//   m1 = m2 the ciphertexts of them me1 = me2 mod N
//  
//  We asay that textbook RSA insecure since:
//  
//      The encryption of same messages have the same ciphertext
//      The encrypted message is malleable that is
//  
//  Enckpub(2) * c=Enckpub(2) * Enckpub(m) = Enckpub(2*m)
//  So, an attacker can modify the ciphertext and create valid plaintexts.
//
//  Deterministic encryption is not CPA-secure.
//  
//  Insert randomness and format the data in order to see the modification
//  in the ciphertext.
//
//  When using a Padding scheme like PKCS#1 v1.5, one important aspect is that
//    the padding is random, thus differs each time when you encrypt.
//
//  In PKCS#1 v1.5 for RSA, m is padded to
//   x = 0x00 || 0x02 || r || 0x00 || m
//   and the ciphertext is c = x**e mod N instead of m**e mod N.
//   Here r is a long enough random string.
//   Therefore, even having m1 = m2, the ciphertexts of them will be
//   produced over x1 ? x2, thus will look totally different.
//  
//  Of course, the length of r is very important.
//   If it is too short, then there won't be enough randomness
//   and attacks are still possible. In the standard, it rules that.
//  
//  Let N be k bytes long, then m must be = k-11 bytes long.
//   The padded string (x) must be k bytes long.
//  
//  Thus r is of k-3-|m| bytes long (|m| is how many bytes the plaintext m is),
//   which is at least 8 bytes long. However, this may still not be enough.
//   I remember in Kats & Lindell's book, it mentions that r needs to be
//   roughly half the length of N, in order for us to consider RSA CPA secure.
//
void PaddingRsaData(char* _datbuf, int _cnt)
  {
  BigInteger outblock(RSA_BUFFER_SIZE);  // Define class

  // Sets the starting seed value for the pseudorandom number generator.
  // srand() seeds the random-number generator with the current time  
  //  so that the numbers will be different every time we run.  
  srand((unsigned)time(NULL));  
  StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("\0D\x0A")_T("Padding random number = %08X\x0D\x0A"), rand());

  editTextField(_tDebugBuf);
  //ha//rsa.__randomNGeneration(outblock, RSA_BUFFER_SIZE/sizeof(int));   //ha// DEBUG 512/4 = 128 dwords max
  rsa.randomNGeneration(outblock, RSA_BUFFER_SIZE/sizeof(int));           // 512/4 = 128 dwords max
  rsaWordCount = outblock.__getDigits(RSA_MODE_PADDATA, RSA_HIDE_DIGITS); // RSA_SHOW_DIGITS: Debug only

  // Prepare PKCS#1 v1.5 Padding initializer
  // p = 0x00 || 0x02 || r || 0x00
  pszRsaPadbuf[0] = PAD;                      // 0x00                    
  pszRsaPadbuf[1] = RSAPAD;                   // 0x02

  // Store padding rnd into pszRsaData
  // Random number may never contain 0s (i.e. the terminating PAD char)
  for (i=2; i<rsaWordCount*4-2; i++)
    {
    if (pszRsaPadbuf[i] == 0) pszRsaPadbuf[i] |= 0x01; // No 0s allowed in rndNrs 
    }

  int j = 0;
  for (i=RSA_BUFFER_SIZE-_cnt; i < _cnt+RSA_BUFFER_SIZE; i++)
    {
    pszRsaPadbuf[i] = _datbuf[j++];
    }
  // Padding terminator: Zero-indicator just before start of message
  pszRsaPadbuf[RSA_BUFFER_SIZE-_cnt-1] = PAD; // =0x00  

  //DoRsaSave(hMain, pszRsaPadbuf, RSA_MODE_PADDATA, rsaWordCount*sizeof(int)); //ha// DEBUG only
  } // PaddingRsaData

  
//------------------------------------------------------------------------------
//
//                     ReadRsaData
//
BOOL ReadRsaData(HWND _hwnd, LPTSTR lpszFileName, int _mode) 
  {
  TCHAR szLoadedData[] = _T("\x0D\x0ALoaded data:\x0D\x0A");
  int szLoadedDataSize = sizeof(szLoadedData);
  TCHAR szCRLF[] = _T("\x0D\x0A");
  int szCRLFSize = sizeof(szCRLF);
   
  BOOL bSuccess = FALSE;
  DWORD dwRead, fsize;   // bytesrd
  int i;

  // int _wstat64(                       // Check filesize
  //   const wchar_t *path,
  //   struct __stat64 *buffer
  // );
  //_wstat64(lpszFileName, &fstatBuf64); // Usage: UNICODE 
  //fsize64 = fstatBuf64.st_size;        // Usage: Filesize may be > 4Gbyte
  //
  struct __stat64 fstatBuf64;   // Size >= 4Gbyte
  __int64 fsize64;

  // Open the file for reading, and retrieve the size of the file. 
  HANDLE hFile = CreateFile(
    lpszFileName, 
    GENERIC_READ, 
    FILE_SHARE_READ, 
    (LPSECURITY_ATTRIBUTES) NULL, 
    OPEN_EXISTING, 
    FILE_ATTRIBUTE_NORMAL,          
    (HANDLE)NULL); 

  if (hFile != INVALID_HANDLE_VALUE)
    {
    // Read the input file
    // ----------------------
    switch(_mode)
      {
      case RSA_MODE_PUBKEYE:
        if (ReadFile(hFile, pszRsaPubKey, RSA_BUFFER_SIZE, &dwRead, NULL)) bSuccess = dwRead;
        if (dwRead != szRsaPubKeySize)
          {
          DisplayLastError(HA_ERROR_KEY_SIZE_RSA);
          CloseHandle(hFile);
          return FALSE;
          } 
        rsa.loadKey(RSA_MODE_PUBKEYN);                               
        rsa.loadKey(RSA_MODE_PUBKEYE);                               
        rsa.showPublicKey(NULL);
        break;

      case RSA_MODE_PRVKEYD:
        if (ReadFile(hFile, pszRsaPrvKey, RSA_BUFFER_SIZE, &dwRead, NULL)) bSuccess = dwRead;
        if (dwRead != szRsaPrvKeySize)
          {
          DisplayLastError(HA_ERROR_KEY_SIZE_RSA);
          CloseHandle(hFile);
          return FALSE;
          } 
        rsa.loadKey(RSA_MODE_PRVKEYN);                               
        rsa.loadKey(RSA_MODE_PRVKEYD);                               
        rsa.showLodedPrivateKey(NULL);
        break;

      case RSA_MODE_ENCDATA:                     // Encrypt
        // Clear szRsaDatabuf[] from previous operation(s) 512 bytes max
        for (i=0; i<RSA_BUFFER_SIZE; i++) szRsaDatabuf[i] = 0;

        _wstat64(lpszFileName, &fstatBuf64);     // Check valid filesize 
        fsize64 = fstatBuf64.st_size;            // Filesize may be > 4Gbyte

        if (fsize64 > RSA_BUFFER_SIZE - RSA_BLOCK_SIZE) // 496 bytes max (reserve RSA_BLOCK_SIZE for padding)
          {
          StringCbPrintf(_tDebugBuf, _tDebugbufSize, szErrorFileSizeRSA, RSA_BUFFER_SIZE - RSA_BLOCK_SIZE);
          DisplayLastError(_ERR);
          CloseHandle(hFile);
          return FALSE;
          }
        // Read 512 bytes max   
        if (ReadFile(hFile, szRsaDatabuf, RSA_BUFFER_SIZE, &dwRead, NULL)) bSuccess = dwRead;
        else
          {
          DisplayLastError(ERROR_FILE_NOT_FOUND);
          CloseHandle(hFile);
          return FALSE;
          } 
        editTextField(szLoadedData);
        editTextField(_T("["));

        editTextField(AnsiToUnicode(szRsaDatabuf, dwRead));

        editTextField(_T("]"));
        editTextField(szCRLF);
        break;

      case RSA_MODE_DECDATA:                     // Decipher
        // Clear szRsaDatabuf[] from previous operation(s), 1024 bytes max
        for (i=0; i<2*RSA_BUFFER_SIZE; i++) szRsaDatabuf[i] = 0;

        _wstat64(lpszFileName, &fstatBuf64);     // Check valid filesize 
        fsize64 = fstatBuf64.st_size;            // Filesize may be > 4Gbyte

        if (fsize64 > 2*RSA_BUFFER_SIZE)         // 1024 bytes max
          {
          StringCbPrintf(_tDebugBuf, _tDebugbufSize, szErrorFileSizeRSA, RSA_BUFFER_SIZE);
          DisplayLastError(_ERR);
          CloseHandle(hFile);
          return FALSE;
          }
        // Read 1024 bytes max   
        if (ReadFile(hFile, szRsaDatabuf, 2*RSA_BUFFER_SIZE, &dwRead, NULL)) bSuccess = dwRead;
        else
          {
          DisplayLastError(ERROR_FILE_NOT_FOUND);
          CloseHandle(hFile);
          return FALSE;
          } 
        editTextField(szLoadedData);
        editTextField(_T("["));

        editTextField(AnsiToUnicode(szRsaDatabuf, dwRead));

        editTextField(_T("]"));
        editTextField(szCRLF);
        break;

      default:
        break;
      } // end switch

    CloseHandle(hFile);
    } // end if (hfile)
                      
  else DisplayLastError(HA_ERROR_FILE_OPEN);

  return bSuccess;
  } // ReadRsaData


//-----------------------------------------------------------------------------
//
//                     WriteRsaData
//
BOOL WriteRsaData(LPCTSTR pszFileName, char* _rsaDatabuf, int _bytCount)
  {
  BOOL bSuccess = FALSE;
  int __lastErr = ERROR_SUCCESS;   // Assume no errors

  HANDLE hFile = CreateFile(
    pszFileName, 
    GENERIC_WRITE, 
    0, 
    NULL,
    CREATE_ALWAYS, 
    FILE_ATTRIBUTE_NORMAL, 
    NULL);

  if (hFile != INVALID_HANDLE_VALUE)
    {
    DWORD dwWritten;

    // Copy the text of the specified window's title bar (if it has one) into a buffer.
    // Write dwTxtLen (i.e. w/o zero terminator)
    if (WriteFile(hFile, _rsaDatabuf, _bytCount, &dwWritten, NULL)) bSuccess = TRUE;
    else __lastErr = GetLastError();              // Save error code  from 'WriteFile'
    CloseHandle(hFile);
    } // end if(hfile)
 
  else __lastErr = GetLastError();  // Save error code  from 'CreateFile()'
  
  CloseHandle(hFile);
  return bSuccess;
  } // WriteRsaData

//-----------------------------------------------------------------------------
//
//                          RsaLoadData
//
OPENFILENAME datofn={0};            // Global to remember the 'ofn.lpstrInitialDir'

int RsaLoadData(HWND _hwnd, int _mode)
  {
  TCHAR szFileName[MAX_PATH+1] = _T("");
  int bytesrd;
       
  SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); // Clean up statusbar part 0 from 'paint' 
  SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T(""));         // Clear statusbar part 1
  SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)_T(""));         // Clear statusbar part 1

  ZeroMemory(&datofn, sizeof(OPENFILENAME));

  datofn.lStructSize = sizeof(OPENFILENAME);
  datofn.hwndOwner   = _hwnd;
  datofn.lpstrFilter = pszRsaFileExtensionFilter;
  datofn.lpstrFile   = szFileName;
  datofn.nMaxFile    = MAX_PATH;
  datofn.lpstrDefExt = NULL;          // No auto appending any extension
  datofn.lpstrTitle  = NULL;
  datofn.Flags       = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
  
  if (_mode == RSA_MODE_ENCDATA)
    {
    datofn.lpstrTitle  = _T("Open a file");
    SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("RSA /Encrypt"));
    SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)szFileNamePub);  // Display filename
    }
  else if (_mode == RSA_MODE_DECDATA)
    {
    datofn.lpstrTitle  = _T("Open an encrypted file");
    SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("RSA /Decipher"));
    SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)szFileNamePrv);  // Display filename
    }

  if (GetOpenFileName(&datofn))
    {
    if ((bytesrd=ReadRsaData(hEdit, szFileName, _mode)) == FALSE) return(0);  // Read file  
    SetWindowText(hMain, szFileName); // Display filename in mainwindow's title field
    }
  else return 0;

  SendMessage(hStatusbar, SB_SETTEXT, 1, NULL);  // Clear filename
  return(bytesrd);
  } // RsaLoadData


//-----------------------------------------------------------------------------
//
//                          DoRsaLoadKey
//
OPENFILENAME keyofn={0}; // Global to remember the 'ofn.lpstrInitialDir'

void DoRsaLoadKey(HWND _hwnd, int _mode)
  {
  TCHAR szFileName[MAX_PATH+1] = _T("");
  TCHAR* szOpenTitlePub = _T("Import public key");
  TCHAR* szOpenTitlePrv = _T("Load private key");
  int i, bytesrd;
       
  SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); // Clean up statusbar part 0 from 'paint' 
  SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T(""));         // Clear statusbar part 1
  SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)_T(""));         // Clear statusbar part 1

  ZeroMemory(&keyofn, sizeof(OPENFILENAME));

  keyofn.lStructSize = sizeof(OPENFILENAME);
  keyofn.hwndOwner   = _hwnd;
  keyofn.lpstrFilter = pszRsaFileExtensionFilter;
  keyofn.lpstrFile   = szFileName;
  keyofn.nMaxFile    = MAX_PATH;
  keyofn.lpstrDefExt = NULL;      // No auto appending any extension
  keyofn.lpstrTitle  = NULL;
  keyofn.Flags       = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
  
  if (_mode == RSA_MODE_PUBKEYE) keyofn.lpstrTitle = szOpenTitlePub;
  else if (_mode == RSA_MODE_PRVKEYD) keyofn.lpstrTitle = szOpenTitlePrv;

  if (GetOpenFileName(&keyofn))
    {
    if ((bytesrd=ReadRsaData(hEdit, szFileName, _mode)) == FALSE) return;  // Read file 

    else if (_mode == RSA_MODE_PUBKEYE)
      {
      for (i=0; i<MAX_PATH; i++) szFileNamePub[i] = szFileName[i];
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("/RSA %i bytes public key imported"), bytesrd);
      pubKeyFlag=TRUE;
      }

    else if (_mode == RSA_MODE_PRVKEYD)
      {
      for (i=0; i<MAX_PATH; i++) szFileNamePrv[i] = szFileName[i];
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("/RSA %i bytes private key loaded"), bytesrd);
      prvKeyFlag=TRUE;
      }

    SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_tDebugBuf);
    SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)szFileName);            // Display filename read
    }
  } // DoRsaLoadKey


//-----------------------------------------------------------------------------
//
//                            DoRsaSave
//
void DoRsaSave(HWND _hwnd, char* _pszRsabuf, int _rsaMode, int _bytCount)
  {
  TCHAR szWarningFileExists[] =_T("WARNING: Overwrite existing file?\n\n%s\\%s");
  TCHAR szFileName[MAX_PATH] = _T("");
  TCHAR* pszFileName = szFileName;

  TCHAR wzPath[MAX_PATH+1];
  LPWSTR pwzPath = wzPath;

  int msgID;

  SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); // Clean up statusbar part 0 from 'paint' 

  GetCurrentDirectory(MAX_PATH, pwzPath);
  switch(_rsaMode)
    {
    case RSA_MODE_PADDATA:            // Save padded data (debug only)
      pszFileName =_T("#rsaPadData[ ].bin");
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("/RSA Save padded data [ ]\n\n%s\\%s"), pwzPath, pszFileName);
      break;
  
    case RSA_MODE_KEYDATA:            // Save random key
      StringCbPrintf(pszFileName, MAX_PATH+1, _T("#rsaRandomKey[%i].bin"), rsaWordCount*2*RSA_BLOCK_SIZE);
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%s\\%s"), pwzPath, pszFileName);
      if (PathFileExists(_tDebugBuf)) // Checking for file existence (=1, TRUE)
        StringCbPrintf(_tDebugBuf, _tDebugbufSize, szWarningFileExists, pwzPath, pszFileName);
      else
        StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("/RSA Save random key [%i]\n\n%s\\%s"),
                                                      rsaWordCount*2*RSA_BLOCK_SIZE, pwzPath, pszFileName);
      break;

    case RSA_MODE_ENCDATA:            // Save encrypted data
      pszFileName =_T("#rsaEncData[ ].bin");
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%s\\%s"), pwzPath, pszFileName);
      if (PathFileExists(_tDebugBuf)) // Checking for file existence (=1, TRUE)
        StringCbPrintf(_tDebugBuf, _tDebugbufSize, szWarningFileExists, pwzPath, pszFileName);
      else
        StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("/RSA Save encrypted data [ ]\n\n%s\\%s"), pwzPath, pszFileName);
      break;

    case RSA_MODE_DECDATA:            // Save deciphered data
      pszFileName =_T("#rsaDecData[ ].bin");
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%s\\%s"), pwzPath, pszFileName);
      if (PathFileExists(_tDebugBuf)) // Checking for file existence (=1, TRUE)
        StringCbPrintf(_tDebugBuf, _tDebugbufSize, szWarningFileExists, pwzPath, pszFileName);
      else
        StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("/RSA Save deciphered data [ ]\n\n%s\\%s"), pwzPath, pszFileName);
      break;
  
    default:
      return;
    } // end switch

  // Query the user if he/she wants to save the file
  msgID = CBTCustomMessageBox(hMain, _tDebugBuf, pwzPath, MB_YESNO, IDI_HACRYPT_ICON);

  SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/RSA"));
  if (msgID == IDNO) return;
   
  if (!WriteRsaData((LPCTSTR)pszFileName, _pszRsabuf, _bytCount))
    {
    DisplayLastError(HA_ERROR_FILE_WRITE);
    return;
    }
 
  StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("/RSA %i bytes written"), _bytCount);
  SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_tDebugBuf);
  SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)pszFileName);  // Display filename written
  } // DoRsaSave

//-----------------------------------------------------------------------------
//
//                          SaveRsaKeys
//
void SaveRsaKeys(HWND _hwnd)
  {
  TCHAR* pszWarningRsaKeysExists =_T("WARNING: Overwrite the existing RSA key pair?\n\n%s\\%s\n%s\\%s");
  TCHAR* pszFileNamePub          =_T("#rsaPublicKey[N,e].bin");
  TCHAR* pszFileNamePrv          =_T("#rsaPrivateKey[N,d].bin");
  TCHAR* pszFileNamePair         =_T("#PublicKey[N,e].bin + #rsaPrivateKey[N,d].bin");

  TCHAR wzPath[MAX_PATH+1];
  LPWSTR pwzPath = wzPath;
                                                               
  int msgID, _bytCount;

  SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); // Clean up statusbar part 0 from 'paint' 

  GetCurrentDirectory(MAX_PATH, pwzPath);
  StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%s\\%s"), pwzPath, pszFileNamePrv);
  if (PathFileExists(_tDebugBuf)) // Checking for file existence (=1, TRUE)
    StringCbPrintf(_tDebugBuf, _tDebugbufSize, pszWarningRsaKeysExists,
                                               pwzPath, pszFileNamePub, pwzPath, pszFileNamePrv);
  else
    StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("/RSA Save key pair\n\n%s\\%s\n%s\\%s"),
                                                  pwzPath, pszFileNamePub, pwzPath, pszFileNamePrv);

  SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/RSA Save public & private key pair..."));
  msgID = CBTCustomMessageBox(hMain, _tDebugBuf, pwzPath, MB_YESNO, IDI_HACRYPT_ICON);
  if (msgID == IDNO)
    {
    SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/RSA")); 
    SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)szStatusClear);  
    return;
    } 

  int _pubCnt = (1*RSA_SIZE+1) * sizeof(int);   // Convert dword count into number of bytes (=(8+1)*4=36 bytes)
  int _prvCnt = (2*RSA_SIZE)   * sizeof(int);   // 2*8 *4 = 64 bytes
  if (!WriteRsaData((LPCTSTR)pszFileNamePub, pszRsaPubKey, _pubCnt) ||
      !WriteRsaData((LPCTSTR)pszFileNamePrv, pszRsaPrvKey, _prvCnt))
    {
    DisplayLastError(HA_ERROR_FILE_WRITE);
    return;
    }
 
  StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("/RSA %i + %i bytes written"), _pubCnt, _prvCnt);
  SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_tDebugBuf);
  SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)pszFileNamePair);  // Display filename written
  pubKeyFlag = TRUE;
  prvKeyFlag = TRUE;
  } // SaveRsaKeys


//------------------------------------------------------------------------------
//
//                     GenRsaRandomKeyNoZeros
//
// Random keys may not contain 0s (to allow copy & paste within text field)
//
BOOL GenRsaRandomKeyNoZeros(int _keysize)
  {
  RSAfunc rsa(RSA_BUFFER_SIZE);          // Define class
  BigInteger outblock(RSA_BUFFER_SIZE);  // Define class
   
  int _initialRndnr;

  SendMessage(hStatusbar, SB_SETTEXT, 0, NULL);  // Clear statusbar
  SendMessage(hStatusbar, SB_SETTEXT, 1, NULL);

  // Sets the starting seed value for the pseudorandom number generator.
  // srand() seeds the random-number generator with the current time  
  //  so that the numbers will be different every time we run.  
  srand((unsigned)time(NULL));
  _initialRndnr = rand();
    
  rsa.randomNGeneration(outblock, _keysize/(2*RSA_BLOCK_SIZE)); // 128/256 bits
  rsaWordCount = outblock.__getDigits(RSA_MODE_DATA, RSA_HIDE_DIGITS);

  // Random number may not contain 0s (to allow copy & paste within text field)
  for (i=0; i<rsaWordCount*4; i++)
    {
    if (pszRsabuf[i] == 0) return(FALSE);  // Return: Found zeros within random key
    }
  
  // Random key does not contain any zeros and so it is accepted
  StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("Initial random number = %08X\x0D\x0A"), _initialRndnr);
  editTextField(_tDebugBuf);
  editTextField(_T("Random key =\x0D\x0A"));
  rsaWordCount = outblock.__getDigits(RSA_MODE_DATA, RSA_SHOW_DIGITS);
  outblock.showStringA(rsaWordCount * sizeof(int));               

  return(TRUE);
  } // GenRsaRandomKeyNoZeros

//------------------------------------------------------------------------------
//
//                     DoRsaGenRandomKey
//
void DoRsaGenRandomKey(HWND _hwnd, int _keysize)
  {
  SendMessage(hStatusbar, SB_SETTEXT, 0, NULL);  // Clear statusbar
  SendMessage(hStatusbar, SB_SETTEXT, 1, NULL);

  // Repeat until Random key dose not contain any zeros
  while (GenRsaRandomKeyNoZeros(_keysize) == FALSE) ; 

  DoRsaSave(hMain, pszRsabuf, RSA_MODE_KEYDATA, rsaWordCount * sizeof(int));
  } // DoRsaGenRandomKey

//-----------------------------------------------------------------------------
//
//                          DoRsaEncrypt
//
void DoRsaEncrypt(HWND _hwnd)                                                           
  {
  int i, j, _k, bytesrd;

  // Verify current RSA public key used
  if (keypairGenFlag == TRUE && pubKeyFlag == FALSE)
    {
    DisplayLastError(HA_ERROR_KEY_GEN_RSA);
    return;
    }
  if (pubKeyFlag == FALSE)   // Check if a public key has been imported
    {
    DisplayLastError(HA_ERROR_NOPUBKEY_RSA);
    return;
    }

  rsa.showPublicKey(szFileNamePub);      // Display current RSA public key used
  
  // Load a file into 'pszRsaDatabuf' and show as text
  if ((bytesrd=RsaLoadData(_hwnd, RSA_MODE_ENCDATA)) == FALSE) return;
  StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("/RSA Encrypt: %i bytes read"), bytesrd);
  SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_tDebugBuf);

  // RSA PKCS v1.5 random padding
  PaddingRsaData(pszRsaDatabuf, bytesrd); // --> pszRsaPadbuf contains padded data
  editTextField(_T("\x0D\x0A")
                _T("Encrypt (random padding):")
                _T("\x0D\x0A"));

  rsaWordCount = 0; _k = 0;
  for (i=0; i<RSA_BUFFER_SIZE; i += RSA_BLOCK_SIZE)
    {
    // Get 16 bytes from 'pszRsaPadbuf' into 'inblock'
    rsa.__setDigits(inblock, &pszRsaPadbuf[i], RSA_BLOCK_SIZE);

    //int _debug1b = inblock.__getDigits(RSA_MODE_ENCDATAIN, RSA_SHOW_DIGITS);    //ha// DEBUG
    //inblock.showStringA(RSA_BLOCK_SIZE);                                        //ha// DEBUG

    rsa.encryption(inblock, outblock);
    // Here: 'pszRsabuf' contains an encrypted outblock
    //rsaWordCount += outblock.__getDigits(RSA_MODE_ENCDATAOUT, RSA_SHOW_DIGITS); //ha// DEBUG 
    rsaWordCount += outblock.__getDigits(RSA_MODE_ENCDATAOUT, RSA_HIDE_DIGITS);  

    // Show encrypted data block as ANSI chars                                    //ha// DEBUG
    //outblock.showStringA(2*RSA_BLOCK_SIZE);                                     //ha// DEBUG

    // Wait some 50ms to show algo steps (it's too fast otherwise)
    Sleep(50);  
    editTextField(_T("."));              // Show dots only

    // Accumulate encrypted data blocks from 'pszRsabuf' into ' pszRsaData'
    for (j=0; j<2*RSA_BLOCK_SIZE; j++)                         
    pszRsaData[j + _k] = pszRsabuf[j];
    _k += 2*RSA_BLOCK_SIZE;              // 32 bytes/block (output)
    }

  editTextField(_T("\x0D\x0A"));
  editTextField(_T("\x0D\x0A"));         // Add CRLF if shown dots only
  editTextField(_T("Encrypted data:")
                _T("\x0D\x0A")
                _T("["));                // UNICODE

  editTextField(AnsiToUnicode(pszRsaData, _k));  // ANSI -> UNICODE (..important!)

  editTextField(_T("]"));                // UNICODE

  DoRsaSave(hMain, pszRsaData, RSA_MODE_ENCDATA, rsaWordCount * sizeof(int));
  } // DoRsaEncrypt


//-----------------------------------------------------------------------------
//
//                          DoRsaDecipher
//
void DoRsaDecipher(HWND _hwnd)
  {
  int bytesrd, i, j, _k;

  // Verify the RSA private key in use
  if (keypairGenFlag == TRUE && pubKeyFlag == FALSE)
    {
    DisplayLastError(HA_ERROR_KEY_GEN_RSA);
    return;
    }
  if (prvKeyFlag == FALSE)           // Check if the private key is loaded
    {
    DisplayLastError(HA_ERROR_NOPRVKEY_RSA);
    return;
    }
  
  rsa.showLodedPrivateKey(szFileNamePrv);        // Display the RSA private key in use

  // Load a file into 'pszRsaDatabuf' and show as text
  if ((bytesrd = RsaLoadData(_hwnd, RSA_MODE_DECDATA)) == FALSE) return;
  StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("/RSA Decipher: %i bytes read"), bytesrd);
  SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_tDebugBuf);


  // RSA PKCS v1.5 decipher (crypt data with random padding)
  editTextField(_T("\x0D\x0A")_T("Decipher:\x0D\x0A"));

  // IMPORTANT: Init clear BigInteger::outblock.digit[] array
  rsaWordCount = outblock.__getDigits(RSA_MODE_DECDATA, RSA_HIDE_DIGITS);  

  // Initialize loop counters
  rsaWordCount = 0; _k = 0;
  for (i=0; i<2*RSA_BUFFER_SIZE; i += 2*RSA_BLOCK_SIZE)
    {
    // Get 32 bytes from 'pszRsaDatabuf' into 'inblock'
    rsa.__setDigits(inblock, &pszRsaDatabuf[i], 2*RSA_BLOCK_SIZE);

    //int _debug3b = inblock.__getDigits(RSA_MODE_DECDATA, RSA_SHOW_DIGITS);   //ha// DEBUG

    rsa.decryption(inblock, outblock);
    // Here: 'pszRsabuf' contains a deciphered outblock
    //rsaWordCount += outblock.__getDigits(RSA_MODE_DECDATA, RSA_SHOW_DIGITS); //ha// DEBUG 
    rsaWordCount += outblock.__getDigits(RSA_MODE_DECDATA, RSA_HIDE_DIGITS);  

    // Show deciphered data block                                              //ha// DEBUG
    //outblock.showStringA(RSA_BLOCK_SIZE); // Show ANSI chars                 //ha// DEBUG
    editTextField(_T("."));                 // Show dots only

    // Accumulate deciphered data blocks from 'pszRsabuf' into ' pszRsaData'
    for (j=0; j<RSA_BLOCK_SIZE; j++)                             
      pszRsaData[j + _k] = pszRsabuf[j];
    _k += RSA_BLOCK_SIZE;                // 16 Bytes/block (output)
    }

  // Check for valid PKCS#1 padding introducer
  if (pszRsaData[0] != PAD || pszRsaData[1] != RSAPAD)
    {
    DisplayLastError(HA_ERROR_KEY_SIZE_RSA);
    return;
    }
  
  // Skip padding and point to the plaintext message   
  for (i=2; i < _k; i++)
    {                                                               
    if (pszRsaData[i] == PAD) break;                             
    }

  editTextField(_T("\x0D\x0A"));
  editTextField(_T("\x0D\x0A"));         // Additional CRLF if shown dots only
  editTextField(_T("Deciphered data:")
                _T("\x0D\x0A")
                _T("["));                // UNICODE

  editTextField(AnsiToUnicode(&pszRsaData[i+1], _k-(i+1))); // ANSI -> UNICODE (..important!)

  editTextField(_T("]"));                // UNICODE

//ha//  SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/RSA Private key"));
//ha//  SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)szFileNamePrv); // Display filename

  DoRsaSave(hMain, &pszRsaData[i+1], RSA_MODE_DECDATA, _k-(i+1));
  } // DoRsaDecipher

//------------------------------------------------------------------------------
//
//                     WindowsDoAlgorithmRSA
//
//  -- ===================
//  -- Main RSA structures
//  -- ===================
//  RSAPublicKey ::= SEQUENCE {
//    modulus INTEGER, -- n
//    publicExponent INTEGER -- e
//    }
//
//  -- Representation of RSA private key with information for the CRT algorithm.
//  --
//  RSAPrivateKey ::= SEQUENCE {
//    version Version,
//    modulus INTEGER, -- n
//    publicExponent INTEGER, -- e
//    privateExponent INTEGER, -- d
//    prime1 INTEGER, -- p
//    prime2 INTEGER, -- q
//    exponent1 INTEGER, -- d mod (p-1)
//    exponent2 INTEGER, -- d mod (q-1)
//    coefficient INTEGER, -- (inverse of q) mod p
//    otherPrimeInfos OtherPrimeInfos OPTIONAL
//    }
//
void WindowsDoAlgorithmRSA()
  {
  char szFoxRaw[] = "The quick brown fox jumped over the lazy dog.";
  int szFoxRawSize = sizeof(szFoxRaw)-1;
  char* pszFoxRaw = szFoxRaw;

  int i, _k, _blockCount=0;

  if ((szFoxRawSize % RSA_BLOCK_SIZE) != 0)
    _blockCount = ((szFoxRawSize+RSA_BLOCK_SIZE)/RSA_BLOCK_SIZE)*RSA_BLOCK_SIZE;

  _blockCount += RSA_BLOCK_SIZE;  // Allow some space for padding

  // Clean up statusbar from 'paint'
  PaintColoredStatusMsg(szStatusClear);
  SendMessage(hStatusbar, SB_SETBKCOLOR, 1, (LPARAM)CLR_DEFAULT); 
  SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)szStatusClear);  

  // Sets the starting seed value for the pseudorandom number generator.
  // srand() seeds the random-number generator with the current time  
  //  so that the numbers will be different every time we run.  
  srand((unsigned)time(NULL));  
  StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("RSA Algorithm keysize = 256 bits\x0D\x0A")
                                             _T("Initial random number = %08X\x0D\x0A"), rand());
  editTextField(_tDebugBuf);

  //--------------------------------------------------------------------
  //
  // Random Prime Number Generation 'p' and 'q'  (128 bits each)
  // RSA key-pair Generation [N,e] and [N,d]     (256 bits each)
  // RSA phi Generation (p-1)*(q-1)              (256 bits)
  //
  BigInteger primeNumberP(RSA_BUFFER_SIZE), primeNumberQ(RSA_BUFFER_SIZE);


  editTextField(_T("Generating: Random Prime Number 'p' ")); // ... done.
  rsa.primeNumberGeneration(primeNumberP, RSA_SIZE/2);       // 128/256 bits

  editTextField(_T("Generating: Random Prime Number 'q' ")); // ... done.
  rsa.primeNumberGeneration(primeNumberQ, RSA_SIZE/2);       // 128/256 bits

  rsa.init(primeNumberP, primeNumberQ);            // phi generation 256 bits

  // At this point: [N, e, d, phi] have been generated.
  // Next: Show and store into pszRsaPubKey[] and pszRsaPrvKey[] for SaveRsaKeys(...)
  rsa.showPublicKey(NULL);                             // Show and store [N, e]
  rsa.showPrivateKey(primeNumberP, primeNumberQ);  // Show and store [N, d, p, q, phi]
  // Save RSA keys (Public/private key pair)
  SaveRsaKeys(hMain); 

  // We generated a new pair of keys, that, however, might no have been saved.
  // If not saved the public/private keys will not be available later on
  // and so they are useless (must check pubKeyFlag/prvKeyFlag for usable keys).
  keypairGenFlag = TRUE;

  //--------------------------------------------------------------------
  //
  // RSA key Verification: Encrypt/Decipher using the generated RSA keys
  // Encrypt with #rsaPublicKey[N,e]:
  //
  editTextField(_T("\x0D\x0A")
                _T("Verification Test (Blocksize = 128 bits)")
                _T("\x0D\x0A"));
  
  editTextField(_T("Plaintext: ["));             // UNICODE
  
  editTextField(AnsiToUnicode(pszFoxRaw, strlen(pszFoxRaw)));

  editTextField(_T("]\x0D\x0A")                  // UNICODE
                _T("\x0D\x0A")
                _T("Encrypt padded plaintext with RSAPublicKey (N,e)")
                _T("\x0D\x0A"));

  // Transfer the test message into 'pszRsaDatabuf'
  for (i=0; i<szFoxRawSize; i++) pszRsaDatabuf[i] = pszFoxRaw[i];
  // RSA PKCS v1.5 random padding
  PaddingRsaData(pszRsaDatabuf, szFoxRawSize); // Result is in pszRsaPadbuf  

  // Patch the test message to fit into the end of 'pszRsaPadbuf'
  int j = 0;
  for (i=_blockCount-szFoxRawSize; i < szFoxRawSize+_blockCount; i++)
    pszRsaPadbuf[i] = pszRsaDatabuf[j++];
  
  // Index to be adjusted according to size of message
  pszRsaPadbuf[_blockCount-szFoxRawSize-1] = PAD; 

  rsaWordCount = 0; _k = 0;
  for (i=0; i<_blockCount; i += RSA_BLOCK_SIZE)
    {
    rsa.__setDigits(inblock, &pszRsaPadbuf[i], RSA_BLOCK_SIZE);  // 16 bytes (input)
    rsa.encryption(inblock, outblock);
    //ha//rsaWordCount += outblock.getDigits(RSA_MODE_ENCDATA, RSA_SHOW_DIGITS);

    rsaWordCount += outblock.__getDigits(RSA_MODE_ENCDATAOUT, RSA_SHOW_DIGITS);
    outblock.showStringA(2*RSA_BLOCK_SIZE);

    for (j=0; j<2*RSA_BLOCK_SIZE; j++) pszRsaData[j + _k] = pszRsabuf[j];
    _k += 2*RSA_BLOCK_SIZE;                                    // 32 bytes (output)
    }
  //DoRsaSave(hMain, pszRsaData, RSA_MODE_ENCDATA, rsaWordCount * sizeof(int));  //ha// DEBUG

  //--------------------------------------------------------------------
  //
  // RSA key Verification: Encrypt/Decipher using the generated RSA keys
  // Decipher with #rsaPrivatecKey[N,d]:
  //
  editTextField(_T("\x0D\x0A")
                _T("Decipher padded crypto data with RSAPrivateKey (N,d)")
                _T("\x0D\x0A"));

  // Transfer the crypto data into 'pszRsaDatabuf'
  for (i=0; i<2*RSA_BUFFER_SIZE; i++) pszRsaDatabuf[i] = szRsaData[i];

  // IMPORTANT: Init clear BigInteger::outblock.digit[] array
  rsaWordCount = outblock.__getDigits(RSA_MODE_DECDATA, RSA_HIDE_DIGITS);  
  
  rsaWordCount = 0; _k = 0;
  for (i=0; i<2*_blockCount; i += 2*RSA_BLOCK_SIZE)
    {
    rsa.__setDigits(inblock, &pszRsaDatabuf[i], 2*RSA_BLOCK_SIZE);   // 32 bytes (input)
    rsa.decryption(inblock, outblock);
    //ha//rsaWordCount += outblock.getDigits(RSA_MODE_DECDATA, RSA_SHOW_DIGITS);
    rsaWordCount += outblock.__getDigits(RSA_MODE_DECDATA, RSA_SHOW_DIGITS);
    outblock.showStringA(RSA_BLOCK_SIZE);

    for (j=0; j<RSA_BLOCK_SIZE; j++) pszRsaData[j + _k] = pszRsabuf[j];                             
    _k += RSA_BLOCK_SIZE;                                          // 16 Bytes (output)
    }

  // Check for valid PKCS#1 padding introducer
  if (pszRsaData[0] != PAD || pszRsaData[1] != RSAPAD)  
    {
    DisplayLastError(HA_ERROR_KEY_SIZE_RSA);
    return;
    }
  
  // Skip padding and extract the deciphered message   
  for (i=2; i < _k; i++)
    {
    if (pszRsaData[i] == PAD) break;  // Message found - break.
    }

  //DoRsaSave(hMain, &pszRsaData[i+1], RSA_MODE_DECDATA, _k-i-1);   //ha// DEBUG
  } // WindowsDoAlgorithmRSA

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha////----------------------------------------------------------------------------------------
//ha////
//ha////                          DEBUG_HEXBUF
//ha////
//ha//void DEBUG_HEXBUF(char* infoStr, char* _debBuf, int _count)
//ha//  {
//ha//  switch(_count)
//ha//    {
//ha//    case 16:
//ha//      sprintf(DebugBuf, "%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n\n \
//ha//%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
//ha//                     (UCHAR)_debBuf[0], (UCHAR)_debBuf[1], (UCHAR)_debBuf[2], (UCHAR)_debBuf[3],
//ha//                     (UCHAR)_debBuf[4], (UCHAR)_debBuf[5], (UCHAR)_debBuf[6], (UCHAR)_debBuf[7], 
//ha//                     (UCHAR)_debBuf[8], (UCHAR)_debBuf[9], (UCHAR)_debBuf[10],(UCHAR)_debBuf[11],
//ha//                     (UCHAR)_debBuf[12],(UCHAR)_debBuf[13],(UCHAR)_debBuf[14],(UCHAR)_debBuf[15],
//ha//                     (UCHAR)_debBuf[0], (UCHAR)_debBuf[1], (UCHAR)_debBuf[2], (UCHAR)_debBuf[3],
//ha//                     (UCHAR)_debBuf[4], (UCHAR)_debBuf[5], (UCHAR)_debBuf[6], (UCHAR)_debBuf[7], 
//ha//                     (UCHAR)_debBuf[8], (UCHAR)_debBuf[9], (UCHAR)_debBuf[10],(UCHAR)_debBuf[11],
//ha//                     (UCHAR)_debBuf[12],(UCHAR)_debBuf[13],(UCHAR)_debBuf[14],(UCHAR)_debBuf[15]);
//ha//      MessageBoxA(NULL, DebugBuf, infoStr, MB_OK);
//ha//      break;
//ha//
//ha//    case 32:
//ha//      sprintf(DebugBuf, " %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n \
//ha//%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n\n \
//ha//%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
//ha//                     (UCHAR)_debBuf[0], (UCHAR)_debBuf[1], (UCHAR)_debBuf[2], (UCHAR)_debBuf[3],
//ha//                     (UCHAR)_debBuf[4], (UCHAR)_debBuf[5], (UCHAR)_debBuf[6], (UCHAR)_debBuf[7], 
//ha//                     (UCHAR)_debBuf[8], (UCHAR)_debBuf[9], (UCHAR)_debBuf[10],(UCHAR)_debBuf[11],
//ha//                     (UCHAR)_debBuf[12],(UCHAR)_debBuf[13],(UCHAR)_debBuf[14],(UCHAR)_debBuf[15],
//ha//                     (UCHAR)_debBuf[16],(UCHAR)_debBuf[17],(UCHAR)_debBuf[18],(UCHAR)_debBuf[19],
//ha//                     (UCHAR)_debBuf[20],(UCHAR)_debBuf[21],(UCHAR)_debBuf[22],(UCHAR)_debBuf[23], 
//ha//                     (UCHAR)_debBuf[24],(UCHAR)_debBuf[25],(UCHAR)_debBuf[26],(UCHAR)_debBuf[27],
//ha//                     (UCHAR)_debBuf[28],(UCHAR)_debBuf[29],(UCHAR)_debBuf[30],(UCHAR)_debBuf[31],
//ha//                     (UCHAR)_debBuf[0], (UCHAR)_debBuf[1], (UCHAR)_debBuf[2], (UCHAR)_debBuf[3],
//ha//                     (UCHAR)_debBuf[4], (UCHAR)_debBuf[5], (UCHAR)_debBuf[6], (UCHAR)_debBuf[7], 
//ha//                     (UCHAR)_debBuf[8], (UCHAR)_debBuf[9], (UCHAR)_debBuf[10],(UCHAR)_debBuf[11],
//ha//                     (UCHAR)_debBuf[12],(UCHAR)_debBuf[13],(UCHAR)_debBuf[14],(UCHAR)_debBuf[15],
//ha//                     (UCHAR)_debBuf[16],(UCHAR)_debBuf[17],(UCHAR)_debBuf[18],(UCHAR)_debBuf[19],
//ha//                     (UCHAR)_debBuf[20],(UCHAR)_debBuf[21],(UCHAR)_debBuf[22],(UCHAR)_debBuf[23], 
//ha//                     (UCHAR)_debBuf[24],(UCHAR)_debBuf[25],(UCHAR)_debBuf[26],(UCHAR)_debBuf[27],
//ha//                     (UCHAR)_debBuf[28],(UCHAR)_debBuf[29],(UCHAR)_debBuf[30],(UCHAR)_debBuf[31]);
//ha//      MessageBoxA(NULL, DebugBuf, infoStr, MB_OK);
//ha//      break;
//ha//
//ha//    default:
//ha//      MessageBoxA(NULL, "Count <> 16", infoStr, MB_OK);
//ha//      break;
//ha//    } // end switch
//ha//  } // DEBUG_HEXBUF
//ha////----------------------------------------------------------------------------------------
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//-----------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, pwzPath);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG STOP Start"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//// Format data into whataever is of interest
//ha//sprintf(DebugBuf,
//ha//                  "pszRsaData = %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n"
//ha//                  "pszRsaData = %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n"
//ha//                  "_datbuf = %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n"
//ha//                  "_datbuf = %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n"
//ha//                  "i = %i  [j = %i]  _cnt=%i\n%s",
//ha//                     (UCHAR)pszRsaData[i+0], (UCHAR)pszRsaData[i+1], (UCHAR)pszRsaData[i+2], (UCHAR)pszRsaData[i+3],
//ha//                     (UCHAR)pszRsaData[i+4], (UCHAR)pszRsaData[i+5], (UCHAR)pszRsaData[i+6], (UCHAR)pszRsaData[i+7], 
//ha//                     (UCHAR)pszRsaData[i+8], (UCHAR)pszRsaData[i+9], (UCHAR)pszRsaData[i+10],(UCHAR)pszRsaData[i+11],
//ha//                     (UCHAR)pszRsaData[i+12],(UCHAR)pszRsaData[i+13],(UCHAR)pszRsaData[i+14],(UCHAR)pszRsaData[i+15],
//ha//                     (UCHAR)pszRsaData[i+16],(UCHAR)pszRsaData[i+17],(UCHAR)pszRsaData[i+18],(UCHAR)pszRsaData[i+19],
//ha//                     (UCHAR)pszRsaData[i+20],(UCHAR)pszRsaData[i+21],(UCHAR)pszRsaData[i+22],(UCHAR)pszRsaData[i+23], 
//ha//                     (UCHAR)pszRsaData[i+24],(UCHAR)pszRsaData[i+25],(UCHAR)pszRsaData[i+26],(UCHAR)pszRsaData[i+27],
//ha//                     (UCHAR)pszRsaData[i+28],(UCHAR)pszRsaData[i+29],(UCHAR)pszRsaData[i+30],(UCHAR)pszRsaData[i+31],
//ha//                     (UCHAR)_datbuf[j+0], (UCHAR)_datbuf[j+1], (UCHAR)_datbuf[j+2], (UCHAR)_datbuf[j+3],
//ha//                     (UCHAR)_datbuf[j+4], (UCHAR)_datbuf[j+5], (UCHAR)_datbuf[j+6], (UCHAR)_datbuf[j+7], 
//ha//                     (UCHAR)_datbuf[j+8], (UCHAR)_datbuf[j+9], (UCHAR)_datbuf[j+10],(UCHAR)_datbuf[j+11],
//ha//                     (UCHAR)_datbuf[j+12],(UCHAR)_datbuf[j+13],(UCHAR)_datbuf[j+14],(UCHAR)_datbuf[j+15],
//ha//                     (UCHAR)_datbuf[j+16],(UCHAR)_datbuf[j+17],(UCHAR)_datbuf[j+18],(UCHAR)_datbuf[j+19],
//ha//                     (UCHAR)_datbuf[j+20],(UCHAR)_datbuf[j+21],(UCHAR)_datbuf[j+22],(UCHAR)_datbuf[j+23], 
//ha//                     (UCHAR)_datbuf[j+24],(UCHAR)_datbuf[j+25],(UCHAR)_datbuf[j+26],(UCHAR)_datbuf[j+27],
//ha//                     (UCHAR)_datbuf[j+28],(UCHAR)_datbuf[j+29],(UCHAR)_datbuf[j+30],(UCHAR)_datbuf[j+31],
//ha//                     i, j, _cnt, _datbuf); 
//ha//// Display data in a message box window
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG 1 pszRsaData", MB_OK);
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
