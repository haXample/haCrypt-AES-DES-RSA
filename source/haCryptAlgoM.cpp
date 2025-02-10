// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptM.cpp - C++ Developer source file.
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

// DES/AES/3DES Symmetric Crypto Algorithm Modes for file encryption
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
#include <strsafe.h>  //  <strsafe.h> must be included after <tchar.h>
#include <time.h>
      
#include "haCrypt.h"
#include "RSAbigIntegerC.h"
#include "RSAfuncC.h"

using namespace std;

//-----------------------------------------------------------------------------
//
#define UCHAR unsigned char
#define UINT unsigned int
#define ULONG unsigned long int

//----------------------------------------------------------------------------
//                          External declarations
//
#ifdef DES_AES_QUICK // DESquick, AESquick (C++)
extern void desAlgorithm(char *, char *);          // C++ Module Interface
extern void desKeyInit(char *, int);               // C++ Module Interface
extern void aesAlgorithm (char*, char*, int);      // C++ Module Interface
extern void aesKeyInit(char*, int, int);           // C++ Module Interface
#else                // DESfast, AESfast (ASM)
extern "C" void desAlgorithm(char*, char*);        // Assembler Module Interface
extern "C" void desKeyInit(char*, int);            // Assembler Module Interface
extern "C" void aesAlgorithm (char*, char*, int);  // Assembler Module Interface
extern "C" void aesKeyInit(char*, int, int);       // Assembler Module Interface
#endif

extern "C" void desAlgorithm2 (char*, char*, int); // Assembler Module Interface
extern "C" void tdesKeyInit2(char*, int, int);     // Assembler Module Interface

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//extern "C" void _aesDebugbufProc(UCHAR *);   // Interface for debugging the ASM-Modules
//ha//UCHAR _asmBuf[64];
//ha//UCHAR * pszAsmBuf = _asmBuf;
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
 
extern void DisplayProgressCount(ULONG, int); // Progressbar and ln count display
extern BOOL CheckEscapeAbort();
extern void PaintColoredStatusMsg(TCHAR*);

extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern int largeFileFlag, _largeFileLastBlock, _escFlag;
extern ULONG FileProcessingMode;
extern DWORD dwCryptFileSize;

extern HWND hMain;
extern HWND hEdit;
extern HWND hStatusbar;
extern TCHAR szStatusClear[];

extern int _keylength, GlobalCryptMode;  // AES default keysize = 128 bits

//----------------------------------------------------------------------------
//                          Global declarations
//
int _algoBlockSize;

//AES_BLOCK_SIZE = Also enough static space for DES, 3DES
char Icvblock[AES_BLOCK_SIZE] = {
  PAD, PAD, PAD, PAD, PAD, PAD, PAD, PAD, \
  PAD, PAD, PAD, PAD, PAD, PAD, PAD, PAD
  }; // Provide space for size of 128bits;

char Lastblock[2*AES_BLOCK_SIZE], LastblockSave[2*AES_BLOCK_SIZE];

char pszFileInbuf[AES_BLOCK_SIZE];
char pszFileOutbuf[AES_BLOCK_SIZE];

char Inbuf1[AES_BLOCK_SIZE], Inbuf2[AES_BLOCK_SIZE];
char Outbuf1[AES_BLOCK_SIZE];

UCHAR szRB128[AES_BLOCK_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x87}; // CMAC AES
UCHAR szRB64[TDES_BLOCK_SIZE] = {0,0,0,0,0,0,0,0x1B};                 // CMAC DES, 3DES
UCHAR* pszRB = szRB128;                                               // Default

int i, j, bytesrd;//, rsaWordCount;
unsigned long lk, ln;

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

//------------------------------------------------------------------------------
//
//                          DoKeyInit
//
//  DES, AES, 3DES 
//               
void DoKeyInit(char* _keybuf, int _keylen, int _cmode)
  {
  switch(FileProcessingMode & CRYPT_ALGO_MASK)
    {
    // Calculate DES key schedule
    case CRYPT_DES:
      _algoBlockSize = DES_BLOCK_SIZE;
      pszRB = szRB64;                   // CMAC DES    
      desKeyInit(_keybuf, _cmode); 
      break;

    // Calculate AES key schedule
    case CRYPT_AES:
      _algoBlockSize = AES_BLOCK_SIZE;
      pszRB = szRB128;                  // CMAC AES
      aesKeyInit(_keybuf, _keylen, _cmode); 
      break;

    // Calculate 3DES key schedule
    case CRYPT_TDES:
      _algoBlockSize = TDES_BLOCK_SIZE;        
      pszRB = szRB64;                   // CMAC 3DES
      switch(_cmode)          
        {
        case ENCRYPT:
          tdesKeyInit2(&_keybuf[0],  ENCRYPT,  1);
          tdesKeyInit2(&_keybuf[8],  DECIPHER, 2);
          tdesKeyInit2(&_keybuf[16], ENCRYPT,  3);
          break;
        case DECIPHER:
          tdesKeyInit2(&_keybuf[16], DECIPHER, 1);
          tdesKeyInit2(&_keybuf[8],  ENCRYPT,  2);
          tdesKeyInit2(&_keybuf[0],  DECIPHER, 3);
          break;
        }
      break;
    } // end switch
  } // DoKeyInit


//------------------------------------------------------------------------------
//
//                          DoCryptoAlgorithm
//
//  DES, AES, 3DES 
//               
void DoCryptoAlgorithm(char _inbuf[], char _outbuf[], int _cmode)
  {
  switch(FileProcessingMode & CRYPT_ALGO_MASK)
    {
    // Perform the DES algorithm
    case CRYPT_DES:
      desAlgorithm(_inbuf, _outbuf);           
      break;

    // Perform the AES algorithm
    case CRYPT_AES:
      aesAlgorithm(_inbuf, _outbuf, _cmode);   
      break;

    // Perform the 3DES algorithm
    case CRYPT_TDES:
      desAlgorithm2(_inbuf, _outbuf, 1);             // 1st step
      for (i=0; i<TDES_BLOCK_SIZE; i++) _inbuf[i] = _outbuf[i];
      desAlgorithm2(_inbuf, _outbuf, 2);             // 2nd step
      for (i=0; i<TDES_BLOCK_SIZE; i++) _inbuf[i] = _outbuf[i];
      desAlgorithm2(_inbuf, _outbuf, 3);             // 3rd step
      break;
    } // end switch
  } // DoCryptoAlgorithm


//-----------------------------------------------------------------------------
//
//                      WindowsDoAlgorithmStealECB
//
//  ENCRYPT/DECIPHER - Electronic Code Book (ciphertext stealing)
//  **Implemented simple i/o-block method: inblock=outblock (one buffer only)**
//
void WindowsDoAlgorithmStealECB(char* _ioblock, char* _keybuf, int _cmode)
  {
  DoKeyInit(_keybuf, _keylength, _cmode); // Calculate key schedule
  
  ln = 0;                       // Init byte counter (seek position in ioblock)
  bytesrd = _algoBlockSize;     // init bytesrd, filesize is at least 8 bytes

  while (ln < dwCryptFileSize)
    {
    // Keep track of bytesrd
    if ((ln+_algoBlockSize) > dwCryptFileSize)
      bytesrd = (int)(dwCryptFileSize % _algoBlockSize);

    // Read external input buffer into local buffer (Read Pi..Pn)
    // infile.read(ioblock, bytesrd);
    for (i = 0; i < bytesrd; i++) pszFileInbuf[i] = _ioblock[ln+i];     

    if (bytesrd >= _algoBlockSize)
      {
      DoCryptoAlgorithm(pszFileInbuf, pszFileOutbuf, _cmode);      // Crypt locally
      // outfile.write(outblock, bytesrd);                         // Write Ci..Cn
      for (i=0; i<bytesrd; i++) _ioblock[ln+i] = pszFileOutbuf[i]; // Write local buffer to external buffer
      }

    // CIPHERTEXT STEALING:
    // We do not want to change filesizes, so we dont use padding.
    // The following special handling of the last block implements
    // "Ciphertext Stealing" if the last block is less than _algoBlockSize.
    // For the last 2 blocks: Des(Pn-1) = Cn||C' and Des(Pn||C') = Cn-1
    //  Note: Pn-1 = Plaintext of _algoBlockSize
    //        Pn = Last plaintext < _algoBlockSize
    //        C' = Ciphertext padded to Pn, stolen from previous block
    //        Cn-1 = New Ciphertext of _algoBlockSize for previous block
    //        Cn = Ciphertext < BLOCKSIZE from previous block, used last.
    //
    // Example: Encrypt Key = 12345678
    //          Pn-1 = 0A 0D 0A 0D 0A 0D 0A 0D   (EF 29 7C 97 61 5B 80 9E)
    //          Pn   = 0A 0D 0A 0D 0A
    //          C'   = 5B 80 9E
    //          Cn-1 = 91 03 D1 32 FA 54 C2 17
    //          Cn   = EF 29 7C 97 61
    //
    //  before: lastblock[] = 00 00 00 00 00 00 00 00 EF 29 7C 97 61 00 00 00
    //          ioblock[]   = 0A 0D 0A 0D 0A 5B 80 9E
    //
    //  after:  lastblock[] = 91 03 D1 32 FA 54 C2 17 EF 29 7C 97 61
    //
    else  // bytesrd < _algoBlockSize
      {
      for (i = 0; i < bytesrd; i++) Lastblock[_algoBlockSize + i] = pszFileOutbuf[i];
      for (i = bytesrd; i < _algoBlockSize; i++) pszFileInbuf[i] = pszFileOutbuf[i];
      DoCryptoAlgorithm(pszFileInbuf, Lastblock, _cmode);
    
      // outfile.seekp(0, ios::end);                         // Seek to the end of the file
      // outfile.seekp(-_algoBlockSize, ios::cur);           // Back up BLOCK_SIZE
      // outfile.write(Lastblock, bytesrd + _algoBlockSize); // Write to external buffer
      for (i = 0; i < bytesrd + _algoBlockSize; i++) _ioblock[ln+i-_algoBlockSize] = Lastblock[i];   
      }

    ln += (ULONG)bytesrd;              // Update counter total bytes read

    // Begin--ESC Abort-------------------------------------------------------------
    // Here we allow to abort reading very lengthy files by pressing the ESC key // |
    if (CheckEscapeAbort() == TRUE) return;                                      // |
    // End----ESC Abort-------------------------------------------------------------

    DisplayProgressCount(ln, 1);       // Display ln counter in KB on statusbar
    } // end while
  } // WindowsDoAlgorithmStealECB


//------------------------------------------------------------------------------
//
//                          WindowsDoAlgorithmStealCBCE
//
//  ENCRYPT - Cipher Block Chaining (Ciphertext Stealing)
//               
void WindowsDoAlgorithmStealCBCE(char* inblock, char* outblock, char* _icvblock, char* _keybuf)
  {
  char* pszInblockSave;
  int ciphStealing = FALSE;

  DoKeyInit(_keybuf, _keylength, ENCRYPT); // Calculate key schedule

  for (i=0; i<_algoBlockSize; i++) Icvblock[i] =_icvblock[i]; // Save icv
  pszInblockSave = inblock;   // Init local pointer to save external file buffer

  ln = 0;
  DWORD lk = 0;
  do
    {
    if (ciphStealing == TRUE) break;             // ciphStealing -break

    // Keep track of bytesrd
    if ((dwCryptFileSize - ln) >= _algoBlockSize) bytesrd = _algoBlockSize;     
    else bytesrd = dwCryptFileSize - ln;                          

    // infile.read(inblock, bytesrd);        
    for (i = 0; i < bytesrd; i++)                // Read Pi..Pn
      {                                          // Read external input buffer
      pszFileInbuf[i] = *inblock;                //  into local buffer
      inblock++;                                 // Advance input buffer pointer
      }
    lk = ln;      // Adjust external write buffer position (outblock index)    

    if (bytesrd >= _algoBlockSize)
      for (i=0; i<_algoBlockSize; i++) pszFileInbuf[i] ^= _icvblock[i]; // CBC: inbuf XOR ICV

    // Ciphertext stealing
    else if (bytesrd < _algoBlockSize)
      {
      for (i = 0; i < _algoBlockSize-bytesrd; i++) pszFileInbuf[i+bytesrd] = PAD; // Pn* = Pn||0s (zero-padded) 
      for (i = 0; i < _algoBlockSize; i++) pszFileInbuf[i] ^= pszFileOutbuf[i];   // Pn* XOR Cn-1*
      for (i = 0; i < _algoBlockSize; i++) Outbuf1[i] = pszFileOutbuf[i];         // save Cn-1

      // CIPHERTEXT STEALING CBC ENCRYPT:
      // We do not want to change filesizes, so we dont use padding.
      // The following special handling of the last block implements
      // "Ciphertext Stealing" if the last block is less than _algoBlockSize.
      // For the last 2 blocks: Aes(Pn-1) = Cn||C' and Aes(Pn||C') = Cn-1
      //  Note: Pn-1      = Previous Plaintext of _algoBlockSize
      //        Pn        = Last plaintext < _algoBlockSize
      //        Pn*       = Last plaintext padded with zeros
      //        Cn-1      = Previous Ciphertext of Pn-1
      //        Cn-1*     = Ciphertext padded to Pn, stolen from previous block
      //        Cn-1(new) = New Ciphertext of _algoBlockSize for previous block
      //        Cn-1**    = Ciphertext < BLOCKSIZE from previous block, used last.
      //
      // Example: Encrypt Key = 12345678
      //          Pn-1   = 0A 0D 0A 0D 0A 0D 0A 0D
      //          Cn-1   = F5 AC DD BE 5F 21 C0 2B
      //          Pn   = 0A 0D 0A 0D 0A
      //          Cn-1*  = 21 C0 2B
      //          Cn-1** = F5 AC DD BE 5F
      //
      // Steps:   Pn* = Pn||0s = 0A 0D 0A 0D 0A 00 00 00  (zero-padded)
      //          Pn* ^ Cn-1   = FF A1 D7 B3 55 21 C0 2B  (inblock to be encrypted
      //          Cn-1(new)    = 72 F6 82 BA DA D8 88 91    yields a new previous Block)
      //          Cn-1**       = F5 AC DD BE 5F           (Lastblock < _algoBlockSize)
      //
      //  before: Lastblock[] = 00 00 00 00 00 00 00 00 F5 AC DD BE 5F 00 00 00
      //          inblock[]   = FF A1 D7 B3 55 21 C0 2B
      //
      //  after:  Lastblock[] = 72 F6 82 BA DA D8 88 91 F5 AC DD BE 5F [Cn-1(new) || Cn-1**]
      //
      ciphStealing = TRUE;
      } // end else if

    // ---------------------------------------------
    // Performing the AES (i.e., Standard Algorithm)
    // ---------------------------------------------
    DoCryptoAlgorithm(pszFileInbuf, pszFileOutbuf, ENCRYPT);
    if (ciphStealing == TRUE)
      {
      // Build the last block(s) [Cn-1(new) || Cn-1**],
      //  where Cn-1(new) consists of the encrypted incomplete block of Pn
      //  and the stolen chunk Cn-1* which has been encrypted twice.
      //
      for (i = 0; i < _algoBlockSize; i++) Lastblock[i] = pszFileOutbuf[i];     // Cn-1(new)
      for (i = 0; i < bytesrd; i++) Lastblock[_algoBlockSize + i] = Outbuf1[i]; // Cn-1**
      }

    ln += (ULONG)bytesrd;                // Update counter total bytes read

    // --------------------------
    // Continue normal processing
    // --------------------------
    if (ciphStealing == FALSE)
      {
      // outfile.write(outblock, bytesrd);                          // Write Ci..Cn
      for (i=0; i<bytesrd; i++) outblock[lk+i] = pszFileOutbuf[i];  // Write Ci..Cn
      for (i=0; i<bytesrd; i++) _icvblock[i] = pszFileOutbuf[i];    // Update ICV
      }

    else if (ciphStealing == TRUE)                     // Special handling for the last 2 blocks   
      {
      // outfile.seekp(0, ios::end);                   // seek to the end of the file
      lk = dwCryptFileSize;                            // Not really needed when using buffer technique
      // outfile.seekp(-_algoBlockSize, ios::cur);     // back up 16 bytes
      lk = dwCryptFileSize - _algoBlockSize - bytesrd; // Back up -(bytesrd + _algoBlockSize)
      // outfile.write(lastblock, bytesrd + _algoBlockSize);
      for (i = 0; i < bytesrd + _algoBlockSize; i++) outblock[lk+i] = Lastblock[i];
      break;
      }

    // Begin--ESC Abort-------------------------------------------------------------
    // Here we allow to abort reading very lengthy files by pressing the ESC key // |
    if (CheckEscapeAbort() == TRUE) return;                                      // |
    // End----ESC Abort-------------------------------------------------------------

    DisplayProgressCount(ln, 1);         // Display ln counter in KB on statusbar
    }
  while (ln < dwCryptFileSize); // end do while

  inblock = pszInblockSave;              // Restore pointer to caller's inblock
  for (i=0; i<_algoBlockSize; i++) _icvblock[i] = Icvblock[i]; // Restore icv
  } // WindowsDoAlgorithmStealCBCE


//------------------------------------------------------------------------------
//
//                        WindowsDoAlgorithmStealCBCD
//
//  DECIPHER - Cipher Block Chaining (Ciphertext Stealing)
//
void WindowsDoAlgorithmStealCBCD(char* inblock, char* outblock, char* _icvblock, char* _keybuf)
  {
  char * pszInblockSave;
  int ciphStealing = FALSE;
  
  DoKeyInit(_keybuf, _keylength, DECIPHER);

  for (i=0; i<_algoBlockSize; i++)  Icvblock[i] =_icvblock[i]; // Save icv
  pszInblockSave = inblock;  // Init local pointer to save external file buffer

  for (i=0; i<_algoBlockSize; i++) Inbuf2[i] = 0;   // IMPORTANT: Init-clear Cn-2 block
    
  ln = 0;
  DWORD lk = 0;
  do
    {
    if (ciphStealing == TRUE) break;                   // ciphStealing - break

    // Keep track of bytesrd
    if ((dwCryptFileSize - ln) >= _algoBlockSize) bytesrd = _algoBlockSize;   
    else bytesrd = dwCryptFileSize - ln;               //  ifstream won't tell us   

    // infile.read(inblock, bytesrd);                  // Read from input file
    for (i = 0; i < bytesrd; i++)                      // Read Pi..Pn
      {                                                // Read external input buffer
      pszFileInbuf[i] = *inblock;                      //  into local buffer
      inblock++;                                       // Advance input buffer pointer
      }
    lk = ln;                  // Adjust external write buffer position (outblock index)

    if ((dwCryptFileSize-ln) > 2*_algoBlockSize && (dwCryptFileSize % _algoBlockSize) != 0) 
      for (i=0; i<_algoBlockSize; i++) Inbuf2[i] = pszFileInbuf[i]; // CBC save Cn-2 block

    if (bytesrd == _algoBlockSize)
      for (i=0; i<_algoBlockSize; i++) Inbuf1[i] = pszFileInbuf[i]; // CBC save 1st block

    // Ciphertext stealing
    else if (bytesrd < _algoBlockSize)
      {
      // CIPHERTEXT STEALING CBC DECIPHER:
      // We do not want to change filesizes, so we dont use padding.
      // The following special handling of the last block implements
      // "Ciphertext Stealing" if the last block is less than _algoBlockSize.
      // For the last 2 blocks: Aes(Pn-1) = Cn||C' and Aes(Pn||C') = Cn-1
      //  Note: Pn-1      = Previous Plaintext of _algoBlockSize
      //        Pn = Last plaintext < _algoBlockSize
      //        Pn*       = Last plaintext padded with zeros
      //        Cn-1      = Previous Ciphertext of Pn-1
      //        Cn-1*     = Ciphertext padded to Pn, stolen from previous block
      //        Cn-1(new) = New Ciphertext of _algoBlockSize for previous block
      //        Cn-1**    = Ciphertext < BLOCKSIZE from previous block, used last.
      //
      // Example: Decipher Key = 12345678
      //          Cn-1(new) = 72 F6 82 BA DA D8 88 91  (Previous block)
      //          Cn-1*     = 21 C0 2B
      //          Cn-1**    = F5 AC DD BE 5F           (Last block)
      //
      // Steps:   Cn-1(new)                = 72 F6 82 BA DA D8 88 91  (partly encrypted twice)
      //          Pn* ^ Cn-1               = FF A1 D7 B3 55 21 C0 2B  (deciphered once)
      //          Cn-1 = Cn-1** || Cn-1*   = F5 AC DD BE 5F 21 C0 2B
      //          Must save Cn-1           =[F5 AC DD BE 5F 21 C0 2B]
      //          Pn-1                     = 0A 0D 0A 0D 0A 0D 0A 0D  (Pn-1 deciphered)
      //          Pn = (Pn* ^ Cn-1) ^ Cn-1 = 0A 0D 0A 0D 0A           (Pn Lastblock deciphered)
      //
      //  before: Lastblock[] = F5 AC DD BE 5F 21 C0 2B F5 AC DD BE 5F 21 C0 2B
      //  after:  outblock[]  = 0A 0D 0A 0D 0A 0D 0A 0D                          (Decipher)
      //
      //  before: Lastblock[] = FF A1 D7 B3 55 21 C0 2B F5 AC DD BE 5F 21 C0 2B
      //  after:  Lastblock[] = 0A 0D 0A 0D 0A 00 00 00 F5 AC DD BE 5F 21 C0 2B  (XOR)
      //
      for (i = 0; i < _algoBlockSize; i++) Lastblock[i] = Lastblock[_algoBlockSize + i];
      for (i = 0; i < bytesrd; i++) Lastblock[i] = pszFileInbuf[i];
      
      for (i = 0; i < sizeof(Lastblock); i++) LastblockSave[i] = Lastblock[i];  // Save for 3DES
      DoCryptoAlgorithm(Lastblock, pszFileOutbuf, DECIPHER);
      for (i = 0; i < sizeof(Lastblock); i++) Lastblock[i] = LastblockSave[i];  // Restore for 3DES

      for (i = 0; i < _algoBlockSize; i++) pszFileOutbuf[i] ^= Inbuf2[i];
      for (i = 0; i < _algoBlockSize; i++) Lastblock[i]  ^= Lastblock[_algoBlockSize + i];

      for (i = 0; i < _algoBlockSize; i++) Lastblock[i+_algoBlockSize] = Lastblock[i]; // swap Pn-1
      for (i = 0; i < _algoBlockSize; i++) Lastblock[i] = pszFileOutbuf[i];            // concatenate Pn chunk

      ciphStealing = TRUE;
      } // end else if                                                                

    // ---------------------------------------------
    // Performing the AES (i.e., Standard Algorithm)
    // ---------------------------------------------
    if (ciphStealing == FALSE)
      {
      DoCryptoAlgorithm(pszFileInbuf, pszFileOutbuf, DECIPHER);

      if (bytesrd == _algoBlockSize && ciphStealing == FALSE)
        for (i=0; i<_algoBlockSize; i++) pszFileInbuf[i] = pszFileOutbuf[i];
      }

    ln += (ULONG)bytesrd;                              // Update counter total bytes read
    
    if (ciphStealing == FALSE)                         // Special handling for the last 2 blocks
      {
      for (i=0; i<_algoBlockSize; i++) Lastblock[_algoBlockSize+i] = pszFileOutbuf[i];   // Save Cn-1
      for (i=0; i<_algoBlockSize; i++) pszFileOutbuf[i] ^= _icvblock[i]; // CBC specific XOR function
      for (i=0; i<_algoBlockSize; i++) _icvblock[i] = Inbuf1[i];         // CBC copy 1st block
      // outfile.write(outblock, bytesrd);

      for (i=0; i<bytesrd; i++) outblock[lk+i] = pszFileOutbuf[i];
      }
    else                                               // Special handling for the last 2 blocks
      {
      // outfile.seekp(0, ios::end);                   // Seek to the end of the file
      lk = dwCryptFileSize;                            // Not really needed when using buffer technique
      // outfile.seekp(-_algoBlockSize, ios::cur);     // back up 16 bytes
      lk = dwCryptFileSize - _algoBlockSize - bytesrd; // Back up -(bytesrd + _algoBlockSize)
      // outfile.write(Lastblock, bytesrd + _algoBlockSize);                        // Write [Pn-1 || Pn]
      for (i = 0; i < bytesrd + _algoBlockSize; i++) outblock[lk+i] = Lastblock[i]; // Write [Pn-1 || Pn]
      break;
      }

    // Begin--ESC Abort-------------------------------------------------------------
    // Here we allow to abort reading very lengthy files by pressing the ESC key // |
    if (CheckEscapeAbort() == TRUE) return;                                      // |
    // End----ESC Abort-------------------------------------------------------------

    DisplayProgressCount(ln, 1);            // Display ln counter in KB on statusbar
    } 
  while (ln < dwCryptFileSize); // end do while

  inblock = pszInblockSave;                 // Restore pointer to caller's inblock
  for (i=0; i<_algoBlockSize; i++) _icvblock[i] = Icvblock[i]; // Restore icv
  } // WindowsDoAlgorithmStealCBCD


//-----------------------------------------------------------------------------
//
//                              WindowsDoAlgorithmIsoECB
//
//  ENCRYPT/DECIPHER - Electronic Code Book (ISO Padding)
//
void WindowsDoAlgorithmIsoECB(char* inblock, char* outblock, char* _keybuf, int _cmode)
  {
  int isoPad = 0; j = 0;
  char * pszInblockSave;

  DoKeyInit(_keybuf, _keylength, _cmode);  // Calculate key schedule

  pszInblockSave = inblock;    // Init local pointer to external file buffer

  ln = 0;

  bytesrd = _algoBlockSize;    // init bytesrd, filesize is at least 8 bytes
  while (ln < dwCryptFileSize)
    {
    // Keep track of bytesrd
    if ((ln+_algoBlockSize) > dwCryptFileSize) bytesrd = (int)(dwCryptFileSize % _algoBlockSize);

    ln += (ULONG)bytesrd;              // Update counter total bytes read

    // infile.read(inblock, bytesrd);
    for (i = 0; i < bytesrd; i++)      // Read Pi..Pn
      {                                // Read external input buffer
      pszFileInbuf[i] = *inblock;      //  into local buffer
      inblock++;                       // Advance input buffer pointer
      }
    lk = ln-bytesrd;                   // Adjust external write buffer position (outblock index)

    if (bytesrd == _algoBlockSize)
      {
      DoCryptoAlgorithm(pszFileInbuf, pszFileOutbuf, _cmode); // Crypt locally

      if (_cmode == ENCRYPT)
        // outfile.write(outblock, bytesrd);                         // Write Ci..Cn
        for (i=0; i<bytesrd; i++) outblock[lk+i] = pszFileOutbuf[i]; // Write local buffer to external buffer

      else if ((_cmode == DECIPHER) && (ln != dwCryptFileSize))
        {
        // outfile.write(outblock, _algoBlockSize); // Write all blocks, except the last block
        for (i=0; i<_algoBlockSize; i++) outblock[lk+i] = pszFileOutbuf[i];  // Write to external buffer
        }

      else if ((_cmode == DECIPHER) && (ln == dwCryptFileSize)) // Last block requires special handling
        {
        j=_algoBlockSize;
        if ((FileProcessingMode & CRYPT_ISO) == CRYPT_ISO)      // Either a whole block of padding
          {                                                     //  or a partly padded block
          int isoPadFlag = 0;                                   
          for (i=0; i<_algoBlockSize; i++)
            {
            j--;
            if ((pszFileOutbuf[j] & 0xFF) == ISOPAD) // ISOPAD 0x80 rendered as 0xFFFFFF80 long int ????
              {  
              isoPadFlag = 1;                                   
              break;
              }
            } // end for
          if (j == 0 && isoPadFlag == 0) j=_algoBlockSize;       // Error, not an ISO padded file
          } // end if

        else if ((FileProcessingMode & CRYPT_PKCS) == CRYPT_PKCS)
          {
          if ((pszFileOutbuf[_algoBlockSize-1] & 0xFF) > _algoBlockSize ||
              pszFileOutbuf[_algoBlockSize-1] == 0)              // Error, not a PKCS padded file
            {
            break;                                               
            }
          j = _algoBlockSize - pszFileOutbuf[_algoBlockSize-1];  // Number of plain text bytes 
          }

        // outfile.write(outblock, j);                // Write until ISOPAD
        for (i=0; i<j; i++) outblock[lk+i] = pszFileOutbuf[i];  // Write local buffer to external buffer
        dwCryptFileSize -= (ULONG)(_algoBlockSize-j); // Adjust filesize for the outside world
        ln = dwCryptFileSize;                         // Set counter to actual size of plain text file
        break;                                        // Stop while loop if ISOPAD
        } // end else
      }

    //
    // ISO PADDING:
    // Using ISO padding we always increase the filesize.
    // The following handling of the last block implements ISO Padding.
    // For the last block: Aes(Pn) = Cn||PB
    //  Note: Pn = Plaintext of <=_algoBlockSize
    //        Cn = Ciphertext > Pn, padded to BLOCKSIZE or appended with BLOCKSIZE.
    //
    // Example1: Encrypt Key = 12345678
    //           Pn      = 0A 0D 0A 0D 0A
    //           Pn||PB  = 0A 0D 0A 0D 0A 80 00 00
    //           Cn      = xx xx xx xx xx xx xx xx
    //
    // Example2: Encrypt Key = 12345678
    //           Pn      = 0A 0D 0A 0D 0A 12 34 45
    //           Pn||PB  = 0A 0D 0A 0D 0A 12 34 45 80 00 00 00 00 00 00 00    
    //           Cn      = xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx
    //
    // Pkcs PADDING:
    // Using Pkcs padding we always increase the filesize.
    // The following handling of the last block implements Pkcs Padding.
    // For the last block: Aes(Pn) = Cn||PB
    //  Note: Pn = Plaintext of <=_algoBlockSize
    //        Cn = Ciphertext > Pn, padded to BLOCKSIZE or appended with BLOCKSIZE.
    //
    // Example1: Encrypt Key = 12345678
    //           Pn      = 0A 0D 0A 0D 0A
    //           Pn||PB  = 0A 0D 0A 0D 0A 03 03 03
    //           Cn      = xx xx xx xx xx xx xx xx
    //
    // Example2: Encrypt Key = 12345678
    //           Pn      = 0A 0D 0A 0D 0A 12 34 45
    //           Pn||PB  = 0A 0D 0A 0D 0A 12 34 45 08 08 08 08 08 08 08 08    
    //           Cn      = xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx
    //
    else // ENCRYPT: bytesrd < _algoBlockSize
      {
      //
      // The last block is padded.
      //
      if ((FileProcessingMode & CRYPT_ISO) == CRYPT_ISO)
        {
        pszFileInbuf[bytesrd] = ISOPAD;
        for (i=bytesrd+1; i<_algoBlockSize; i++) pszFileInbuf[i] = PAD;
        }
      else if ((FileProcessingMode & CRYPT_PKCS) == CRYPT_PKCS)
        {
        for (i=bytesrd; i<_algoBlockSize; i++) pszFileInbuf[i] = _algoBlockSize-bytesrd;
        }
      dwCryptFileSize += (ULONG)(_algoBlockSize-bytesrd); // Adjust filesize for the outside world
      ln = dwCryptFileSize;                               // Set counter to actual size of plain text file

      DoCryptoAlgorithm(pszFileInbuf, pszFileOutbuf, _cmode); // Crypt locally

      // outfile.write(outblock, _algoBlockSize);
      for (i=0; i<_algoBlockSize; i++) outblock[lk+i] = pszFileOutbuf[i];  // Write to external buffer
      isoPad = 1;
      }

    // Begin--ESC Abort-------------------------------------------------------------
    // Here we allow to abort reading very lengthy files by pressing the ESC key // |
    if (CheckEscapeAbort() == TRUE) return;                                      // |
    // End----ESC Abort-------------------------------------------------------------

    DisplayProgressCount(ln, 1);               // Display ln counter in KB on statusbar
    } // end while
  
  // Need to add a whole padding block.
  // (does not apply to encrypted text which is always padded MOD(8))
  if ((_cmode == ENCRYPT) && (isoPad == 0))   
    {
    if ((FileProcessingMode & CRYPT_ISO) == CRYPT_ISO)
      {
      pszFileInbuf[0]=ISOPAD;
      for (i=1; i<_algoBlockSize; i++) pszFileInbuf[i] = PAD;
      }
    else if ((FileProcessingMode & CRYPT_PKCS) == CRYPT_PKCS)
      {
      for (i=0; i<_algoBlockSize; i++) pszFileInbuf[i] = _algoBlockSize;
      }

    DoCryptoAlgorithm(pszFileInbuf, pszFileOutbuf, _cmode); // Crypt locally

    // outfile.write(outblock, _algoBlockSize);// Write to external buffer
    for (i=0; i<_algoBlockSize; i++) outblock[lk+_algoBlockSize+i] = pszFileOutbuf[i];
    dwCryptFileSize += (ULONG)(_algoBlockSize);     // Adjust filesize for the outside world
    ln = dwCryptFileSize;                           // Set counter to actual size of plain text file
    }

  inblock = pszInblockSave;                    // Restore pointer to caller's inblock
  } // WindowsDoAlgorithmIsoECB


//------------------------------------------------------------------------------
//
//                              WindowsDoAlgorithmIsoCBCE
//
//  ENCRYPT - Cipher Block Chaining (ISO Padding)
//
void WindowsDoAlgorithmIsoCBCE(char* inblock, char* outblock, char* _icvblock, char* _keybuf)
  {
  int isoPad = 0; j = 0;
  char * pszInblockSave;

  DoKeyInit(_keybuf, _keylength, ENCRYPT); // Calculate key schedule

  for (i=0; i<_algoBlockSize; i++)  Icvblock[i] =_icvblock[i]; // Save icv
  pszInblockSave = inblock;  // Save external file inbuffer in local pointer for later 

  ln = 0;

  bytesrd = _algoBlockSize;  // init bytesrd, filesize is at least 8 bytes
  while (ln < dwCryptFileSize)
    {
    // Keep track of bytesrd
    if ((ln+_algoBlockSize) > dwCryptFileSize) bytesrd = (int)(dwCryptFileSize % _algoBlockSize);

    ln += (ULONG)bytesrd;              // Update counter total bytes read

    // infile.read(inblock, bytesrd);
    for (i = 0; i < bytesrd; i++)      // Read Pi..Pn
      {                                // Read external input buffer
      pszFileInbuf[i] = *inblock;      //  into local buffer
      inblock++;                       // Advance input buffer pointer
      }
    lk = ln-bytesrd;                   // Adjust external write buffer position (outblock index)

    if (bytesrd == _algoBlockSize)
      {
      // CBC specific XOR function
      for (i=0; i<_algoBlockSize; i++) pszFileInbuf[i] ^= _icvblock[i]; // CBC; inbuf XOR ICV

      DoCryptoAlgorithm(pszFileInbuf, pszFileOutbuf, ENCRYPT);          // Crypt locally

      // outfile.write(outblock, bytesrd); // Write local buffer to external buffer                          
      for (i=0; i<bytesrd; i++) outblock[lk+i] = pszFileOutbuf[i];      // Write Ci..Cn

      for (i=0; i<_algoBlockSize; i++) _icvblock[i] = outblock[lk+i];   // Update ICV
      }

    //
    // ISO PADDING:
    // Using ISO padding we always increase the filesize.
    // The following handling of the last block implements ISO Padding.
    // For the last block: Aes(Pn) = Cn||PB
    //  Note: Pn = Plaintext of <=_algoBlockSize
    //        Cn = Ciphertext > Pn, padded to BLOCKSIZE or appended with BLOCKSIZE.
    //
    // Example1: Encrypt Key = 12345678
    //           Pn      = 0A 0D 0A 0D 0A
    //           Pn||PB  = 0A 0D 0A 0D 0A 80 00 00
    //           Cn      = xx xx xx xx xx xx xx xx
    //
    // Example2: Encrypt Key = 12345678
    //           Pn      = 0A 0D 0A 0D 0A 12 34 45
    //           Pn||PB  = 0A 0D 0A 0D 0A 12 34 45 80 00 00 00 00 00 00 00    
    //           Cn      = xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx
    //
    // Pkcs PADDING:
    // Using Pkcs padding we always increase the filesize.
    // The following handling of the last block implements Pkcs Padding.
    // For the last block: Aes(Pn) = Cn||PB
    //  Note: Pn = Plaintext of <=_algoBlockSize
    //        Cn = Ciphertext > Pn, padded to BLOCKSIZE or appended with BLOCKSIZE.
    //
    // Example1: Encrypt Key = 12345678
    //           Pn      = 0A 0D 0A 0D 0A
    //           Pn||PB  = 0A 0D 0A 0D 0A 03 03 03
    //           Cn      = xx xx xx xx xx xx xx xx
    //
    // Example2: Encrypt Key = 12345678
    //           Pn      = 0A 0D 0A 0D 0A 12 34 45
    //           Pn||PB  = 0A 0D 0A 0D 0A 12 34 45 08 08 08 08 08 08 08 08    
    //           Cn      = xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx
    //
    else
      {
      //
      // The last block is padded.
      //
      if ((FileProcessingMode & CRYPT_ISO) == CRYPT_ISO)
        {
        pszFileInbuf[bytesrd] = ISOPAD;
        for (i=bytesrd+1; i<_algoBlockSize; i++) pszFileInbuf[i] = PAD;
        }
      else if ((FileProcessingMode & CRYPT_PKCS) == CRYPT_PKCS)
        {
        for (i=bytesrd; i<_algoBlockSize; i++) pszFileInbuf[i] = _algoBlockSize-bytesrd;
        }

      dwCryptFileSize += (ULONG)(_algoBlockSize-bytesrd); // Adjust filesize for the outside world
      ln = dwCryptFileSize;                               // Set counter to actual size of plain text file

      //
      // CBC specific XOR function
      //
      for (i=0; i<_algoBlockSize; i++) pszFileInbuf[i] ^= pszFileOutbuf[i]; // CBC XOR

      DoCryptoAlgorithm(pszFileInbuf, pszFileOutbuf, ENCRYPT); // Crypt locally

      // outfile.write(outblock, _algoBlockSize);// Write to external buffer
      for (i=0; i<_algoBlockSize; i++) outblock[lk+i] = pszFileOutbuf[i]; 
      isoPad = 1;
      }

    // Begin--ESC Abort-------------------------------------------------------------
    // Here we allow to abort reading very lengthy files by pressing the ESC key // |
    if (CheckEscapeAbort() == TRUE) return;                                      // |
    // End----ESC Abort-------------------------------------------------------------

    DisplayProgressCount(ln, 1);               // Display ln counter in KB on statusbar
    } // end while

  //
  // Encrypt and decipher modes must be handled differently.
  // Encrypt: If the srcFileSize is a multiple of _algoBlockSize we must append
  //          a whole block of ISO padding.
  // Decipher: Nothing to do, no final check required.
  //
  if (isoPad == 0)                             // Need to add a whole padding block
    {                                          //  which is always padded MOD(8)
    if ((FileProcessingMode & CRYPT_ISO) == CRYPT_ISO)
      {
      pszFileInbuf[0]=ISOPAD;                    
      for (i=1; i<_algoBlockSize; i++) pszFileInbuf[i] = PAD;
      }
    else if ((FileProcessingMode & CRYPT_PKCS) == CRYPT_PKCS)
      {
      for (i=0; i<_algoBlockSize; i++) pszFileInbuf[i] = _algoBlockSize;
      }

    // CBC specific XOR function
    for (i=0; i<_algoBlockSize; i++) pszFileInbuf[i] ^= pszFileOutbuf[i]; // CBC XOR

    DoCryptoAlgorithm(pszFileInbuf, pszFileOutbuf, ENCRYPT); // Crypt locally

    // outfile.write(outblock, _algoBlockSize); // Write to external buffer
    for (i=0; i<_algoBlockSize; i++) outblock[lk+_algoBlockSize+i] = pszFileOutbuf[i];
    dwCryptFileSize += (ULONG)(_algoBlockSize); // Adjust filesize for the outside world
    ln = dwCryptFileSize;                       // Set counter to actual size of plain text file
    }

  inblock = pszInblockSave;                     // Restore pointer to caller's inblock
  for (i=0; i<_algoBlockSize; i++) _icvblock[i] = Icvblock[i]; // Restore icv
  } // WindowsDoAlgorithmIsoCBCE


//-----------------------------------------------------------------------------
//
//                              WindowsDoAlgorithmIsoCBCD
//
//  DECIPHER - Cipher Block Chaining (ISO Padding)
//
void WindowsDoAlgorithmIsoCBCD(char* inblock, char* outblock, char* _icvblock, char* _keybuf)
  {
  char * pszInblockSave;
  
  DoKeyInit(_keybuf, _keylength, DECIPHER);  // Calculate key schedule

  for (i=0; i<_algoBlockSize; i++) Icvblock[i] =_icvblock[i]; // Save icv
  pszInblockSave = inblock;  // Save external file inbuffer in local pointer for later 

  ln = 0;
  DWORD lk = 0;

  bytesrd = _algoBlockSize;  // Init bytesrd, filesize is always a multiple of _algoBlockSize
  do
    {
    // infile.read(inblock, bytesrd);
    for (i = 0; i < bytesrd; i++)      // Read Pi..Pn
      {                                // Read external input buffer
      pszFileInbuf[i] = *inblock;      //  into local buffer
      inblock++;                       // Advance input buffer pointer
      }
    if (bytesrd == _algoBlockSize)
      for (i=0; i<_algoBlockSize; i++) Inbuf1[i] = pszFileInbuf[i];   // CBC save 1st block (needed for 3DES)

    lk = ln;                           // Adjust external write buffer position (outblock index)
    ln += (ULONG)bytesrd;              // Update counter total bytes read

    DoCryptoAlgorithm(pszFileInbuf, pszFileOutbuf, DECIPHER); // Crypt locally
    //
    // CBC specific XOR function
    //
    for (i=0; i<_algoBlockSize; i++) pszFileOutbuf[i] ^= _icvblock[i]; // CBC XOR
    for (i=0; i<_algoBlockSize; i++) _icvblock[i] = Inbuf1[i];         // CBC copy

    //
    // Encrypt and decipher modes must be handled differently.
    // Encrypt: Since "bytesrd==_algoBlockSize" we just write outblock to dstfile.
    // Decipher: Since ISO padding was applied to the enrypted file, it is
    //           guaranteed that the srcFileSize is a multiple of _algoBlockSize.
    //           However, we should remove the ISO padding from the deciphered
    //           plaintext, which is done here.
    //
    if (ln != dwCryptFileSize)
      {
      // outfile.write(outblock, _algoBlockSize);// Write to external buffer
      for (i=0; i<_algoBlockSize; i++) outblock[lk+i] = pszFileOutbuf[i];  
      }
    else                                // (ln == dwCryptFileSize)
      {                                 // Remove ISO padding from plaintext before fwrite
      j=_algoBlockSize;
      if ((FileProcessingMode & CRYPT_ISO) == CRYPT_ISO) // Either a whole block of padding
        {                                                //  or a partly padded block
        int isoPadFlag = 0;                                   
        for (i=0; i<_algoBlockSize; i++)
          {
          j--;
          if ((pszFileOutbuf[j] & 0xFF) == ISOPAD)  // Stop at ISOPAD, rendered as long int ????
            {
            isoPadFlag = 1;                                   
            break;
            }
          }  // end for
        if (j == 0 && isoPadFlag == 0) j=_algoBlockSize;       // Error, not an ISO padded file
        } // end if

      else if ((FileProcessingMode & CRYPT_PKCS) == CRYPT_PKCS)
        {
        if ((pszFileOutbuf[_algoBlockSize-1] & 0xFF) > _algoBlockSize ||
            pszFileOutbuf[_algoBlockSize-1] == 0)              // Error, not a PKCS padded file
          {
          break;
          }
        j = _algoBlockSize - pszFileOutbuf[_algoBlockSize-1];  // Number of plain text bytes
        }

      // outfile.write(outblock, j);// Write local buffer to external buffer             
      for (i=0; i<j; i++) outblock[lk+i] = pszFileOutbuf[i];  // Write until ISOPAD
      dwCryptFileSize -= (ULONG)(_algoBlockSize-j); // Adjust filesize for the outside world
      ln = dwCryptFileSize;                         // Set counter to actual size of plain text file
      break;                                        // Stop while loop if ISOPAD
      } // end else

    // Begin--ESC Abort-------------------------------------------------------------
    // Here we allow to abort reading very lengthy files by pressing the ESC key // |
    if (CheckEscapeAbort() == TRUE) return;                                      // |
    // End----ESC Abort-------------------------------------------------------------

    DisplayProgressCount(ln, 1);        // Display ln counter in KB on statusbar
    }
  while (ln < dwCryptFileSize); // end do while

  inblock = pszInblockSave;             // Restore pointer to caller's inblock
  for (i=0; i<_algoBlockSize; i++) _icvblock[i] = Icvblock[i]; // Restore icv
  } // WindowsDoAlgorithmIsoCBCD


//----------------------------------------------------------------------------
//
//               WindowsDoAlgorithmMac (CMAC NIST SP 800-38B)
//
// First step:  Two subkeys K1, K2 are generated from the key K.
// Second step: The input message is formatted into a sequence of complete blocks
//              in which the final block has been masked by a subkey.
// 
// There are two cases:
// 1.) If the message length is a positive multiple of the block size,
//     then the message is partitioned into complete blocks.
//     The final block is masked with the first subkey; in other words,
//     the final block in the partition is replaced
//     with the exclusive-OR of the final block with the FIRST subkey K1.
//     The resulting sequence of blocks is the formatted message
//     (no additional ISO Padding is applied).
// 
// 2.) If the message length is not a positive multiple of the block size,
//     then the message is partitioned into complete blocks
//     to the greatest extent possible, i.e., into a sequence of complete blocks
//     followed by a final bit string whose length is less than the block size.
//     A padding string is appended to this final bit string,
//     in particular, a single ‘1’ bit followed by the minimum number of ‘0’ bits,
//     possibly none, that are necessary to form a complete block (= ISO Padding).
//     The complete final block is masked, with the SECOND subkey K2.
//     The resulting sequence of blocks is the formatted message.
//
//  NOTE: Large files > 1G arrive here in chunks of 64M, where each 64M-Block
//        could be treated with K1 as described in 'case 1' above.
//        However, the last block will be processed referring to one of the two cases.
//        (Focusing only on the last block of very large files involves
//         a somewhat complicated memory handling).   
// 
void WindowsDoAlgorithmMac(char* inblock, char* outblock, char* _icvblock, char* _keybuf)
  {
  int msbFlag;

  //UCHAR pszRB128[AES_BLOCK_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x87};
  //UCHAR pszRB64[TDES_BLOCK_SIZE] = {0,0,0,0,0,0,0,0x1B};

  char pszZeroBlock[AES_BLOCK_SIZE];
  char pszSubkeyK1[AES_BLOCK_SIZE+1]; // Adding one 0-byte for ROL operation
  char pszSubkeyK2[AES_BLOCK_SIZE];

  DoKeyInit(_keybuf, _keylength, ENCRYPT);   // Calculate key schedule

  for (i=0; i<_algoBlockSize; i++)  Icvblock[i] =_icvblock[i]; // Save icv
  char* pszInblockSave;  // Save external file inbuffer in local pointer for later
 
  // DES: Generating the subkeys K1 and K2
  //  
  //  Example:
  //  Block cipher is the DES algorithm:
  //    Key =        8aa83bf8 cbda1062
  //
  //  Subkey K1, K2 Generation
  //    CIPHK(064) = DA FF D1 15 C4 DC F5 3E
  //    K1 =         85 FF A2 2B 89 B9 EA 67
  //    K2 =         6B FF 44 57 13 73 D4 D5
  //
  // Example Mlen = 64:
  //    M =          6bc1bee2 2e409f96
  //    T =          20 37 34 C0 22 B2 26 C8
  //
  // Example Mlen = 160:
  //    M =          6bc1bee2 2e409f96 e93d7e11 7393172a
  //                 ae2d8a57
  //    T =          E3 A8 DD 10 1A 7B CB B5
  //
  // Example Mlen = 256:
  //    M =          6bc1bee2 2e409f96 e93d7e11 7393172a
  //                 ae2d8a57 1e03ac9c 9eb76fac 45af8e51
  //    T =          59 EB 8D B9 78 9D AF C7

  //---------------------------------------------------------------------------
  // 3DES: Generating the subkeys K1 and K2
  //  
  //  Example 1:
  //  Block cipher is the TDES algorithm (Three Key TDEA):
  //    Key1 =       8aa83bf8 cbda1062
  //    Key2 =       0bc1bf19 fbb6cd58
  //    Key3 =       bc313d4a 371ca8b5  
  //
  //  Subkey K1, K2 Generation
  //    CIPHK(064) = C8 CC 74 E9 8A 73 29 A2  ok
  //    K1 =         91 98 E9 D3 14 E6 53 5F  ok
  //    K2 =         23 31 D3 A6 29 CC A6 A5  ok
  //
  // Example Mlen = 64:
  //    M =          6bc1bee2 2e409f96
  //    T =          8E 8F 29 31 36 28 37 97
  //
  // Example Mlen = 160:
  //    M =          6bc1bee2 2e409f96 e93d7e11 7393172a
  //                 ae2d8a57
  //    T =          74 3D DB E0 CE 2D C2 ED
  //
  // Example Mlen = 256:
  //    M =          6bc1bee2 2e409f96 e93d7e11 7393172a
  //                 ae2d8a57 1e03ac9c 9eb76fac 45af8e51
  //    T =          33 E6 B1 09 24 00 EA E5
  //

  //  Example 2:
  //  Block cipher is the TDES algorithm (Two Key TDEA):
  //    Key1 =       4cf15134 a2850dd5
  //    Key2 =       8a3d10ba 80570d38
  //    Key3 =       4cf15134 a2850dd5  
  //
  //  Subkey K1, K2 Generation
  //    CIPHK(064) = C7 67 9B 9F 6B 8D 7D 7A  ok
  //    K1 =         8E CF 37 3E D7 1A FA EF  ok
  //    K2 =         1D 9E 6E 7D AE 35 F5 C5  ok
  //
  // Example Mlen = 64:
  //    M =          6bc1bee2 2e409f96
  //    T =          4F F2 AB 81 3C 53 CE 83
  //
  // Example Mlen = 160:
  //    M =          6bc1bee2 2e409f96 e93d7e11 7393172a
  //                 ae2d8a57
  //    T =          62 DD 1B 47 19 02 BD 4E
  //
  // Example Mlen = 256:
  //    M =          6bc1bee2 2e409f96 e93d7e11 7393172a
  //                 ae2d8a57 1e03ac9c 9eb76fac 45af8e51
  //    T =          31 B1 E4 31 DA BC 4E B8  ok
  
  //---------------------------------------------------------------------------
  // AES: Generating the subkeys K1 and K2
  //  
  //  Example:
  //  Block cipher is the AES algorithm with the following 128bit key K:
  //    Key128 =      2b7e1516 28aed2a6 abf71588 09cf4f3c
  //
  //  ( Key192 =      8E73B0F7 DA0E6452 C810F32B 809079E5 )
  //  (               62F8EAD2 522C6B7B                   )
  //  (                                                   )
  //  ( Key256 =      603DEB10 15CA71BE 2B73AEF0 857D7781 )
  //  (               1F352C07 3B6108D7 2D9810A3 0914DFF4 )
  //
  //  Subkey K1, K2 Generation (128bit)
  //    CIPHK(0128) = 7df76b0c 1ab899b3 3e42f047 b91b546f
  //    K1 =          fbeed618 35713366 7c85e08f 7236a8de
  //    K2 =          f7ddac30 6ae266cc f90bc11e e46d513b  
  //
  //  Example Mlen = 128bit (16Bytes):
  //    M =           6bc1bee2 2e409f96 e93d7e11 7393172a
  //
  //    T(Key128) =   070a16b4 6b4d4144 f79bdd9d d04a287c
  //
  //    T(Key192) =   9e99a7bf 31e71090 0662f65e 617c5184
  //
  //    T(Key256) =   28a7023f 452e8f82 bd4bf28d 8c37c35c
  //
  //  Example Mlen = 160bit (20Bytes):
  //    M =           6bc1bee2 2e409f96 e93d7e11 7393172a
  //                  ae2d8a57
  //
  //    T(Key128) =   7D85449E A6EA19C8 23A7BF78 837DFADE
  //
  //    T(Key192) =   3D75C194 ED960704 44A9FA7E C740ECF8
  //
  //    T(Key256) =   156727DC 0878944A 023C1FE0 3BAD6D93
  //
  //  Example Mlen = 320bit (40Bytes):
  //    M =           6bc1bee2 2e409f96 e93d7e11 7393172a
  //                  ae2d8a57 1e03ac9c 9eb76fac 45af8e51
  //                  30c81c46 a35ce411
  //
  //    T(Key128) =   dfa66747 de9ae630 30ca3261 1497c827
  // 
  //    T(Key192) =   8a1de5be 2eb31aad 089a82e6 ee908b0e
  //
  //    T(Key256) =   aaf3d8f1 de5640c2 32f5b169 b9c911e6
  //
  //  Example Mlen = 512bit (64Bytes):
  //    M =           6bc1bee2 2e409f96 e93d7e11 7393172a
  //                  ae2d8a57 1e03ac9c 9eb76fac 45af8e51
  //                  30c81c46 a35ce411 e5fbc119 1a0a52ef
  //                  f69f2445 df4f9b17 ad2b417b e66c3710
  //
  //    T(Key128) =   51f0bebf 7e3b9d92 fc497417 79363cfe
  // 
  //    T(Key192) =   a1d5df0e ed790f79 4d775896 59f39a11
  //
  //    T(Key256) =   e1992190 549f6ed5 696a2c05 6c315410
  
  //---------------------------------------------------------------------------

  pszSubkeyK1[_algoBlockSize+0] = 0; // Ensure K1 last shifted bit = 0

  for (i=0; i<_algoBlockSize; i++)
    pszZeroBlock[i] = _icvblock[i];  // Init Zero - block

  // K1
  DoCryptoAlgorithm(pszZeroBlock, pszSubkeyK1, ENCRYPT);

  msbFlag = (UCHAR)pszSubkeyK1[0] & 0x80; // Set flag for XOR K1 later

  for (i=0; i<_algoBlockSize; i++)
    {
    pszSubkeyK1[i] = pszSubkeyK1[i] << 1;
    pszSubkeyK1[i] = pszSubkeyK1[i] | ((pszSubkeyK1[i+1] & 0x80) >> 7);
    }                                                                             

  if (msbFlag != 0)
    {
    for (i=0; i<_algoBlockSize; i++) pszSubkeyK1[i] ^= pszRB[i];
    }

  // K2
  for (i=0; i<_algoBlockSize; i++)
    pszSubkeyK2[i] = (pszSubkeyK1[i] << 1) | ((pszSubkeyK1[i+1] & 0x80) >> 7);
  
  msbFlag = (UCHAR)pszSubkeyK1[0] & 0x80; // Set flag for XOR K1 later
  if (msbFlag != 0)
    {
    for (i=0; i<_algoBlockSize; i++) pszSubkeyK2[i] ^= pszRB[i];
    }

  if (largeFileFlag == FALSE || (largeFileFlag & _largeFileLastBlock) == TRUE)
    {
    // Prepare the last block of _algoBlockSize in inblock:
    // 1) Message length is a positive multiple of the block size  
    if (dwCryptFileSize % _algoBlockSize == 0)
      {
      ln = dwCryptFileSize-_algoBlockSize;
      for (i=0; i<_algoBlockSize; i++) inblock[ln+i] ^= pszSubkeyK1[i];
      }
    
    // 2) Message length is not a positive multiple of the block size  
    else
      {
      int lenPad = _algoBlockSize - (dwCryptFileSize % _algoBlockSize);
      ln = dwCryptFileSize + lenPad;

      for (i=(int)(dwCryptFileSize % _algoBlockSize); i<_algoBlockSize; i++)
        {
        // CMAC Padding starts with 10000000b and continues with all bits zeroed
        if (i == (int)(dwCryptFileSize % _algoBlockSize)) inblock[ln-_algoBlockSize+i] = ISOPAD;       
        else  inblock[ln-_algoBlockSize+i] = PAD;
        }

      for (i=0; i<_algoBlockSize; i++) inblock[ln-_algoBlockSize+i] ^= pszSubkeyK2[i];

      dwCryptFileSize = ln;  // Adjust to positive multiple of the block size
      } // end else
    } // end if (largeFileFlag)

  // CMAC 
  pszInblockSave = inblock;        // Save external file inbuffer in local pointer for later 

  ln = 0;                          // init counter
  bytesrd = _algoBlockSize;        // init bytesrd, filesize is at least 8 bytes

  while (ln < dwCryptFileSize)
    {
    if ((dwCryptFileSize - ln) >= _algoBlockSize) bytesrd = _algoBlockSize; // Keep track of bytesrd,    
    else bytesrd = dwCryptFileSize - ln;                                    //  ifstream won't tell us   

    // infile.read(inblock, bytesrd);
    for (i = 0; i < bytesrd; i++)      // Read Pi..Pn
      {                                // Read external input buffer
      pszFileInbuf[i] = *inblock;      //  into local buffer
      inblock++;                       // Advance input buffer pointer
      }

    for (i=0; i<_algoBlockSize; i++) pszFileInbuf[i] ^= _icvblock[i]; // CBC: inbuf XOR  ICV

    DoCryptoAlgorithm(pszFileInbuf, pszFileOutbuf, ENCRYPT);
    for (i=0; i<_algoBlockSize; i++) _icvblock[i] = pszFileOutbuf[i]; // Update ICV w/ next block

    ln += (ULONG)bytesrd;                      // Update counter total bytes read

    // Begin--ESC Abort-------------------------------------------------------------
    // Here we allow to abort reading very lengthy files by pressing the ESC key // |
    if (CheckEscapeAbort() == TRUE) return;                                      // |
    // End----ESC Abort-------------------------------------------------------------

    DisplayProgressCount(ln, 1);               // Display ln counter in KB on statusbar
    } // end while

  // outfile.write(outblock, _algoBlockSize);// Emit the MAC to file
  for (i=0; i<_algoBlockSize; i++) outblock[i] = pszFileOutbuf[i];

  inblock = pszInblockSave;                    // Restore pointer to caller's inblock
  for (i=0; i<_algoBlockSize; i++) _icvblock[i] = Icvblock[i]; // Restore icv
  } // WindowsDoAlgorithmMac

//-----------------------------------------------------------------------------

//ha//  if (_keybuf[6] == 'F') _keybuf[6] = 0xFF;   // Adjust key, simulate keypad entry
//ha//  if (_keybuf[7] == 'F') _keybuf[7] = 0xFF;   //  Alt+255

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//{
//ha//TCHAR* pszTxtE = TEXT("%lu bytes encrypted.");
//ha//StringCbPrintf(pszCountBuf, sizeof pszCountBuf, pszTxtE, ln);
//ha//SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)pszCountBuf);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG STOP", MB_OK);
//ha//}
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
//ha//                  (UCHAR)pszSubkeyK1[0],(UCHAR)pszSubkeyK1[1],
//ha//                  (UCHAR)pszSubkeyK1[2],(UCHAR)pszSubkeyK1[3],
//ha//                  (UCHAR)pszSubkeyK1[4],(UCHAR)pszSubkeyK1[5],
//ha//                  (UCHAR)pszSubkeyK1[6],(UCHAR)pszSubkeyK1[7], 
//ha//                  (UCHAR)pszSubkeyK1[8],(UCHAR)pszSubkeyK1[9],
//ha//                  (UCHAR)pszSubkeyK1[10],(UCHAR)pszSubkeyK1[11],
//ha//                  (UCHAR)pszSubkeyK1[12],(UCHAR)pszSubkeyK1[13],
//ha//                  (UCHAR)pszSubkeyK1[14],(UCHAR)pszSubkeyK1[15]); 
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG AES ECB pszSubkeyK1", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "ln=%i\ndwCryptFileSize=%i\n%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X", ln, dwCryptFileSize, 
//ha//                  (UCHAR)inblock[ln-AES_BLOCK_SIZE+0], (UCHAR)inblock[ln-AES_BLOCK_SIZE+1],
//ha//                  (UCHAR)inblock[ln-AES_BLOCK_SIZE+2], (UCHAR)inblock[ln-AES_BLOCK_SIZE+3],
//ha//                  (UCHAR)inblock[ln-AES_BLOCK_SIZE+4], (UCHAR)inblock[ln-AES_BLOCK_SIZE+5],
//ha//                  (UCHAR)inblock[ln-AES_BLOCK_SIZE+6], (UCHAR)inblock[ln-AES_BLOCK_SIZE+7], 
//ha//                  (UCHAR)inblock[ln-AES_BLOCK_SIZE+8], (UCHAR)inblock[ln-AES_BLOCK_SIZE+9],
//ha//                  (UCHAR)inblock[ln-AES_BLOCK_SIZE+10],(UCHAR)inblock[ln-AES_BLOCK_SIZE+11],
//ha//                  (UCHAR)inblock[ln-AES_BLOCK_SIZE+12],(UCHAR)inblock[ln-AES_BLOCK_SIZE+13],
//ha//                  (UCHAR)inblock[ln-AES_BLOCK_SIZE+14],(UCHAR)inblock[ln-AES_BLOCK_SIZE+15]); 
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG AES CMAC inblock[ln-AES_BLOCK_SIZE]", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---



