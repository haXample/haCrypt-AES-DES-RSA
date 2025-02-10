// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// rsabiginteger.cpp - C++ Developer source file.
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

// https://www.tutorialspoint.com/cplusplus-program-to-implement-the-rsa-algorithm
// https://github.com/jubaer-pantho/RSA-Implementation-Cpp/blob/master/BigInteger.cpp

#include <stdlib.h>
#include <cmath>
#include <iostream>
#include <malloc.h>

#include <string>      // sprintf, etc.

#include <windows.h>
#include <commctrl.h>  // Library Comctl32.lib
#include <winuser.h>
#include <commdlg.h>
#include <tchar.h>
#include <strsafe.h>  //  <strsafe.h> must be included after <tchar.h>

#include "haCrypt.h"
#include "RSAbigIntegerC.h"
#include "RSAfuncC.h"

using namespace std;

//ha// #define MAX(x, y) ((x) > (y) ? (x) : (y))
int _l = 0;                             // Init

// External variables
extern unsigned __int64 recoursionCnt;

extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text

extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;
//
extern int szRsaTempbuf[];     // For temporary usage

extern char szRsaPubbufN[];
extern int szRsaPubbufNSize;

extern char szRsaPubbufE[];
extern int szRsaPubbufESize;

extern char szRsaPubKey[];   
extern int szRsaPubKeySize;

extern char szRsaPrvbufN[];
extern int szRsaPrvbufNSize;

extern char szRsaPrvbufD[];
extern int szRsaPrvbufDSize;

extern char szRsaPrvKey[];   
extern int szRsaPrvKeySize;

extern char szRsaPadbuf[];
extern int szRsaPadbufSize;

extern char szRsaDatabuf[];    
extern int szRsaDatabufSize;

extern char szRsabuf[];       // Publicly used here for the outside world
extern int szRsabufSize;

extern void editTextField(TCHAR*);
extern TCHAR* AnsiToUnicode(char*, int);
extern int CBTMessageBox(HWND, LPCTSTR, LPCTSTR, UINT); // Centered Messagebox within parent window

extern HWND hMain;

//-----------------------------------------------------------------------------
//
//                  BigInteger::BigInteger(int)
//
BigInteger::BigInteger(int n)
  {
  nSize = n;
  digit = new unsigned int[n];
  digitResult = new unsigned int[n];  // Resulting integer
  digitReverse = new unsigned int[n]; //ha// Reverse order

  for (int i = 0; i < nSize; i++) digit[i] = 0;  // Clear digit array
  } // BigInteger::BigInteger(int)


//-----------------------------------------------------------------------------
//
//                  BigInteger::BigInteger(const BigInteger)
//
//  Using copy constructor
//
BigInteger::BigInteger(const BigInteger& obj)
  {
  nSize = obj.nSize;
  digit = new unsigned int[nSize];
  digitResult = new unsigned int[nSize];  // Resulting integer

  for (int i=0; i < nSize; i++)
    {
    digit[i] = obj.digit[i];
    digitResult[i] = obj.digitResult[i];
    }
  } // BigInteger::BigInteger(&obj)


//-----------------------------------------------------------------------------
//
//                  BigInteger::~BigInteger()
//
BigInteger::~BigInteger()
  {
  delete [] digit;
  delete [] digitResult;
  } // BigInteger::~BigInteger


//ha//-----------------------------------------------------------------------------
//
//                  BigInteger::__getDigits(int, int)
//
// This fixes the handling of arbitrary 0s within plaintext digit[] array
// However, the "old" function 'BigInteger::getDigits' is still needed, too.
//
int BigInteger::__getDigits(int _mode, int _show)
  {
  char* pszRsaExternbuf;
  int szRsaExternbufSize;
  int i, j, k, _m, _o=0;

  //-----------------------------------------------------------------------------
  //
  //                           Initial  cases
  //
  switch (_mode)
    {
    case RSA_MODE_PUBKEYN:
      nSize = (RSA_SIZE + 1)*sizeof(int);            // = 8 dwords +1
      pszRsaExternbuf = szRsaPubbufN;
      szRsaExternbufSize = szRsaPubbufNSize;
      break;
    case RSA_MODE_PUBKEYE:                     
      nSize = (RSA_SIZE/RSA_SIZE + 1)*sizeof(int);   // = 1 dword +1
      pszRsaExternbuf = szRsaPubbufE;
      szRsaExternbufSize = szRsaPubbufESize;
      break;
    case RSA_MODE_PRVKEYN:
      nSize = (RSA_SIZE + 1)*sizeof(int);            // = 8 dwords +1
      pszRsaExternbuf = szRsaPrvbufN;
      szRsaExternbufSize = szRsaPrvbufNSize;
      break;
    case RSA_MODE_PRVKEYD:
      nSize = (RSA_SIZE + 1)*sizeof(int);            // = 8 dwords +1
      pszRsaExternbuf = szRsaPrvbufD;
      szRsaExternbufSize = szRsaPrvbufDSize;
      break;

    case RSA_MODE_PADDATA:                           // = 128 words, Debug only
      if (_show == RSA_SHOW_DIGITS)
        editTextField(_T("Random padding = \x0D\x0A"));                     
      pszRsaExternbuf = szRsaPadbuf;
      szRsaExternbufSize = szRsaPadbufSize;
      break;

    case RSA_MODE_ENCDATAIN:
      for (i=0; i<RSA_BLOCK_SIZE/4; i++) szRsaTempbuf[i] = 0; // Init clear
      nSize = RSA_BLOCK_SIZE/4;             // = 4 dwords

      j=0; _m=0; _l=0; _o=0;
      for (i=(nSize-1); i>=0; i--)
        {
        if (digit[i] != 0)
          {
          _l = 1; _m++;
          szRsaTempbuf[j++] = digit[i];
          }
        else if (_l == 1)
          {
          szRsaTempbuf[j++] = digit[i];
          _m++;
          }
        else if (digit[i] == 0) _o++;       // Count the leading 0s in digit[]
        } // end for (nSize)

      // Inverse: leading 0s to trailing 0s
      if (_o > 0)
        {
        for (i=0; i<=_o; i++) szRsaTempbuf[_o-i] = digit[i];
        }
      // Transfer into 'digitResult'
      for (i=0; i<RSA_BLOCK_SIZE/4; i++) digitResult[i] = 0; // Init clear
      if (_m < RSA_BLOCK_SIZE) _m = RSA_BLOCK_SIZE/4;
      for (i=0; i<_m; i++)  digitResult[i] = szRsaTempbuf[i];
      break;  // end RSA_MODE_ENCDATAIN

    case RSA_MODE_ENCDATAOUT:
      for (i=0; i<RSA_BLOCK_SIZE/2; i++) szRsaTempbuf[i] = 0; // Init clear
      nSize = RSA_BLOCK_SIZE;              // = 8 dwords! (at least 16 required?!)

      j=0; _m=0; _l=0; _o=0;
      for (i=(nSize-1); i>=0; i--)
        {
        if (digit[i] != 0)
          {
          _l = 1; _m++;
          szRsaTempbuf[j++] = digit[i];
          }
        else if (_l == 1)
          {
          szRsaTempbuf[j++] = digit[i];
          _m++;
          }
        else if (digit[i] == 0) _o++;       // Count the leading 0s in digit[]
        } // end for (nSize)

      // Inverse: leading 0s to trailing 0s
      _o -= nSize/2;                        // Adjust = 8 dwords!
      if (_o > 0)
        {
        for (i=0; i<=_o; i++) szRsaTempbuf[_o-i] = digit[i];
        }
      // Transfer 'szRsaTempbuf' into 'digitResult'
      for (i=0; i<RSA_BLOCK_SIZE/2; i++) digitResult[i] = 0; // Init clear
      if (_m < RSA_BLOCK_SIZE) _m = RSA_BLOCK_SIZE/2;
      for (i=0; i<_m; i++) digitResult[i] = szRsaTempbuf[i];
      break;  // end RSA_MODE_ENCDATAOUT

    case RSA_MODE_DECDATA:
      nSize = RSA_BUFFER_SIZE;///sizeof(int); // = 128 dwords
      j=0; k=0;                         // Init
      for (i = (nSize-1); i >= 0; i--)  // nsize = 512
        {
        if (digit[i] != 0)   
          {
          if (_show == RSA_SHOW_DIGITS)
            {
            StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%08X "), digit[i]);
            editTextField(_tDebugBuf);
            }
          szRsabuf[sizeof(int)*i+0] = (char)((digit[j] & 0xFF000000) >> 24);
          szRsabuf[sizeof(int)*i+1] = (char)((digit[j] & 0x00FF0000) >> 16);
          szRsabuf[sizeof(int)*i+2] = (char)((digit[j] & 0x0000FF00) >>  8);
          szRsabuf[sizeof(int)*i+3] = (char)((digit[j] & 0x000000FF));
          // Increment dword index & count
          j++; k++;
          // Format to fit into text field                                            
          if (_show == RSA_SHOW_DIGITS && k % 8 == 0) editTextField(_T("\x0D\x0A"));
          } // end if (digit[i] != 0)
        } // end for (i = (nSize-1)

      // Format to fit into text field                                            
      if (_show == RSA_SHOW_DIGITS && 
          digit[i+1] != 0          &&
          k != 0                   &&
          k <= 4)                   
        editTextField(_T("\x0D\x0A"));
      break; // end case RSA_MODE_DECDATA:

    case RSA_MODE_DATA:
      nSize = 2*RSA_BLOCK_SIZE/sizeof(int);            // = 8 dwords
      // Init-clear data interception buffer
      for (j=0; j<szRsabufSize; j++) szRsabuf[j] = 0; 
      pszRsaExternbuf = szRsaDatabuf;
      szRsaExternbufSize = szRsaDatabufSize;
      break;

    default:
      return 0;  // No data processed
      break;
    } // end switch

  //-----------------------------------------------------------------------------
  //
  //                        Intermediate  cases
  //
  switch (_mode)
    {
    case RSA_MODE_ENCDATA:         // Nothing to do
    case RSA_MODE_ENCDATAIN:
    case RSA_MODE_ENCDATAOUT:
      break;
    case RSA_MODE_DECDATA:         // Something to do: 0s displayed in debug mode 
      break;                       // (nothing urgent)

    case RSA_MODE_PUBKEYN:
    case RSA_MODE_PUBKEYE:
    case RSA_MODE_PRVKEYN:
    case RSA_MODE_PRVKEYD:
    case RSA_MODE_PADDATA:          // = 128 dwords, Debug only
    case RSA_MODE_DATA:
      j=0; k=0;                         // Init
      for (i = (nSize-1); i >= 0; i--)  // nsize = 512
        {
        if (digit[i] != 0)   
          {
          if (_show == RSA_SHOW_DIGITS)
            {
            StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%08X "), digit[i]);
            editTextField(_tDebugBuf);
            }
          szRsabuf[sizeof(int)*i+0] = (char)((digit[j] & 0xFF000000) >> 24);
          szRsabuf[sizeof(int)*i+1] = (char)((digit[j] & 0x00FF0000) >> 16);
          szRsabuf[sizeof(int)*i+2] = (char)((digit[j] & 0x0000FF00) >>  8);
          szRsabuf[sizeof(int)*i+3] = (char)((digit[j] & 0x000000FF));
          // Increment dword index & count
          j++; k++;
          // Format to fit into text field                                            
          if (_show == RSA_SHOW_DIGITS && k % 8 == 0) editTextField(_T("\x0D\x0A"));
          } // end if (digit[i] != 0)
        } // end for (i = (nSize-1)

      // Format to fit into text field                                            
      if (_show == RSA_SHOW_DIGITS && 
          digit[i+1] != 0          &&
          k != 0                   &&
          k <= 4)                   
        editTextField(_T("\x0D\x0A"));
      break;
    default:
      return 0;                     // No data processed
      break;
    } // end switch


  //-----------------------------------------------------------------------------
  //
  //                        Exit cases
  //
  switch (_mode)
    {
    case RSA_MODE_PUBKEYN:                
      for (i=0; i<2*RSA_BLOCK_SIZE; i++)
        szRsaPubKey[i] = szRsabuf[i];                  // [N] = 32 bytes, 8 dwords
      break;
    case RSA_MODE_PUBKEYE:
      for (i=0; i<RSA_BLOCK_SIZE/sizeof(int); i++)
        szRsaPubKey[i+2*RSA_BLOCK_SIZE] = szRsabuf[i]; // [e] = Only 4 bytes, 1 dword
      break;

    case RSA_MODE_PRVKEYN:
      for (i=0; i<2*RSA_BLOCK_SIZE; i++)               // [N] = 32 bytes, 8 dwords
        szRsaPrvKey[i] = szRsabuf[i];
      break;
    case RSA_MODE_PRVKEYD:
      for (i=0; i<2*RSA_BLOCK_SIZE; i++)               // [d] = 32 bytes, 8 dwords
        szRsaPrvKey[i+2*RSA_BLOCK_SIZE] = szRsabuf[i];
      break;

    case RSA_MODE_PADDATA:          // 512 bytes max (debug only)
    case RSA_MODE_DATA:
      szRsaExternbufSize = nSize;
      for (j=0; j<szRsaExternbufSize; j++) pszRsaExternbuf[j] = szRsabuf[j]; 
      break;

    case RSA_MODE_ENCDATA:
      break;
    case RSA_MODE_ENCDATAIN:
    case RSA_MODE_ENCDATAOUT:
      j=0; k=0;             // Init
      for (i=0; i<_m; i++)  // _m = amout of relevant data dwords
        {
        if (_show == RSA_SHOW_DIGITS)
          {
          StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%08X "), digitResult[i]);
          editTextField(_tDebugBuf);
          }
        szRsabuf[sizeof(int)*i+0] = (char)((digitResult[j] & 0xFF000000) >> 24);
        szRsabuf[sizeof(int)*i+1] = (char)((digitResult[j] & 0x00FF0000) >> 16);
        szRsabuf[sizeof(int)*i+2] = (char)((digitResult[j] & 0x0000FF00) >>  8);
        szRsabuf[sizeof(int)*i+3] = (char)((digitResult[j] & 0x000000FF));
        // Increment dword index & count
        j++; k++;
        // Format to fit into text field                                            
        if (_show == RSA_SHOW_DIGITS && k % 8 == 0) editTextField(_T("\x0D\x0A"));
        } // end for (i = (nSize-1)

        // Format to fit into text field                                            
        if (_show == RSA_SHOW_DIGITS && 
            k != 0                   &&
            k <= 4)                   
          editTextField(_T("\x0D\x0A"));
      break;

    case RSA_MODE_DECDATA:
      // Reload szRsabuf, because getDigit does not handle 0s in plain message 
      j = RSA_BLOCK_SIZE/sizeof(int); 
      for (i=0; i<RSA_BLOCK_SIZE; i+=sizeof(int))
        {
        j--;
        if (_show == RSA_SHOW_DIGITS && digit[j] == 0)
          {
          StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("%08X "), digit[j]);
          editTextField(_tDebugBuf);
          }
        szRsabuf[i+0] = (UCHAR)((digit[j] & 0xFF000000)>>24);
        szRsabuf[i+1] = (UCHAR)((digit[j] & 0x00FF0000)>>16);
        szRsabuf[i+2] = (UCHAR)((digit[j] & 0x0000FF00)>> 8);
        szRsabuf[i+3] = (UCHAR)((digit[j] & 0x000000FF));
        } // end for
  
      // Format to fit into text field                                            
      if (_show == RSA_SHOW_DIGITS && digit[j] == 0)
        editTextField(_T("\x0D\x0A"));
      break;

    default:
      return 0;                     // No data processed
      break;
    } // end switch

  return(k);
  } // BigInteger::__getDigits


//ha//-----------------------------------------------------------------------------
//
//                     BigInteger::showStringA(int)
//
void BigInteger::showStringA(int _length)
  {
  int i, j;

  editTextField(_T("["));

  if (_length == 2*RSA_BLOCK_SIZE)          //32 Bytes
    {
    BigInteger::byteSwap16(&digit[4], &digitReverse[RSA_BLOCK_SIZE]);
    BigInteger::byteSwap16(&digit[0], &digitReverse[0]);
    editTextField(AnsiToUnicode((char*)&digitReverse[RSA_BLOCK_SIZE], RSA_BLOCK_SIZE));
    editTextField(AnsiToUnicode((char*)&digitReverse[0], RSA_BLOCK_SIZE));
    }

  else if (_length == TYPED_KEY_SIZE_MAX)   // 24 Bytes
    {
    BigInteger::byteSwap16(&digit[4], &digitReverse[RSA_BLOCK_SIZE]);
    BigInteger::byteSwap16(&digit[0], &digitReverse[0]);
    editTextField(AnsiToUnicode((char*)&digitReverse[RSA_BLOCK_SIZE], RSA_BLOCK_SIZE/2));
    editTextField(AnsiToUnicode((char*)&digitReverse[0], RSA_BLOCK_SIZE));
    }

  else if (_length == 1*RSA_BLOCK_SIZE)     // 16 Bytes
    {
    BigInteger::byteSwap16(&digit[0], &digitReverse[0]);
    editTextField(AnsiToUnicode((char*)&digitReverse[0], RSA_BLOCK_SIZE));
    }
    
  editTextField(_T("]")_T("\x0D\x0A"));
  } // BigInteger::showStringA


//ha//-----------------------------------------------------------------------------
//
//          BigInteger::byteSwap16(unsigned int*, unsigned int*, int)
//
void BigInteger::byteSwap16(unsigned int* _dwInbuf, unsigned int* _dwOutbuf)
  {
  int i, j = RSA_BLOCK_SIZE/sizeof(unsigned int);
  for (i=0; i < RSA_BLOCK_SIZE/sizeof(unsigned int); i++)
    {
    j--; 
    _dwOutbuf[i] = 0; // Clear 4-byte array                          // _dwOutbuf
    _dwOutbuf[i] |= ((_dwInbuf[j] & 0xFF000000)) >> 24; //  A >> 24; // Byte 0
    _dwOutbuf[i] |= ((_dwInbuf[j] & 0x00FF0000)) >>  8; //  B >>  8; // Byte 1
    _dwOutbuf[i] |= ((_dwInbuf[j] & 0x0000FF00)) <<  8; //  C <<  8; // Byte 2
    _dwOutbuf[i] |= ((_dwInbuf[j] & 0x000000FF)) << 24; //  D << 24; // Byte 3
    }
  } // BigInteger::byteSwap16()


///ha//-----------------------------------------------------------------------------
//
//              BigInteger::copy2digits()
//
void BigInteger::copy2digits(char* szRsaData, int _dwCnt)
  {
  int i, j=0, _dataInt;

  _dwCnt /= sizeof(int);  // Adjust to DWORD indexing
  clearBigInteger();      // Init-clear digit[]

  for (i = (_dwCnt-1); i >= 0; i--)  // Reverse big interger notation
    {
    _dataInt = 0;         // Init-clear
    _dataInt |= (UINT)((szRsaData[4*i+3] & 0x000000FF));
    _dataInt |= (UINT)((szRsaData[4*i+2] & 0x000000FF) <<  8);
    _dataInt |= (UINT)((szRsaData[4*i+1] & 0x000000FF) << 16);
    _dataInt |= (UINT)((szRsaData[4*i+0] & 0x000000FF) << 24);

    if (_dataInt != 0) digit[j] = _dataInt;
    j++;
    }
  } //BigInteger::copy2digits


//ha//-------------------------------------------------------------------------
//
//              BigInteger::loadBigInteger(BigInteger&, int)
//
void BigInteger::loadBigInteger(int _mode)
  {
  switch(_mode)
    {
    case RSA_MODE_PUBKEYN:
      copy2digits(szRsaPubKey, szRsaPubKeySize - 1*sizeof(int));               // [N]
      break;
    case RSA_MODE_PUBKEYE:
      copy2digits((char*)&szRsaPubKey[szRsaPubKeySize - 1*sizeof(int)], 1*sizeof(int)); // [e]
      break;
    case RSA_MODE_PRVKEYN:
      copy2digits(szRsaPrvKey, szRsaPrvKeySize/2);                             // [N]
      break;
    case RSA_MODE_PRVKEYD:
      copy2digits((char*)&szRsaPrvKey[szRsaPrvKeySize/2], szRsaPrvKeySize/2);  // [d]
      break;
    default:
      return;
    }
  } // loadBigInteger


//-----------------------------------------------------------------------------
//
//                  BigInteger::setDigits(int)
//
void BigInteger::setDigits(int index)
  {
  if (index == 0) digit[0] = 1;

  else if (index == 1)
    {
    digit[0] = 2;  // 429496725; = 0x19999995
    digit[1] = 0;
    }
  } // BigInteger::setDigits


//-----------------------------------------------------------------------------
//
//              BigInteger::addBigInteger(BigInteger&, BigInteger&)
//
void BigInteger::addBigInteger(BigInteger& a, BigInteger& b)
  {
  unsigned __int64 base = 4294967296; // =0x100000000 Number base (64 bits).
  unsigned int k = 0;

  for (int i=0; i<nSize; i++)
    {
    unsigned __int64 sum = 0;
    sum = (unsigned __int64) a.digit[i] + (unsigned __int64) b.digit[i] + k;
    digit[i] = (unsigned int) (sum % base);
    k = (unsigned int) (sum / base);
    }
  } // BigInteger::addBigInteger


//-----------------------------------------------------------------------------
//
//              BigInteger::subBigInteger(BigInteger&, BigInteger&)
//
void BigInteger::subBigInteger(BigInteger& a, BigInteger& b)
  {
  __int64 base = 4294967296;          // =0x100000000 Number base (64 bits).
  int k = 0;

  for (int i=0; i<nSize; i++)
    {
    unsigned __int64 sum = 0;
    sum = (__int64) a.digit[i] - (__int64) b.digit[i] + k;
    digit[i] = (unsigned int) (sum % base);
    k = sum / base;
    }
  } // BigInteger::subBigInteger


//-----------------------------------------------------------------------------
//
//              BigInteger::multBigInteger(BigInteger&, BigInteger&)
//
void BigInteger::multBigInteger(BigInteger& a, BigInteger& b)
  {
  int smallN = a.nSize/2;
  unsigned __int64 base = 4294967296; // =0x100000000 Number base (64 bits).

  for (int k=0; k<nSize; k++) digit[k] = 0;

  for (int j=0; j<smallN; j++)
    {
    if (b.digit[j] == 0) digit[j+smallN] = 0;

    else
      {
      unsigned int k = 0;

      for (int i=0; i<smallN; i++)
        {
        unsigned __int64 t = ((unsigned __int64)a.digit[i]) * b.digit[j] + (unsigned __int64)digit[i+j] + k;
        digit[i+j] = t % base;
        k = t/base;
        }
      }
    }
 } // BigInteger::multBigInteger


//-----------------------------------------------------------------------------
//
//              BigInteger::addBigInteger(BigInteger&, int)
//
void BigInteger::copyBigInteger(BigInteger& a, int index)
  {
  for (int i=0; i<nSize; i++)
    {
    if (i>=index && (i-index) < a.nSize) digit[i] = a.digit[i-index];
    else digit[i] =0;
    }
  } //BigInteger::copyBigInteger


//-----------------------------------------------------------------------------
//
//              Compare(BigInteger&, BigInteger&)
//
int Compare(BigInteger& first, BigInteger& second)
  {
  int i, nResult=0;

  for (i = (first.nSize-1); i >= 0 ; i--)
    {
    if (first.digit[i] != second.digit[i])
      {
      if (first.digit[i] > second.digit[i])
        {
        nResult = 1;
        break;
        }
      else if (first.digit[i] < second.digit[i])
        {
        nResult = -1;
        break;
        }
     }
  } // Compare

  return nResult;
  }


//-----------------------------------------------------------------------------
//
//              BigInteger::msbBigInteger()
//
int BigInteger::msbBigInteger()
  {
  int i, msb=0;

  for (i = (nSize-1); i >= 0; i--)
    {
    if (digit[i] != 0)
      {
      msb = i;
      break;
      }
    }
  return msb;
  } // BigInteger::msbBigInteger


//-----------------------------------------------------------------------------
//
//              BigInteger::clearBigInteger()
//
void BigInteger::clearBigInteger()
  {
  for (int i = (nSize-1); i >= 0 ; i--) digit[i] = 0;
  } // BigInteger::clearBigInteger


//-----------------------------------------------------------------------------
//
//              normalize(unsigned __int64)
//
__int64 normalize(unsigned __int64 x)
  {
  __int64 n;

  if (x == 0) return(32);
  n = 0;
  if (x <= 0x00000000FFFFFFFF) {n = n + 32; x = x <<32;}
  if (x <= 0x0000FFFFFFFFFFFF) {n = n + 16; x = x <<16;}
  if (x <= 0x00FFFFFFFFFFFFFF) {n = n +  8; x = x << 8;}
  if (x <= 0x0FFFFFFFFFFFFFFF) {n = n +  4; x = x << 4;}
  if (x <= 0x3FFFFFFFFFFFFFFF) {n = n +  2; x = x << 2;}
  if (x <= 0x7FFFFFFFFFFFFFFF) {n = n +  1;}
  return n;
  } // normalize


//-----------------------------------------------------------------------------
//
//     divBigInteger(BigInteger&, BigInteger&, BigInteger&, BigInteger&)
//
int divBigInteger(BigInteger& u, BigInteger& v, BigInteger& q, BigInteger& r)
  {
  int flagCompare = Compare(u, v);

  if (flagCompare == -1)
    {
    q.clearBigInteger();
    r.copyBigInteger(u, 0);
    }

  else if (flagCompare == 0)
    {
    q.clearBigInteger();
    r.clearBigInteger();
    q.digit[0]=1;
    }

  else
    {
    int m = u.msbBigInteger() + 1;
    int n = v.msbBigInteger() + 1;
    unsigned __int64 b = 4294967296;  // =0x100000000 Number base (64 bits).

    // Normalized form of u, v.
    unsigned int *unorm = new unsigned int[2*(m+1)];
    unsigned int *vnorm = new unsigned int[2*n];
    // Estimated quotient digit.
    unsigned __int64 qhat;
    unsigned __int64 rhat;
    // Product of two digits.
    unsigned __int64 p;
    __int64 s, i, j, t, k;

    if (m < n || n <= 0 || v.digit[n-1] == 0)
      return 1;              // Return if invalid param.

    if (n == 1)
      {                      // Take care of the case of a
      k = 0;
      for (j=m-1; j >= 0; j--)
        {                                                // single-digit
        q.digit[j] = (k*b + u.digit[j])/v.digit[0];      // divisor here.
        k = (k*b + u.digit[j]) - q.digit[j]*v.digit[0];
        }
      r.digit[0] = k;
      return 0;
      }

    s = normalize(v.digit[n-1]) - 32;        // 0 <= s <= 15.
    //vnorm = (unsigned int *)malloc(2*n);
    for (i = n-1; i > 0; i--)
      vnorm[i] = (v.digit[i] << s) | (v.digit[i-1] >> (32-s));

    vnorm[0] = v.digit[0] << s;

    //unorm = (unsigned int *)malloc(2*(m + 1));
    unorm[m] = u.digit[m-1] >> (32-s);
    for (i = m-1; i > 0; i--)
      unorm[i] = (u.digit[i] << s) | (u.digit[i-1] >> (32-s));

    unorm[0] = u.digit[0] << s;

    //step D2, D3 loop
    for (j = m-n; j >= 0; j--)
      {
      qhat = (unorm[j+n]*b + unorm[j+n-1])/vnorm[n-1];
      rhat = (unorm[j+n]*b + unorm[j+n-1]) - qhat*vnorm[n-1];

//----
again:
//----

      MSG msg;                                      //ha// Dummy for PeekMessage()
      PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE);   //ha//  seems to solve an issue?

      if (qhat >= b || qhat*vnorm[n-2] > b*rhat + unorm[j+n-2])
        {
        qhat = qhat - 1;
        rhat = rhat + vnorm[n-1];
        if (rhat < b) goto again;
        }

      // D4 Multiply and subtract.
      k = 0;
      for (i=0; i < n; i++)
        {
        p = qhat*vnorm[i];
        t = unorm[i+j] - k - (p & 0xFFFFFFFF);
        unorm[i+j] = t;
        k = (p >> 32) - (t >> 32);
        }

      t = unorm[j+n] - k;
      unorm[j+n] = t;

      q.digit[j] = qhat;              // Store quotient digit.
      if (t < 0)
        {                             // If we subtracted too much, 
        q.digit[j] = q.digit[j] - 1;  // add back.
        k = 0;
        for (i=0; i < n; i++)
          {
          t = unorm[i+j] + vnorm[i] + k;
          unorm[i+j] = t;
          k = t >> 32;
          }

        unorm[j+n] = unorm[j+n] + k;
        }
      } // End for (j)

    for (i=0; i < n; i++)
      r.digit[i] = (unorm[i] >> s) | (unorm[i+1] << (32-s));

    delete[] unorm;
    delete[] vnorm;
    }
  return 0;
  } // divBigInteger


//-----------------------------------------------------------------------------
//
//     gcdBigInteger(BigInteger&, BigInteger&, BigInteger&)
//
void gcdBigInteger(BigInteger& a, BigInteger& b, BigInteger& result)
  {
  BigInteger tmpa(a.nSize);
  BigInteger tmpb(a.nSize);

  tmpa.copyBigInteger(a, 0);
  tmpb.copyBigInteger(b, 0);

  if (tmpb.msbBigInteger() == 0 && tmpb.digit[0] == 0)
    {
    for (int i=0; i<result.nSize; i++)
      {
      result.digit[i] = tmpa.digit[i];
      }
    }
  else
    {
    BigInteger q(a.nSize);
    BigInteger r(a.nSize);
    divBigInteger(tmpa, tmpb, q, r);
    gcdBigInteger(tmpb, r, result);
    }
  } // gcdBigInteger


//-----------------------------------------------------------------------------
//
// BigInteger::expoModNBigInteger(BigInteger&, BigInteger&, BigInteger&, BigInteger&)
//
// Encryption
//  BigInteger temp(SIZE);
//  temp.expoModNBigInteger(msg, e, N, code);     // RSA Public key
//
// Decipher
//  BigInteger temp(SIZE);
//  temp.expoModNBigInteger(code, d, N, msg);     // RSA Private key
//
// !! Must try/catch an exception here (if Prime Number gets to big and may overflow) !!
//
void BigInteger::expoModNBigInteger(BigInteger& x, BigInteger& y, BigInteger& N, BigInteger& result)
  {
  /////////////////////////////////////  //ha//
  //   EXCEPTION DETECTION START     //  //ha//
  //                                 //  //ha//
  //  Start of code section that     //  //ha//
  //   might cause an exception      //  //ha//
  //                                 //  //ha//
  try {                              //  //ha//
  /////////////////////////////////////  //ha//

    // Display a dot every 5000 re-entry loops to show we're working on it         //ha//
    // However, sometimes calculation the prime numbers might lock up things here. //ha//
    // No idea what exactly happens. So restart program and try again.             //ha//
    //                                                                             //ha//
    recoursionCnt++;                                          // Counter           //ha//
    if (recoursionCnt % 5000LL == 0) editTextField(_T("."));  // Display           //ha//

    if (y.msbBigInteger() == 0 && y.digit[0] == 0)
      {
      result.digit[0] = 1;
      for (int i=1; i < result.nSize; i++) result.digit[i] = 0;
      }

    else
      {
      BigInteger temp(nSize);
      BigInteger reminder(nSize);

      BigInteger value2(nSize);
      value2.digit[0] = 2;

      divBigInteger(y, value2, *this, reminder);

      temp.copyBigInteger(*this, 0);

      // Recoursion, sometimes causes an exception! //ha//
      expoModNBigInteger(x, temp, N, result);  

      multBigInteger(result, result);

      temp.copyBigInteger(*this, 0);
      if (y.digit[0] % 2 != 0)
        {
        multBigInteger(temp, x);
        temp.copyBigInteger(*this, 0);
        }

      BigInteger q(nSize), r(nSize);
      divBigInteger(temp, N, q, r);
      result.copyBigInteger(r, 0);
      }

    /////////////////////////////////////  //ha//
    //   EXCEPTION DETECTION END       //  //ha//
    //                                 //  //ha//
    //   End of code section that      //  //ha//
    //   might cause an exception      //  //ha//
    //                                 //  //ha//
    } // end try                       //  //ha//
    //                                 //  //ha//
    /////////////////////////////////////  //ha//

  /////////////////////////////////////  //ha//
  //       EXCEPTION HANDLING        //  //ha//
  //                                 //  //ha//
  //  Code to handle any exception   //  //ha//
  //                                 //  //ha//
  catch(...) {                       //  //ha//
    // Alert the user                /////////////////////////////////////////////////  //ha//
    CBTMessageBox(NULL, _T("Random Prime Number overflow.\n\nExiting program ...\n")//  //ha//
                        _T( "Please restart and try again."),                       //  //ha//
                        _T( " - EXCEPTION - "), MB_OK | MB_ICONERROR);              //  //ha//
    // 'haCrypt*.EXE' task is still pending and needs to be removed.                //  //ha//
    UINT uExitCode = 0x01;                       // Just any number <> 0            //  //ha//
    DWORD dwProcessId = GetCurrentProcessId();                                      //  //ha//
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessId);           //  //ha//
    BOOL result = TerminateProcess(hProcess, uExitCode);                            //  //ha//
    CloseHandle(hProcess);                                                          //  //ha//
//#ifdef x64 // 64 bit (Visual Studio 2019)      // Kill task by filename           //  //ha//
    //system("taskkill /f /im haCrypt64.exe");   // Alternative, deprecated         //  //ha//
//#else      // 32 bit                                                              //  //ha//
    //system("taskkill /f /im haCrypt.exe");     // Alternative, deprecated         //  //ha//
//#endif                                                                            //  //ha//
    // Perform the 'Exit' command                                                   //  //ha//
    PostMessage(hMain, WM_COMMAND, ID_FILE_EXIT, 0);                                //  //ha//
    } // end catch(...)              /////////////////////////////////////////////////  //ha//
  //                                 //  //ha//
  /////////////////////////////////////  //ha//

  return;
  } // BigInteger::expoModNBigInteger


//-----------------------------------------------------------------------------
//
//                      BigInteger::setSize(int)
//
void BigInteger::setSize(int n)
  {
  nSize = n;
  digit = new unsigned int[n];
  digitResult = new unsigned int[n];

  for (int i=0; i < nSize; i++)
    {
    digit[i] = 0;
    digitResult[i] = 0;
    }
  } // BigInteger::setSize

//-----------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "j=%i\ndigit[7..0] = %08X %08X %08X %08X %08X %08X %08X %08X\n"
//ha//                  "pszRsaExternbuf[ 0..15] = %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X"
//ha//                  "pszRsaExternbuf[16..31] = %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
//ha//                    j,
//ha//                    digit[7], digit[6], digit[5], digit[4],
//ha//                    digit[3], digit[2], digit[1], digit[0],
//ha//                    (UCHAR)pszRsaExternbuf[0],  (UCHAR)pszRsaExternbuf[1],  (UCHAR)pszRsaExternbuf[2],  (UCHAR)pszRsaExternbuf[3],
//ha//                    (UCHAR)pszRsaExternbuf[4],  (UCHAR)pszRsaExternbuf[5],  (UCHAR)pszRsaExternbuf[6],  (UCHAR)pszRsaExternbuf[7],
//ha//                    (UCHAR)pszRsaExternbuf[8],  (UCHAR)pszRsaExternbuf[9],  (UCHAR)pszRsaExternbuf[10], (UCHAR)pszRsaExternbuf[11],
//ha//                    (UCHAR)pszRsaExternbuf[12], (UCHAR)pszRsaExternbuf[13], (UCHAR)pszRsaExternbuf[14], (UCHAR)pszRsaExternbuf[15],
//ha//                    (UCHAR)pszRsaExternbuf[16], (UCHAR)pszRsaExternbuf[17], (UCHAR)pszRsaExternbuf[18], (UCHAR)pszRsaExternbuf[19],
//ha//                    (UCHAR)pszRsaExternbuf[20], (UCHAR)pszRsaExternbuf[21], (UCHAR)pszRsaExternbuf[22], (UCHAR)pszRsaExternbuf[23],
//ha//                    (UCHAR)pszRsaExternbuf[24], (UCHAR)pszRsaExternbuf[25], (UCHAR)pszRsaExternbuf[26], (UCHAR)pszRsaExternbuf[27],
//ha//                    (UCHAR)pszRsaExternbuf[28], (UCHAR)pszRsaExternbuf[29], (UCHAR)pszRsaExternbuf[30], (UCHAR)pszRsaExternbuf[31]
//ha//                    );
//ha//// Display data in a message box window
//ha//MessageBoxA(NULL, DebugBuf, "digit[] #0", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "_l=%i\nszRsaTempbuf[%i] = %08X\ndigit[%i]=%08X", _l, j, szRsaTempbuf[j], i, digit[i]);
//ha//// Display data in a message box window
//ha//MessageBoxA(NULL, DebugBuf, "BigInteger::__getDigits 1", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "digit[%i] = %08X\ndigit[j] = %08X\ndigit[j-1] = %08X\n
//ha//                   i, digit[i], digit[j], digit[j-1], (4*(i-l)),
//ha//                   (UCHAR)szRsaDatabuf[4*(i-l)+0], (UCHAR)szRsaDatabuf[4*(i-l)+1],
//ha//                   (UCHAR)szRsaDatabuf[4*(i-l)+2], (UCHAR)szRsaDatabuf[4*(i-l)+3],
//ha//                   i, j, k, l, (4*i));
//ha//MessageBoxA(NULL, DebugBuf, "BigInteger::showDigits 1", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "digit[j] = %08X\ndigit[j-1] = %08X\nszRsaDatabuf[%i] = %02X%02X%02X%02X\ni = %i\nj = %i\nk = %i\nl = %i\n(4*i) = %i",
//ha//                   digit[j], digit[j-1], (4*(i-l)),
//ha//                   (UCHAR)szRsaDatabuf[4*(i-l)+0], (UCHAR)szRsaDatabuf[4*(i-l)+1],
//ha//                   (UCHAR)szRsaDatabuf[4*(i-l)+2], (UCHAR)szRsaDatabuf[4*(i-l)+3],
//ha//                   i, j, k, l, (4*i));
//ha//MessageBoxA(NULL, DebugBuf, "BigInteger::showDigits 1", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "digit[%i] = %08X\nszRsaDatabuf[%i] = %02X%02X%02X%02X\nk = %i",
//ha//                   j, digit[j], 4*i,
//ha//                   (UCHAR)szRsaDatabuf[4*i+0], (UCHAR)szRsaDatabuf[4*i+1],
//ha//                   (UCHAR)szRsaDatabuf[4*i+2], (UCHAR)szRsaDatabuf[4*i+3],
//ha//                   k);
//ha//MessageBoxA(NULL, DebugBuf, "BigInteger::showDigits 4", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "_buf = %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
//ha//                     (UCHAR)&digitReverse[0], (UCHAR)&digitReverse[1], (UCHAR)&digitReverse[2], (UCHAR)&digitReverse[3],
//ha//                     (UCHAR)&digitReverse[4], (UCHAR)&digitReverse[5], (UCHAR)&digitReverse[6], (UCHAR)&digitReverse[7], 
//ha//                     (UCHAR)&digitReverse[8], (UCHAR)&digitReverse[9], (UCHAR)&digitReverse[10],(UCHAR)&digitReverse[11],
//ha//                     (UCHAR)&digitReverse[12],(UCHAR)&digitReverse[13],(UCHAR)&digitReverse[14],(UCHAR)&digitReverse[15]);
//ha//// Display data in a message box window
//ha//MessageBoxA(NULL, DebugBuf, "digitReverse[]", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "_buf = %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
//ha//  (UCHAR)szRsabuf[0], (UCHAR)szRsabuf[1], (UCHAR)szRsabuf[2], (UCHAR)szRsabuf[3],
//ha//  (UCHAR)szRsabuf[4], (UCHAR)szRsabuf[5], (UCHAR)szRsabuf[6], (UCHAR)szRsabuf[7], 
//ha//  (UCHAR)szRsabuf[8], (UCHAR)szRsabuf[9], (UCHAR)szRsabuf[10],(UCHAR)szRsabuf[11],
//ha//  (UCHAR)szRsabuf[12],(UCHAR)szRsabuf[13],(UCHAR)szRsabuf[14],(UCHAR)szRsabuf[15]);
//ha//// Display data in a message box window
//ha//MessageBoxA(NULL, DebugBuf, "digitReverse[]", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

