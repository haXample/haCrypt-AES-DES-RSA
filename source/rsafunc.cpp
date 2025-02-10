// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// rsafunc.cpp - C++ Developer source file.
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
// https://github.com/jubaer-pantho/RSA-Implementation-Cpp/blob/master/RSABigInteger.cpp

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

#include "haCrypt.h"
#include "RSAfuncC.h"

using namespace std;

extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text

extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern unsigned __int64 recoursionCnt;

extern void editTextField(TCHAR*);

//-----------------------------------------------------------------------------
//
//                RSAfunc::RSAfunc(int)
//
RSAfunc::RSAfunc(int nSize)
  {
  SIZE= nSize;
  N.setSize(nSize);
  d.setSize(nSize);
  e.setSize(nSize);
  _phi.setSize(nSize);     //ha//
  } // RSAfunc::RSAfunc


//-----------------------------------------------------------------------------
//
//                RSAfunc::~RSAfunc
//
RSAfunc::~RSAfunc()
  {
  } // RSAfunc::~RSAfunc


//-----------------------------------------------------------------------------
//
//                RSAfunc::init(BigInteger&, BigInteger&)
//
void RSAfunc::init(BigInteger&p, BigInteger& q)
  {
  N.multBigInteger(p, q);

  BigInteger one(p.nSize);
  BigInteger phi(p.nSize);
  BigInteger tempP(p.nSize), tempQ(p.nSize);

  one.digit[0] = 1;

  tempP.subBigInteger(p, one);
  tempQ.subBigInteger(q, one);

  phi.multBigInteger(tempP, tempQ);
  _phi.copyBigInteger(phi, 0);      //ha// Copy starts at index[0]

  eGeneration(phi, e);
  CalculateD(e, phi, d);
  } // RSAfunc::init


//ha//-----------------------------------------------------------------------------
//
//                RSAfunc::loadKey()
//
void RSAfunc::loadKey(int _mode)
  {
  switch(_mode)
    {
    case RSA_MODE_PUBKEYN:
      N.loadBigInteger(_mode);
      break;
    case RSA_MODE_PUBKEYE:
      e.loadBigInteger(_mode);
      break;
    case RSA_MODE_PRVKEYN:
      N.loadBigInteger(_mode);
      break;
    case RSA_MODE_PRVKEYD:
      d.loadBigInteger(_mode);
      break;
    default:
      return;
    }
  } // RSAfunc::loadKey


//-----------------------------------------------------------------------------
//
//                RSAfunc::eGeneration(BigInteger&, BigInteger&)
//
void RSAfunc::eGeneration(BigInteger& phi, BigInteger& result)
  {
  BigInteger temp(phi.nSize);
  temp.digit[0]=3;
  BigInteger value2(phi.nSize);
  value2.digit[0]=2;
  BigInteger temp2(phi.nSize);

  while(1)
    {
    BigInteger gcdValue(phi.nSize);
    gcdBigInteger(phi, temp, gcdValue);

    if (gcdValue.msbBigInteger() == 0 && gcdValue.digit[0]==1)
      {
      break;
      }
    temp2.addBigInteger(temp, value2);
    temp.copyBigInteger(temp2, 0);
    }
  result.copyBigInteger(temp, 0);
  } // RSAfunc::eGeneration


//ha//-----------------------------------------------------------------------------
//
//                    RSAfunc::showPublicKey()
//
//
//  RSAPublicKey ::= SEQUENCE {
//    modulus INTEGER, -- n
//    publicExponent INTEGER -- e                   // e stands for 'encrypt'
//    }
//
void RSAfunc::showPublicKey(TCHAR* _filename)
  {
  if (_filename != NULL)
    {
    editTextField(_filename);
    editTextField( _T("\x0D\x0A"));
    }
     
  // Store into edit field
  editTextField(_T("\x0D\x0A")
                _T("RSAPublicKey ::= SEQUENCE {\x0D\x0A"));
 
  editTextField(_T("  rsaModulus (p*q) INTEGER N    = ")); // Append.
  N.__getDigits(RSA_MODE_PUBKEYN, RSA_SHOW_DIGITS);

  editTextField(_T("  publicExponent INTEGER e      = ")); // Append
  e.__getDigits(RSA_MODE_PUBKEYE, RSA_SHOW_DIGITS);

  editTextField(_T("  }\x0D\x0A")); // Append
  } // RSAfunc::showPublicKey


//ha//-----------------------------------------------------------------------------
//
//                  RSAfunc::showPrivateKey()
//
//
//  RSAPrivateKey ::= SEQUENCE {
//    version Version,
//    modulus INTEGER, -- n
//    publicExponent INTEGER, -- e                  // e stands for 'encrypt'
//    privateExponent INTEGER, -- d                 // d stands for 'decipher'
//    prime1 INTEGER, -- p
//    prime2 INTEGER, -- q
//    exponent1 INTEGER, -- d mod (p-1)
//    exponent2 INTEGER, -- d mod (q-1)
//    coefficient INTEGER, -- (inverse of q) mod p
//    otherPrimeInfos OtherPrimeInfos OPTIONAL
//    }
//
void RSAfunc::showPrivateKey(BigInteger& primeNumberP, BigInteger& primeNumberQ)
  {
  // Store into edit field
  editTextField(_T("\x0D\x0A")
                _T("RSAPrivateKey ::= SEQUENCE {\x0D\x0A"));
  
  editTextField(_T("  rsaModulus (p*q) INTEGER N    = ")); // Append.
  N.__getDigits(RSA_MODE_PRVKEYN, RSA_SHOW_DIGITS);

  editTextField(_T("  privateExponent INTEGER d     = ")); // Append
  d.__getDigits(RSA_MODE_PRVKEYD, RSA_SHOW_DIGITS);

  editTextField(_T("  prime1 INTEGER p              = ")); // Append
  primeNumberP.__getDigits(RSA_MODE_DATA, RSA_SHOW_DIGITS);

  editTextField(_T("  prime2 INTEGER q              = ")); // Append
  primeNumberQ.__getDigits(RSA_MODE_DATA, RSA_SHOW_DIGITS);

  editTextField(_T("  phi  INT (p-1)*(q-1)          = ")); // Append
  _phi.__getDigits(RSA_MODE_DATA, RSA_SHOW_DIGITS);

  editTextField(_T("  exp1 INT d mod (p-1)          = N/A\x0D\x0A")); // Append
  editTextField(_T("  exp2 INT d mod (q-1)          = N/A\x0D\x0A")); // Append
  editTextField(_T("  coef INT (inverse of q) mod p = N/A\x0D\x0A")); // Append
  editTextField(_T("  }\x0D\x0A"));                        // Append
  } // RSAfunc::showPrivateKey


//ha//-----------------------------------------------------------------------------
//
//                  RSAfunc::showLoadedPrivateKey()
//
//
//  RSAPrivateKey ::= SEQUENCE {
//    version Version,
//    modulus INTEGER, -- n
//    publicExponent INTEGER, -- e                  // e stands for 'encrypt'
//    privateExponent INTEGER, -- d                 // d stands for 'decipher'
//    prime1 INTEGER, -- p
//    prime2 INTEGER, -- q
//    exponent1 INTEGER, -- d mod (p-1)
//    exponent2 INTEGER, -- d mod (q-1)
//    coefficient INTEGER, -- (inverse of q) mod p
//    otherPrimeInfos OtherPrimeInfos OPTIONAL
//    }
//
void RSAfunc::showLodedPrivateKey(TCHAR* _filename)
  {
  if (_filename != NULL)
    {
    editTextField(_filename);
    editTextField( _T("\x0D\x0A"));
    } 

  // Store into edit field
  editTextField(_T("\x0D\x0A")
                _T("RSAPrivateKey ::= SEQUENCE {\x0D\x0A"));
  
  editTextField(_T("  rsaModulus (p*q) INTEGER N    = ")); // Append.
  N.__getDigits(RSA_MODE_PRVKEYN, RSA_SHOW_DIGITS);

  editTextField(_T("  privateExponent INTEGER d     = ")); // Append
  d.__getDigits(RSA_MODE_PRVKEYD, RSA_SHOW_DIGITS);

  editTextField(_T("  }\x0D\x0A")); // Append
  } // RSAfunc::showLoadedPrivateKey


//ha//-----------------------------------------------------------------------------
//
//                  RSAfunc::__setDigits(BigInteger&, int)
//
void RSAfunc::__setDigits(BigInteger& randResult, char* inbuf, int _n)
  {
  int i, j=0;

  for (i=0; i < RSA_BUFFER_SIZE; i++) randResult.digit[i] = 0;

  for (i=(_n/sizeof(int))-1; i >= 0; i--)
    {
    randResult.digit[i] |= (inbuf[j++] << 24) & 0xFF000000;
    randResult.digit[i] |= (inbuf[j++] << 16) & 0x00FF0000;
    randResult.digit[i] |= (inbuf[j++] <<  8) & 0x0000FF00;
    randResult.digit[i] |= inbuf[j++]         & 0x000000FF;
    }
  } // RSAfunc::__setDigits


//-----------------------------------------------------------------------------
//
//                RSAfunc::encryption(BigInteger&, BigInteger&)
//
void RSAfunc::encryption(BigInteger& msg, BigInteger& code)
  {
  recoursionCnt = 0;              //ha// Reset recoursion counter          

  BigInteger temp(SIZE);
  temp.expoModNBigInteger(msg, e, N, code);     // RSA Public key
  } // RSAfunc::encryption


//-----------------------------------------------------------------------------
//
//                RSAfunc::decryption(BigInteger&, BigInteger&)
//
void RSAfunc::decryption(BigInteger& code, BigInteger& msg)
  {
  recoursionCnt = 0;              //ha// Reset recoursion counter          

  BigInteger temp(SIZE);
  temp.expoModNBigInteger(code, d, N, msg);     // RSA Private key
  } // RSAfunc::decryption


//-----------------------------------------------------------------------------
//
//            RSAfunc::primeNumberGeneration(BigInteger&, int)
//
void RSAfunc::primeNumberGeneration(BigInteger& randPrime, int n)
  {
  int index;
  recoursionCnt = 0LL;                   //ha// Init clear dot counter

  BigInteger valueOne(randPrime.nSize);
  valueOne.digit[0] = 1;
  BigInteger valueTwo(randPrime.nSize);
  valueTwo.digit[0] = 2;
  BigInteger valueThree(randPrime.nSize);
  valueThree.digit[0] = 3;

  BigInteger tempPrime(randPrime.nSize);
  BigInteger tempExpoDummy(randPrime.nSize);
  BigInteger ExpoDummy(randPrime.nSize);

  BigInteger tempRemainder(randPrime.nSize);
  BigInteger tempPrimeMinusOne(randPrime.nSize);
  randomNGeneration(tempPrime, n);

  while(1)   // ("Please wait. ");
    {
    tempPrimeMinusOne.clearBigInteger();
    tempRemainder.clearBigInteger();
    ExpoDummy.clearBigInteger();
    tempExpoDummy.clearBigInteger();
    tempPrimeMinusOne.subBigInteger(tempPrime, valueOne);

    ExpoDummy.expoModNBigInteger(valueTwo, tempPrimeMinusOne, tempPrime, tempRemainder);

    if (tempRemainder.msbBigInteger()==0 && tempRemainder.digit[0]==1)
      {
      editTextField(_T("-"));            //ha// Show that we re-entered this function
      tempRemainder.clearBigInteger();
      tempExpoDummy.expoModNBigInteger(valueThree, tempPrimeMinusOne, tempPrime, tempRemainder);
      if (tempRemainder.msbBigInteger()==0 && tempRemainder.digit[0]==1)
        {
        break;
        }
      }

    tempPrime.clearBigInteger();
    randomNGeneration(tempPrime, n);
    } // end while(1)

  editTextField(_T(" done.\x0D\x0A"));   //ha// Append
  recoursionCnt = 0LL;                   //ha// Reset dot counter
  
  randPrime.copyBigInteger(tempPrime, 0);
  } // RSAfunc::primeNumberGeneration


//-----------------------------------------------------------------------------
//
//            RSAfunc::__randomNGeneration(BigInteger&, int)  -FOR DEBUG ONLY-
//
void RSAfunc::__randomNGeneration(BigInteger& randResult, int n)
  {
  int i;

  for (i = 0; i < 2*n; i++) randResult.digit[i] = 0;

  for (i = 0; i < n; i++)
    {
    randResult.digit[i] = 0x12345678;
    }
  } // RSAfunc::__randomNGeneration


//-----------------------------------------------------------------------------
//
//            RSAfunc::randomNGeneration(BigInteger&, int)
//
void RSAfunc::randomNGeneration(BigInteger& randResult, int n)
  {
  int i;

  for (i = 0; i < 2*n; i++) randResult.digit[i] = 0; //ha// Ensures 256 bits are clear

  for (i = 0; i < n; i++)
    {
    MSG msg;                                      //ha// Dummy for PeekMessage()
    PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE);   //ha//  seems to solve an issue?

    unsigned int rnd = rand();
    randResult.digit[i] = randResult.digit[i] | rnd<<16;
    rnd = rand();
    randResult.digit[i] = randResult.digit[i] | rnd<<1;
    }
  randResult.digit[0] = randResult.digit[0] | 1;
  randResult.digit[n-1] = randResult.digit[n-1] | 1<<30;
  } // RSAfunc::randomNGeneration


//-----------------------------------------------------------------------------
//
//      RSAfunc::CalculateD(BigInteger&, BigInteger&, BigInteger&)
//
void RSAfunc::CalculateD(BigInteger& e, BigInteger& phi, BigInteger& d)
  {
  int i = 0;
  BigInteger temp1(phi.nSize), temp2(phi.nSize), quotient(phi.nSize), remainder(phi.nSize);
  BigInteger one(phi.nSize);
  one.digit[0] = 1;
  BigInteger k(phi.nSize);
  while(true)
    {
    i++;
    k.digit[0] = i;
    temp1.multBigInteger(k, phi);
    temp2.addBigInteger(temp1, one);
    divBigInteger(temp2, e, quotient, remainder);
    if (remainder.msbBigInteger() == 0 && remainder.digit[0] == 0)
      {
      d.copyBigInteger(quotient, 0);
      break;
      }
    }
  } // RSAfunc::CalculateD

//-----------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf,
//ha//                  "code[15..8] = %08X %08X %08X %08X %08X %08X %08X %08X\n"
//ha//                  "code[7..0] = %08X %08X %08X %08X %08X %08X %08X %08X\n"
//ha//                  "msg[15..0] = %08X %08X %08X %08X %08X %08X %08X %08X\n"
//ha//                  "msg[7..0] = %08X %08X %08X %08X %08X %08X %08X %08X",
//ha//                    code.digit[15], code.digit[14], code.digit[13], code.digit[12],
//ha//                    code.digit[11], code.digit[10], code.digit[9],  code.digit[8],
//ha//                    code.digit[7], code.digit[6], code.digit[5], code.digit[4],
//ha//                    code.digit[3], code.digit[2], code.digit[1], code.digit[0],
//ha//                    msg.digit[15], msg.digit[14], msg.digit[13], msg.digit[12],
//ha//                    msg.digit[11], msg.digit[10], msg.digit[9],  msg.digit[8],
//ha//                    msg.digit[7], msg.digit[6], msg.digit[5], msg.digit[4],
//ha//                    msg.digit[3], msg.digit[2], msg.digit[1], msg.digit[0]
//ha//                    );
//ha//// Display data in a message box window
//ha//MessageBoxA(NULL, DebugBuf, "RSAfunc::decryption 1", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "_buf = %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
//ha//  (UCHAR)((digit[3] & 0xFF000000)>>24), (UCHAR)((digit[3] & 0x00FF0000)>>16), (UCHAR)((digit[3] & 0x0000FF00)>>8), (UCHAR)(digit[3] & 0xFF),
//ha//  (UCHAR)((digit[2] & 0xFF000000)>>24), (UCHAR)((digit[2] & 0x00FF0000)>>16), (UCHAR)((digit[2] & 0x0000FF00)>>8), (UCHAR)(digit[2] & 0xFF),
//ha//  (UCHAR)((digit[1] & 0xFF000000)>>24), (UCHAR)((digit[1] & 0x00FF0000)>>16), (UCHAR)((digit[1] & 0x0000FF00)>>8), (UCHAR)(digit[1] & 0xFF),
//ha//  (UCHAR)((digit[0] & 0xFF000000)>>24), (UCHAR)((digit[0] & 0x00FF0000)>>16), (UCHAR)((digit[0] & 0x0000FF00)>>8), (UCHAR)(digit[0] & 0xFF));
//ha//// Display data in a message box window
//ha//MessageBoxA(NULL, DebugBuf, "digitReverse[]", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "j=%i\n_n/sizeof(int)=%i\nrandResult.digit[%i]=%08X", j, _n/sizeof(int), i, randResult.digit[i]);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG RSAfunc::__setDigits 01", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
