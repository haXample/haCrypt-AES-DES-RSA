// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// rsabigintegerC.h - C++ Developer source file.
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

// https://www.tutorialspoint.com/cplusplus-program-to-implement-the-rsa-algorithm
// https://github.com/jubaer-pantho/RSA-Implementation-Cpp/blob/master/BigInteger.h

#ifndef BIGINTEGER_H
#define BIGINTEGER_H

//----------------------------------------------------------------------------
//
//                        class BigInteger
//
//  -----------------------------------------------------------------------------
//  If you would like to ensure that a class is instantiated only once,
//   then I would use the singleton pattern
//   (well, it's the purpose of this pattern :) ):
//  
//  class BigInteger
//  {
//  public:
//      static void init() { if (_instance == 0) _instance = new BigInteger(); }
//      static void term() { delete _instance; }
//  
//      // Here you have some options, like automatically initializing, 
//      // or throwing an exception etc. if init() has not been called
//      static BigInteger* instance() { return _instance; } 
//  
//  
//      ... void draw(unsigned int depth);
//  
//  private:
//      // Hide constructor
//      BigInteger(); 
//      // Hide copy constructor (no implementation needed)
//      BigInteger(const BigInteger&); 
//      // Hide assignment operator (no implementation needed)
//      BigInteger& operator=(const BigInteger&); 
//  
//      // Your one and only instance of the class
//      static BigInteger* _instance;
//  
//      ... float vertexArray[3840][3];
//      ... float texCoords[3840][2];
//  
//      // functions go here that fill above arrays
//  };
//  
//  In your source file:
//  BigInteger* BigInteger::_instance = 0; // same as with extern BigInteger BigInteger;
//  
//  Using the BigInteger functions somewhere in other code:
//  BigInteger::instance()->draw();
//  
//  And don't forget to init the BigInteger class somewhere in your code
//   (or make it automatic on first call of instance()).
//   Call to term() is necessary to avoid mem leak.
//  Having a singleton class is better than an extern variable
//   because you ensure that you have exactly one instance of the class,
//   and you have more precise control of when the single instance is initialized
//   (say, you may want glInit() to be called before glGenBuffers()
//   you might use in BigInteger constructor).
//  -----------------------------------------------------------------------------
//
class BigInteger
  {
  public:
    int nSize;
    unsigned int *digit;
    unsigned int *digitReverse;  //ha//
    unsigned int *digitResult;   //ha//

    BigInteger() {}
    BigInteger(int n);
    BigInteger(const BigInteger &obj);
    ~BigInteger();

    void addBigInteger(BigInteger& a, BigInteger& b);
    void subBigInteger(BigInteger& a, BigInteger& b);
    void multBigInteger(BigInteger& a, BigInteger& b);
    void copyBigInteger(BigInteger& a, int index);
    void expoModNBigInteger(BigInteger& x, BigInteger& y, BigInteger& N, BigInteger& result);
    void setSize(int n);
    int msbBigInteger();
    void clearBigInteger();
    void loadBigInteger(int);                             //ha//
    void readDigits();                                    //ha//
    void writeDigits();                                   //ha//
    void byteSwap16(unsigned int*, unsigned int*);        //ha//
    void showStringA(int);                                //ha//
    void showDigitsResult(int);                           //ha//
    int __getDigits(int, int);                            //ha//
    void copy2digits(char*, int);                         //ha//
    void setDigits(int index);

  }; // class BigInteger

int Compare(BigInteger& first, BigInteger& second);
int divBigInteger(BigInteger& u, BigInteger& v, BigInteger& q, BigInteger& r);
void gcdBigInteger(BigInteger& a, BigInteger& b, BigInteger& result);

#endif // BIGINTEGER_H




























