// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// rsafuncC.h - C++ Developer source file.
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
// https://github.com/jubaer-pantho/RSA-Implementation-Cpp/blob/master/RSABigInteger.h

#ifndef RSABIGINTEGER_H
#define RSABIGINTEGER_H

#include "RSAbigIntegerC.h"

//----------------------------------------------------------------------------
//
//                    class RSAfunc
//
//  -----------------------------------------------------------------------------
//  If you would like to ensure that a class is instantiated only once,
//   then I would use the singleton pattern
//   (well, it's the purpose of this pattern :) ):
//  
//  class RSAfunc
//  {
//  public:
//      static void init() { if (_instance == 0) _instance = new RSAfunc(); }
//      static void term() { delete _instance; }
//  
//      // Here you have some options, like automatically initializing, 
//      // or throwing an exception etc. if init() has not been called
//      static RSAfunc* instance() { return _instance; } 
//  
//  
//      ... void draw(unsigned int depth);
//  
//  private:
//      // Hide constructor
//      RSAfunc(); 
//      // Hide copy constructor (no implementation needed)
//      RSAfunc(const RSAfunc&); 
//      // Hide assignment operator (no implementation needed)
//      RSAfunc& operator=(const RSAfunc&); 
//  
//      // Your one and only instance of the class
//      static RSAfunc* _instance;
//  
//      ... float vertexArray[3840][3];
//      ... float texCoords[3840][2];
//  
//      // functions go here that fill above arrays
//  };
//  
//  In your source file:
//  RSAfunc* RSAfunc::_instance = 0; // same as with extern RSAfunc RSAfunc;
//  
//  Using the RSAfunc functions somewhere in other code:
//  RSAfunc::instance()->draw();
//  
//  And don't forget to init the RSAfunc class somewhere in your code
//   (or make it automatic on first call of instance()).
//   Call to term() is necessary to avoid mem leak.
//  Having a singleton class is better than an extern variable
//   because you ensure that you have exactly one instance of the class,
//   and you have more precise control of when the single instance is initialized
//   (say, you may want glInit() to be called before glGenBuffers()
//   you might use in RSAfunc constructor).
//  -----------------------------------------------------------------------------
//
class RSAfunc
  {
  public:
    RSAfunc() {}
    RSAfunc(int nSize);
    virtual ~RSAfunc();

    void CalculateD(BigInteger& e, BigInteger& phi, BigInteger& d);
    void init(BigInteger&p, BigInteger& q);
    void eGeneration(BigInteger& phi,BigInteger& result);
    void showPublicKey(TCHAR*);                                                    //ha//
    void loadKey(int);                                                       //ha//
    void showPrivateKey(BigInteger& primeNumberP, BigInteger& primeNumberQ); //ha//
    void showLodedPrivateKey(TCHAR*);                                              //ha// "showLoaded.."
    void __setDigits(BigInteger& randResult, char* inbuf, int n);            //ha//
    void __randomNGeneration(BigInteger& randResult, int n);                 //ha// FOR DEBUG ONLY
    void randomNGeneration(BigInteger& randResult, int n);
    void encryption(BigInteger& msg, BigInteger& code);
    void decryption(BigInteger& code, BigInteger& msg);
    void primeNumberGeneration(BigInteger& randPrime, int n);

  private:
    int SIZE;
    BigInteger N;
    BigInteger d;
    BigInteger e;
    BigInteger _phi;

  }; // class RSAfunc

#endif // RSABIGINTEGER_H
