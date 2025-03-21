;; haCrypt - Crypto tool for DES, AES, TDEA and RSA.
;; tdesfast.asm - MASM Developer source file for 3DES.
;; (c)2021 by helmut altmann

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 2 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program; see the file COPYING.  If not, write to
;; the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
;; Boston, MA 02111-1307, USA.

.MODEL FLAT
.686P                   ; All latest Intel CPUs (won't run on older PCs)
.XMM                    ; All latest Intel CPUs (won't run on older PCs)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                                                                           ;;
;; MS Visual C++ specific memset() prototype                                 ;;
;; It is defined in <cstring> header file.                                   ;;
;;  void* memset(void* dest, int ch, size_t count);                          ;;
;;                                                                           ;;
;;memset PROTO C, dest:DWORD, char:DWORD, count:DWORD ; = EXTRN _memset:PROC ;;
;;                                                                           ;;
;; memset() Parameters                                                       ;;
;;    dest: Pointer to the object to copy the character.                     ;;
;;    ch: The character to copy.                                             ;;
;;    count: Number of times to copy.                                        ;;
;;                                                                           ;;
;; memset() Return value                                                     ;;
;; The memset() function returns dest, a pointer to the destination string.  ;;
;;                                                                           ;;
;; The memset() function takes three arguments;  dest, ch and count.         ;;
;;  The character represented by ch is first converted to unsigned char      ;;
;;   and then copies it into the first count characters                      ;;
;;    of the object pointed to by dest.                                      ;;
;;                                                                           ;;
;; Example C++:                                                              ;;
;;                                                                           ;;
;;#include <cstring>                                                         ;;
;;#include <iostream>                                                        ;;
;;                                                                           ;;
;;using namespace std;                                                       ;;
;;                                                                           ;;
;;int main()                                                                 ;;
;;{                                                                          ;;
;;    char dest[50];                                                         ;;
;;    char ch = 'a';                                                         ;;
;;    mmset(dest, ch, 20);                                                   ;;
;;                                                                           ;;
;;    cout << "After calling memset" << endl;                                ;;
;;    cout << "dest contains " << dest;                                      ;;
;;    return 0;                                                              ;;
;;}                                                                          ;;
;; When you run the program, the output will be:                             ;;
;;  After calling memset                                                     ;;
;;  dest contains aaaaaaaaaaaaaaaaaaaa                                       ;;
;;                                                                           ;;
;; cdecl convention; params pushed on stack right to left                    ;;
;;                                                                           ;;
;;;;;;;;;; MS Visual C++ specific "_memset" Parameters:                      ;;
        ;; param 3 = count                              = push BLOCK_SIZE    ;;
        ;; param 2 = (unsigned char)(0) to be copied    = push 0             ;;
;;;;;;;;;; param 1 = destination (outblock)             = push eax           ;;
;;                                                                           ;;
;;      INVOKE memset, eax, 0, BLOCK_SIZE  ; permute                         ;;
;;      INVOKE memset, ecx, 0, eax         ; desalgorithm                    ;;
;;                                                                           ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;
;; The PERMUTATION_48BIT_BLOCK macro supports the definition of the permuted
;; choice tables. It transforms the notation described in the DES specs into
;; the convention expected by this algorithm. Its purpose is mainatin legibility.
;;
PERMUTATION_48BIT_BLOCK MACRO b1, b2, b3, b4, b5, b6
  DB b1;-1
  DB b2;-1
  DB b3;-1
  DB b4;-1
  DB b5;-1
  DB b6;-1
  ENDM

PERMUTATION_56BIT_BLOCK MACRO b1, b2, b3, b4, b5, b6, b7
  DB b1;-1
  DB b2;-1
  DB b3;-1
  DB b4;-1
  DB b5;-1
  DB b6;-1
  DB b7;-1
  ENDM
;
; Supported DES Algorithm Modes
;
ENCRYPT         EQU     0       ; Encrypts a block of plain text (see desmain.cpp)
DECIPHER        EQU     1       ; Deciphers a block of encrypted text  (see desmain.cpp)

CPU586          EQU     5       ; Family ID for Pentium (no 'cmov' instructions support)
CPU686          EQU     6       ; Family ID for Pentium Pro and later

_DATA SEGMENT
        ORG $+4 ; align

;------------------------------------------------------------------------------
;       DES Substitution Boxes
;
; The table is organized just as described in the common DES documentations.
; It is very easy to survey and understand.
;
; The SBoxTable is accessed by a 6-bit index:
;
;       [ *  *  r1 c3 c2 c1 c0 r0 ]
;
;        Bits r1r0 = [5,0] select one of 4 rows in a box
;        Bits c3..c0 = [4:1] select one of 16 colums in a box
;
;       Within a loop all eight S-Boxes are consulted for DES substitution.
;
;       Depending on the selection either the lsb or the msb from the
;       table value (column) is used for substitution (see DES specification).
;
SBoxTable:
;
; S[1]     c0     c1     c2      c3     c4    c5     c6     c7     c8     c9     cA     cB     cC     cD     cE     cF
;
SBox1 LABEL BYTE ; SHL 4
     DB   14*16,  4*16, 13*16,  1*16,  2*16, 15*16, 11*16,  8*16,  3*16, 10*16,  6*16, 12*16,  5*16,  9*16,  0*16,  7*16   ; r0
     DB    0*16, 15*16,  7*16,  4*16, 14*16,  2*16, 13*16,  1*16, 10*16,  6*16, 12*16, 11*16,  9*16,  5*16,  3*16,  8*16   ; r1
     DB    4*16,  1*16, 14*16,  8*16, 13*16,  6*16,  2*16, 11*16, 15*16, 12*16,  9*16,  7*16,  3*16, 10*16,  5*16,  0*16   ; r2
     DB   15*16, 12*16,  8*16,  2*16,  4*16,  9*16,  1*16,  7*16,  5*16, 11*16,  3*16, 14*16, 10*16,  0*16,  6*16, 13*16   ; r3
SBOX_SIZE EQU $-SBox1 ; All S-boxes have the same size

;
; S[2]    c0  c1  c2  c3  c4  c5  c6  c7  c8  c9  cA  cB  cC  cD  cE  cF
;
SBox2 LABEL BYTE ; !! SHL 0 no shift left !!
     DB   15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10  ; r0
     DB    3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5  ; r1
     DB    0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15  ; r2
     DB   13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9  ; r3

;
; S[3]
;
SBox3 LABEL BYTE ; SHL 4
     DB   10*16,  0*16,  9*16, 14*16,  6*16,  3*16, 15*16,  5*16,  1*16, 13*16, 12*16,  7*16, 11*16,  4*16,  2*16,  8*16   ; r0
     DB   13*16,  7*16,  0*16,  9*16,  3*16,  4*16,  6*16, 10*16,  2*16,  8*16,  5*16, 14*16, 12*16, 11*16, 15*16,  1*16   ; r1
     DB   13*16,  6*16,  4*16,  9*16,  8*16, 15*16,  3*16,  0*16, 11*16,  1*16,  2*16, 12*16,  5*16, 10*16, 14*16,  7*16   ; r2
     DB    1*16, 10*16, 13*16,  0*16,  6*16,  9*16,  8*16,  7*16,  4*16, 15*16, 14*16,  3*16, 11*16,  5*16,  2*16, 12*16   ; r3

;
; S[4]
;
SBox4 LABEL BYTE ; !! SHL 0 no shift left !!
     DB    7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15  ; r0
     DB   13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9  ; r1
     DB   10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4  ; r2
     DB    3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14  ; r3

;
; S[5]
;
SBox5 LABEL BYTE ; SHL 4
     DB    2*16, 12*16,  4*16,  1*16,  7*16, 10*16, 11*16,  6*16,  8*16,  5*16,  3*16, 15*16, 13*16,  0*16, 14*16,  9*16  ; r0
     DB   14*16, 11*16,  2*16, 12*16,  4*16,  7*16, 13*16,  1*16,  5*16,  0*16, 15*16, 10*16,  3*16,  9*16,  8*16,  6*16  ; r1
     DB    4*16,  2*16,  1*16, 11*16, 10*16, 13*16,  7*16,  8*16, 15*16,  9*16, 12*16,  5*16,  6*16,  3*16,  0*16, 14*16  ; r2
     DB   11*16,  8*16, 12*16,  7*16,  1*16, 14*16,  2*16, 13*16,  6*16, 15*16,  0*16,  9*16, 10*16,  4*16,  5*16,  3*16  ; r3

;
; S[6]
;
SBox6 LABEL BYTE ; !! SHL 0 no shift left !!
     DB   12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11  ; r0
     DB   10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8  ; r1
     DB    9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6  ; r2
     DB    4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13  ; r3

;
; S[7]
;
SBox7 LABEL BYTE ; SHL 4
     DB    4*16, 11*16,  2*16, 14*16, 15*16,  0*16,  8*16, 13*16,  3*16, 12*16,  9*16,  7*16,  5*16, 10*16,  6*16,  1*16  ; r0
     DB   13*16,  0*16, 11*16,  7*16,  4*16,  9*16,  1*16, 10*16, 14*16,  3*16,  5*16, 12*16,  2*16, 15*16,  8*16,  6*16  ; r1
     DB    1*16,  4*16, 11*16, 13*16, 12*16,  3*16,  7*16, 14*16, 10*16, 15*16,  6*16,  8*16,  0*16,  5*16,  9*16,  2*16  ; r2
     DB    6*16, 11*16, 13*16,  8*16,  1*16,  4*16, 10*16,  7*16,  9*16,  5*16,  0*16, 15*16, 14*16,  2*16,  3*16, 12*16  ; r3

;
; S[8]
;
SBox8 LABEL BYTE ; !! SHL 0 no shift left !!
     DB   13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7  ; r0
     DB   01, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2  ; r1
     DB   07, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8  ; r2
     DB   02,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11  ; r3


;------------------------------------------------------------------------------
;
PermutationPC2 LABEL BYTE
        PERMUTATION_48BIT_BLOCK         13, 16, 10, 23,  0,  4
        PERMUTATION_48BIT_BLOCK          2, 27, 14,  5, 20,  9
        PERMUTATION_48BIT_BLOCK         22, 18, 11,  3, 25,  7
        PERMUTATION_48BIT_BLOCK         15,  6, 26, 19, 12,  1
        PERMUTATION_48BIT_BLOCK         40, 51, 30, 36, 46, 54
        PERMUTATION_48BIT_BLOCK         29, 39, 50, 44, 32, 47
        PERMUTATION_48BIT_BLOCK         43, 48, 38, 55, 33, 52
        PERMUTATION_48BIT_BLOCK         45, 41, 49, 35, 28, 31

PermutationPC1 LABEL BYTE               ; Permuted choice table (key)
        PERMUTATION_56BIT_BLOCK         56, 48, 40, 32, 24, 16,  8
        PERMUTATION_56BIT_BLOCK          0, 57, 49, 41, 33, 25, 17
        PERMUTATION_56BIT_BLOCK          9,  1, 58, 50, 42, 34, 26
        PERMUTATION_56BIT_BLOCK         18, 10,  2, 59, 51, 43, 35
        PERMUTATION_56BIT_BLOCK         62, 54, 46, 38, 30, 22, 14
        PERMUTATION_56BIT_BLOCK          6, 61, 53, 45, 37, 29, 21
        PERMUTATION_56BIT_BLOCK         13,  5, 60, 52, 44, 36, 28
        PERMUTATION_56BIT_BLOCK         20, 12,  4, 27, 19, 11,  3


;------------------------------------------------------------------------------
;
PermutationIP   DD      40h, 10h, 04h, 01h, 80h, 20h, 08h, 02h
ReferenceIP     DD      01h, 02h, 04h, 08h, 10h, 20h, 40h, 80h

Permutation48i \
        DB      24, 15,  6, 19, 20, 28, 20, 28, 11, 27, 16,  0,
                16,  0, 14, 22, 25,  4, 25,  4, 17, 30,  9,  1,
                 9,  1,  7, 23, 13, 31, 13, 31, 26,  2,  8, 18,
                 8, 18, 12, 29,  5, 21,  5, 21, 10,  3, 24, 15


;
; Note: Bit 0 is left-most in byte (big-endian)
;
NotationTable8Bit \
        DD      80h, 40h, 20h, 10h, 08h, 04h, 02h, 01h

NotationTable48Bit \
        DD      00800000h, 00400000h, 00200000h, 00100000h,
                00080000h, 00040000h, 00020000h, 00010000h,
                00008000h, 00004000h, 00002000h, 00001000h,
                00000800h, 00000400h, 00000200h, 00000100h,
                00000080h, 00000040h, 00000020h, 00000010h,
                00000008h, 00000004h, 00000002h, 00000001h
NOTATION_48BIT_SIZE EQU $-NotationTable48Bit

PC1LeftRotationTable LABEL BYTE                 ; Number left rotations of pc1
        DB      1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
;
; Temporary auxiliary pointer (placed at SIZEOF PermutationArray48a-d + SIZEOF QWORD)
;
pfill   DD      FLAT:PermutationArray48a + (4*256*2)+8   ; =2056                
_stepnr DD      1       ; TDES step

_cmp48x DD      0

_cpuType DW     6       ; .686 = Default  (Performance)

_DATA ENDS


_BSS SEGMENT
BLOCK_SIZE      EQU     8                       ; Size of a DES plaintext block
SBOX_ARRAY_SIZE EQU     8 * (8*SBOX_SIZE)       ; =4096

IgnitedDES      DD      0                       ; Init flag

KeyArray        DD      BLOCK_SIZE * SIZEOF DWORD DUP (?)    ; _stepnr 1

SBoxArray12       DB    SBOX_ARRAY_SIZE DUP (?)   
SBoxArray34       DB    SBOX_ARRAY_SIZE DUP (?)   
SBoxArray56       DB    SBOX_ARRAY_SIZE DUP (?)   
SBoxArray78       DB    SBOX_ARRAY_SIZE DUP (?)   

PermutationArray48a       DD  2*256 DUP (?)
PermutationArray48b       DD  2*256 DUP (?)
PermutationArray48c       DD  2*256 DUP (?)
PermutationArray48d       DD  2*256 DUP (?)

KeyArray_tdes2  DD      BLOCK_SIZE * SIZEOF DWORD DUP (?)    ; _stepnr 2

SBoxArray12_tdes2 DB    SBOX_ARRAY_SIZE DUP (?)   
SBoxArray34_tdes2 DB    SBOX_ARRAY_SIZE DUP (?)   
SBoxArray56_tdes2 DB    SBOX_ARRAY_SIZE DUP (?)   
SBoxArray78_tdes2 DB    SBOX_ARRAY_SIZE DUP (?)   

PermutationArray48a_tdes2 DD  2*256 DUP (?)
PermutationArray48b_tdes2 DD  2*256 DUP (?)
PermutationArray48c_tdes2 DD  2*256 DUP (?)
PermutationArray48d_tdes2 DD  2*256 DUP (?)

KeyArray_tdes3  DD      BLOCK_SIZE * SIZEOF DWORD DUP (?)     ; _stepnr 3

SBoxArray12_tdes3 DB    SBOX_ARRAY_SIZE DUP (?)   
SBoxArray34_tdes3 DB    SBOX_ARRAY_SIZE DUP (?)   
SBoxArray56_tdes3 DB    SBOX_ARRAY_SIZE DUP (?)   
SBoxArray78_tdes3 DB    SBOX_ARRAY_SIZE DUP (?)   

PermutationArray48a_tdes3 DD  2*256 DUP (?)
PermutationArray48b_tdes3 DD  2*256 DUP (?)
PermutationArray48c_tdes3 DD  2*256 DUP (?)
PermutationArray48d_tdes3 DD  2*256 DUP (?)

;;ha;;;;---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
;;ha;;_3desDebugbuf DB 16 DUP ('A')  ; debug only
;;ha;;;;---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
_BSS ENDS

;;ha;;_TEXT SEGMENT
_SMC SEGMENT ; Self-modifying Code (SMC) special section name: _SMC (rd/wr/ex)
             ; The linker option is appropriatetly defined in "haCrypt.NMK"

tdesKeyInit2 PROTO C, _key:DWORD, _edf:DWORD, _stp:DWORD
desAlgorithm2 PROTO C, inblock:DWORD, outblock:DWORD, _stp:DWORD
tdes_permute PROTO C, _inblock:DWORD, PermutationIP:DWORD, ReferenceIP:DWORD, _outblock:DWORD   


;+----------------------------------------------------------------------------
;
;                        ChkCpuFamily2
;
;   "cpuid" INPUT EAX = 1:
;     Version Information Returned by CPUID in EAX 
;      and returns Feature Information in ECX and EDX
;
;   Code instruction requirements for the different CPUs are handled here.
;
;        --------------------------
;        Bit#   Information (eax)
;        --------------------------
;        0-3    Stepping ID
;        4-7    Model
;        8-11   Family ID
;        12-13  Processor Type
;        14-15  Reserved
;        16-19  Extended Model ID
;        20-27  Extended Family ID
;        28-31  Reserved
;        --------------------------
;
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
kinitCode586a_2 LABEL DWORD             ; Code replacement for .586 CPUs in             ~
        je      @F                      ;  routine kinit, where cmov Instructions       ~
        mov     edx, eax                ;  are not suppported.                          ~
@@:                                     ;                                               ~
kinitCode586b_2 LABEL DWORD             ; Code replacement for .586 CPUs in             ~
        jb      @F                      ;  routine kinit, where cmov Instructions       ~
        mov     ecx, ebx                ;  are not suppported.                          ~
@@:                                     ;                                               ~
                                        ;                                               ~
desAlgoCode586_2 LABEL DWORD            ; Code replacement for .586 CPUs in             ~
        jne     @F                      ;  routine DesAlgorithm (no cmov Instructions)  ~
        mov     ebx, ecx                ; EVN: ebx = _swap                              ~
        jmp     SHORT desAlgo2a_2               ;                                       ~
@@:                                     ;                                               ~
        mov     edi, ecx                ; ODD: edi = _swap                              ~
desAlgo2a_2:                            ;                                               ~
                                        ;                                               ~
permuteCode586_2 LABEL DWORD            ; Code replacement for .586 CPUs in             ~
        je      @F                      ;  routine Permute, where cmov Instructions     ~
        mov     ecx, DWORD PTR [eax]    ;  are not suppported (slower performance)      ~
@@:                                     ;                                               ~
                                        ;                                               ~
;;ha;;_kiniCode586a LABEL DWORD         ; Code replacement for .586 CPUs                ~
;;ha;;  DD      0D08B0274h              ; DB 74h,02h,8Bh,0D0h                           ~
;;ha;;_kiniCode586b LABEL DWORD         ; Code replacement for .586 CPUs                ~
;;ha;;  DD      0CB8B0274h              ; DB 74h,02h,8Bh,0CBh                           ~
;;ha;;                                  ;                                               ~
;;ha;;_desAlgoCode586 LABEL DWORD       ; Code replacement for .586 CPUs                ~
;;ha;;  DD      0D98B0475h              ; DB 75h, 04h,8Bh,0D9h                          ~
;;ha;;  DD      0F98B02EBh              ; DB 0EBh,02h,8Bh,0F9h                          ~
;;ha;;                                  ;                                               ~
;;ha;;tdes_permuteCode586 LABEL DWORD   ; Code replacement for .586 CPUs                ~
;;ha;;  DD      088B0274h               ; DB 74h,02h,8Bh,08h                            ~
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ChkCpuFamily2 PROC C USES eax ebx ecx edx esi edi
        mov     eax, 1                  ; CPUID Input parameter = 01
        cpuid                           ;  Get family/model/stepping
        and     eax, 00000F00h          ; Isolate Family [11:08]
        shr     eax, 8                  ; Right justfy familyID
        mov     WORD PTR _cpuType, ax   ; Set _cpuType with family
        cmp     ax, CPU686              ; 'cmov' instructions supported?
        je      @F                      ; Yes - skip and continue.

;~ Self-Modifying Code: 
;~ This procedure replaces the performant 'cmov' instructions 
;~  when running on an older Pentium CPU (FamilyID=5).
;~   The replaced code reduces performance by 37%
;~    when running on a Pentium Pro (FamilyID=6).
;~ 
        lea     esi, OFFSET kinitCode586a_2   ;~ kinit PROC
        lea     edi, OFFSET kinit686a_2
        movsd
        lea     esi, OFFSET kinitCode586b_2
        lea     edi, OFFSET kinit686b_2
        movsd

        lea     esi, OFFSET desAlgoCode586_2  ;~ desAlgorithm PROC
        lea     edi, OFFSET desAlgo686_2
        movsd
        movsd

        lea     esi, OFFSET permuteCode586_2  ;~ permute PROC
        lea     edi, OFFSET permute686_2
        movsd

@@:     ret                                 ;~ Done.
ChkCpuFamily2 ENDP


;+----------------------------------------------------------------------------
;
;                               tdesKeyInit2
;
;               kinit PROTO C, key:DWORD, edf:DWORD
;
;       Language type: PROC C (Public interface to desmain.cpp)
;       desmain.cpp: extern "C" void kinit(char* p, int);
;
; Initialize key schedule array. Discard the key parity and take only 56 bits
;
; Function compile flags: /Ogtpy
; COMDAT ?kinit@@YAXPADH@Z PROC PUBLIC (C++ without language type!)
;
tdesKeyInit2 PROC C PUBLIC USES ebx esi edi, _key:DWORD, _edf:DWORD, _stp:DWORD
        LOCAL   _k:DWORD
        LOCAL   _PermutationPC1m[56]:BYTE
        LOCAL   _pcr[56]:BYTE

        mov     eax, _stp
        mov     _stepnr, eax            ; Save TDES step number

;;ha;;;;---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
;;ha;;  push    esi
;;ha;;  push    edi
;;ha;;  push    ecx
;;ha;;  mov     esi, DWORD PTR _key
;;ha;;  mov     edi, OFFSET _3desDebugbuf
;;ha;;  mov     ecx, SIZEOF _3desDebugbuf/2     ; 1st half to intercept _key
;;ha;;  rep movs BYTE PTR [edi], [esi]     
;;ha;;; -----------------------------------
;;ha;;  mov     ecx, DWORD PTR _stepnr          ; 2nd half multi purpose
;;ha;;  mov     DWORD PTR [edi], ecx
;;ha;;  pop     ecx
;;ha;;  pop     edi
;;ha;;  pop     esi
;;ha;;;;---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

        cmp     DWORD PTR IgnitedDES, 1 ; Speed optimization
        je      SHORT @F                ; Skip ChkCpuFamily if already done

        call    ChkCpuFamily2           ; Adjust performance coding for older CPUs
@@:
        call    tdes_p48init            ; Prepared for Algorithm here (optimal speed)
;
; Convert PermutationPC1 to bits of key
;
        mov     esi, DWORD PTR _key
        xor     edx, edx

        ALIGN 16        ; Code starts at an xxxxxxx0 addr (see the listing)

kinit_1:
        movsx   ecx, BYTE PTR PermutationPC1[edx]

        mov     eax, ecx
        and     ecx, 7
        sar     eax, 3

        movsx   eax, BYTE PTR [eax+esi]
        test    eax, DWORD PTR NotationTable8Bit[ecx*4]
        movsx   ecx, BYTE PTR PermutationPC1[edx+1]
        setne   al
        mov     BYTE PTR _PermutationPC1m[edx], al

        mov     eax, ecx
        sar     eax, 3
        and     ecx, 7

        movsx   eax, BYTE PTR [eax+esi]
        test    eax, DWORD PTR NotationTable8Bit[ecx*4]
        movsx   ecx, BYTE PTR PermutationPC1[edx+2]
        setne   al
        mov     BYTE PTR _PermutationPC1m[edx+1], al

        mov     eax, ecx
        sar     eax, 3
        and     ecx, 7
        movsx   eax, BYTE PTR [eax+esi]
        test    eax, DWORD PTR NotationTable8Bit[ecx*4]
        movsx   ecx, BYTE PTR PermutationPC1[edx+3]
        setne   al
        mov     BYTE PTR _PermutationPC1m[edx+2], al

        mov     eax, ecx
        sar     eax, 3
        and     ecx, 7

        movsx   eax, BYTE PTR [eax+esi]
        test    eax, DWORD PTR NotationTable8Bit[ecx*4]
        setne   al
        mov     BYTE PTR _PermutationPC1m[edx+3], al

        add     edx, 4
        cmp     edx, 56
        jl      kinit_1

        xor     ecx, ecx                                ; Init incremental ptr
        mov     DWORD PTR _k, 30

        ALIGN 16        ; Code starts at an xxxxxxx0 addr (see the listing)

kinit_2:
        push    ecx                                     ; Save incremental ptr
        lea     eax, DWORD PTR [ecx+ecx]
        mov     edx, DWORD PTR _k

        cmp     DWORD PTR _edf, DECIPHER                ; Encrypt/Decipher Flag

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~;
kinit686a_2::                      ;~
        cmovne  edx, eax           ;~                   ; .686 CPUs only, Encrypt/Decipher
        nop                        ;~                   ; Place holder for .586 CPU code replacement
;;      je      @F                 ;~                   ;~ Code replacement for .586 CPUs in         ~
;;      mov     edx, eax           ;~                   ;~  routine Permute, where cmov Instructions ~
;;@@:                              ;~                   ;~  are not suppported (slower performance)  ~
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        movsx   edi, BYTE PTR PC1LeftRotationTable[ecx]
        lea     ebx, DWORD PTR [edi-28]

        xor     esi, esi

kinit_sc123:
        cmp     DWORD PTR _stp, 1
        je      kinit_sg1
        cmp     DWORD PTR _stp, 2
        je      kinit_sh2
        jmp     kinit_si3 ; _stp 3
kinit_sg1:
        mov     DWORD PTR KeyArray[edx*4+4], 0          ; _stepnr = 1
        mov     DWORD PTR KeyArray[edx*4], 0
        jmp     @F
kinit_sh2:
        mov     DWORD PTR KeyArray_tdes2[edx*4+4], 0    ; _stepnr = 2
        mov     DWORD PTR KeyArray_tdes2[edx*4], 0
        jmp     @F
kinit_si3:
        mov     DWORD PTR KeyArray_tdes3[edx*4+4], 0    ; _stepnr = 3
        mov     DWORD PTR KeyArray_tdes3[edx*4], 0
@@:
kinit_3:
        cmp     esi, 28
        sbb     eax, eax
        and     eax, 0FFFFFFE4h
        add     eax, 56
        mov     ecx, edi
        cmp     edi, eax

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~;
kinit686b_2::                      ;~
        cmovge  ecx, ebx           ;~                   ; .686 CPUs only
        nop                        ;~                   ; Place holder for .586 CPU code replacement
;;      jb      @F                 ;~                   ;~ Code replacement for .586 CPUs in         ~
;;      mov     ecx, ebx           ;~                   ;~  routine Permute, where cmov Instructions ~
;;@@:                              ;~                   ;~  are not suppported (slower performance)  ~
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        mov     al, BYTE PTR _PermutationPC1m[ecx]
        mov     BYTE PTR _pcr[esi], al

        inc     edi
        inc     ebx
        inc     esi
        cmp     esi, 56
        jl      SHORT kinit_3

        xor     eax, eax

        ALIGN 16        ; Code starts at an xxxxxxx0 addr (see the listing) 

kinit_4:
        movsx   ecx, BYTE PTR PermutationPC2[eax]
        cmp     BYTE PTR _pcr[ecx], 0
        je      SHORT @F

        mov     ecx, DWORD PTR NotationTable48Bit[eax*4]

kinit_sa123:
        cmp     DWORD PTR _stp, 1
        je      kinit_sa1
        cmp     DWORD PTR _stp, 2
        je      kinit_sb2
        jmp     kinit_sc3 ; _stp 3
kinit_sa1:
        or      DWORD PTR KeyArray[edx*4], ecx
        jmp     @F
kinit_sb2:
        or      DWORD PTR KeyArray_tdes2[edx*4], ecx
        jmp     @F
kinit_sc3:
        or      DWORD PTR KeyArray_tdes3[edx*4], ecx
@@:
        movsx   ecx, BYTE PTR PermutationPC2[eax+24]
        cmp     BYTE PTR _pcr[ecx], 0
        je      SHORT @F

        mov     ecx, DWORD PTR NotationTable48Bit[eax*4]

kinit_sb123:
        cmp     DWORD PTR _stp, 1
        je      kinit_sd1
        cmp     DWORD PTR _stp, 2
        je      kinit_se2
        jmp     kinit_sf3 ; _stp 3
kinit_sd1:
        or      DWORD PTR KeyArray[edx*4+4], ecx
        jmp     @F
kinit_se2:
        or      DWORD PTR KeyArray_tdes2[edx*4+4], ecx
        jmp     @F
kinit_sf3:
        or      DWORD PTR KeyArray_tdes3[edx*4+4], ecx
@@:
        inc     eax
        cmp     eax, 24
        jl      kinit_4

        pop     ecx                     ; Restore incremantal ptr
        inc     ecx
        sub     DWORD PTR _k, 2
        jge     kinit_2

        ret
tdesKeyInit2 ENDP ; tdesKeyInit2


;+----------------------------------------------------------------------------
;
;                          desAlgorithm2
;
;       desAlgorithm PROTO C, inblock:DWORD, outblock:DWORD
;
;       Language type: PROC C (Public interface to desmain.cpp)
;       desmain.cpp: extern "C" void desAlgorithm (char* p1, char* p2);
;
;       Note: 1) The Language type may be defined for each function seperately.
;             2) C++ Compiler uses "ebp and [ebp]" when "/O2" option is used.
;                                                                                                   
;       see: Intel(R) 64 and IA-32 Optimization Reference Manual
;            "unrolling loops"
;
; Function compile flags: /Ogtpy
; COMDAT ?desAlgorithm@@YAXPAD0@Z PROC PUBLIC (C++ without language type!)
;
desAlgorithm2 PROC C PUBLIC USES ebx edi esi, _inblock:DWORD, _outblock:DWORD, _stp:DWORD
        LOCAL   __ebp:DWORD ; We can't use "ebp" (because of "INVOKE" convention)
        LOCAL   _keys:DWORD
        LOCAL   _swap[16]:BYTE
        LOCAL   _scratch[8]:BYTE
         
        lea     esi, DWORD PTR _scratch         ; Init pointer to _scratch
        INVOKE tdes_permute, _inblock, OFFSET PermutationIP, OFFSET ReferenceIP, esi    

        lea     edi, DWORD PTR _swap            ; Init pointer to _swap
        lea     ebx, DWORD PTR _swap[16]        ; Init end-of _swap

        ALIGN 16

desAlgorit_1:
        movsx   edx, BYTE PTR [esi][0]          ; Data of _scratch[0]
        lea     esi, DWORD PTR [esi+4]          ; Pointer to _scratch from tdes_permute
        movzx   eax, BYTE PTR [esi-3]           ; Data of _scratch[1]
        shl     eax, 16
        shl     edx, 24
        or      edx, eax

        movzx   eax, BYTE PTR [esi-2]           ; Data of _scratch[2]
        shl     eax, 8
        or      edx, eax

        movzx   eax, BYTE PTR [esi-1]           ; Data of _scratch[3]
        or      edx, eax

        mov     ecx, edx
        mov     eax, edx
        sar     ecx, 2
        and     eax, 01F80000h
        and     ecx, 0007E000h
        or      ecx, eax

        mov     eax, edx
        shr     ecx, 2
        and     eax, 1F800000h
        or      ecx, eax

        mov     eax, edx
        sar     eax, 9
        shr     ecx, 11
        and     eax, 007C0000h
        or      ecx, eax

        mov     eax, edx
        and     eax, 1
        shl     eax, 23
        or      ecx, eax
        mov     DWORD PTR [edi], ecx            ; Data of _swap

        mov     eax, edx
        and     eax, 00001F80h                          
        mov     ecx, edx
        and     ecx, 0001F800h                          
        shl     ecx, 2
        or      ecx, eax

        mov     eax, edx
        shl     ecx, 2
        and     eax, 000001F8h                          
        or      ecx, eax

        mov     eax, edx
        shl     ecx, 2
        and     eax, 0000001Fh                          
        or      ecx, eax
        sar     edx, 31
        add     ecx, ecx
        and     edx, 1
        or      ecx, edx
        mov     DWORD PTR [edi+4], ecx          ; _swap[+4]

        add     edi, 8
        cmp     edi, ebx                        ; Reached end of _swap?
        jb      desAlgorit_1                    ; Continue looping
;       --------------------------              ------------------

        lea     edi, DWORD PTR _swap            ; Pointer to _swap[0] (1st half)
        lea     ebx, DWORD PTR _swap[8]         ; Pointer to _swap[8] (2nd half)

        mov     eax, OFFSET KeyArray
        cmp     DWORD PTR _stp, 1
        je      @F
        mov     eax, OFFSET KeyArray_tdes2
        cmp     DWORD PTR _stp, 2
        je      @F
        mov     eax, OFFSET KeyArray_tdes3

@@:
        mov     DWORD PTR __ebp, 16             ; Init loop counter

        ALIGN 16

desAlgorit_2:
        mov     ecx, DWORD PTR [ebx]            ; Data of _swap
        xor     ecx, DWORD PTR [eax]            ; Data of keyArray

        add     eax, SIZEOF DWORD
        mov     DWORD PTR _keys, eax
        mov     eax, ecx
        sar     eax, 12
        and     ecx, 00000FFFh

desAlgorit_sa1:
        cmp     DWORD PTR _stp, 1
        jne     desAlgorit_sb2
        movzx   eax, BYTE PTR SBoxArray12[eax]
        mov     edx, DWORD PTR PermutationArray48a[eax*8]
        mov     esi, DWORD PTR PermutationArray48a[eax*8+4]
        movzx   eax, BYTE PTR SBoxArray34[ecx]
        mov     ecx, DWORD PTR [ebx+4]  
        add     ebx, 8                          ; Move pointer to _swap[+8]
        or      edx, DWORD PTR PermutationArray48b[eax*8]
        or      esi, DWORD PTR PermutationArray48b[eax*8+4]
        jmp     @F
desAlgorit_sb2:
        cmp     DWORD PTR _stp, 2
        jne     desAlgorit_sc3
        movzx   eax, BYTE PTR SBoxArray12_tdes2[eax]
        mov     edx, DWORD PTR PermutationArray48a_tdes2[eax*8]
        mov     esi, DWORD PTR PermutationArray48a_tdes2[eax*8+4]
        movzx   eax, BYTE PTR SBoxArray34_tdes2[ecx]
        mov     ecx, DWORD PTR [ebx+4]  
        add     ebx, 8                          ; Move pointer to _swap[+8]
        or      edx, DWORD PTR PermutationArray48b_tdes2[eax*8]
        or      esi, DWORD PTR PermutationArray48b_tdes2[eax*8+4]
        jmp     @F
desAlgorit_sc3:         ; _stp 3
        movzx   eax, BYTE PTR SBoxArray12_tdes3[eax]
        mov     edx, DWORD PTR PermutationArray48a_tdes3[eax*8]
        mov     esi, DWORD PTR PermutationArray48a_tdes3[eax*8+4]
        movzx   eax, BYTE PTR SBoxArray34_tdes3[ecx]
        mov     ecx, DWORD PTR [ebx+4]  
        add     ebx, 8                          ; Move pointer to _swap[+8]
        or      edx, DWORD PTR PermutationArray48b_tdes3[eax*8]
        or      esi, DWORD PTR PermutationArray48b_tdes3[eax*8+4]
@@:
        mov     eax, DWORD PTR _keys
        xor     ecx, DWORD PTR [eax]
        add     eax, SIZEOF DWORD
        mov     DWORD PTR _keys, eax
        mov     eax, ecx
        sar     eax, 12
        and     ecx, 00000FFFh

desAlgorit_sd1:
        cmp     DWORD PTR _stp, 1
        jne     desAlgorit_se2
        movzx   eax, BYTE PTR SBoxArray56[eax]
        or      edx, DWORD PTR PermutationArray48c[eax*8]
        or      esi, DWORD PTR PermutationArray48c[eax*8+4]
        movzx   ecx, BYTE PTR SBoxArray78[ecx]
        mov     eax, DWORD PTR PermutationArray48d[ecx*8]
        or      eax, edx
        xor     DWORD PTR [edi], eax            ; _swap
        mov     eax, DWORD PTR PermutationArray48d[ecx*8+4]
        jmp     @F
desAlgorit_se2:
        cmp     DWORD PTR _stp, 2
        jne     desAlgorit_sf3
        movzx   eax, BYTE PTR SBoxArray56_tdes2[eax]
        or      edx, DWORD PTR PermutationArray48c_tdes2[eax*8]
        or      esi, DWORD PTR PermutationArray48c_tdes2[eax*8+4]
        movzx   ecx, BYTE PTR SBoxArray78_tdes2[ecx]
        mov     eax, DWORD PTR PermutationArray48d_tdes2[ecx*8]
        or      eax, edx
        xor     DWORD PTR [edi], eax            ; _swap
        mov     eax, DWORD PTR PermutationArray48d_tdes2[ecx*8+4]
        jmp     @F
desAlgorit_sf3:          ; _stp 3
        movzx   eax, BYTE PTR SBoxArray56_tdes3[eax]
        or      edx, DWORD PTR PermutationArray48c_tdes3[eax*8]
        or      esi, DWORD PTR PermutationArray48c_tdes3[eax*8+4]
        movzx   ecx, BYTE PTR SBoxArray78_tdes3[ecx]
        mov     eax, DWORD PTR PermutationArray48d_tdes3[ecx*8]
        or      eax, edx
        xor     DWORD PTR [edi], eax            ; _swap
        mov     eax, DWORD PTR PermutationArray48d_tdes3[ecx*8+4]

@@:
        or      eax, esi
        xor     DWORD PTR [edi+SIZEOF DWORD], eax ; _swap[+4]
        add     edi, 8                            ; Move pointer to _swap[+8]

        lea     ecx, DWORD PTR _swap            ; Prepare _swap[0] pointer reload 
        test    BYTE PTR __ebp, 1               ; Test _swap-index evn/odd

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~;
desAlgo686_2::                     ;~           ; :: QWORD Label to insert .586 code if needed
        cmove   ebx, ecx           ;~           ; .686 EVN: ebx = _swap (performance)
        cmovnbe edi, ecx           ;~           ; .686 ODD: edi = _swap (performance)
        nop                        ;~           ; Place holder for .586 CPU code replacement
        nop                        ;~           ; Place holder for .586 CPU code replacement
;;      jne     @F                 ;~           ;~ 'cmov' Instructions not suppported (slower performance) ~
;;      mov     ebx, ecx           ;~           ;~ .586 EVN: ebx = _swap                                   ~
;;      jmp     SHORT _desAlgo2a   ;~           ;~                                                         ~
;;@@:                              ;~           ;~                                                         ~
;;      mov     edi, ecx           ;~           ;~ .586 ODD: edi = _swap                                   ~
;;_desAlgo2a:                      ;~           ;~                                                         ~
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 

        mov     eax, DWORD PTR _keys
        dec     DWORD PTR __ebp
        jnz     desAlgorit_2                    ; Continue looping
;       --------------------                    ------------------

        mov     ecx, DWORD PTR [edi]            ; Get _swap data
        mov     eax, DWORD PTR [ebx]            ; Get _swap data
        mov     DWORD PTR [edi], eax            ; Put _swap data
        mov     DWORD PTR [ebx], ecx            ; Put _swap data

        mov     ecx, DWORD PTR [edi+4]          ; Get _swap data
        mov     eax, DWORD PTR [ebx+4]          ; Get _swap data
        mov     DWORD PTR [edi+4], eax          ; Put _swap data
        mov     DWORD PTR [ebx+4], ecx          ; Put _swap data

        lea     esi, DWORD PTR _scratch         ; Pointer to _scratch[0]
        lea     edi, DWORD PTR _swap            ; Pointer to _swap[0]
        lea     ebx, DWORD PTR _swap[16]        ; Init pointer to end-of _swap

        ALIGN 16

desAlgorit_3:
        mov     edx, DWORD PTR [edi]            ; Get _swap data
        mov     ecx, edx

        mov     eax, edx
        sar     ecx, 13
        sar     eax, 15
        xor     cl, al

        mov     eax, edx
        and     cl, 0Fh
        sar     eax, 15
        xor     cl, al

        lea     esi, DWORD PTR [esi+2]          ; Pointer to _scratch
        mov     BYTE PTR [esi-2], cl            ; Data of _scratch[0]

        mov     eax, edx
        mov     ecx, edx
        sar     ecx, 1
        sar     eax, 3
        xor     cl, al
        sar     edx, 3
        and     cl, 0Fh
        xor     cl, dl

        mov     BYTE PTR [esi-1], cl

        add     edi, SIZEOF DWORD               ; Move _swap pointer
        cmp     edi, ebx
        jb      SHORT desAlgorit_3              ; Continue looping
;       --------------------------              ------------------

        lea     eax, DWORD PTR _scratch
        INVOKE tdes_permute, eax, OFFSET ReferenceIP, OFFSET PermutationIP, _outblock   

        ret
desAlgorithm2 ENDP ; desAlgorithm




;+----------------------------------------------------------------------------
;
;                       tdes_permute  (very fast, .686 only)
;
;       see: Intel(R) 64 and IA-32 Optimization Reference Manual
;            "unrolling LOOPs, using CMOVcc instructions instead of Jcc"
;
tdes_permute PROC C USES ebx edi esi, __inblock:DWORD, _test:DWORD, _vals:DWORD, __outblock:DWORD
        mov     esi, DWORD PTR __inblock        ; Init ptr to __inblock
        mov     edi, DWORD PTR __outblock       ; Init ptr to __outblock
        mov     DWORD PTR [edi], 0              ; Clear _outblock 
        mov     DWORD PTR [edi][BLOCK_SIZE/2], 0; Compiler uses "memset()"

        mov     eax, DWORD PTR _vals            ; ReferenceIP

        lea     ebx, DWORD PTR [edi+8]          ; End-of __outblock
        lea     ecx, DWORD PTR [esi+8]          ; End-of __inblock

permute_1:
        mov     edx, DWORD PTR _test            ; PermutationIP
        push    ecx                             ; Save end-of __inblock
        push    edi                             ; Save start-of __outblock  

        ALIGN 16

permute_2:                                        ; - Performance optimized -
        movsx   ecx, BYTE PTR [esi]               ; Data from __inblock
        lea     edx, DWORD PTR [edx+SIZEOF DWORD] ; PermutationIP
        and     ecx, DWORD PTR [edx-SIZEOF DWORD] ; ZR: ecx=0, NZ ecx=data (Perm / RefIP)

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~;
permute686::                        ;~          ; :: DWORD Label to insert .586 code if needed
permute686_2::                      ;~          ; :: DWORD Label to insert .586 code if needed
        cmovnbe ecx, DWORD PTR [eax];~          ; .686 NZ: Prepare data for __outblock (performance)
        nop                         ;~          ; Place holder for .586 CPU code replacement
;;      je      @F                  ;~          ;~ Code replacement for .586 CPUs in         ~
;;      mov     ecx, DWORD PTR [eax];~          ;~  routine Permute, where cmov Instructions ~
;;@@:                               ;~          ;~  are not suppported (slower performance)  ~
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        or      BYTE PTR [edi], cl                ; ZR/NZ: Apply to __outblock data

        inc     edi                             ; Advance __outblock
        cmp     edi, ebx                        ; End-of __outblock?
        jb      SHORT permute_2

        pop     edi                             ; Restore start-of __outblock
        pop     ecx                             ; Restore end-of __inblock
        add     eax, SIZEOF DWORD               ; ReferenceIP (_vals)
        inc     esi                             ; Advance __inblock
        cmp     esi, ecx                        ; End-of __inblock?
        jb      SHORT permute_1                 ; "loop permute_1"

        ret
tdes_permute ENDP ; tdes_permute                         


;+----------------------------------------------------------------------------
;
;                               tdes_p48init
;
tdes_p48init PROC C USES ebx edi esi
        xor     edi, edi                ; Init index counter

        ALIGN 16

tdes_p48init_1:
        mov     ecx, edi               

        mov     eax, edi
        and     eax, 00000800h
        shr     ecx, 1                 
        mov     esi, ecx
        mov     edx, edi
        and     esi, 000003C0h 
        and     edx, 00000001h
        or      esi, eax
        shl     edx, 4

        mov     eax, edi
        shr     esi, 4
        and     eax, 00000040h
        and     ecx, 0000000Fh                                  
        or      esi, eax
        or      edx, ecx               

        mov     eax, edi
        shr     esi, 2
        and     eax, 00000020h                                  
        or      edx, eax
                                                ; _stp 1
        movzx   eax, BYTE PTR SBox2[edx]        ; Merge SBox1 & SBox2
        or      al, BYTE PTR SBox1[esi]
        mov     BYTE PTR SBoxArray12[edi], al
        movzx   eax, BYTE PTR SBox4[edx]        ; Merge SBox3 & SBox4
        or      al, BYTE PTR SBox3[esi]
        mov     BYTE PTR SBoxArray34[edi], al
        movzx   eax, BYTE PTR SBox6[edx]        ; Merge SBox5 & SBox6
        or      al, BYTE PTR SBox5[esi]
        mov     BYTE PTR SBoxArray56[edi], al
        movzx   eax, BYTE PTR SBox8[edx]        ; Merge SBox7 & SBox8
        or      al, BYTE PTR SBox7[esi]
        mov     BYTE PTR SBoxArray78[edi], al
                                                ; _stp 2
        movzx   eax, BYTE PTR SBox2[edx]        ; Merge SBox1 & SBox2
        or      al, BYTE PTR SBox1[esi]
        mov     BYTE PTR SBoxArray12_tdes2[edi], al
        movzx   eax, BYTE PTR SBox4[edx]        ; Merge SBox3 & SBox4
        or      al, BYTE PTR SBox3[esi]
        mov     BYTE PTR SBoxArray34_tdes2[edi], al
        movzx   eax, BYTE PTR SBox6[edx]        ; Merge SBox5 & SBox6
        or      al, BYTE PTR SBox5[esi]
        mov     BYTE PTR SBoxArray56_tdes2[edi], al
        movzx   eax, BYTE PTR SBox8[edx]        ; Merge SBox7 & SBox8
        or      al, BYTE PTR SBox7[esi]
        mov     BYTE PTR SBoxArray78_tdes2[edi], al
                                                ; _stp 3
        movzx   eax, BYTE PTR SBox2[edx]        ; Merge SBox1 & SBox2
        or      al, BYTE PTR SBox1[esi]
        mov     BYTE PTR SBoxArray12_tdes3[edi], al
        movzx   eax, BYTE PTR SBox4[edx]        ; Merge SBox3 & SBox4
        or      al, BYTE PTR SBox3[esi]
        mov     BYTE PTR SBoxArray34_tdes3[edi], al
        movzx   eax, BYTE PTR SBox6[edx]        ; Merge SBox5 & SBox6
        or      al, BYTE PTR SBox5[esi]
        mov     BYTE PTR SBoxArray56_tdes3[edi], al
        movzx   eax, BYTE PTR SBox8[edx]        ; Merge SBox7 & SBox8
        or      al, BYTE PTR SBox7[esi]
        mov     BYTE PTR SBoxArray78_tdes3[edi], al
@@:
        inc     edi                             ; Advance SBoxArray merge index 
        cmp     edi, SBOX_ARRAY_SIZE            ; 4096
        jl      tdes_p48init_1

;------------------------------------------------------------------------------
;
;       PermutationArray48a-d dispatcher
;
        xor     ebx, ebx                        ; Jump table start index

tdes_p48initDispatch:                           ; Fill PermutationArrays
        cmp     ebx, 3
        ja      p48xinit_exit                   ; Done.
        jmp     DWORD PTR p48xinit_jmp[ebx*SIZEOF DWORD]        

p48xinit_jmp:                     
        DD      InitArray48a                    ; Jump table
        DD      InitArray48b
        DD      InitArray48c
        DD      InitArray48d

InitArray48a:
        mov     DWORD PTR _cmp48x, 0
        mov     DWORD PTR pfill, OFFSET PermutationArray48a ; pfill 48a
        cmp     DWORD PTR _stepnr, 1
        je      p48xinit
        mov     DWORD PTR pfill, OFFSET PermutationArray48a_tdes2 ; pfill 48a
        cmp     DWORD PTR _stepnr, 2
        je      p48xinit
        mov     DWORD PTR pfill, OFFSET PermutationArray48a_tdes3 ; pfill 48a
        jmp     p48xinit

InitArray48b:
        mov     DWORD PTR _cmp48x, 8
        mov     DWORD PTR pfill, OFFSET PermutationArray48b ; pfill 48b
        cmp     DWORD PTR _stepnr, 1
        je      p48xinit
        mov     DWORD PTR pfill, OFFSET PermutationArray48b_tdes2 ; pfill 48b
        cmp     DWORD PTR _stepnr, 2
        je      p48xinit
        mov     DWORD PTR pfill, OFFSET PermutationArray48b_tdes3 ; pfill 48b
        jmp     p48xinit

InitArray48c:
        mov     DWORD PTR _cmp48x, 16
        mov     DWORD PTR pfill, OFFSET PermutationArray48c ; pfill 48c
        cmp     DWORD PTR _stepnr, 1
        je      p48xinit
        mov     DWORD PTR pfill, OFFSET PermutationArray48c_tdes2 ; pfill 48c
        cmp     DWORD PTR _stepnr, 2
        je      p48xinit
        mov     DWORD PTR pfill, OFFSET PermutationArray48c_tdes3 ; pfill 48c
        jmp     p48xinit

InitArray48d:
        mov     DWORD PTR _cmp48x, 24
        mov     DWORD PTR pfill, OFFSET PermutationArray48d ; pfill 48d
        cmp     DWORD PTR _stepnr, 1
        je      p48xinit
        mov     DWORD PTR pfill, OFFSET PermutationArray48d_tdes2 ; pfill 48d
        cmp     DWORD PTR _stepnr, 2
        je      p48xinit
        mov     DWORD PTR pfill, OFFSET PermutationArray48d_tdes3 ; pfill 48d
        jmp     p48xinit

;------------------------------------------------------------------------------
;
;               Init PermutationArray48a-d
;
p48xinit:
        push    ebx                     ; Save jmp table index from dispatcher
        mov     ebx, DWORD PTR pfill    ; Get pointer to PermutationArray48x 

        xor     ecx, ecx                ; Init array index count

        ALIGN   16

p48xinit_2:
        mov     DWORD PTR [ebx][ecx*8], 0      ;;ha;; .586 & .686  CPU Clear next chunk
        mov     DWORD PTR [ebx+4][ecx*8], 0    ;;ha;; .586 & .686  CPU  of PermutationArray48x.

        xor     edx, edx

p48xinit_3:
        movzx   esi, BYTE PTR Permutation48i[edx]
        mov     eax, esi
        and     eax, 0FFFFFFF8h                                 
        cmp     eax, DWORD PTR _cmp48x          ; 0,8,16,24
        jne     SHORT @F

        and     esi, 7
        test    DWORD PTR NotationTable8Bit[esi*4], ecx
        je      SHORT @F

        mov     eax, DWORD PTR NotationTable48Bit[edx*4]
        or      DWORD PTR [ebx][ecx*8], eax
@@:
        inc     edx
        cmp     edx, NOTATION_48BIT_SIZE / SIZEOF DWORD
        jl      SHORT p48xinit_3

        mov     edi, NOTATION_48BIT_SIZE / SIZEOF DWORD
        mov     esi, OFFSET NotationTable48Bit

p48xinit_4:
        movzx   edx, BYTE PTR Permutation48i[edi]
        mov     eax, edx
        and     eax, 0FFFFFFF8h
        cmp     eax, DWORD PTR _cmp48x          ; 0,8,16,24
        jne     SHORT @F

        and     edx, 7
        test    DWORD PTR NotationTable8Bit[edx*4], ecx
        je      SHORT @F

        mov     eax, DWORD PTR [esi]
        or      DWORD PTR [ebx][ecx*8+4], eax
@@:
        add     esi, SIZEOF DWORD
        inc     edi
        cmp     esi, OFFSET NotationTable48Bit+NOTATION_48BIT_SIZE
        jl      SHORT p48xinit_4

        inc     ecx
        cmp     ecx, 256
        jl      p48xinit_2

        pop     ebx                     ; Restore jmp table index
        inc     ebx                     ; Advance jmp table entry
        jmp     tdes_p48initDispatch    ; Init next p48Array

p48xinit_exit:
        ret
tdes_p48init ENDP ; tdes_p48init

;------------------------------------------------------------------------------

;;ha;;_TEXT ENDS
_SMC    ENDS      ; Self-modifying Code (SMC) special section name: _SMC (rd/wr/ex)
        END       ; The linker option is appropriatetly defined in "haCrypt.NMK"

;------------------------------------------------------------------------------
      
