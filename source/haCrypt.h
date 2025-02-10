// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCrypt.h - Developer header file.
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

// CRYPT_MAC: Already defined in "wincrypt.h(493)"
#undef CRYPT_MAC // Definition Macro in <wincrypt.h(493)> not used!
                                         
// Workaround to prevent fail of 'SendMessage TTM_ADDTOOL'.
#if _WIN32_WINNT > 0x0500                                // Current Version Windows 10 = 1537
  #define SIZE_TOOLINFO sizeof(TOOLINFO) - sizeof(void*) // 44 bytes (TTTOOLINFOW_V2_SIZE)  
#else                                               
  #define SIZE_TOOLINFO sizeof(TOOLINFO)                 // 48 bytes (sizeof(TOOLINFO))
#endif                                                

// Private error codes (starting at 1000)
#define _ERR                    -1 // General error

#define HA_TOO_MANY_FILES     1000
#define HA_NO_FILE_SELECTED   1001
#define HA_NO_FILE_COPIED     1002
#define HA_ERROR_FILE_WRITE   1003
#define HA_ERROR_FILE_OPEN    1004
#define HA_ERROR_FILESIZE_DES 1005
#define HA_ERROR_FILESIZE_AES 1006
#define HA_ERROR_MEMORY_ALLOC 1007
#define HA_ERROR_KEY_FILESIZE 1008
#define HA_ERROR_IV_FILESIZE  1009
#define HA_ERROR_FILESIZE_RSA 1010
#define HA_ERROR_KEY_SIZE_RSA 1011
#define HA_ERROR_KEY_GEN_RSA  1012
#define HA_ERROR_REN_FILETYPE 1013
#define HA_ERROR_REN_WILDCARD 1014
#define HA_ERROR_REN_ZIPFILE  1015
#define HA_ERROR_NOPUBKEY_RSA 1016
#define HA_ERROR_NOPRVKEY_RSA 1017

// General project definitions
#define T_BLUE  1              // Blue text color on transparent background
#define T_GREEN 2              // Green text color on transparent background
#define T_RED   3              // Red text color on transparent background

#define FGNDWHITE_BGNDBLUE   0 // White text color on blue background in statusbar
#define FGNDWHITE_BGNDRED    1 // White text color on red background in statusbar
#define FGNDGREEN_BGNDTRANS  2 // Green Info text color in statusbar
#define FGNDBLUE_BGNDTRANS   3 // Blue copy text color in statusbar (deprecated)
#define FGNDBLACK_BGNDTRANS  4 // Black standard text color in statusbar

#define PROGRESS_LOAD_PCENT  0 // Blue KB counter and %
#define PROGRESS_CRYPT_BAR   1 // Green progress bar, KB counter and %
#define PROGRESS_SAVE_PCENT  2 // Blue KB counter and %
#define PROGRESS_COPY_PCENT  3 // Blue KB counter and %
#define PROGRESS_CRYPT_PCENT 4 // Green KB counter and %

#define MULTIFILE_BROWSER_RENAME  1 // CBTProc control
#define MULTIFILE_BROWSER_CRYPTO  2 // CBTProc control

// Dialog answers
#define A_YES       11
#define A_NO        12
#define A_YESALL    13
#define A_NOALL     14
#define A_CANCEL    15
#define A_PLAINTEXT 16
#define A_KEY       17
#define A_IV        18
#define A_TESTSAVE  19
#define A_CONTINUE  20
#define A_CRYPTO    21

#define ENCRYPT  0
#define DECIPHER 1

#define ISOPAD 0x80
#define PAD    0x00
#define RSAPAD 0x02

#define KEY_LENGTH_64         64  //  64 bit DES key
#define KEY_LENGTH_128       128  // 128 bit AES Key
#define KEY_LENGTH_192       192  // 192 bit AES Key and 168 bit 3DES Key 
#define KEY_LENGTH_256       256  // 256 bit AES key

#define KEY_SIZE_8         64/8 //  8 bytes (=64 bits)
#define KEY_SIZE_16       128/8 // 16 bytes (=128 bits)
#define KEY_SIZE_24       192/8 // 24 bytes (192 bits AES, 168 bits 3DES)
#define KEY_SIZE_32       256/8 // 32 bytes (=256 bits)

#define KEY_SIZE_MAX       256/8  // 32 bytes (=256 bits)
#define TYPED_KEY_SIZE_MAX 192/8  // 24 bytes (=192 bits)                                   

#define COUNTBUF_SIZE      80     // Size of multipurpose temp buffer 

#define EDIT_TEXT_MAXSIZE  29*1024   // Textsize above this limit is 'read only'
#define CRYPT_TEXT_MAXSIZE 4096      // Crypto data displayed in text-field is truncated
#define FILE_BLOCK_SIZE    1024*1024 // 1M //2048   // 4*2048

// Start/end of invariant Hedit.exe binary block for DES-MAC
#define HEDIT_MAC_START    0x0200 
#define HEDIT_MAC_END      HEDIT_MAC_START+(16*1024) 

// Exponet base 2 (2.e+) range: 16..30
// Examples:
// 2.e+16 = 0x00010000 =   64K =        64*1024
// 2.e+26 = 0x04000000 =   64M =   64*1024*1024
// 2.e+27 = 0x08000000 =  128M =  128*1024*1024
// 2.e+28 = 0x10000000 =  256M =  256*1024*1024
// 2.e+30 = 0x40000000 = 1024M = 1024*1024*1024 = 1G
#define BASE2_EXPONENT_64K   16     
#define BASE2_EXPONENT_16M   24     
#define BASE2_EXPONENT_32M   25     
#define BASE2_EXPONENT_64M   26     
#define BASE2_EXPONENT_128M  27     
#define BASE2_EXPONENT_256M  28     
#define BASE2_EXPONENT_1G    30     
#define FILE_BLOCK_16M       0x01000000LL
#define FILE_BLOCK_32M       0x02000000LL
#define FILE_BLOCK_64M       0x04000000LL
#define FILE_BLOCK_128M      0x08000000LL
#define FILE_BLOCK_256M      0x10000000LL
#define FILE_BLOCK_1G        0x40000000LL

#define DES_BLOCK_SIZE        8      // DES Crypto blocksize
#define TDES_BLOCK_SIZE       8      // TDEA Crypto blocksize
#define AES_BLOCK_SIZE       16      // AES Crypto blocksize

#define RSA_BLOCK_SIZE       16      // RSA Crypto blocksize
#define RSA_BUFFER_SIZE      512     // Array size (512..)
#define RSA_SIZE             256/32  // =8, Adjust to 8 DWORDs

#define RSA_HIDE_DIGITS 0            // Don't display digits
#define RSA_SHOW_DIGITS 1            // Display digits

#define RSA_MODE_PUBKEY      0       // RSA modes 
#define RSA_MODE_PRVKEY      1       
#define RSA_MODE_ENCDATA     2       
#define RSA_MODE_DECDATA     3       
#define RSA_MODE_PUBKEYN     4       
#define RSA_MODE_PUBKEYE     5       
#define RSA_MODE_PRVKEYN     6       
#define RSA_MODE_PRVKEYD     7       
#define RSA_MODE_PADDATA     9       
#define RSA_MODE_DATA       10       
#define RSA_MODE_KEYDATA    11       
#define RSA_MODE_KEYS       12       
#define RSA_MODE_ENCDATAIN  13       
#define RSA_MODE_ENCDATAOUT 14       

// Crypto control flags
#define FILEMODE_TEXT     0x00000000
#define FILEMODE_TEXTNEW  0x10000000

#define CRYPT_ALGO_MASK   0x0FFF0000
#define CRYPT_DES         0x00010000
#define CRYPT_TDES        0x00100000
#define CRYPT_AES         0x01000000

#define CRYPT_MODE_MASK   0x0000FFFF
#define CRYPT_CBCECB_MASK 0x000000FF

#define CRYPT_NONE        0x00000000
#define CRYPT_CBC         0x00000001
#define CRYPT_ECB         0x00000010
#define CRYPT_ISO         0x00000100
#define CRYPT_PKCS        0x00000200
#define CRYPT_MAC         0x00001001  // MAC always CBC mode (CRYPT_MAC | CRYPT_CBC ??? obscure problems) 

// SUBCLASSPROC
#define SUBCLASSDRAW    20000
#define SUBCLASSBUTTON  20001

// Main Window dimmensions
#if _MSC_VER == 1600               // _MSC_VER == 1600 (32 bit Visual Studio 2010 version 10.0) 
  #define MAINWINDOW_WIDTH   908   // 908, 320: Initial size (width, height) Windows XP VS 2010
  #define MAINWINDOW_HEIGHT  320
#else                              // _MSC_VER == 1928 (64 bit Visual Studio 2019 version 16.8)
  #define MAINWINDOW_WIDTH   918   // 918, 330: Initial size (width, height) Windows 10 VS 2019
  #define MAINWINDOW_HEIGHT  330
#endif

#define IDC_STATIC  -1

// Status bar dimmensions
#define STATUSBAR_P0_WIDTH   231         // 231: Initial width of status part 0
#define STATUSBAR_P1_WIDTH   IDC_STATIC  //  -1: Remaining width for status part 1

// Info helptext windows
#define IDC_TEST               193
#define IDC_TEXTFIELD          194
#define IDC_KEYFILE            195
#define IDC_MULTIFILE          196
#define IDC_CIPH_STEALING      197
#define IDC_PADDING_ISO        198
#define IDC_PADDING_PKCS       199

// Main window geometry
#define IDR_MAINMENU           200
#define IDC_MAIN_EDIT          201
#define IDC_MAIN_TOOL          202
#define IDC_MAIN_STATUS        203

// Modal dialog boxes
#define IDD_HACRYPT_FILEC      204
#define IDD_HACRYPT_FILEX      205
#define IDD_HACRYPT_FILEXR     206
#define IDD_HACRYPT_ESC        207
#define IDD_HACRYPT_FILECL     208
#define IDD_HACRYPT_FILESAV    209
#define IDD_HACRYPT_EDITCRYPT  210
#define IDD_HACRYPT_ASCHEX2BIN 211
#define IDD_HACRYPT_TEST_ERROR 212
#define IDD_HACRYPT_TEST_KEEP  213

// Buttons and text fields
#define IDC_HACRYPT_YES      6000
#define IDC_HACRYPT_NO       6001
#define IDC_HACRYPT_YESALL   6002
#define IDC_HACRYPT_NOALL    6003
#define IDC_HACRYPT_CANCEL   6004
#define IDC_FILE_EXIST       6005
#define IDC_FILE_REPLACE     6006
#define IDC_SHOWCOUNT        6007
#define IDC_TEXT_X           6008
#define IDC_TEXT_XOLD        6009
#define IDC_TEXT_XNEW        6010
#define IDC_CONTINUE         6011
#define IDC_KEYDLG_CONTEXT   6012
#define IDC_SHOWVERSION      6013
#define IDC_RENAME           6014
#define IDC_SHOWFOLDER       6015
#define IDC_TEST_PLAINTEXT   6016
#define IDC_TEST_KEY         6017
#define IDC_TEST_IV          6018
#define IDC_TEST_SAVE        6019
#define IDC_LAST_CRYPTO      6020
#define IDC_TEXT_AESKEY      6021
#define IDC_TEXT_AESIV       6022
#define IDC_TEXT_RSAQUICK    6023
#define IDC_TEXT_AESQUICK    6024
#define IDC_TEXT_QUICK       6025
#define IDC_TEST_KEEP        6026
#define IDC_TEST_KEEPKEY     6027
#define IDC_TEST_KEEPIV      6028
#define IDC_TEST_CRYPTO      6029

// -------------------------------------
// Main program Symbol-Icon 32x32 Pixels
#define IDI_HACRYPT_ICON     1000  

// ----------------------------------------------
// Toolbar Icons *.ico 16x16 Pixels (Transparent)
#define IDI_DESE             1001
#define IDI_3DESE            1002
#define IDI_AESE             1003
#define IDI_AESMAC           1004

#define IDI_TXTNEW           1005
#define IDI_TXTOPN           1006
#define IDI_TXTSAV           1007
#define IDI_CRYENC           1008
#define IDI_CRYDEC           1009
#define IDI_CRYSAV           1010
#define IDI_CRYMAC           1011
#define IDI_CRYREDO          1012
#define IDI_HAABOUT          1013
#define IDI_CONSOLE          1014
#define IDI_DOS_HEDIT        1015
#define IDI_EXIT             1016
#define IDI_INVISIBLE        1017

// --------------------------------
// Toolbar Icons *.bmp 16x16 Pixels
#define IDB_DESE             1031
#define IDB_3DESE            1032
#define IDB_AESE             1033
#define IDB_AESMAC           1034

#define IDB_TXTNEW           1035
#define IDB_TXTOPN           1036
#define IDB_TXTSAV           1037
#define IDB_CRYENC           1038
#define IDB_CRYDEC           1039
#define IDB_CRYSAV           1040
#define IDB_CRYMAC           1041
#define IDB_CRYREDO          1042
#define IDB_HAABOUT          1043

//---------------------
// Help-SubMenu Windows
#define IDD_ABOUT_AESQUICK       107
#define IDD_ABOUT_RSAQUICK       108
#define IDD_ABOUT_RSA            109
#define IDD_ABOUT_DES            110
#define IDD_ABOUT_TDES           111
#define IDD_ABOUT_AES            112
#define IDD_ABOUT_MAC            113
#define IDD_ABOUT_CONSOLE        114
#define IDD_ABOUT_MULTIFILE      115
#define IDD_ABOUT_KEYFILE        116
#define IDD_ABOUT_VERSION        117
#define IDD_ABOUT_QUICK          118
#define IDD_ABOUT_TEXTFIELD      119
#define IDD_ABOUT_CIPH_STEALING  120
#define IDD_ABOUT_PADDING_ISO    121
#define IDD_ABOUT_PADDING_PKCS   122
#define IDD_ABOUT_TEST           123
#define IDD_ABOUT                124

// -----------------------------------
// MAINMENU 0: File-SubMenu Selections
#define ID_FILE_TEXT_NEW            40000
#define ID_FILE_TEXT_OPEN           40001
#define ID_FILE_TEXT_SAVEAS         40002
#define ID_FILE_TEXT_RENAME         40003
#define ID_FILE_EXIT                40004

// -------------------------------------
// MAINMENU 1: Crypto-SubMenu Selections
//DES
#define ID_CRYPTO_DES_ECBENCRYPT    40005
#define ID_CRYPTO_DES_ECBDECIPHER   40006
#define ID_CRYPTO_DES_ENCRYPT       40007
#define ID_CRYPTO_DES_DECIPHER      40008
#define ID_CRYPTO_DES_ECBE          40009
#define ID_CRYPTO_DES_ECBD          40010
#define ID_CRYPTO_DES_CBCE          40011
#define ID_CRYPTO_DES_CBCD          40012
#define ID_CRYPTO_DES_ECBE_PKCS     40013
#define ID_CRYPTO_DES_ECBD_PKCS     40014
#define ID_CRYPTO_DES_CBCE_PKCS     40015
#define ID_CRYPTO_DES_CBCD_PKCS     40016
#define ID_CRYPTO_DES_MAC           40017
#define ID_FILE_CRYPT_DES_SAVEAS    40018

//3DES
#define ID_CRYPTO_TDES_ECBENCRYPT   40019
#define ID_CRYPTO_TDES_ECBDECIPHER  40020
#define ID_CRYPTO_TDES_ENCRYPT      40021
#define ID_CRYPTO_TDES_DECIPHER     40022
#define ID_CRYPTO_TDES_ECBE         40023
#define ID_CRYPTO_TDES_ECBD         40024
#define ID_CRYPTO_TDES_CBCE         40025
#define ID_CRYPTO_TDES_CBCD         40026
#define ID_CRYPTO_TDES_ECBE_PKCS    40027
#define ID_CRYPTO_TDES_ECBD_PKCS    40028
#define ID_CRYPTO_TDES_CBCE_PKCS    40029
#define ID_CRYPTO_TDES_CBCD_PKCS    40030
#define ID_CRYPTO_TDES_MAC          40031
#define ID_FILE_CRYPT_TDES_SAVEAS   40032

//AES                                      // All AES Must be higher value than DES, TDES
#define ID_CRYPTO_AES_ECBENCRYPT    40033  // <-- Must be 1st (used in haCryptAlgo.cpp)
#define ID_CRYPTO_AES_ECBDECIPHER   40034
#define ID_CRYPTO_AES_ENCRYPT       40035
#define ID_CRYPTO_AES_DECIPHER      40036
#define ID_CRYPTO_AES_ECBE          40037
#define ID_CRYPTO_AES_ECBD          40038
#define ID_CRYPTO_AES_CBCE          40039
#define ID_CRYPTO_AES_CBCD          40040
#define ID_CRYPTO_AES_ECBE_PKCS     40041
#define ID_CRYPTO_AES_ECBD_PKCS     40042
#define ID_CRYPTO_AES_CBCE_PKCS     40043
#define ID_CRYPTO_AES_CBCD_PKCS     40044
#define ID_CRYPTO_AES_MAC           40045
#define ID_FILE_CRYPT_AES_SAVEAS    40046

#define ID_CRYPTO_RSA_GENERATE_KEYS  40047
#define ID_CRYPTO_RSA_PUTPUBLIC_KEY  40048
#define ID_CRYPTO_RSA_GETPUBLIC_KEY  40049
#define ID_CRYPTO_RSA_PUTPRIVATE_KEY 40050
#define ID_CRYPTO_RSA_GETPRIVATE_KEY 40051
#define ID_CRYPTO_RSA_ENCRYPT        40052
#define ID_CRYPTO_RSA_DECIPHER       40053
#define ID_CRYPTO_RSA_GEN_RNDKEY128  40054
#define ID_CRYPTO_RSA_GEN_RNDKEY256  40055

// --------------------------------------
// MAINMENU 2: Console-SubMenu Selections
#define ID_CONSOLE_HEDIT            40056
#define ID_CONSOLE_HEDIT_FILEOPEN   40057
#define ID_CONSOLE_HEDIT_CRYPT      40058

// --------------------------------------
// MAINMENU 3: Keyfile-SubMenu Selections
#define ID_KEYFILE_OPEN             40059
#define ID_IVFILE_OPEN              40060
                                           // Available numbers: 40061..40079
// -----------------------------------
// MAINMENU 4: Help-SubMenu Selections
#define ID_HELP_ABOUT_QUICKBMP      40080  // BMP image instead of text string
#define ID_HELP_ABOUT_QUICK         40081
#define ID_HELP_ABOUT_AESQUICK      40082
#define ID_HELP_ABOUT_RSAQUICK      40083
#define ID_HELP_ABOUT_DES           40084
#define ID_HELP_ABOUT_TDES          40085
#define ID_HELP_ABOUT_AES           40086
#define ID_HELP_ABOUT_RSA           40087
#define ID_HELP_ABOUT_CIPH_STEALING 40088
#define ID_HELP_ABOUT_PADDING_ISO   40089
#define ID_HELP_ABOUT_PADDING_PKCS  40090
#define ID_HELP_ABOUT_MAC           40091
#define ID_HELP_ABOUT_CONSOLE       40092
#define ID_HELP_ABOUT_MULTIFILE     40093
#define ID_HELP_ABOUT_KEYFILE       40094
#define ID_HELP_ABOUT_TEXTFIELD     40095
#define ID_HELP_ABOUT_TEST          40096
#define ID_HELP_ABOUT_VERSION       40097                                         
#define ID_HELP_ABOUT               40098  // Last of MAINMENU

// ----------------------------------
// Toolbar special crypo icon buttons
#define ID_TOOLBAR_DES              40100  
#define ID_TOOLBAR_AES              40101  
#define ID_TOOLBAR_TDES             40102  
#define ID_TOOLBAR_ENCRYPT          40103  
#define ID_TOOLBAR_DECIPHER         40104  
#define ID_TOOLBAR_MAC              40105 
#define ID_TOOLBAR_CRYPT_CONTINUE   40106
#define ID_FILE_CRYPT_SAVEAS        40107   // = ID_TOOLBAR_CRYPT_SAVEAS

// Toolbar dialog boxes 
#define ID_TOOLBAR_KEYEDIT          40110   // = ID_DIALOG_EDIT_KEY
#define ID_TOOLBAR_IVEDIT           40111   // = ID_DIALOG_EDIT_IV

// -----------------------------------
// Toolbar standard button dimmensions 
#define BUTTON_WIDTH    70
#define BUTTON_HEIGHT   20                  // Button and dialog box height

#define ID_DIALOG_KEY               40120   // = ID_BUTTON_SET_KEY
#define ID_DIALOG_IV                40121   // = ID_BUTTON_SET_IV
#define ID_HEX_DISPLAY              40122   // = ID_BUTTON_HEX_TEXT
#define ID_BUTTON_DELIM             40123   // = ID_BUTTON_DELIM

// --------------------------------------------
// CONTEXT MENU: Toolbar display, key selection
#define ID_HIDEKEY                  40130
#define ID_SHOWKEY                  40132
#define ID_FANCYTOOLBAR_TOGGLE      40133
#define ID_ESC_ABORT_NOQUERY        40134
#define ID_CRYPTO_TOGGLE_TEXTEDIT   40135
#define ID_CRYPTO_TEST_TEXTEDIT     40136
#define ID_ASCHEX2BIN_TEXTEDIT      40137
#define ID_CRYPTO_MFRESULT_BROWSER  40138   // Multifile Browser (filtered)

// -------------
// Keyboard keys
#define ID_KEYBOARD_ESC             40200   // Not used

//---------------------------------------------------






                   