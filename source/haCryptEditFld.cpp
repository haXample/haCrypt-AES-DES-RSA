// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptEditFld.cpp - C++ Developer source file.
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
int dwTxtLen, dwKeyFileSizeSave, dwIcvFileSizeSave;
DWORD dwWritten;

TCHAR szEncFilePath[MAX_PATH]    = {0};
TCHAR szEncFileNameExt[MAX_PATH] = {0};

// External variables
extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern TCHAR _tTimeBuf[];    // File Time&Date buffer
extern int _tTimebufSize;
extern TCHAR* psz_tTimeBuf;

extern TCHAR* pszCountBuf;   // Temporary buffer for formatted text
extern int szCountBufsize;

extern int _hexMode, GlobalCryptMode, _testMode;
extern int _escFlag, dfltFlag, _testContextFlag;
extern int _keylength, keyDisplayMode, textColor, _valAQ;

extern DWORD _lastErr;
extern DWORD dwKeyFileSize, dwIvFileSize, dwTextFileSize;

extern ULONG ln, dwFileSize, dwCryptFileSize;
extern ULONG FileProcessingMode, FileProcessingModeContinue;

extern LPSTR pszHexTxtFileIn, pszTextFileIn;
extern LPSTR pszCryptFileIn, pszCryptFileDisplay, pszTextFileIn;

extern TCHAR szKeyFileName[];
extern TCHAR szIcvFileName[];
extern TCHAR szKeyNull[];
extern TCHAR szKeyHidden[];

extern TCHAR* pszTxtE;       // = TEXT("%lu bytes encrypted.");

extern TCHAR* pszTextFileExtensionFilter;
extern TCHAR* pszCurrentModeTooltip;
extern TCHAR* pszTxtE;

extern PTSTR szTruncPath;

extern char szKeyFileIn[];
extern char szIvFileIn[];
extern char KeyDialog_In[];
extern char IcvDialog_In[];

extern char* pszKeyBuffer;   // Key buffer (max key length for AES = 256 bits)
extern char* pszIcvBuffer;   // IV buffer (max key length for AES = 256 bits)

extern WPARAM gwCryptContinue;

extern HINSTANCE g_hInst;    // Main hInstance

extern HWND hStatusbar;
extern HWND hButtonHex;
extern HWND hEdit;
extern HWND hMain;

// External functions declaration
extern int AscHex2Bin(char*, char*, int); 
extern void Bin2Txt();
extern void Bin2Hex(int);
extern BOOL CheckBin2Txt(int);

extern int CBTCustomMessageBox(HWND, LPCTSTR, LPCTSTR, UINT, UINT);
extern void TruncateFilePath(LPWSTR, int, int);
extern void CtrlHideShowWindow(HWND, int);
extern void InitCryptoKeyFromFile(HWND, int);
extern void GetLastWriteTime(TCHAR*, LPTSTR, DWORD);
extern void DispayKeyFileHex(HWND, char[], int);
extern void DispayKeyDialogHex(HWND, char[], int);

extern void DisplayLastError(int);
extern void DisplayCryptoMenu();
extern void DoBinFileSave(HWND);
extern void RsaControlCryptoMenu(int);

extern void InitCryptAlgoContinue(WPARAM);
extern void DispatchCryptoAlgofunction(LPSTR, LPSTR, LPSTR, LPSTR);
extern void WindowsDoAlgorithmStealCBCE(LPSTR, LPSTR, LPSTR, LPSTR);
extern void WindowsDoAlgorithmStealCBCD(LPSTR, LPSTR, LPSTR, LPSTR);

extern INT_PTR CALLBACK DialogProcMultiFile(HWND, UINT, WPARAM, LPARAM); 
extern void DoEvents();

// Forward declaration of functions included in this code module:
BOOL SaveAesEncryptEditedText(LPSTR, int);

//---------------------------------------------------------------------
//
//         AscHex2BinEditedText ["Test: AscHex2Bin edited text"]
//
// AscHex2Bin of the edited text in the text display field
//
BOOL AscHex2BinEditedText()
  {
  BOOL bSuccess = FALSE;
  int i, dwTxtLen;

  _testMode = TRUE;
  _escFlag = FALSE;  // Reset any pending ESC-Abort condition

  // Edit field either loaded from file with edited text
  // or new text has been typed using the keyboard
  // NOTE:
  //  The user may have changed the loaded text with the keyboard.
  //  Thus 'dwTextFileSize' reflects not the actual size of the edited contents)
  //  
  // If the specified window is an edit control, the function
  //  retrieves the length of the text within the control.
  dwTxtLen = GetWindowTextLength(hEdit);

  // No need to bother if there's no text.
  if (dwTxtLen == 0)
    {
    StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("TEST-MODE ERROR: No text edited.")); 
    DisplayLastError(_ERR);         // Display formatted _tDebugBuf contents
    SendMessage(hEdit, EM_SETREADONLY, TRUE, 0);  // Disable text editor field 
    _testMode = FALSE;
    return(bSuccess);
    }

  if (pszTextFileIn == NULL)        // Allocate text buffer
    pszTextFileIn = (LPSTR)GlobalAlloc(GPTR, dwTxtLen + FILE_BLOCK_SIZE + 1);       

  if (pszCryptFileDisplay == NULL)  // Allocate hex/txt display buffer
    pszCryptFileDisplay = (LPSTR)GlobalAlloc(GPTR, CRYPT_TEXT_MAXSIZE*(3+1) + 1);   

  pszHexTxtFileIn = pszTextFileIn;  // For hex/text display

  GetWindowTextA(hEdit, pszTextFileIn, dwTxtLen + 1);    // Forces a zero-Terminater at 'dwTxtLen+1'

  LPSTR pchTmp = (LPSTR)LocalAlloc(LPTR, dwTxtLen + AES_BLOCK_SIZE + 1);    // +1 for zero terminator           
  LPSTR pchTmpOut = (LPSTR)LocalAlloc(LPTR, dwTxtLen + AES_BLOCK_SIZE + 1); // +1 for zero terminator           
  if (pchTmp != NULL)
    {
    // Copy the text of the specified window's title bar (if it has one) into a buffer.
    if (GetWindowTextA(hEdit, pchTmp, dwTxtLen + 1))     // Forces a zero-Terminater at 'dwTxtLen+1'
      {
      if (dwTxtLen < AES_BLOCK_SIZE)
        {
        for (i=dwTxtLen; i<AES_BLOCK_SIZE; i++) pchTmp[i] = ' '; // Append Spaces to text 
        dwTxtLen = AES_BLOCK_SIZE;                               // Force to 16 bytes (AES requirement)
        }

      dwFileSize = AscHex2Bin(pchTmp, pchTmpOut, dwTxtLen);      // Output: pchTmpOut[]

      // Check if edit field contains only ascii-hex text '0'..'F'
      if (dwFileSize == _ERR)                     // If ERR then pchTmpOut[] = invalid data
        {
        _hexMode = FALSE;                         // Default: text display. So he/she can examine the contents in hex
        EnableWindow(hButtonHex, TRUE);           // Enable Hex/Txt Button
        CtrlHideShowWindow(hButtonHex, SW_HIDE);  // Show/Enable Hex/Txt Button

        int msgID = CBTCustomMessageBox(hMain, _T("This service is provided for verfification of test vectors.\n\n\
TEST-MODE ERROR: Illegal AscHex format.\n\n\
Ascii-Hexadecimal format example:\n \
  01 9A FF 00 AC EB ...\n \
  019aff00aceb ...\n\n\
In the 'Text field' binary 0s are rendered as spaces.\n\
Keep this in mind when saving displayed text."),
                                   _T(" Ascii-Hexadecimal to Binary conversion"),
                                   MB_OK, IDI_HACRYPT_ICON);

        FileProcessingMode = FILEMODE_TEXTNEW;        // Set /TEXT
        SendMessage(hEdit, EM_SETREADONLY, FALSE, 0); // Enable text editor field
        _testMode = FALSE;
        return(bSuccess);
        } // end if (dwFileSize == _ERR)

      if ((int)gwCryptContinue == ID_TOOLBAR_CRYPT_CONTINUE)  // No crypto mode selected?
        {
        //StringCbPrintf(_tDebugBuf, _tDebugbufSize, szSelectCryptoMenu); 
        //DisplayLastError(_ERR);         // Display formatted _tDebugBuf contents as error
        DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_TEST_ERROR), hMain, DialogProcMultiFile, IDD_HACRYPT_TEST_ERROR); 
        SetWindowTextA(hEdit, pchTmp);
        SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/TEXT"));
        RsaControlCryptoMenu(MF_GRAYED);  // Disable RSA (not an allowed Test-Mode)              
        _testContextFlag = TRUE;          // Reflect that we are in TEST-MODE
        DisplayCryptoMenu();              // Pop up the Crypto menu                                                                
        RsaControlCryptoMenu(MF_ENABLED); // Re-enable RSA                                       
        //---------
        DoEvents(); // Ensure message queue is emptied, i.e. all Tooltip data is available
        //---------
        InitCryptAlgoContinue((WPARAM)gwCryptContinue); // Set FileProcessingMode && Tooltips 
        if ((int)gwCryptContinue == ID_TOOLBAR_CRYPT_CONTINUE) // Still no crypto mode selected?
          {
          if (GetWindowTextLength(hEdit) > EDIT_TEXT_MAXSIZE) 
            SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/TEXT (read only)"));
          else SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/TEXT")); // Show string
          SendMessage(hStatusbar, SB_SETTEXT, 1, NULL);
          _testMode = FALSE;
          return(bSuccess);                                    // Abort
          }
        }
//---------------
dialogAschex2Bin:   // The easiest way to gain comfort for usage
//---------------
      SendMessage(hEdit, EM_SETREADONLY, FALSE, 0); // Enable rd/wr in edit field 
      SetWindowTextA(hEdit, 0);                     // Required, but doesn't work alone
      // -------------------------------------------------------------------------           
      // Init-clear the Text Field (simulate new '/TEXT editor' mode: this works) |          
      extern LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);    // OK       |          
      WndProc(hMain, WM_COMMAND, ID_FILE_TEXT_NEW, 0);                // OK       |          
      // Restore FileProcessingMode (changed in 'WM_COMMAND, ID_FILE_TEXT_NEW')   | //ha//
      FileProcessingMode = FileProcessingModeContinue; // For DispayKeyFileHex()  | //ha//
      // -------------------------------------------------------------------------
      
      // Fill valid binary into pszHexTxtFileIn[] (needed for Bin2Txt())
      for (i=0; i<dwFileSize; i++) pszHexTxtFileIn[i] = pchTmpOut[i]; 

      // Display the crypto result as ANSI text
      textColor = T_GREEN;                        // Green text
      SetFocus(hEdit);
      Bin2Txt();                                  // Input: pszHexTxtFileIn[]
      SetWindowTextA(hEdit, pszCryptFileDisplay); // Change text within text field
      SetFocus (hMain);                           // Deviate focus to hMain
      textColor = FALSE;                          // Black text

      SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("Binary data"));
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT("%s"), pszCurrentModeTooltip);
      DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_ASCHEX2BIN), hMain, DialogProcMultiFile, IDD_HACRYPT_ASCHEX2BIN);
      //_valAQ==A_PLAINTEXT _valAQ==A_KEY _valAQ==A_IV _valAQ==A_A_TESTSAVE _valAQ==A_CANCEL

      switch(_valAQ)
        {
        //--------------------------------------------------------------------
        //
        //                         [CRYPTO]
        //
        case A_CRYPTO:                                // Crypto menu invocation
          Bin2Hex(TRUE);                              // Conversion binary into ascii-hex
          SetWindowTextA(hEdit, pszCryptFileDisplay); // Change text within text field   
          RsaControlCryptoMenu(MF_GRAYED);            // Disable RSA (not an allowed Test-Mode)              
          _testContextFlag = TRUE;                    // Reflect that we are in TEST-MODE
          DisplayCryptoMenu();                        // Pop up the Crypto menu                                                                
          RsaControlCryptoMenu(MF_ENABLED);           // Re-enable RSA                                       
          FileProcessingMode = FILEMODE_TEXTNEW;      // Set /TEXT
          SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/TEXT"));                             
          //---------
          DoEvents(); // Ensure message queue is emptied, i.e. all Tooltip data is available
          //---------
          InitCryptAlgoContinue((WPARAM)gwCryptContinue); // Set FileProcessingMode && Tooltips 
          bSuccess = TRUE;
          goto dialogAschex2Bin;                      // Bring up the dialog again with new algo choice
          break;                                      // Abort

        //--------------------------------------------------------------------
        //
        //                         [KEY]
        case A_KEY:
          {
          if (dwFileSize > KEY_SIZE_MAX)
            {
            DisplayLastError(HA_ERROR_KEY_FILESIZE);
            SetWindowTextA(hEdit, pchTmp);
            }

          else if (dwFileSize <= KEY_SIZE_MAX)       // key-file
            {
            for (i=0; i<KEY_SIZE_MAX; i++)           // CLear buffer
              szKeyFileIn[i] = 0;

            for (i=0; i<dwFileSize; i++)             // Load key buffer
              szKeyFileIn[i] = pszHexTxtFileIn[i];

            szKeyFileIn[dwFileSize+1] = 0;           // Add null terminator
            dwKeyFileSize = dwFileSize;
            InitCryptoKeyFromFile(hMain, 0);
            DispayKeyFileHex(hMain, szKeyFileIn, 0); // Abuse key file as TEST-KEY
            szKeyFileName[0] = 0;                    // Treat it as TEST-KEY
            _hexMode = FALSE;                        // Default = Text display
            bSuccess = TRUE;
            }
          }
          break;

        //--------------------------------------------------------------------
        //
        //                         [IV]
        case A_IV:
          {
          if (dwFileSize > AES_BLOCK_SIZE)
            {
            DisplayLastError(HA_ERROR_IV_FILESIZE);
            SetWindowTextA(hEdit, pchTmp);
            }

          else if (dwFileSize <= AES_BLOCK_SIZE)    // IV-file
            {
            for (i=0; i<AES_BLOCK_SIZE; i++)        // CLear buffer
              szIvFileIn[i] = 0;

            for (i=0; i<dwFileSize; i++)            // Load IV buffer
              szIvFileIn[i] = pszHexTxtFileIn[i];

            szIvFileIn[dwFileSize+1] = 0;           // Add null terminator
            dwIvFileSize = dwFileSize;
            InitCryptoKeyFromFile(hMain, 1);
            DispayKeyFileHex(hMain, szIvFileIn, 1); // Abuse IV file as TEST-IV
            szIcvFileName[0] = 0;                   // Treat it as TEST-IV
            _hexMode = FALSE;                       // Default = Text display
            bSuccess = TRUE;
            }
          }   
          break;

        //--------------------------------------------------------------------
        //
        //                         [PLAINTEXT]
        case A_PLAINTEXT:
          if ((int)gwCryptContinue < ID_CRYPTO_AES_ECBENCRYPT &&       // ENUM'd see haCrypt.h
              dwFileSize < DES_BLOCK_SIZE)
            {
            DisplayLastError(HA_ERROR_FILESIZE_DES);
            SetWindowTextA(hEdit, pchTmp);
            }

          else if ((int)gwCryptContinue >= ID_CRYPTO_AES_ECBENCRYPT && // ENUM'd see haCrypt.h
                   dwFileSize < AES_BLOCK_SIZE)
            {
            DisplayLastError(HA_ERROR_FILESIZE_AES);
            SetWindowTextA(hEdit, pchTmp);
            }

          else
            {
            dwCryptFileSize = dwFileSize; // dwCryptFileSize: Needed for Crypto algo.
            FileProcessingMode = FileProcessingModeContinue;
            DispatchCryptoAlgofunction(pszHexTxtFileIn,  pszHexTxtFileIn, pszIcvBuffer, pszKeyBuffer);
            dwFileSize = ln;                              // Remember MAC, padding!
            EnableWindow(hButtonHex, TRUE);               // Enable Hex/Txt Button
            CtrlHideShowWindow(hButtonHex, SW_SHOW);      // Show/Enable Hex/Txt Button
            Bin2Hex(TRUE);                                // Conversion into ascii-hex

            SendMessage(hEdit, EM_SETREADONLY, FALSE, 0); // Enable rd/wr in edit field 
            SetWindowTextA(hEdit, 0);                     // Required, but doesn't work alone
            // -------------------------------------------------------------------------           
            // Init-clear the Text Field (simulate new '/TEXT editor' mode: this works) |          
            extern LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);    // OK       |          
            WndProc(hMain, WM_COMMAND, ID_FILE_TEXT_NEW, 0);                // OK       |          
            // Restore FileProcessingMode (changed in 'WM_COMMAND, ID_FILE_TEXT_NEW')   | //ha//
            FileProcessingMode = FileProcessingModeContinue; // For DispayKeyFileHex()  | //ha//
            // -------------------------------------------------------------------------           

            // Display the crypto result in ascii-hex
            textColor = T_GREEN;                        // Green text                              
            SetFocus(hEdit);                                                                       
            SetWindowTextA(hEdit, pszCryptFileDisplay); // Change text within text field   
            SetFocus (hMain);                           // Deviate focus to hMain                  
            textColor = FALSE;                          // Black text                              

            // Display the key being currently used for TEST-MODE                                                  
            if (dwIvFileSize > 0) szIcvFileName[0] = 0;      // IcvFilebuffer used as TEST-IV from now on
            if (dwKeyFileSize > 0)                           // KeyFilebuffer used as TEST-KEY from now on
              {
              szKeyFileName[0] = 0;                      // Treat it as TEST-KEY
              DispayKeyFileHex(hMain, szKeyFileIn, 0);
              SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("Result (TEST-KEY)"));                             
              }
            else
              {
              DispayKeyDialogHex(hMain, KeyDialog_In, 0);                                              
              SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("Result (Key)"));                            
              }
            if (keyDisplayMode == MF_UNCHECKED)                                                    
              SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)szKeyHidden);

            pszCryptFileIn = (LPSTR)GlobalFree(pszCryptFileIn);
            FileProcessingMode = FILEMODE_TEXTNEW;      // Set /TEXT
            _hexMode = TRUE;                            // Default = Hex display
            bSuccess = TRUE;
            }
          break;

        //--------------------------------------------------------------------
        //
        //                         [SAVE]  Save binary data
        case A_TESTSAVE:
          dwCryptFileSize = dwFileSize; // dwCryptFileSize: Needed for Crypto algo.
          if (pszCryptFileIn != NULL) pszCryptFileIn = (LPSTR)GlobalFree(pszCryptFileIn);
          pszCryptFileIn = (LPSTR)GlobalAlloc(GPTR, dwCryptFileSize + 1);
          for (i=0; i<dwCryptFileSize; i++) pszCryptFileIn[i] = pszHexTxtFileIn[i]; 
          DoBinFileSave(hMain);           
          pszCryptFileIn = (LPSTR)GlobalFree(pszCryptFileIn);
          FileProcessingMode = FILEMODE_TEXTNEW;      // Set /TEXT
          SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/TEXT"));                             
          bSuccess = TRUE;
          break;

        //--------------------------------------------------------------------
        //
        //                         [CANCEL]  ESC-Key
        case A_CANCEL:
          FileProcessingMode = FILEMODE_TEXTNEW;      // Set /TEXT
          SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/TEXT"));                             
          break;
        } // end switch(valAQ)

      EnableWindow(hButtonHex, TRUE);           // Enable Hex/Txt Button
      CtrlHideShowWindow(hButtonHex, SW_SHOW);  // Show/Enable Hex/Txt Button
      } // end if (GetWindowTextA)

    pchTmp = (LPSTR)LocalFree(pchTmp);          // Free allocated memory
    pchTmpOut = (LPSTR)LocalFree(pchTmpOut);
    } // end if (pchTmp != NULL)

  _testMode = FALSE;
  return(bSuccess);
  } // AscHex2BinEditedText

//---------------------------------------------------------------------
//
//            CryptoTestEditedText ["Test: Crypto edited text"]
//
// Encryption of the edited text in the text display field (gwCryptContinue???)
//
BOOL CryptoTestEditedText(int cryptMode)
  {
  BOOL bSuccess = FALSE;
  int i;

  _testMode = TRUE;
  _escFlag = FALSE;          // Reset any pending ESC-Abort condition

  // Edit field either loaded from file with edited text
  // or new text has been typed using the keyboard
  // NOTE:
  //  The user may have changed the loaded text with the keyboard.
  //  (Thus 'dwTextFileSize' not reflects the actual size of the edited contents)
  //  
  // If the specified window is an edit control, the function
  //  retrieves the length of the text within the control.
  dwTxtLen = GetWindowTextLength(hEdit);

  // No need to bother if there's no text.
  if (dwTxtLen == 0)
    {
    StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("TEST-MODE ERROR: No text edited.")); 
    DisplayLastError(_ERR);     // Display formatted _tDebugBuf contents
    SendMessage(hEdit, EM_SETREADONLY, TRUE, 0);  // Disable text editor field 
    _testMode = FALSE;
    return(bSuccess);
    }

  //-----------------------------------------------------------------------------------
  // TEST-MODE ERROR: Select a mode from Crypt-Menu and then invoke again.
  //
  if ((int)gwCryptContinue == ID_TOOLBAR_CRYPT_CONTINUE)  // No crypto mode selected?
    {
    DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_TEST_ERROR), hMain, DialogProcMultiFile, IDD_HACRYPT_TEST_ERROR);         
    RsaControlCryptoMenu(MF_GRAYED);  // Disable RSA (not an allowed Test-Mode)                       
    _testContextFlag = TRUE;          // Reflect that we are in TEST-MODE
    DisplayCryptoMenu();              // Pop up the Crypto menu                                                                
    RsaControlCryptoMenu(MF_ENABLED); // Re-enable RSA                                                
    //---------
    DoEvents(); // Ensure message queue is emptied, i.e. all Tooltip data is available
    //---------
    InitCryptAlgoContinue((WPARAM)gwCryptContinue); // Set FileProcessingMode && Tooltips
    if ((int)gwCryptContinue == ID_TOOLBAR_CRYPT_CONTINUE) // Still no crypto mode selected?
      {
      if (GetWindowTextLength(hEdit) > EDIT_TEXT_MAXSIZE) 
        SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/TEXT (read only)"));
      else SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/TEXT")); // Show string
      SendMessage(hStatusbar, SB_SETTEXT, 1, NULL);
      _testMode = FALSE;
      return(bSuccess);                                    // Abort
      }
    }
  
//---------------
dialogEditedText:   // The easiest way to gain comfort for usage
//---------------
  // Maximum memory buffer size possible: Windows System dependent ~ 1.6G
  dwTxtLen = GetWindowTextLength(hEdit);
  dwFileSize = (ULONG)dwTxtLen; // dwFileSize: Needed for CheckBin2Txt(1), 

  // -----------------------
  // Allocate global buffers
  //                                
  // Free possibly occupied /TEXT memory Only if not already freed
  if (pszTextFileIn != NULL) pszTextFileIn = (LPSTR)GlobalFree(pszTextFileIn);
    
  // Free occupied hex/txt display buffer
  if (pszCryptFileDisplay != NULL) pszCryptFileDisplay = (LPSTR)GlobalFree(pszCryptFileDisplay);

  pszTextFileIn = (LPSTR)GlobalAlloc(GPTR, dwTxtLen + FILE_BLOCK_SIZE + 1);     // Allocate enough text buffer      
  pszCryptFileDisplay = (LPSTR)GlobalAlloc(GPTR, CRYPT_TEXT_MAXSIZE*(3+1) + 1); // Allocate hex/txt display buffer  

  // Load the edited text (faked as a textfile)
  GetWindowTextA(hEdit, pszTextFileIn, dwTxtLen + 1); // Forces a zero-Terminater at 'dwTxtLen+1'
  pszHexTxtFileIn = pszTextFileIn;                    // For hex/text display

  LPSTR pchTmpSav = (LPSTR)LocalAlloc(LPTR, dwTxtLen + FILE_BLOCK_SIZE + 1);    // Save buffer            
  for (i=0; i<dwTxtLen; i++) pchTmpSav[i] = pszTextFileIn[i];                   // Save pszTextFileIn for later
   
  LPSTR pchTmp = (LPSTR)LocalAlloc(LPTR, dwTxtLen + AES_BLOCK_SIZE + 1); // +1 for zero terminator            
  if (pchTmp != NULL)
    {
    // Copy the edited text into local buffer.
    if (GetWindowTextA(hEdit, pchTmp, dwTxtLen + 1))  // Forces a zero-Terminater at 'dwTxtLen+1'
      {
      if ((FileProcessingModeContinue & CRYPT_AES) == CRYPT_AES && dwTxtLen < AES_BLOCK_SIZE)
        {
        for (i=dwTxtLen; i<AES_BLOCK_SIZE; i++) pchTmp[i] = ' '; // AES: Append Spaces to edited text 
        dwTxtLen = AES_BLOCK_SIZE;                               // Force to 16 bytes (AES requirement)
        }
      else if (dwTxtLen < DES_BLOCK_SIZE)                          
        {
        for (i=dwTxtLen; i<DES_BLOCK_SIZE; i++) pchTmp[i] = ' '; // DES, 3DES(TDES): Append Spaces to text 
        dwTxtLen = DES_BLOCK_SIZE;                               // Force to 8 bytes (DES, 3DES requirement)
        }

      dwCryptFileSize = (ULONG)dwTxtLen;  // dwCryptFileSize: Needed for Crypto algo.
      dwFileSize =      (ULONG)dwTxtLen;  // dwFileSize: Needed for Hex/Text display and backup. 

      DispatchCryptoAlgofunction(pchTmp, pchTmp, pszIcvBuffer, pszKeyBuffer);   // Any selected mode from Crypto-Menu
      dwFileSize = ln;                    // Remember padding and MAC!

      // Save 'pchTmp' into a static buffer for later usage.
      // pszHexTxtFileIn must persist after exiting this function.
      // Must use 'dwFileSize=ln" (Complete output from crypto functions -> padding and MAC!)
      for (i=0; i<dwFileSize; i++) pszHexTxtFileIn[i] = pchTmp[i];
      Bin2Txt();                          //  .. and fill pszCryptFileDisplay buffer   

      // -------------------------------------------------------------------------  
      // Init-clear the Text Field (simulate new '/TEXT editor' mode: this works) | 
      extern LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);    // OK       | 
      WndProc(hMain, WM_COMMAND, ID_FILE_TEXT_NEW, 0);                // OK       | 
      // Restore FileProcessingMode (changed in 'WM_COMMAND, ID_FILE_TEXT_NEW')   | //ha//
      FileProcessingMode = FileProcessingModeContinue; // For DispayKeyFileHex()  | //ha//
      // -------------------------------------------------------------------------  

      textColor = T_GREEN;                // Green text
      SetFocus(hEdit);
      // Change text within specified text field (crypto display may be truncated)
      if (SetWindowTextA(hEdit, pszCryptFileDisplay)) bSuccess = TRUE;
      SetFocus (hMain);                   // Deviate focus to hMain
      textColor = FALSE;                  // Black text

      //-----------------------------------------------------------------------------------
      // [Question: Do you want to keep the 'Crypto' text?]
      //
      DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_TEST_KEEP), hMain, DialogProcMultiFile, IDD_HACRYPT_TEST_KEEP);            

      _hexMode = FALSE;                               // Default: Text display.

      // Change text within text field
      SetFocus(hEdit);
      switch(_valAQ)
        {
        case A_CRYPTO:                                // Crypto menu invocation
          FileProcessingMode = FILEMODE_TEXTNEW;      // Set /TEXT
          SetWindowTextA(hEdit, pchTmpSav);           // Restore and display edited text as is
          EnableWindow(hButtonHex, FALSE);            // Disable Hex/Txt Button
          CtrlHideShowWindow(hButtonHex, SW_HIDE);    // Hide/Disable Hex/Txt Button
          RsaControlCryptoMenu(MF_GRAYED);            // Disable RSA (not an allowed Test-Mode)              
          _testContextFlag = TRUE;                    // Reflect that we are in TEST-MODE
          DisplayCryptoMenu();                        // Pop up the Crypto menu                                                                
          RsaControlCryptoMenu(MF_ENABLED);           // Re-enable RSA                                       
          SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/TEXT"));                             
          //---------
          DoEvents(); // Ensure message queue is emptied, i.e. all Tooltip data is available
          //---------
          InitCryptAlgoContinue((WPARAM)gwCryptContinue); // Set FileProcessingMode && Tooltips 
          pchTmp = (LPSTR)LocalFree(pchTmp);              // Release allocated memory
          pchTmpSav = (LPSTR)LocalFree(pchTmpSav);
          goto dialogEditedText;                          // Bring up the dialog again with new algo choice
          break;

        case A_YES:                                    // [YES] Fill pszCryptFileDisplay
          SetWindowTextA(hEdit, pszCryptFileDisplay);  // Display encrypted text truncated
          // So he/she can examine the contents in hex
          EnableWindow(hButtonHex, TRUE);              // Enable Hex/Txt Button
          CtrlHideShowWindow(hButtonHex, SW_SHOW);     // Show/Enable Hex/Txt Button

          // Display the key being currently used for TEST-MODE                                                  
          if (dwKeyFileSize > 0)                       // KeyFilebuffer used for TEST-KEY
            {
            szKeyFileName[0] = 0;                      // Treat it as TEST-KEY from now on
            DispayKeyFileHex(hMain, szKeyFileIn, 0);
            SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("Result (TEST-KEY)"));                             
            }
          else
            {
            DispayKeyDialogHex(hMain, pszKeyBuffer, 0);                                              
            SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("Result (Key)"));                            
            }
          if (keyDisplayMode == MF_UNCHECKED)                                                    
            SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)szKeyHidden);
                                     
          _hexMode = FALSE;                        // Default = Text display
          FileProcessingMode = FILEMODE_TEXTNEW;   // Set /TEXT
          bSuccess = TRUE;
          break;

        case A_NO:                                 // [NO] Keep pszHexTxtFileIn
          SetWindowTextA(hEdit, pchTmpSav);        // Restore and display edited text as is
          EnableWindow(hButtonHex, FALSE);         // Disable Hex/Txt Button
          CtrlHideShowWindow(hButtonHex, SW_HIDE); // Hide/Disable Hex/Txt Button
          if (GetWindowTextLength(hEdit) > EDIT_TEXT_MAXSIZE) 
            SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/TEXT (read only)"));
          else SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/TEXT")); // Show string
          SendMessage(hStatusbar, SB_SETTEXT, 1, NULL);
          break;
    
        }  // end swirch

      SetFocus (hMain);                           // Deviate focus to hMain
      bSuccess = TRUE;                            

      pchTmp = (LPSTR)LocalFree(pchTmp);          // Release allocated memory
      pchTmpSav = (LPSTR)LocalFree(pchTmpSav);
      } // end if (GetWindowTextA)
    } // end if (pchTmp != NULL)

  _testMode = FALSE;
  return(bSuccess);
  } // CryptoTestEditedText


//---------------------------------------------------------------------
//
//            AesEncryptEditedText ["AES encrypt edited text"]
//
// AES Encryption of the edited text in the text display field ("Password Vault")
//
BOOL AesEncryptEditedText(int cryptMode)
  {
  BOOL bSuccess = FALSE;
  int i, dwTxtLen;

  _escFlag = FALSE;          // Reset any pending ESC-Abort condition

  FileProcessingMode = CRYPT_AES | CRYPT_CBC;  // AES /Encrypt (Ciphertext stealing)

  // Edit field either loaded from file with edited text
  // or new text has been typed using the keyboard
  // NOTE:
  //  The user may have changed the loaded text with the keyboard.
  //  (Thus 'dwTextFileSize' not reflects the actual size of the edited contents)
  //  
  // If the specified window is an edit control, the function
  //  retrieves the length of the text within the control.
  dwTxtLen = GetWindowTextLength(hEdit);

  // No need to bother if there's no text.
  if (dwTxtLen == 0)
    {
    StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("ERROR: No text edited.")); 
    DisplayLastError(_ERR);     // Display formatted _tDebugBuf contents
    return(bSuccess);
    }

  // Maximum memory buffer size possible: Windows System dependent ~ 1.6G
  dwTxtLen = GetWindowTextLength(hEdit);
  dwFileSize = (ULONG)dwTxtLen; // dwFileSize: Needed for CheckBin2Txt(1), 

  // -----------------------
  // Allocate global buffers
  //                                
  // Free possibly occupied /TEXT memory Only if not already freed
  if (pszTextFileIn != NULL) pszTextFileIn = (LPSTR)GlobalFree(pszTextFileIn);
    
  // Free occupied hex/txt display buffer
  if (pszCryptFileDisplay != NULL) pszCryptFileDisplay = (LPSTR)GlobalFree(pszCryptFileDisplay);

  pszTextFileIn = (LPSTR)GlobalAlloc(GPTR, dwTxtLen + FILE_BLOCK_SIZE + 1);     // Allocate text buffer      
  pszCryptFileDisplay = (LPSTR)GlobalAlloc(GPTR, CRYPT_TEXT_MAXSIZE*(3+1) + 1); // Allocate hex/txt display buffer  

  pszHexTxtFileIn = pszTextFileIn;            // For hex/text display

  GetWindowTextA(hEdit, pszTextFileIn, dwTxtLen + 1); // Forces a zero-Terminater at 'dwTxtLen+1'

  // Check if edit field is an edited ascii text
  if (CheckBin2Txt(1) == TRUE)
    {
    StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("ERROR: Not a plain ansi text.")); 
    DisplayLastError(_ERR);                   // Display formatted _tDebugBuf contents as error
    _hexMode = FALSE;                         // Default: text display. So he/she can examine the contents in hex
    EnableWindow(hButtonHex, TRUE);           // Enable Hex/Txt Button
    CtrlHideShowWindow(hButtonHex, SW_SHOW);  // Show/Enable Hex/Txt Button
    return(bSuccess);
    }

  LPSTR pchTmp = (LPSTR)LocalAlloc(LPTR, dwTxtLen + AES_BLOCK_SIZE + 1); // +1 for zero terminator            
  if (pchTmp != NULL)
    {
    // Copy the text of the specified window's title bar (if it has one) into a buffer.
    if (GetWindowTextA(hEdit, pchTmp, dwTxtLen + 1)) // Forces a zero-Terminater at 'dwTxtLen+1'
      {
      if (dwTxtLen < AES_BLOCK_SIZE)
        {
        for (i=dwTxtLen; i<AES_BLOCK_SIZE; i++) pchTmp[i] = ' '; // Append Spaces to text 
        dwTxtLen = AES_BLOCK_SIZE;                               // Force to 16 bytes (AES requirement)
        }

      dwCryptFileSize = (ULONG)dwTxtLen;  // dwCryptFileSize: Needed for Crypto algo.
      dwFileSize =      (ULONG)dwTxtLen;  // dwFileSize: Needed for Hex/Text display and backup. 

      // Force crypto mode = 'AES /Encrypt (CBC Ciphertext stealing)'
      FileProcessingMode = CRYPT_AES | CRYPT_CBC;
      WindowsDoAlgorithmStealCBCE(pchTmp, pchTmp, pszIcvBuffer, pszKeyBuffer);

      pszHexTxtFileIn = pchTmp;           // For hex/text display             
      Bin2Txt();                          // Fill pszCryptFileDisplay with crypto data        

//ha//// Init-clear the Text Field  ???? All this doesn't work!
//ha//      SetFocus(hEdit);
//ha//      SendMessage(hEdit, EM_SETREADONLY, FALSE, 0); // ??? Enable text editor field   ???? doesn't work
//ha//      SetWindowText(hEdit, _T(""));                 // ??? Init-clear the Text Field  ???? doesn't work
//ha//      SetDlgItemText(hMain, IDC_MAIN_EDIT, NULL);   // ??? Clear text edit field      ???? doesn't work

      // -------------------------------------------------------------------------  
      // Init-clear the Text Field (simulate new '/TEXT editor' mode: this works) | 
      extern LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);    // OK       | //ha//
      WndProc(hMain, WM_COMMAND, ID_FILE_TEXT_NEW, 0);                // OK       | //ha//
      // Restore dwCryptFileSize (was zeroed in 'WM_COMMAND, ID_FILE_TEXT_NEW')   | //ha//
      dwCryptFileSize = dwFileSize;                                   // Reload   | //ha//
      // -------------------------------------------------------------------------  

      StringCbPrintf(pszCountBuf, szCountBufsize, pszTxtE, ln);
      SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)pszCountBuf);
      SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)szEncFilePath);

      textColor = T_GREEN;                      // Green text
      SetFocus(hEdit);
      // Change text within specified text field
      //if (SetWindowTextA(hEdit, pchTmp)) bSuccess = TRUE;            // Display as is
      if (SetWindowTextA(hEdit, pszCryptFileDisplay)) bSuccess = TRUE; // Display truncated
      SetFocus (hMain);                         // Deviate focus to hMain
      textColor = FALSE;                        // Black text

      _hexMode = FALSE;                         // Default = text display
      EnableWindow(hButtonHex, TRUE);           // Enable Hex/Txt Button
      CtrlHideShowWindow(hButtonHex, SW_SHOW);  // Show/Enable Hex/Txt Button

      //-----------------------------------------------------------------------------------
      // Question: Do you want to save the 'AES /Encrypt' text?
      //
      //int msgID = CustomMessageBox(hMain, _T(" The edited text has been encrypted with\n \
      //Mode = 'AES /Encrypt (CBC Ciphertext stealing)'.\n\n \
      //Text shorter than AES blocksize is appended with spaces.\n \
      //      The current AES Key/IV settings have been used.\n \
      //         You must remember these settings, because\n \
      //              Mode and secret Key/IV are required\n \
      //                 to '/Decipher' the encrypted text\n \
      //                     residing in the saved file.\n\n \
      //Do You want to save the encrypted ascii text into a file?            "),
      //                                   _T(" AES /Encrypt (CBC Ciphertext stealing)"),
      //                                   MB_YESNO, IDI_HACRYPT_ICON);
      //
      //if (msgID == IDYES) SaveAesEncryptEditedText(pchTmp, dwTxtLen);

      DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_EDITCRYPT), hMain, DialogProcMultiFile, IDD_HACRYPT_EDITCRYPT);
      if (_valAQ == A_YES) bSuccess = SaveAesEncryptEditedText(pchTmp, dwTxtLen);
      //-----------------------------------------------------------------------------------
 
      // Force crypto mode = 'AES /Decipher (CBC Ciphertext stealing)'
      FileProcessingMode = CRYPT_AES | CRYPT_CBC;
      WindowsDoAlgorithmStealCBCD(pchTmp, pchTmp, pszIcvBuffer, pszKeyBuffer);

      // -------------------------------------------------------------------------  
      // Init-clear the Text Field (simulate new '/TEXT editor' mode: this works) | 
      extern LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);    // OK       | 
      WndProc(hMain, WM_COMMAND, ID_FILE_TEXT_NEW, 0);                // OK       | 
      // -------------------------------------------------------------------------  

      if (bSuccess == TRUE)
        {
        StringCbPrintf(_tDebugBuf, _tDebugbufSize, pszTxtE, dwWritten);
        SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)_tDebugBuf);
        SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)szEncFilePath);
        }

      // Change text within specified text field
      SetFocus(hEdit);
      if (SetWindowTextA(hEdit, pchTmp)) bSuccess = TRUE;  // Display as is
      SetFocus(hMain);                          // Deviate focus to hMain

      _hexMode = FALSE;                         // Init text display (default)
      EnableWindow(hButtonHex, FALSE);          // Disable Hex/Txt Button
      CtrlHideShowWindow(hButtonHex, SW_HIDE);  // Hide Hex/Txt Button
      } // end if (GetWindowTextA)

    pchTmp = (LPSTR)LocalFree(pchTmp);
    } // end if (pchTmp != NULL)

  return(bSuccess);
  } // AesEncryptEditedText

//-----------------------------------------------------------------------------
//
//            SaveAesEncryptEditedText  ["AES encrypt edited text"]
//
//  OPENFILENAME cryofn;   (Global)
//
OPENFILENAME cryofn = {0};  // Global to remember the 'ofn.lpstrInitialDir'

TCHAR* pszEncFileExtension = _T(".A~e");
TCHAR* pszEncTitle         = _T("Save encrypted text");

BOOL SaveAesEncryptEditedText(LPSTR pszWrBuf, int wrBufSize)
  {
  BOOL bSuccess = FALSE;
  
  ZeroMemory(&cryofn, sizeof(OPENFILENAME));

  cryofn.lStructSize     = sizeof(OPENFILENAME);
  cryofn.hwndOwner       = hMain;
  cryofn.lpstrFilter     = pszTextFileExtensionFilter;
  cryofn.lpstrFile       = szEncFilePath;       // Complete file path
  cryofn.nMaxFile        = MAX_PATH;
  cryofn.lpstrFileTitle  = szEncFileNameExt;    // Filename + Extension (w/o path info)
  cryofn.lpstrTitle      = pszEncTitle;
  cryofn.lpstrInitialDir = NULL;
  cryofn.lpstrDefExt     = NULL;    // Auto-appending doesn' t work?? [.txt] instead of [.A~e] if filename has no extension
  cryofn.nFileExtension;            // Nr of chars up to the file extension
  cryofn.nFileOffset;               // Nr of chars up to the file name
  cryofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY; // | OFN_OVERWRITEPROMPT;

  if (GetSaveFileName(&cryofn))
    {
    hEdit = GetDlgItem(hMain, IDC_MAIN_EDIT);

    //---------------------------------------------------------------------------
    // Auto-appending doesn't work??? Either [.txt] instead of [.A~e] or nothing.
    // GetSaveFileName() not working properly with cryofn.lpstrDefExt???
    // So here's my own solution ...
    //
    if (cryofn.nFileExtension == 0 || StrStrI(szEncFilePath, pszEncFileExtension) == NULL)
      lstrcat(szEncFilePath, pszEncFileExtension);

    if (PathFileExists(szEncFilePath))
      {
      // The original windows prompt would look like this:
      //StringCbPrintf(_tDebugBuf, _tDebugbufSize,
      //               _T("%s  File already exists.\nDo you want to replace it?"),
      //               &szEncFilePath[cryofn.nFileOffset]);
      //int msgID = CustomMessageBox(hMain, _tDebugBuf, _T(" Confirm save as..."),
      //                             MB_YESNO, IDI_HACRYPT_ICON);
      //if (msgID == IDNO) return(bSuccess); // IDNO= user abort, IDYES= fall thru

      GetLastWriteTime(szEncFilePath, _tTimeBuf, MAX_PATH);
      // Calculate [KB] like WINDOWS-Explorer
      int fsRounding = 1;                             // Round to next higher KB value
      if ((dwFileSize % 1024L) == 0) fsRounding = 0;  // Don't round exact values

      TruncateFilePath((PWSTR)szEncFilePath, 55, 0);  // Should fit nicely into dialogbox
      StringCbPrintf(_tDebugBuf, _tDebugbufSize, TEXT(" \
%s\n \
Size: %d KB\n \
Change Date: %s"), szTruncPath, //szCryptoDestName, 
                 (dwFileSize==0L ? 0L : (dwFileSize/1024L)+fsRounding),
                 _tTimeBuf);
  
      // Single file Modal DialogBox "Confirm save as..." "[Yes]" "[No]"
      DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_FILESAV), hMain, DialogProcMultiFile, IDD_HACRYPT_FILESAV);
      if (_valAQ == A_NO) return(bSuccess); // IDNO= user abort, IDYES= fall thru
      } // end if (PathFileExists)
    //---------------------------------------------------------------------------

    // Display saving ...
    SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); // Clean up satusbar from 'paint' 
    SendDlgItemMessage(hMain, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)_T("Saving, please wait ..."));

    HANDLE hFile = CreateFile(
      szEncFilePath, 
      GENERIC_WRITE, 
      0, 
      NULL,
      CREATE_ALWAYS, 
      FILE_ATTRIBUTE_NORMAL, 
      NULL);

    _escFlag = FALSE;          // Reset any pending ESC-Abort condition

    if (hFile != INVALID_HANDLE_VALUE)
      {
      // Write wrBufSize (binary)
      if (WriteFile(hFile, pszWrBuf, wrBufSize, &dwWritten, NULL)) bSuccess = TRUE;
      else
        {
        _lastErr = GetLastError();              // Save error code  from 'WriteFile'
        DisplayLastError(_lastErr);             // Display _lastErr
        }

      CloseHandle(hFile);
      } // end if(hfile)
 
    else DisplayLastError(HA_ERROR_FILE_WRITE);  // General error
    }

  FileProcessingMode = FILEMODE_TEXTNEW;        // Set /TEXT
  return(bSuccess);
  } // SaveAesEncryptEditedText

//--------------------------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//MessageBoxA(NULL, "STOP", "STOP 1", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//StringCbPrintf(_tDebugBuf, _tDebugbufSize, 
//ha//               _T("lpDIS->itemID = %d [%d]\nlpDIS->hwndItem = %d\nhStatusbar = %d\nText = %s"),
//ha//                   lpDIS->itemID, (HMENU)IDC_MAIN_STATUS, lpDIS->hwndItem, hStatusbar, lpDIS->itemData);
//ha//MessageBox(NULL, _tDebugBuf, _T("DEBUG STOP Start"), MB_ICONINFORMATION | MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

