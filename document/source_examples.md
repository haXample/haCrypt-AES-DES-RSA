# haCrypt - Guide to Source Examples

#### 1. Self-modifying Code (32bit version only): 
desfast.asm					       
- _SMC SEGMENT, _SMC ENDS
- ChkCpuFamily PROC C
- desKeyInit PROC C
- desAlgorithm PROC C
- permute PROC C  

haCrypt.nmk
- LFLAGS = /SECTION:_SMC,RWE /MANIFESTUAC:"uiAccess='true'"  
           /MANIFESTUAC:"level='asInvoker' uiAccess='false'"  
           /SUBSYSTEM:WINDOWS  
           /TLBID:1 /DYNAMICBASE /NXCOMPAT

#### 2. Interfacing 32bit: C++ Func calling an Assembler Proc
aesfast.asm  
desfast.asm  
tdesfast.asm  
haCryptAlgoM.cpp
- DoKeyInit  
- DoCryptoAlgorithm    

#### 3. Interfacing 64bit: C++ Func calling an Assembler Proc
aesfast64.asm  
desfast64.asm  
tdesfast64.asm  
haCryptAlgoM.cpp
- DoKeyInit  
- DoCryptoAlgorithm    

#### 4. Debug: C++ Func debugging an Assembler Proc 
haDebug.asm
- DebugbufProc PROC C

haDebug64.asm
- _DebugbufProc	PROC

#### 5. Colored Status Messages
haCryptMain.cpp
- case WM_DRAWITEM:

haCryptDraw.cpp
- PaintColoredStatusInfoMsg
- PaintColoredStatusMsg  
- PaintColoredStatusErrorMsg
- PaintColoredStatusProgressMsg 
- PaintColoredStatusPercentMsg

#### 6. Toolbar fancy color, custom-drawed and owner-drawed buttons
haCryptDraw.cpp  
- CreateTBGradientBrush  
- DrawItemService  
- CustomdDrawService  
- SubclassprocButton

haCryptCtrl.cpp  
- ControlCryptoToolItems    
- ControlToolWindow  

#### 7. Tooltips, Quickinfo  
haCryptMain.cpp  
- case TTN_NEEDTEXT

haCryptWin.cpp  
- CreateToolTip  
  
#### 8. Custom Toolbar with custom icons  
haCryptWin.cpp  
- CreateCustomToolbar  

haCryptMenu.cpp  
- WINAPI CreateMenuItemIcons

#### 9. Owner drawed Menu icons  
haCryptMain.cpp
- case WM_DRAWITEM:

haCryptMenu.cpp  
- #ifdef OWNERDRAW_MENU_ICON  	
- WINAPI CreateMenuItemIcons
- DrawMenuItem  

#### 10. Progressbar
haCryptProgbar.cpp
- CreateProgressBar
- CreateProgressBarL
- DisplayProgressCount
- DisplayProgressCountL

#### 11. Visual Styles (Themes)  
haCrypt.nmk  
haCryptMain.cpp    
- #ifdef THEME

haCryptProgbar.cpp  
- #include <uxtheme.h>
- InitProgressbar
- InitProgressbarL

#### 12. Multiple files	selection
haCryptFileC.cpp
- MultiBinFileOpen
- SaveMultiBinFile
- DisplayListMultipleFiles  

#### 13. Rename file-type of multiple files  
haCryptFileR.cpp  
- DoFileRename  

#### 14. Filter file-types in browser window  
haCryptWRL.cpp  
- EvaluateFileType  
- EvaluateShouldShow  
- class XP_FolderFilterFileType  
- class W10_FolderFilterFileType  
- WRLBrowseCallbackProc  
- BrowserFilterFileType

haCryptDialog.cpp  
- CBTProc (CBTMessageBox)  

#### 15. Console window  
haCryptConsole.cpp  
- ConsoleHeditExeVerify  
- CreateConsole  
- DoConsoleFileOpen  

#### 16. Centered message boxes and centered modal dialog windows  
haCryptDialog.cpp  
- CustomMessageBox  
- CenterInsideParent  
- PIDLIST_ABSOLUTE CBTSHBrowseForFolder  
- CBTProc (CBTMessageBox)  
- DialogProcMultiFile  

#### 17. Large filesize > 4Gbyte  
haCryptAlgoL.cpp
- LoadBinFileCryptoL
- DoLargeBinFileCrypto

haCryptFileC.cpp  
- SaveMultiBinFile

#### 18. Context Menu
haCryptMain.cpp
- case WM_CONTEXTMENU:

haCryptMenu.cpp
- APIENTRY HandleContextMenu

#### 19. Exception handling
rsabiginteger.cpp
- BigInteger::expoModNBigInteger  

#### 20. Ansi to Unicode  
haCryptAlgoRsa.cpp  
- AnsiToUnicode

#### 21. ENTER-key detection 
haCryptMain.cpp 
- case WM_KEYDOWN: 
- case ID_HEX_DISPLAY: 
- case ID_DIALOG_KEY: 
- case ID_DIALOG_IV:

#### 22. ESC-key Thead function 
haCryptMain.cpp  
- WINAPI CheckEscape  
- CheckEscapeAbort

#### 23. Important: Prevent freezing the progressbar window 
haCryptMain.cpp  
- DoEvents

#### 24. Remove dotted line on button  
haCryptWin.cpp  
- CreateButtonSetKey  
- CreateButtonSetIV  
- CreateButtonHexText  

#### 25. Build Version Control
BuildVersion.vbs  
SetVersion.vbs  
haCryptBuildTime.ver  
haCryptBuildTime.cpp        
haCrypt.NMK  
- !IFNDEF SETVERSION
- !IFDEF SETVERSION 

#### 26. Manifest file  
haCryptALL.exe.manifest   
haCrypt.NMK  
- LFLAGS= /MANIFEST  

#### 27. Edit-field text color
haCryptEditFld.cpp
- CryptoTestEditedText  

haCryptMain.cpp  
- case WM_CTLCOLORSTATIC:
- case WM_CTLCOLOREDIT:

#### 28. Embed a bitmap into Help popup window
haCrypt.rc  
- CONTROL ID_HELP_ABOUT_QUICKBMP  

#### 29. Simulate a mouse click
haCryptCtrl.cpp  
- ShowWinMouseClick  
- CtrlHideShowWindow  

#### 30. Icons with transparent background
ha*.ico

#### 31. AES assembler macros
aesfast.inc  
aesfast64.inc

#### 32. DES, AES, 3DES key initialization
haCryptAlgoM.cpp
- DoKeyInit  

haCryptEditFld.cpp  
- AscHex2BinEditedText
- case A_KEY:  
- case A_IV:    
- AesEncryptEditedText
- CryptoTestEditedText    
