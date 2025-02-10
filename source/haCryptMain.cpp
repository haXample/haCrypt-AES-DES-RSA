// haCrypt - Crypto tool for DES, AES, TDEA and RSA.
// haCryptMain.cpp - C++ Developer source file.
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

//# #------------------------------------------------------------------------------
//# # NMake file for the 32bit Windows XP/10 Desktop-App Project: PROJ.EXE
//# #  ---------------------------------------------------------------------------
//# # |                  Copyright (c)2021 by helmut altmann                      |
//# #  ---------------------------------------------------------------------------
//# #                 
//# #     ----------------------------------------------------
//# #    |  Invocation:  NMAKE haCrypt.NMK                    |  28.08.2021 ha
//# #    |  Invocation:  NMAKE haCrypt.nmk /ALL SETVERSION=1  |
//# #     ----------------------------------------------------
//# #
//# #    32bit-Version Build for XP, Vista, Windows 10, ... 
//# #    C:\Program Files (x86)\Microsoft Visual Studio\2010\BuildTools: XP SP3
//# #     (Microsoft (R) Macro Assembler Version 10.00.30319.01)
//# #     Microsoft (R) Macro Assembler Version 14.28.29910.0 <- Better use ML from VS 2019!
//# #     Microsoft (R) C/C++-Optimierungscompiler Version 16.00.30319.01 for 80x86 XP
//# #     Microsoft (R) Incremental Linker Version 10.00.30319.01
//# #     Microsoft (R) Program Maintenance Utility, Version 10.00.30319.01
//# #
//# #    32bit-Version Build for Windows 10 and greater
//# #    C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools:
//# #     Microsoft (R) Macro Assembler Version 14.28.29910.0
//# #     Microsoft (R) C/C++-Optimierungscompiler Version 19.28.29910 for x86
//# #     Microsoft (R) Incremental Linker Version 14.28.29910.0
//# #     Microsoft (R) Program Maintenance Utility, Version 14.28.29910.0
//# #
//# # Product: PROJ.EXE                                                          
//# # Module: PROJ.mnk                                                        
//# #
//# #---------------------------------------------------------------------------
//# 
//# PROJ = haCrypt      # C++ module
//# FOLDER = C:\Temp600\__\     # Folder prefix to the project,
//#         #  using 2019 MS Build-tools.
//# 
//# #OBJ = .^\      # Place to put object files
//# #LST = .\$(@B).LST    # Place to put listing files
//# #LST = .\NUL      # Place to discard files
//# 
//# # -------------------
//# # GLOBAL TOOL OPTIONS
//# # -------------------
//# AFLAGS=/nologo /c /Sn /Sg /Sp84 /Fl
//# 
//# !IFDEF TB_STANDARD
//# CFLAGS=/c /nologo /D_UNICODE /DUNICODE /DWIN32 /D_WINDOWS /DTB_STANDARD
//# RFLAGS=
//# 
//# !ELSE # (THEME = default)
//# CFLAGS=/c /nologo /D_UNICODE /DUNICODE /DWIN32 /D_WINDOWS /DTHEME
//# RFLAGS=/dTHEME
//# !ENDIF # THEME # TB_STANDARD
//# 
//# # LFLAGS=/nologo /INCREMENTAL /MANIFEST \
//# #       /MANIFESTUAC:"level='asInvoker' uiAccess='false'" /MANIFEST:EMBED \
//# #       /DEBUG:FASTLINK /SUBSYSTEM:WINDOWS \
//# #        /TLBID:1 /DYNAMICBASE /NXCOMPAT 
//# # 
//# 
//# # Self-modifying Code (SMC) special section name: _SMC,[Rd/Wr/Ex]
//# #                     LFLAGS=/SECTION:_SMC,RWE /MANIFESTUAC:"uiAccess='true'"
//# # 
//# LFLAGS=/nologo /INCREMENTAL /MANIFEST \
//#        /SECTION:_SMC,RWE /MANIFESTUAC:"uiAccess='true'" \
//#        /MANIFESTUAC:"level='asInvoker' uiAccess='false'" \
//#        /SUBSYSTEM:WINDOWS \
//#        /TLBID:1 /DYNAMICBASE /NXCOMPAT 
//# 
//# LIBS= KERNEL32.LIB USER32.LIB GDI32.LIB WINSPOOL.LIB COMDLG32.LIB ADVAPI32.LIB \
//#       SHELL32.LIB OLE32.LIB OLEAUT32.LIB UUID.LIB ODBC32.LIB ODBCCP32.LIB \
//#       Comctl32.lib shlwapi.lib uxtheme.lib Propsys.lib
//# 
//# # -----------------------------------------------------------------------------
//# #       MACRO DEFINITIONS OF THE PROJEC OBJECT MODULE DEPEDENCIES
//# # -----------------------------------------------------------------------------
//# OBJECTS = $(FOLDER)$(PROJ)Main.obj $(FOLDER)$(PROJ)Win.obj $(FOLDER)$(PROJ)Draw.obj \
//#           $(FOLDER)$(PROJ)FileC.obj $(FOLDER)$(PROJ)FileT.obj $(FOLDER)$(PROJ)FileK.obj \
//#           $(FOLDER)$(PROJ)FileL.obj $(FOLDER)$(PROJ)FileB.obj $(FOLDER)$(PROJ)FileR.obj \
//#           $(FOLDER)$(PROJ)Browse.obj $(FOLDER)$(PROJ)Console.obj $(FOLDER)$(PROJ)Err.obj \
//#           $(FOLDER)$(PROJ)Key.obj $(FOLDER)$(PROJ)Dialog.obj $(FOLDER)$(PROJ)Ctrl.obj \
//#           $(FOLDER)$(PROJ)Progbar.obj $(FOLDER)$(PROJ)EditFld.obj $(FOLDER)$(PROJ)Menu.obj \
//#           $(FOLDER)$(PROJ)Algo.obj $(FOLDER)$(PROJ)AlgoL.obj $(FOLDER)$(PROJ)AlgoM.obj \
//# !IF ($(FLAG) == "64bit Version")        # For Win10
//#           $(FOLDER)desfast64.obj \
//#           $(FOLDER)tdesfast64.obj \
//#           $(FOLDER)aesfast64.obj \
//#           $(FOLDER)haDebug64.obj \
//# !ELSE                                   # For Windows XP and Win10
//#           $(FOLDER)desfast.obj \
//#           $(FOLDER)tdesfast.obj \
//#           $(FOLDER)aesfast.obj \
//#           $(FOLDER)haDebug.obj \
//# !ENDIF     
//#           $(FOLDER)$(PROJ)AlgoRsa.obj $(FOLDER)rsafunc.obj $(FOLDER)rsabiginteger.obj \
//#           $(FOLDER)$(PROJ)WRL.obj $(FOLDER)$(PROJ)BuildTime.obj $(FOLDER)$(PROJ).res
//# 
//# OBJECTSQUICK = $(FOLDER)$(PROJ)Main.obj $(FOLDER)$(PROJ)Win.obj $(FOLDER)$(PROJ)Draw.obj \
//#           $(FOLDER)$(PROJ)FileC.obj $(FOLDER)$(PROJ)FileT.obj $(FOLDER)$(PROJ)FileK.obj \
//#           $(FOLDER)$(PROJ)FileL.obj $(FOLDER)$(PROJ)FileB.obj $(FOLDER)$(PROJ)FileR.obj \
//#           $(FOLDER)$(PROJ)Browse.obj $(FOLDER)$(PROJ)Console.obj $(FOLDER)$(PROJ)Err.obj \
//#           $(FOLDER)$(PROJ)Key.obj $(FOLDER)$(PROJ)Dialog.obj $(FOLDER)$(PROJ)Ctrl.obj \
//#           $(FOLDER)$(PROJ)Progbar.obj $(FOLDER)$(PROJ)EditFld.obj $(FOLDER)$(PROJ)Menu.obj \
//#           $(FOLDER)$(PROJ)Algo.obj $(FOLDER)$(PROJ)AlgoL.obj $(FOLDER)$(PROJ)AlgoMQ.obj \
//#           $(FOLDER)des.obj \
//#           $(FOLDER)aes.obj \
//# !IF ($(FLAG) == "64bit Version")        # For Win10
//#           $(FOLDER)tdesfast64.obj \
//# !ELSE                                   # For Windows XP and Win10
//#           $(FOLDER)tdesfast.obj \    
//#   !ENDIF     
//#           $(FOLDER)$(PROJ)AlgoRsa.obj $(FOLDER)rsafunc.obj $(FOLDER)rsabiginteger.obj \
//#           $(FOLDER)$(PROJ)WRL.obj $(FOLDER)$(PROJ)BuildTime.obj $(FOLDER)$(PROJ).res
//#
//# CLEAN =  $(FOLDER)*.ilk
//# 
//# #------------------------------------------------------------------------------
//# #         INFERENCE RULE
//# #------------------------------------------------------------------------------
//# #cl /c /nologo /Gs /Od /MT c:\temp600\__\des.cpp /Foc:\temp600\__\des.obj /Fac:\temp600\__\des.as
//# #ml /c /nologo /Sn /Sg /Sp84 /Flc:\temp600\__\des_od.lst /Foc:\temp600\__\des_od.obj c:\temp600\__\des_od.as
//# #nmake /N /D c:\temp600\__\hacrypt.nmk >C:\temp600\__\_nmk.txt
//# 
//# # --------------
//# # INFERENCE RULE                                                                       
//# # --------------
//# .asm.obj:
//# #       @ML $(AFLAGS) /Fo$(FOLDER)$(@B).obj /Fl$(FOLDER)$(@B).lst $(FOLDER)$(@B).asm
//# #       @ML64 $(AFLAGS) /Fo$(FOLDER)$(@B).obj /Fl$(FOLDER)$(@B).lst $(FOLDER)$(@B).asm
//#         @$(AS) $(AFLAGS) /Fo$(FOLDER)$(@B).obj /Fl$(FOLDER)$(@B).lst $(FOLDER)$(@B).asm
//# 
//# .c.obj:
//#         @CL $(CFLAGS) /Fo$(FOLDER)$(@B).obj $(FOLDER)$(@B).c
//# 
//# .cpp.obj:
//#         @CL $(CFLAGS) /Fo$(FOLDER)$(@B).obj $(FOLDER)$(@B).cpp
//# 
//# .rc.res:
//#         @RC $(RFLAGS) $(FOLDER)$(@B).rc
//#
//# # -------------------------------------------
//# # PSEUDO TARGETs POINTING TO THE REAL TARGETs
//# # -------------------------------------------
//# _all:   $(FOLDER)$(PROJ) \
//#         $(FOLDER)$(PROJ)Fast.exe \
//#         $(FOLDER)$(PROJ)AlgoMQ.obj $(FOLDER)$(PROJ)Quick.exe
//# 
//# # -----------------------------------------------------------------------------
//# #        FOR $(PROJ).EXE: LIST OF DEPENDENCIES FOR EVERY OBJECT FILE
//# # -----------------------------------------------------------------------------
//# 
//# $(FOLDER)$(PROJ).res:           $(FOLDER)$(@B).rc  $(FOLDER)$(PROJ).h $(FOLDER)*.ico
//# 
//# $(FOLDER)$(PROJ)Main.obj:       $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h $(FOLDER)$(PROJ).rc
//# 
//# $(FOLDER)$(PROJ)Win.obj:        $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h $(FOLDER)$(PROJ).rc
//# 
//# $(FOLDER)$(PROJ)Draw.obj:       $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h $(FOLDER)$(PROJ).rc
//# 
//# $(FOLDER)$(PROJ)FileC.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)FileT.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)FileK.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)FileL.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)FileB.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)FileR.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Browse.obj:     $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Console.obj:    $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Err.obj:        $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Key.obj:        $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Dialog.obj:     $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Ctrl.obj:       $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Progbar.obj:    $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)EditFld.obj:    $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Menu.obj:       $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Algo.obj:       $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)AlgoL.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)AlgoM.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)WRL.obj:        $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)BuildTime.obj:  $(FOLDER)$(PROJ)BuildTime.ver
//# 
//# !IF ($(FLAG) == "64bit Version")        # For Win10
//# $(FOLDER)aesfast64.obj:         $(FOLDER)$(@B).asm $(FOLDER)aesfast.inc
//# $(FOLDER)desfast64.obj:         $(FOLDER)$(@B).asm
//# $(FOLDER)tdesfast64.obj:        $(FOLDER)$(@B).asm
//# $(FOLDER)haDebug64.obj:         $(FOLDER)$(@B).asm
//# 
//# !ELSE                                   # For Windows XP and WIN10
//# $(FOLDER)aesfast.obj:           $(FOLDER)$(@B).asm $(FOLDER)aesfast.inc
//# $(FOLDER)desfast.obj:           $(FOLDER)$(@B).asm
//# $(FOLDER)tdesfast.obj:          $(FOLDER)$(@B).asm
//# $(FOLDER)haDebug.obj:           $(FOLDER)$(@B).asm
//# !ENDIF
//# 
//# $(FOLDER)$(PROJ)AlgoRsa.obj:    $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h $(FOLDER)rsafuncC.h $(FOLDER)rsabigintegerC.h
//# $(FOLDER)rsafunc.obj:           $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h $(FOLDER)rsafuncC.h $(FOLDER)rsabigintegerC.h
//# $(FOLDER)rsabiginteger.obj:     $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h $(FOLDER)rsafuncC.h $(FOLDER)rsabigintegerC.h
//# 
//# # Special build: Compiling only C++ modules (not using the fast ASM modules)
//# #
//# #$(FOLDER)$(PROJ)AlgoMQ.obj     $(FOLDER)$(PROJ)AlgoM.cpp
//# #$(FOLDER)des.obj:              $(FOLDER)$(@B).cpp
//# #$(FOLDER)aes.obj:              $(FOLDER)$(@B).cpp $(FOLDER)$(@B).h
//# 
//# #------------------------------------------------------------------------------
//# # 
//# #   $(PROJ) TARGET BUILD (Macros for build-control)
//# #      
//# $(FOLDER)$(PROJ):
//# # 
//# !IFNDEF SETVERSION
//#   date /T >$(FOLDER)haCryptBuildTime.ver
//#   time /T >>$(FOLDER)haCryptBuildTime.ver
//#         $(FOLDER)BuildVersion.vbs
//# !ELSE
//#   $(FOLDER)SetVersion.vbs INIT
//# !ENDIF
//# #      
//# # Set a flag in an NMAKE Makefile if the cl compiler version is 16.
//# # Note that cl /? prints the version information to the standard error stream
//# #  and the help text to the standard output.
//# #  To be able to check the version with the findstr command one must first
//# #  redirect stderr to stdout using 2>&1.
//# # 
//# # -------------------------------------------------
//# # Determine the assembler version in use           |
//# #  Microsoft Visual Studio 2019 (Windows 10 64bit) |
//# #   ML64 Version 14.28.29336.0 for x64             |
//# # Determine the compiler version in use            |
//# #  Microsoft Visual Studio 2010 (XP 32bit)         |
//# #   CL Version 16.00.30319.01 for 80x86            |
//# #  Microsoft Visual Studio 2019 (Windows 10 32bit) |
//# #   CL Version 19.28.29910 for x86                 |
//# # -------------------------------------------------
//# #!IF ([ml64 2>&1 | findstr /C:"x64" > nul] == 0) 
//# #FLAG = "64bit Version"        # 64bit for Windows 10
//# #!ELSEIF ([cl 2>&1 | findstr /C:"Version 16" > nul] == 0)
//# !IF ([cl 2>&1 | findstr /C:"Version 16" > nul] == 0)
//# FLAG = "32bit XP Version"      # 32bit for XP and Win10
//# OS = _XP
//# !ELSE 
//# FLAG = "32bit Version"         # 32bit for Windows 10
//# OS =
//# !ENDIF
//# 
//# 
//# !IFDEF TB_STANDARD
//# #------------------------------------------------------------------------------
//# #   $(PROJ)Fast TARGET BUILD (TB_STANDARD)
//# #------------------------------------------------------------------------------
//# $(FOLDER)$(PROJ)Fast.exe: $(OBJECTS)
//# # 
//# # Detect if "haCrypt" is running. It must be terminated before rebuild.
//# # ":" should appear in TASKLIST output only if the task is NOT found,
//# # Hence FIND will set the ERRORLEVEL to 0 for 'not found' and 1 for 'found'.
//# # 
//# !IF ([tasklist /NH /FI "IMAGENAME eq $(PROJ)STD_XP.exe" | FIND ":" > nul] == 1)
//#         -TASKKILL /F /IM $(@F:Fast=STD_XP) > nul
//# !ENDIF
//# !IF ($(FLAG) == "32bit XP Version")     # For XP and Win10
//#   @ECHO Build: $(@F:Fast=STD_XP) - Windows XP and Win10 Compatible $(FLAG)
//#   LINK $(LFLAGS)  /OUT:$(FOLDER)$(@F:Fast=STD_XP) $** $(LIBS) >$(FOLDER)$(@B:Fast=STD)_XP.link
//# !ELSE                                   # For Win10 only
//#   @ECHO Build: $(@F:Fast=STD) - Win10 only $(FLAG)
//#   LINK $(LFLAGS)  /OUT:$(FOLDER)$(@F:Fast=STD) $** $(LIBS) >$(FOLDER)$(@B:Fast=STD)_WIN10.link
//# !ENDIF
//#   DEL $(CLEAN)
//# !IFDEF SETVERSION
//#   Cscript //nologo $(FOLDER)SetVersion.vbs  32STD
//# !ENDIF
//# 
//# #------------------------------------------------------------------------------
//# # $(PROJ)Quick TARGET (TB_STANDARD Dummy) (..Quick wont be built)
//# # 
//# $(FOLDER)$(PROJ)Quick.exe:
//# !IF ($(FLAG) == "32bit XP Version") # For XP and Win10
//#         @ECHO --- haCryptSTD_XP.exe has been built for XP and Windows 10. ---
//# !ELSE               # For Win10 only
//#         @ECHO --- haCryptSTD.exe has been built (running on Windows 10 only). ---
//# !ENDIF
//#   @ECHO.
//# 
//# 
//# !ELSE # THEME
//# #------------------------------------------------------------------------------
//# #   $(PROJ)Fast TARGET BUILD (THEME = Default)
//# #------------------------------------------------------------------------------
//# $(FOLDER)$(PROJ)Fast.exe: $(OBJECTS)
//# # 
//# # Detect if "haCrypt" is running. It must be terminated before rebuild.
//# # ":" should appear in TASKLIST output only if the task is NOT found,
//# # Hence FIND will set the ERRORLEVEL to 0 for 'not found' and 1 for 'found'.
//# # 
//# !IF ([tasklist /NH /FI "IMAGENAME eq $(PROJ).exe" | FIND ":" > nul] == 1)
//#         -TASKKILL /F /IM $(@B:Fast=).exe > nul
//# !ENDIF
//# !IF ($(FLAG) == "32bit XP Version")     # For XP and Win10
//#   @ECHO Build: $(@F), $(@F:Fast=) - Windows XP and Win10 Compatible $(FLAG)
//#   LINK $(LFLAGS)  /OUT:$(FOLDER)$(@B)_XP.exe $** $(LIBS) >$(FOLDER)$(@B)_XP.link
//#   copy /Y $(FOLDER)$(@B)_XP.exe $(FOLDER)$(@F:Fast=) >nul
//# !ELSE                                   # For Win10 only
//#   @ECHO Build: $(@F) - Windows 10 only $(FLAG)
//#   LINK $(LFLAGS)  /OUT:$@ $** $(LIBS) >$(FOLDER)$(@B)32.link
//# !ENDIF
//#   DEL $(CLEAN)
//# !IFDEF SETVERSION
//#   Cscript //nologo $(FOLDER)SetVersion.vbs  32
//# !ENDIF
//#   @ECHO.
//# 
//# #------------------------------------------------------------------------------
//# #   $(PROJ)Quick TARGET BUILD (THEME = Default)
//# # 
//# $(FOLDER)$(PROJ)AlgoMQ.obj: $(FOLDER)$(PROJ)AlgoM.cpp $(FOLDER)$(PROJ).h
//#   @ECHO Build: $(@F) - $(FLAG)
//#         CL /DDES_AES_QUICK $(CFLAGS) /Fo$@ $(FOLDER)$(PROJ)AlgoM.cpp
//#   @ECHO.
//# 
//# $(FOLDER)$(PROJ)Quick.exe:  $(OBJECTSQUICK)
//# # 
//# # Detect if "haCrypt" is running. It must be terminated before rebuild.
//# # ":" should appear in TASKLIST output only if the task is NOT found,
//# # Hence FIND will set the ERRORLEVEL to 0 for 'not found' and 1 for 'found'.
//# # 
//# !IF ([tasklist /NH /FI "IMAGENAME eq $(PROJ)Quick_XP.exe" | FIND ":" > nul] == 1)
//#         -TASKKILL /F /IM $(@B)_XP.exe > nul
//# !ENDIF
//# !IF ($(FLAG) == "32bit XP Version") # For XP and Win10
//#   @ECHO Build: $(@F) - Windows XP and Win10 Compatible $(FLAG)
//#   LINK $(LFLAGS)  /OUT:$(FOLDER)$(@B)_XP.exe $** $(LIBS) >$(FOLDER)$(@B)_XP.link
//# !ELSE                               # For Win10 only
//#   @ECHO Build: $(@F) - Windows 10 only $(FLAG)
//#   LINK $(LFLAGS)  /OUT:$@ $** $(LIBS) >$(FOLDER)$(@B)32.link
//# !ENDIF
//#   DEL $(CLEAN)
//# !IFDEF SETVERSION
//#   Cscript //nologo $(FOLDER)SetVersion.vbs  32Q
//# !ENDIF
//# 
//# !ENDIF # THEME # TB_STANDARD
//# 
//# # -----------------------------  END OF MAKEFILE 32 BIT ----------------------------
//# 
//# #------------------------------------------------------------------------------
//# # NMake file for the 64bit Win10 Desktop-App Project: PROJ.EXE
//# #  
//# #  ---------------------------------------------------------------------------
//# # |                  Copyright (c)2022 by ha.                                 |
//# # |     This program contains proprietary and confidential information.       |
//# # | All rights reserved, except as may be permitted by prior written consent. |
//# #  ---------------------------------------------------------------------------
//# #                   
//# #     ------------------------------------------------------
//# #    |  Invocation:  NMAKE haCrypt64.nmk /ALL               |  15.02.2022 ha
//# #    |  Invocation:  NMAKE haCrypt64.nmk /ALL SETVERSION=1  |
//# #     ------------------------------------------------------
//# #
//# #    C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools:
//# #
//# #    64bit-Version Build for Windows 10 and greater
//# #      Visual Studio 2019 Developer Command Prompt v16.8.4
//# #      [vcvarsall.bat] Environment initialized for: 'x64'
//# #      Copyright (c) 2020 Microsoft Corporation
//# #      C:\Program Files (x86)\Microsoft Visual Studio\2019\Community>
//# #     Microsoft (R) Macro Assembler (x64) 'ML64' Version 14.28.29336.0
//# #     Microsoft (R) C/C++-Optimierungscompiler Version 19.28.29336 for x64
//# #     Microsoft (R) Incremental Linker Version 14.28.29336.0
//# #     Microsoft (R) Program Maintenance Utility, Version 14.28.29336.0
//# #
//# # Product: PROJ.EXE                                                          
//# # Module: PROJ.mnk                                                        
//# #
//# #------------------------------------------------------------------------------
//# 
//# PROJ = haCrypt      # C++ module
//# FOLDER = C:\Temp600\__\     # Folder prefix to the project,
//#         #  using 2019 MS Build-tools.
//# 
//# #OBJ = .^\      #Place to put object files
//# #LST = .\$(@B).LST    #Place to put listing files
//# #LST = .\NUL      # Place to discard files
//# 
//# # -------------------
//# # GLOBAL TOOL OPTIONS
//# # -------------------
//# AFLAGS=/nologo /c /Sn /Sg /Sp84 /Fl
//# 
//# !IFDEF TB_STANDARD
//# CFLAGS=/c /nologo /D_UNICODE /DUNICODE /DWIN32 /D_WINDOWS /DTB_STANDARD /Dx64
//# RFLAGS=
//# 
//# !ELSE # (THEME = default)
//# CFLAGS=/c /nologo /D_UNICODE /DUNICODE /DWIN32 /D_WINDOWS /DTHEME /Dx64
//# RFLAGS=/dTHEME
//# !ENDIF # THEME # TB_STANDARD
//# 
//# # LFLAGS=/nologo /INCREMENTAL /MANIFEST \
//# #       /MANIFESTUAC:"level='asInvoker' uiAccess='false'" /MANIFEST:EMBED \
//# #       /DEBUG:FASTLINK /SUBSYSTEM:WINDOWS \
//# #       /TLBID:1 /DYNAMICBASE /NXCOMPAT
//# # 
//# 
//# # Self-modifying Code (SMC) special section name: _SMC,[Rd/Wr/Ex]
//# #                     LFLAGS=/SECTION:_SMC,RWE /MANIFESTUAC:"uiAccess='true'"
//# # 
//# #       /SECTION:_SMC,RWE /MANIFESTUAC:"uiAccess='true'"  \
//# 
//# LFLAGS=/nologo /INCREMENTAL /MANIFEST \
//#        /MANIFESTUAC:"level='asInvoker' uiAccess='false'" \
//#        /SUBSYSTEM:WINDOWS \
//#        /TLBID:1 /DYNAMICBASE /NXCOMPAT /LARGEADDRESSAWARE:NO
//# #       /TLBID:1 /DYNAMICBASE /NXCOMPAT
//# 
//# LIBS= KERNEL32.LIB USER32.LIB GDI32.LIB WINSPOOL.LIB COMDLG32.LIB ADVAPI32.LIB \
//#       SHELL32.LIB OLE32.LIB OLEAUT32.LIB UUID.LIB ODBC32.LIB ODBCCP32.LIB \
//#       Comctl32.lib shlwapi.lib uxtheme.lib Propsys.lib
//# 
//# # -----------------------------------------------------------------------------
//# #       MACRO DEFINITIONS OF THE PROJEC OBJECT MODULE DEPEDENCIES
//# # -----------------------------------------------------------------------------
//# OBJECTS = $(FOLDER)$(PROJ)Main.obj $(FOLDER)$(PROJ)Win.obj $(FOLDER)$(PROJ)Draw.obj \
//#     $(FOLDER)$(PROJ)FileC.obj $(FOLDER)$(PROJ)FileT.obj $(FOLDER)$(PROJ)FileK.obj \
//#     $(FOLDER)$(PROJ)FileL.obj $(FOLDER)$(PROJ)FileB.obj $(FOLDER)$(PROJ)FileR.obj \
//#     $(FOLDER)$(PROJ)Browse.obj $(FOLDER)$(PROJ)Console.obj $(FOLDER)$(PROJ)Err.obj \
//#     $(FOLDER)$(PROJ)Key.obj $(FOLDER)$(PROJ)Dialog.obj $(FOLDER)$(PROJ)Ctrl.obj \
//#     $(FOLDER)$(PROJ)Progbar.obj $(FOLDER)$(PROJ)EditFld.obj \
//#     $(FOLDER)$(PROJ)Algo.obj $(FOLDER)$(PROJ)AlgoL.obj $(FOLDER)$(PROJ)AlgoM.obj \
//#     $(FOLDER)desfast64.obj \
//#     $(FOLDER)tdesfast64.obj \
//#     $(FOLDER)aesfast64.obj \
//#     $(FOLDER)$(PROJ)AlgoRsa.obj $(FOLDER)rsafunc.obj $(FOLDER)rsabiginteger.obj \
//#     $(FOLDER)$(PROJ)WRL.obj $(FOLDER)$(PROJ)BuildTime.obj $(FOLDER)$(PROJ).res
//# 
//# #       $(FOLDER)$(PROJ)AlgoM.obj
//# #   $(FOLDER)desfast.obj
//# #   $(FOLDER)aesfast.obj
//#      
//# OBJECTSQUICK = $(FOLDER)$(PROJ)Main.obj $(FOLDER)$(PROJ)Win.obj $(FOLDER)$(PROJ)Draw.obj \
//#     $(FOLDER)$(PROJ)FileC.obj $(FOLDER)$(PROJ)FileT.obj $(FOLDER)$(PROJ)FileK.obj \
//#     $(FOLDER)$(PROJ)FileL.obj $(FOLDER)$(PROJ)FileB.obj $(FOLDER)$(PROJ)FileR.obj \
//#     $(FOLDER)$(PROJ)Browse.obj $(FOLDER)$(PROJ)Console.obj $(FOLDER)$(PROJ)Err.obj \
//#     $(FOLDER)$(PROJ)Key.obj $(FOLDER)$(PROJ)Dialog.obj $(FOLDER)$(PROJ)Ctrl.obj \
//#     $(FOLDER)$(PROJ)Progbar.obj $(FOLDER)$(PROJ)EditFld.obj \
//#     $(FOLDER)$(PROJ)Algo.obj $(FOLDER)$(PROJ)AlgoL.obj $(FOLDER)$(PROJ)AlgoMQ.obj \
//#     $(FOLDER)des.obj \
//#     $(FOLDER)tdesfast64.obj \
//#     $(FOLDER)aes.obj \
//#     $(FOLDER)$(PROJ)AlgoRsa.obj $(FOLDER)rsafunc.obj $(FOLDER)rsabiginteger.obj \
//#     $(FOLDER)$(PROJ)WRL.obj $(FOLDER)$(PROJ)BuildTime.obj $(FOLDER)$(PROJ).res
//# 
//# #       $(FOLDER)$(PROJ)AlgoMQ.obj
//# #   $(FOLDER)des.obj
//# #   $(FOLDER)aes.obj
//#      
//# CLEAN =  $(FOLDER)*.ilk
//# 
//# #------------------------------------------------------------------------------
//# #         INFERENCE RULE
//# #------------------------------------------------------------------------------
//# #cl /c /nologo /Gs /Od /MT c:\temp600\__\des.cpp /Foc:\temp600\__\des.obj /Fac:\temp600\__\des.as
//# #ml64 /c /nologo /Sn /Sg /Sp84 /Flc:\temp600\__\des_od.lst /Foc:\temp600\__\des_od.obj c:\temp600\__\des_od.as
//# #nmake /N /D c:\temp600\__\hacrypt64.nmk >C:\temp600\__\_nmk.txt
//# 
//# # --------------
//# # INFERENCE RULE                          
//# # --------------
//# .rc.res:
//#   @RC $(RFLAGS) $(FOLDER)$(@B).rc
//# 
//# .asm.obj:
//# # @ML64 $(AFLAGS) /Fo$(FOLDER)$(@B).obj /Fl$(FOLDER)$(@B).lst $(FOLDER)$(@B).asm
//#   $(AS) $(AFLAGS) /Fo$(FOLDER)$(@B).obj /Fl$(FOLDER)$(@B).lst $(FOLDER)$(@B).asm
//# 
//# .c.obj:
//#   @CL $(CFLAGS) /Fo$(FOLDER)$(@B).obj $(FOLDER)$(@B).c
//# 
//# .cpp.obj:
//#   @CL $(CFLAGS) /Fo$(FOLDER)$(@B).obj $(FOLDER)$(@B).cpp
//# 
//# # -------------------------------------------
//# # PSEUDO TARGETs POINTING TO THE REAL TARGETs
//# # -------------------------------------------
//# _all: $(FOLDER)$(PROJ) \
//#         $(FOLDER)$(PROJ)Fast64.exe \
//#         $(FOLDER)$(PROJ)AlgoMQ.obj $(FOLDER)$(PROJ)Quick64.exe
//# 
//# # -----------------------------------------------------------------------------
//# #        FOR $(PROJ).EXE: LIST OF DEPENDENCIES FOR EVERY OBJECT FILE
//# # -----------------------------------------------------------------------------
//# 
//# $(FOLDER)$(PROJ).res:           $(FOLDER)$(@B).rc  $(FOLDER)$(PROJ).h $(FOLDER)*.ico
//# 
//# $(FOLDER)$(PROJ)Main.obj:       $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h $(FOLDER)$(PROJ).rc
//# 
//# $(FOLDER)$(PROJ)Win.obj:        $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h $(FOLDER)$(PROJ).rc
//# 
//# $(FOLDER)$(PROJ)Draw.obj:       $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h $(FOLDER)$(PROJ).rc
//# 
//# $(FOLDER)$(PROJ)FileC.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)FileT.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)FileK.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)FileL.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)FileB.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)FileR.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Browse.obj:     $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Console.obj:    $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Err.obj:        $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Key.obj:        $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Dialog.obj:     $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Ctrl.obj:       $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Progbar.obj:    $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)EditFld.obj:    $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)Algo.obj:       $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)AlgoL.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)AlgoM.obj:      $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)WRL.obj:        $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h
//# 
//# $(FOLDER)$(PROJ)BuildTime.obj:  $(FOLDER)$(PROJ)BuildTime.ver
//# 
//# $(FOLDER)aesfast64.obj:         $(FOLDER)$(@B).asm $(FOLDER)aesfast64.inc
//# $(FOLDER)aes.obj:               $(FOLDER)$(@B).cpp $(FOLDER)aes.h
//# 
//# $(FOLDER)desfast64.obj:         $(FOLDER)$(@B).asm
//# $(FOLDER)des.obj:               $(FOLDER)$(@B).cpp
//# 
//# $(FOLDER)tdesfast64.obj:        $(FOLDER)$(@B).asm
//# 
//# $(FOLDER)$(PROJ)AlgoRsa.obj:    $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h $(FOLDER)rsafuncC.h $(FOLDER)rsabigintegerC.h
//# 
//# $(FOLDER)rsafunc.obj:           $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h $(FOLDER)rsafuncC.h $(FOLDER)rsabigintegerC.h
//# 
//# $(FOLDER)rsabiginteger.obj:     $(FOLDER)$(@B).cpp $(FOLDER)$(PROJ).h $(FOLDER)rsafuncC.h $(FOLDER)rsabigintegerC.h
//# 
//# #------------------------------------------------------------------------------
//# # 
//# #   $(PROJ) TARGET BUILD (Macros for build-control)
//# #      
//# $(FOLDER)$(PROJ):
//# # 
//# !IFNDEF SETVERSION
//#   date /T >$(FOLDER)haCryptBuildTime.ver
//#   time /T >>$(FOLDER)haCryptBuildTime.ver
//#         $(FOLDER)BuildVersion.vbs
//# !ELSE
//#   $(FOLDER)SetVersion.vbs INIT
//# !ENDIF
//# #      
//# # Set a flag in an NMAKE Makefile if the cl compiler version is 16.
//# # Note that cl /? prints the version information to the standard error stream
//# #  and the help text to the standard output.
//# #  To be able to check the version with the findstr command one must first
//# #  redirect stderr to stdout using 2>&1.
//# # 
//# # -------------------------------------------------
//# # Determine the assembler version in use           |
//# #  Microsoft Visual Studio 2019 (Windows 10 64bit) |
//# #   ML64 Version 14.28.29336.0 for x64             |
//# # Determine the compiler version in use            |
//# #  Microsoft Visual Studio 2010 (XP 32bit)         |
//# #   CL Version 16.00.30319.01 for 80x86            |
//# #  Microsoft Visual Studio 2019 (Windows 10 32bit) |
//# #   CL Version 19.28.29910 for x86                 |
//# # -------------------------------------------------
//# !IF ([ml64 2>&1 | findstr /C:"x64" > nul] == 0) 
//# FLAG = "64bit Version"         # 64bit for Windows 10
//# !ELSEIF ([cl 2>&1 | findstr /C:"Version 16" > nul] == 0)
//# FLAG = "32bit XP Version"      # 32bit for XP and Win10
//# OS = _XP
//# !ELSE 
//# FLAG = "32bit Version"         # 32bit for Windows 10
//# OS =
//# !ENDIF
//# 
//# 
//# !IFDEF TB_STANDARD
//# #------------------------------------------------------------------------------
//# #     $(PROJ)Fast TARGET BUILD (TB_STANDARD)
//# #------------------------------------------------------------------------------
//# $(FOLDER)$(PROJ)Fast64.exe: $(OBJECTS)
//#   @ECHO Build: $(@F:Fast=STD) - $(FLAG)
//# # 
//# # Detect if "haCrypt" is running. It must be terminated before rebuild.
//# # ":" should appear in TASKLIST output only if the task is NOT found,
//# # Hence FIND will set the ERRORLEVEL to 0 for 'not found' and 1 for 'found'.
//# # 
//# !IF ([tasklist /NH /FI "IMAGENAME eq $(PROJ)STD64.exe" | FIND ":" > nul] == 1)
//#         -TASKKILL /F /IM $(@F:Fast=STD) > nul
//# !ENDIF
//# !IF ($(FLAG) == "32bit XP Version")     # For XP and Win10
//#   LINK $(LFLAGS)  /OUT:$(FOLDER)$(@F:Fast=STD_XP) $** $(LIBS) >$(FOLDER)$(@B:Fast=STD)_XP.link
//# !ELSE                                   # For Win10 only
//#   LINK $(LFLAGS)  /OUT:$(FOLDER)$(@F:Fast=STD) $** $(LIBS) >$(FOLDER)$(@B:Fast=STD).link
//# !ENDIF
//#   DEL $(CLEAN)
//# !IFDEF SETVERSION
//#   Cscript //nologo $(FOLDER)SetVersion.vbs  64
//# !ENDIF
//# 
//# #------------------------------------------------------------------------------
//# # $(PROJ)Quick TARGET (TB_STANDARD Dummy) (..Quick wont be built)
//# # 
//# $(FOLDER)$(PROJ)Quick.exe:
//# !IF ($(FLAG) == "32bit XP Version") # For XP and Win10
//#         @ECHO --- haCryptSTD_XP.exe has been built for XP and Windows 10. ---
//# !ELSE                               # For Win10 only
//#         @ECHO --- haCryptSTD64.exe has been built (running on Windows 10 only). ---
//# !ENDIF
//#   @ECHO.
//# 
//# 
//# !ELSE # THEME
//# #------------------------------------------------------------------------------
//# #   $(PROJ)Fast TARGET BUILD (THEME = Default)
//# #------------------------------------------------------------------------------
//# $(FOLDER)$(PROJ)Fast64.exe: $(OBJECTS)
//# # 
//# # Detect if "haCrypt" is running. It must be terminated before rebuild.
//# # ":" should appear in TASKLIST output only if the task is NOT found,
//# # Hence FIND will set the ERRORLEVEL to 0 for 'not found' and 1 for 'found'.
//# # 
//# !IF ([tasklist /NH /FI "IMAGENAME eq $(PROJ)64.exe" | FIND ":" > nul] == 1)
//#         -TASKKILL /F /IM $(@F:Fast=) > nul
//# !ENDIF
//# !IF ($(FLAG) == "32bit XP Version") # For XP and Win10
//#   @ECHO Build: $(@F:64=), $(PROJ).exe - Windows XP and Win10 Compatible $(FLAG)
//#   LINK $(LFLAGS)  /OUT:$(FOLDER)$(@B:64=)_XP.exe $** $(LIBS) >$(FOLDER)$(@B:64=)_XP.link
//#   copy /Y $(FOLDER)$(@B:64=)_XP.exe $(FOLDER)$(@F:Fast64=) >nul
//# !ELSE                               # For Win10 only
//#   @ECHO Build: $(@F) - Windows 10 only $(FLAG)
//#   LINK $(LFLAGS)  /OUT:$@ $** $(LIBS) >$(FOLDER)$(@B).link
//#   copy /Y $@ $(FOLDER)$(@F:Fast=) >nul
//# !ENDIF
//#   DEL $(CLEAN)
//# !IFDEF SETVERSION
//#   Cscript //nologo $(FOLDER)SetVersion.vbs  64
//# !ENDIF
//#   @ECHO.
//# 
//# #------------------------------------------------------------------------------
//# #   $(PROJ)Quick TARGET BUILD (THEME = Default)
//# # 
//# $(FOLDER)$(PROJ)AlgoMQ.obj: $(FOLDER)$(PROJ)AlgoM.cpp $(FOLDER)$(PROJ).h
//#   @ECHO Build: $(@F) - $(FLAG)
//#         CL /DDES_AES_QUICK $(CFLAGS) /Fo$@ $(FOLDER)$(PROJ)AlgoM.cpp
//#   @ECHO.
//# 
//# $(FOLDER)$(PROJ)Quick64.exe:  $(OBJECTSQUICK)
//# # 
//# # Detect if "haCrypt" is running. It must be terminated before rebuild.
//# # ":" should appear in TASKLIST output only if the task is NOT found,
//# # Hence FIND will set the ERRORLEVEL to 0 for 'not found' and 1 for 'found'.
//# # 
//# !IF ([tasklist /NH /FI "IMAGENAME eq $(PROJ)Quick64.exe" | FIND ":" > nul] == 1)
//#         -TASKKILL /F /IM $(@B).exe > nul
//# !ENDIF
//# !IF ($(FLAG) == "32bit XP Version") # For XP and Win10
//#   @ECHO Build: $(@F:64=) - Windows XP and Win10 Compatible $(FLAG)
//#   LINK $(LFLAGS)  /OUT:$(FOLDER)$(@B:64=)_XP.exe $** $(LIBS) >$(FOLDER)$(@B:64=)_XP.link
//# !ELSE                               # For Win10 only
//#   @ECHO Build: $(@F) - Windows 10 only $(FLAG)
//#   LINK $(LFLAGS)  /OUT:$@ $** $(LIBS) >$(FOLDER)$(@B).link
//# !ENDIF
//#   DEL $(CLEAN)
//# !IFDEF SETVERSION
//#   Cscript //nologo $(FOLDER)SetVersion.vbs  64Q
//# !ENDIF
//# 
//# !ENDIF # THEME # TB_STANDARD
//# 
//# # -----------------------------  END OF MAKEFILE 64 BIT ----------------------------


//********************************************************************************
//--------------------------------------------------------------------------------
//
//            Manifest for actual theme (Visual Studio 10.0 XP)
//            Manifest for actual theme (Visual Studio 2019)
//
// Microsoft Visual Studio\2010\BuildTools                           
// Microsoft Visual Studio\2019\Community>
//
// 1) In Build folder mainfest-file must exist:
//      Filename = haCryptALL.exe.manifest
//
//    <?xml version='1.0' encoding='UTF-8' standalone='yes'?>
//    <assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>
//      <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
//        <security>
//          <requestedPrivileges>
//            <requestedExecutionLevel level='asInvoker' uiAccess='false' />
//          </requestedPrivileges>                                                           
//        </security>
//      </trustInfo>
//      <dependency>
//        <dependentAssembly>
//          <assemblyIdentity 
//          type='win32' 
//          name='Microsoft.Windows.Common-Controls' 
//          version='6.0.0.0' 
//          processorArchitecture='*' 
//          publicKeyToken='6595b64144ccf1df' 
//          language='*' />
//        </dependentAssembly>
//      </dependency>
//    </assembly>
//
// 2) In Resource file hacrypt.rc the following instruction is needed:
//     #ifdef THEME // Visual style of actual Windows Version ('rc /dTHEME hacrypt.rc')
//      CREATEPROCESS_MANIFEST_RESOURCE_ID RT_MANIFEST "haCryptALL.exe.manifest"
//     #endif
//

//--------------------------------------------------------------------------------
//
//            Manifest for actual theme (Visual Studio 2010/2019 WinXP/Win10)
//
// Microsoft Visual Studio\2019\BuildTools
//
// Compiling mode: Visual Style
// In sourcefile hacrypt.cpp:
//  #ifdef THEME
//   #pragma comment(linker,"\"/manifestdependency:type='win32' \
//   name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
//   processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*' \"")
//  #endif
//
//**********************************************************************************

// Compiling mode: Visual Style (not if TB_STANDARD)
#ifdef THEME
 #pragma comment(linker,"\"/manifestdependency:type='win32' \
 name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
 processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*' \"")
#endif

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

#include <uxtheme.h>  // Allow theme styling progress bar (XP / Vista or greater

#include "haCrypt.h"                  

// Compiling modes THEME (default) or TB_STANDARD
// Note: In haCrypt.nmk TB_STANDARD=1 means no 'Theme manifest' coloring style

// Application's title bar: Buffered signon text message.
#ifdef x64 // 64 bit (Visual Studio 2019)
  #ifdef THEME
    TCHAR szSignonTitle[50] = _T("haCrypt (64bit) ");      // Windows 10
  #else    // TB_STANDARD
    TCHAR szSignonTitle[50] = _T("haCryptSTD (64bit) ");   // Windows 10
  #endif

#else      // 32 bit
  #ifdef THEME
    #if _MSC_VER == 1600      // (1600 = Visual Studio 2010 version 10.0)
      TCHAR szSignonTitle[50] = _T("haCrypt (XP) ");       // Windows XP or greater
    #else                     // VS 2019
      TCHAR szSignonTitle[50] = _T("haCrypt (32bit) ");    // Windows 10
    #endif
  #else    // TB_STANDARD
    #if _MSC_VER == 1600      // (1600 = Visual Studio 2010 version 10.0)
      TCHAR szSignonTitle[50] = _T("haCryptSTD (XP) ");    // Windows XP or greater
    #else                     // VS 2019
      TCHAR szSignonTitle[50] = _T("haCryptSTD (32bit) "); // Windows 10
    #endif
  #endif
#endif


// Global variables
// Variables (typedefs: see "Large Integer Functions.pdf")

// e.g. typedef wchar_t WCHAR;
//      typedef WCHAR   TCHAR;

// e.g. typedef wchar_t WCHAR;
//      typedef WCHAR*  LPWSTR;

// e.g. typedef char    CHAR;
//      typedef CHAR*   LPSTR;

// e.g. typedef unsigned long  ULONG;
//      typedef unsigned long  DWORD;

//      typedef int            BOOL;

TCHAR _tTTBuf[2*MAX_PATH];             // Temporary buffer for formatted UNICODE text
int _tTTBufSize = sizeof _tTTBuf;

LPSTR szKeyDialogIn[KEY_SIZE_MAX+1];   // (Unicode)=char* szKeyDialogInKey[..] buffer (max key length for AES=256 bits)  
LPSTR szIcvDialogIn[AES_BLOCK_SIZE+1]; // (Unicode)=char* szIcvDialogInIV[..] buffer (max IV length for AES=128 bits)     

char KeyDialog_In[KEY_SIZE_MAX+1];     // (ANSI,Ascii) Key buffer (max key length for AES = 256 bits)
char IcvDialog_In[AES_BLOCK_SIZE+1];   // (ANSI,Ascii) IV buffer (max key length for AES = 128 bits)
char* pszKeyBuffer = KeyDialog_In;     // (ANSI,Ascii) Default: Dialog-key pointer for Crypto functions
char* pszIcvBuffer = IcvDialog_In;     // (ANSI,Ascii) Default: Dialog-IV pointer for Crypto functions

LPSTR szCmdTextSaved[COUNTBUF_SIZE];

int fancyToolbar = MF_UNCHECKED;       // Compile initially a Standard (gray) colored toolbar
int activeProgbar = FALSE;             // Progressbar activity
int statColor, textColor = FALSE;

DWORD dwTextLength;

int gwtstat = 0;           
int k, _val, _hexMode=FALSE, _cryptEditedTextMode=0, keyDisplayMode = MF_CHECKED, toolButtonFlag = FALSE;
int KeyboardEntry = FALSE;
int _cryptMenuFlag = FALSE;  
int _testContextFlag = FALSE; // Initilally not in TEST-MODE
int _testMode = FALSE;        // Initilally not in TEST-MODE

ULONG FileProcessingMode=CRYPT_NONE, ActiveProcessingMode=CRYPT_CBC, CryptoProcessingMode;
ULONG FileProcessingContinue, ToolProcessingMode, SavedProcessingMode, FileProcessingModeContinue=CRYPT_NONE;

WPARAM gwCryptContinue = ID_TOOLBAR_CRYPT_CONTINUE;

POINT pMouse;              // Mouse position
RECT rcButton, rcToolbar;  // Toolbar rectangle metrics

HINSTANCE g_hInst;         // Main hInstance

HWND hMain;                // Main window handle
HWND hKeyboard;            // Keyboard handle

HMENU hMenu;

HDC hdcStatusbar;          // Handle Drawing Context Statusbar
PAINTSTRUCT _ps;           // Holds info about current painting session.

// The main window class name.
TCHAR szWindowClass[]      = _T("haCryptWindowClass");
TCHAR szRegistrationFail[] = _T("Window Registration Failed.");

TCHAR szEdit[]         = _T("Edit");

TCHAR szIvSaved[]      = _T("IV saved.");
TCHAR szKeySaved[]     = _T("Key saved.");
TCHAR* pszTextKeySaved = szKeySaved;     // Default

TCHAR szKeyNull[]      = _T("Warning: The default key is used.");
TCHAR szHexDisplay[]   = _T("Hex display.");
TCHAR szTextDisplay[]  = _T("Text display.");

// MessageBox Text strings
TCHAR szCreationFail[]     = _T("Window Creation failed.");
TCHAR szEditBoxFail[]      = _T("Edit Box Creation failed.");
TCHAR szCreationToolFail[] = _T("Could not create tool bar.");
TCHAR szDialogFail[]       = _T("Dialog failed!");
TCHAR szError[]            = _T("Error!");

// Painted Text strings
TCHAR szEscapeAbort[]      = _T("ESC aborted.");

//  MessageBoxLastError test strings 'hacryptFileR.cpp'
TCHAR szStatusInfoCBC[]    = _T(" %s %s: Enter Key / IV or accept current settings and continue. ");
TCHAR szStatusInfoECB[]    = _T(" %s %s: Enter Key or accept current settings and continue. ");
TCHAR szStatusClear[]      = _T("");

int _escFlag = FALSE, _escAbortNoQuery = MF_UNCHECKED, _escAbort = FALSE;

// Tooltip strings
LPWSTR szTooltipTexthEdit         = _T(" Crypto-data displayed as text \n is truncated at 4K."); // CRYPT_TEXT_MAXSIZE
LPWSTR szTooltipTexthButtonHex    = _T(" Hexadecimal display \n of Crypto-data");
LPWSTR szTooltipTexthButtonKey    = _T(" Keys may get truncated \n or zero-expanded.\n\
  DES:     8 bytes \n  3DES: 24 bytes\n  AES:   16 | 24 bytes \n  AES:   32 bytes Keyfile");
LPWSTR szTooltipTexthButtonIV     = _T(" Intial chaining vector \n may get truncated\n or zero-expanded.\n\
  DES:     8 bytes \n  3DES:   8 bytes\n  AES:   16 bytes");
LPWSTR szTooltipTexthKeyTextBox   = _T(" Enter secret key\n for all Crypto-modes ");
LPWSTR szTooltipTexthIvTextBox    = _T(" Enter intial chaining\n vector (Default=NULL) ");

TCHAR szCryptAlgo_DES[]      = _T(" DES - Data Encryption Standard \n (ECB with Ciphertext stealing)");
TCHAR szCryptAlgo_AES[]      = _T(" AES - Advanced Encryption Standard \n (CBC with Ciphertext stealing)");
TCHAR szCryptAlgo_3DES[]     = _T(" 3DES - Triple DES\n (CBC Ciphertext stealing) ");  
TCHAR szCryptAlgo_MAC[]      = _T(" /MAC - Message Authentication Code \n Open a file"); 
TCHAR szCryptAlgo_SAVE[]     = _T(" Save encrypted/deciphered data ");
TCHAR szCryptAlgo_ENCRYPT[]  = _T(" /Encrypt\n Open file(s) ");                  // Can't be used for XP (WIN10 ok)
TCHAR szCryptAlgo_DECIPHER[] = _T(" /Decipher\n Open encrypted file(s) ");       // Can't be used for XP (WIN10 ok)

TCHAR szCryptAlgoTitle_ENCRYPT[]  = _T(" /Encrypt - Open file(s) ");             // XP ("\n" in title causes trouble )
TCHAR szCryptAlgoTitle_DECIPHER[] = _T(" /Decipher - Open encrypted file(s) ");  // XP ("\n" in title causes trouble )

TCHAR szCryptAlgo_DES_ECBENCRYPT[]   = _T(" DES /ECBEncrypt\n (ECB with Ciphertext stealing) ");
TCHAR szCryptAlgo_DES_ECBDECIPHER[]  = _T(" DES /ECBDecipher\n (ECB with Ciphertext stealing) ");
TCHAR szCryptAlgo_DES_ENCRYPT[]      = _T(" DES /Encrypt\n (CBC Ciphertext stealing) ");  
TCHAR szCryptAlgo_DES_DECIPHER[]     = _T(" DES /Decipher\n (CBC Ciphertext stealing) "); 
TCHAR szCryptAlgo_DES_ECBE[]         = _T(" DES /ECBE\n (ISO/IEC 7816-4 padding) ");  
TCHAR szCryptAlgo_DES_ECBD[]         = _T(" DES /ECBD\n (ISO/IEC 7816-4 padding) "); 
TCHAR szCryptAlgo_DES_CBCE[]         = _T(" DES /CBCE\n (ISO/IEC 7816-4 padding) ");  
TCHAR szCryptAlgo_DES_CBCD[]         = _T(" DES /CBCD\n (ISO/IEC 7816-4 padding) "); 
TCHAR szCryptAlgo_DES_ECBE_PKCS[]    = _T(" DES /ECBE\n (PKCS padding) ");  
TCHAR szCryptAlgo_DES_ECBD_PKCS[]    = _T(" DES /ECBD\n (PKCS padding) "); 
TCHAR szCryptAlgo_DES_CBCE_PKCS[]    = _T(" DES /CBCE\n (PKCS padding) ");  
TCHAR szCryptAlgo_DES_CBCD_PKCS[]    = _T(" DES /CBCD\n (PKCS padding) "); 
TCHAR szCryptAlgo_DES_MAC[]          = _T(" DES /MAC\n (Crypto signature) ");                

TCHAR szCryptAlgo_3DES_ECBENCRYPT[]  = _T(" 3DES /ECBEncrypt\n (ECB with Ciphertext stealing) ");
TCHAR szCryptAlgo_3DES_ECBDECIPHER[] = _T(" 3DES /ECBDecipher\n (ECB with Ciphertext stealing) ");
TCHAR szCryptAlgo_3DES_ENCRYPT[]     = _T(" 3DES /Encrypt\n (CBC Ciphertext stealing) ");  
TCHAR szCryptAlgo_3DES_DECIPHER[]    = _T(" 3DES /Decipher\n (CBC Ciphertext stealing) "); 
TCHAR szCryptAlgo_3DES_ECBE[]        = _T(" 3DES /ECBE\n (ISO/IEC 7816-4 padding) ");  
TCHAR szCryptAlgo_3DES_ECBD[]        = _T(" 3DES /ECBD\n (ISO/IEC 7816-4 padding) "); 
TCHAR szCryptAlgo_3DES_CBCE[]        = _T(" 3DES /CBCE\n (ISO/IEC 7816-4 padding) ");  
TCHAR szCryptAlgo_3DES_CBCD[]        = _T(" 3DES /CBCD\n (ISO/IEC 7816-4 padding) "); 
TCHAR szCryptAlgo_3DES_ECBE_PKCS[]   = _T(" 3DES /ECBE\n (PKCS padding) ");  
TCHAR szCryptAlgo_3DES_ECBD_PKCS[]   = _T(" 3DES /ECBD\n (PKCS padding) "); 
TCHAR szCryptAlgo_3DES_CBCE_PKCS[]   = _T(" 3DES /CBCE\n (PKCS padding) ");  
TCHAR szCryptAlgo_3DES_CBCD_PKCS[]   = _T(" 3DES /CBCD\n (PKCS padding) "); 
TCHAR szCryptAlgo_3DES_MAC[]         = _T(" 3DES /MAC\n (Crypto signature) ");                

TCHAR szCryptAlgo_AES_ECBENCRYPT[]   = _T(" AES /ECBEncrypt\n (ECB with Ciphertext stealing) ");
TCHAR szCryptAlgo_AES_ECBDECIPHER[]  = _T(" AES /ECBDecipher\n (ECB with Ciphertext stealing) ");
TCHAR szCryptAlgo_AES_ENCRYPT[]      = _T(" AES /Encrypt\n (CBC Ciphertext stealing) ");  
TCHAR szCryptAlgo_AES_DECIPHER[]     = _T(" AES /Decipher\n (CBC Ciphertext stealing) "); 
TCHAR szCryptAlgo_AES_ECBE[]         = _T(" AES /ECBE\n (ISO/IEC 7816-4 padding) ");  
TCHAR szCryptAlgo_AES_ECBD[]         = _T(" AES /ECBD\n (ISO/IEC 7816-4 padding) "); 
TCHAR szCryptAlgo_AES_CBCE[]         = _T(" AES /CBCE\n (ISO/IEC 7816-4 padding) ");  
TCHAR szCryptAlgo_AES_CBCD[]         = _T(" AES /CBCD\n (ISO/IEC 7816-4 padding) "); 
TCHAR szCryptAlgo_AES_ECBE_PKCS[]    = _T(" AES /ECBE\n (PKCS padding) ");  
TCHAR szCryptAlgo_AES_ECBD_PKCS[]    = _T(" AES /ECBD\n (PKCS padding) "); 
TCHAR szCryptAlgo_AES_CBCE_PKCS[]    = _T(" AES /CBCE\n (PKCS padding) ");  
TCHAR szCryptAlgo_AES_CBCD_PKCS[]    = _T(" AES /CBCD\n (PKCS padding) "); 
TCHAR szCryptAlgo_AES_MAC[]          = _T(" AES /MAC\n (Crypto signature (NIST 800-38B)) ");                

TCHAR szCryptAlgo_CONTINUE[]         = _T(" Apply last selection from Crypto-Menu. ");                

TCHAR* pszCurrentModeTooltip = szCryptAlgo_CONTINUE;

// External variables
extern char DebugBuf[];      // Debug only, buffer for formatted ASCII text
extern TCHAR _tDebugBuf[];   // Temporary buffer for formatted UNICODE text
extern int _tDebugbufSize;

extern TCHAR* BuildVersion;

extern TCHAR szKeyFileName[];
extern TCHAR szIcvFileName[];

extern COLORREF ERROR_FGND; 
extern COLORREF ERROR_BGND; 
extern COLORREF STATUS_FGND;
extern COLORREF STATUS_BGND;
extern COLORREF INFO_FGND;  
extern COLORREF INFO_BGND;  
extern COLORREF COPY_FGND;  
extern COLORREF STD_FGND; 
extern COLORREF ALERT_FGND;

extern TCHAR heditExe[], heditTmp[];
extern char szKeyFileIn[];
extern char szIvFileIn[];

extern int GlobalCryptMode, mouseHover, multiFileFlag, _multiFileBrowserFlag;
extern int _valAQ;

extern DWORD dwCryptFileSize, dwKeyFileSize, dwIvFileSize;

extern LPSTR pszCryptFileIn, pszCryptFileDisplay, pszTextFileIn;

extern HWND hTool;
extern HWND hEdit;
extern HWND hProgBar;        // Handle of progress bar.
extern HWND hStatusbar;
extern HWND hButtonDelim;
extern HWND hKeyTextBox;           
extern HWND hIvTextBox;          
extern HWND hButtonKey;
extern HWND hButtonIV;
extern HWND hButtonHex;
extern HWND hTooltip;
extern HWND hwndTT;
//extern HWND hDlgFileExist; // For Modeless Dialog only

// Declarations of functions included in this code module
extern void DispayKeyFileHex(HWND, char[], int);
extern void Bin2Hex(int);
extern void Bin2Txt();

extern void DoTxtFileOpen(HWND);
extern void DoTxtFileSave(HWND);
//ha//extern void DoBinFileOpen(HWND, int);
extern BOOL DoBinFileOpen(HWND, int);
extern void DoBinFileSave(HWND);
extern void DoKeyFileOpen(HWND, int);
extern void DoFileRename();

extern void CreateButtonDelim(HWND);
extern void CreateButtonHexText(HWND);
extern void CreateButtonSetKey(HWND);
extern void CreateButtonSetIV(HWND);
extern void CreateInputDialogKey(HWND);
extern void CreateInputDialogIV(HWND);
extern void CreateToolTip(HWND, LPWSTR, const int);
extern void CreateConsole(int);

//extern HWND CreateStdToolBar(HWND);
extern HWND CreateCustomToolbar(HWND _hwnd);
extern HWND CreateStatusBar(HWND);
extern HWND CreateEditControl(HWND);

extern void WINAPI CreateMenuItemIcons(HWND); 

extern void ControlFileMenu(int);
extern void ControlContextMenu(int);
extern void ControlCryptoToolItems(int, int);

extern void GetHomeDirectory();

extern int UpdateButtons();

extern int CBTCustomMessageBox(HWND, LPCTSTR, LPCTSTR, UINT, UINT);
extern long int CustomdDrawService(LPARAM);
extern long int DrawItemService(LPARAM, WPARAM);

extern void PaintColoredStatusInfoMsg(TCHAR*);
extern void PaintColoredStatusMsg(TCHAR*);
extern void PaintWindowGray(HWND);
//ha//extern void PaintWindowWhite(HWND);

extern void ShowWinMouseClick(HWND, int, int, int);
extern void CtrlHideShowWindow(HWND, int);

extern BOOL CryptoTestEditedText(int);
extern BOOL AscHex2BinEditedText();
extern BOOL AesEncryptEditedText(int);
extern BOOL ConsoleHeditExeVerify();

extern void ClearKeyDialog();
extern void ClearIcvDialog();
extern void InitCryptoKeyFromDialog(int);
extern void DispayKeyDialogHex(HWND, char [], int);

extern void WindowsDoAlgorithmRSA();
extern void DoRsaLoadKey(HWND, int);
extern void DoRsaEncrypt(HWND);
extern void DoRsaDecipher(HWND);
extern void DoRsaGenRandomKey(HWND, int);

extern void APIENTRY HandleContextMenu(HWND, POINT);  // Context menu
extern int CBTMessageBox(HWND, LPCTSTR, LPCTSTR, UINT);

extern LRESULT CALLBACK SubclassprocButton(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR); // Fancy buttons
extern INT_PTR CALLBACK DialogProcMultiFile(HWND, UINT, WPARAM, LPARAM);                     // Multifile, etc. ...
extern INT_PTR CALLBACK AboutDlgProc(HWND, UINT, WPARAM, LPARAM);                            // About menu

// Forward declaration of functions included in this code module:
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

//-----------------------------------------------------------------------------
//
//                        DoEvents (equivalent for C++)
//
// IMPORTANT:
//  This prevents freezing of the Progressbar when operating on lengthy files
//   and focusing other windows while 'haCrypt.exe' is running.
//    Call this routine at a strategic suitable point, i.e. Progressbar and counter
//
void DoEvents()  // !Absolutely needed for 'one thread-only' UIs!
  {
  MSG msg;
  BOOL result;

  while (::PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE))
    {
    result = ::GetMessage(&msg, NULL, 0, 0);
    if (result == 0)                          // WM_QUIT
      {                
      ::PostQuitMessage(msg.wParam);
      break;
      }
    else if (result == -1)
      {
      return;   // Handle errors/exit application, etc.
      }
    else 
      {
      ::TranslateMessage(&msg);
      ::DispatchMessage(&msg);
      }
    }
  } // DoEvents

//-----------------------------------------------------------------------------
//
//                              InitCryptAlgoContinue
//
//  Continues with the selected Algorithm from Crypto Menu currently applied.
//
void InitCryptAlgoContinue(WPARAM _wparam)
  {
  // Restricted to items from Crypto Menu (see [hacyrpt.h])
  if ((LOWORD(_wparam) >= ID_CRYPTO_DES_ECBENCRYPT) &&          // see haCrypt.h
      (LOWORD(_wparam) <= ID_CRYPTO_AES_MAC))                   // Must exclude ID_TOOLBAR_...!                           
    {
    // Enable the toolbar icon button (Recoursive)
    SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_CRYPT_CONTINUE, TRUE);  
    gwCryptContinue = LOWORD(_wparam);
    GlobalCryptMode = ENCRYPT;                                  // Assume ENCRYPT

    switch(gwCryptContinue)
      {
      // DES
      case ID_CRYPTO_DES_ENCRYPT:
        FileProcessingMode = CRYPT_DES | CRYPT_CBC;
        pszCurrentModeTooltip = szCryptAlgo_DES_ENCRYPT;
        break;
      case ID_CRYPTO_DES_DECIPHER:
        GlobalCryptMode = DECIPHER;                             // Set DECIPHER
        FileProcessingMode = CRYPT_DES | CRYPT_CBC;
        pszCurrentModeTooltip = szCryptAlgo_DES_DECIPHER;
        break;
      case ID_CRYPTO_DES_ECBENCRYPT:
        pszCurrentModeTooltip = szCryptAlgo_DES_ECBENCRYPT;
        FileProcessingMode = CRYPT_DES | CRYPT_ECB;
        break;
      case ID_CRYPTO_DES_ECBDECIPHER:
        GlobalCryptMode = DECIPHER;                             // Set DECIPHER
        FileProcessingMode = CRYPT_DES | CRYPT_ECB;
        pszCurrentModeTooltip = szCryptAlgo_DES_ECBDECIPHER;
        break;
      case ID_CRYPTO_DES_ECBE:
        FileProcessingMode = CRYPT_DES | CRYPT_ECB | CRYPT_ISO;
        pszCurrentModeTooltip = szCryptAlgo_DES_ECBE;
        break;
      case ID_CRYPTO_DES_ECBD:
        GlobalCryptMode = DECIPHER;                             // Set DECIPHER
        FileProcessingMode = CRYPT_DES | CRYPT_ECB | CRYPT_ISO; 
        pszCurrentModeTooltip = szCryptAlgo_DES_ECBD;
        break;
      case ID_CRYPTO_DES_CBCE:
        FileProcessingMode = CRYPT_DES | CRYPT_CBC | CRYPT_ISO; 
        pszCurrentModeTooltip = szCryptAlgo_DES_CBCE;
        break;
      case ID_CRYPTO_DES_CBCD:
        GlobalCryptMode = DECIPHER;                             // Set DECIPHER
        FileProcessingMode = CRYPT_DES | CRYPT_CBC | CRYPT_ISO; 
        pszCurrentModeTooltip = szCryptAlgo_DES_CBCD;
        break;
      case ID_CRYPTO_DES_ECBE_PKCS:
        FileProcessingMode = CRYPT_DES | CRYPT_ECB | CRYPT_PKCS;
        pszCurrentModeTooltip = szCryptAlgo_DES_ECBE_PKCS;
        break;
      case ID_CRYPTO_DES_ECBD_PKCS:
        GlobalCryptMode = DECIPHER;                             // Set DECIPHER
        FileProcessingMode = CRYPT_DES | CRYPT_ECB | CRYPT_PKCS;
        pszCurrentModeTooltip = szCryptAlgo_DES_ECBD_PKCS;
        break;
      case ID_CRYPTO_DES_CBCE_PKCS:
        FileProcessingMode = CRYPT_DES | CRYPT_CBC | CRYPT_PKCS;
        pszCurrentModeTooltip = szCryptAlgo_DES_CBCE_PKCS;
        break;
      case ID_CRYPTO_DES_CBCD_PKCS:
        GlobalCryptMode = DECIPHER;                             // Set DECIPHER
        FileProcessingMode = CRYPT_DES | CRYPT_CBC | CRYPT_PKCS;
        pszCurrentModeTooltip = szCryptAlgo_DES_CBCD_PKCS;
        break;
      case ID_CRYPTO_DES_MAC:
        FileProcessingMode = CRYPT_DES | CRYPT_MAC;             
        pszCurrentModeTooltip = szCryptAlgo_DES_MAC;
        break;

      // 3DES
      case ID_CRYPTO_TDES_ENCRYPT:
        FileProcessingMode = CRYPT_TDES | CRYPT_CBC;
        pszCurrentModeTooltip = szCryptAlgo_3DES_ENCRYPT;
        break;
      case ID_CRYPTO_TDES_DECIPHER:
        GlobalCryptMode = DECIPHER;                              // Set DECIPHER
        FileProcessingMode = CRYPT_TDES | CRYPT_CBC;             
        pszCurrentModeTooltip = szCryptAlgo_3DES_DECIPHER;
        break;
      case ID_CRYPTO_TDES_ECBENCRYPT:
        FileProcessingMode = CRYPT_TDES | CRYPT_ECB;             
        pszCurrentModeTooltip = szCryptAlgo_3DES_ECBENCRYPT;
        break;
      case ID_CRYPTO_TDES_ECBDECIPHER:
        GlobalCryptMode = DECIPHER;                              // Set DECIPHER
        FileProcessingMode = CRYPT_TDES | CRYPT_ECB;             
        pszCurrentModeTooltip = szCryptAlgo_3DES_ECBDECIPHER;
        break;
      case ID_CRYPTO_TDES_ECBE:
        FileProcessingMode = CRYPT_TDES | CRYPT_ECB | CRYPT_ISO; 
        pszCurrentModeTooltip = szCryptAlgo_3DES_ECBE;
        break;
      case ID_CRYPTO_TDES_ECBD:
        GlobalCryptMode = DECIPHER;                              // Set DECIPHER
        FileProcessingMode = CRYPT_TDES | CRYPT_ECB | CRYPT_ISO; 
        pszCurrentModeTooltip = szCryptAlgo_3DES_ECBD;
        break;
      case ID_CRYPTO_TDES_CBCE:
        FileProcessingMode = CRYPT_TDES | CRYPT_CBC | CRYPT_ISO; 
        pszCurrentModeTooltip = szCryptAlgo_3DES_CBCE;
        break;
      case ID_CRYPTO_TDES_CBCD:
        GlobalCryptMode = DECIPHER;                              // Set DECIPHER
        FileProcessingMode = CRYPT_TDES | CRYPT_CBC | CRYPT_ISO; 
        pszCurrentModeTooltip = szCryptAlgo_3DES_CBCD;
        break;
      case ID_CRYPTO_TDES_ECBE_PKCS:
        FileProcessingMode = CRYPT_TDES | CRYPT_ECB | CRYPT_PKCS;
        pszCurrentModeTooltip = szCryptAlgo_3DES_ECBE_PKCS;
        break;
      case ID_CRYPTO_TDES_ECBD_PKCS:
        GlobalCryptMode = DECIPHER;                              // Set DECIPHER
        FileProcessingMode = CRYPT_TDES | CRYPT_ECB | CRYPT_PKCS;
        pszCurrentModeTooltip = szCryptAlgo_3DES_ECBD_PKCS;
        break;
      case ID_CRYPTO_TDES_CBCE_PKCS:
        FileProcessingMode = CRYPT_TDES | CRYPT_CBC | CRYPT_PKCS;
        pszCurrentModeTooltip = szCryptAlgo_3DES_CBCE_PKCS;
        break;
      case ID_CRYPTO_TDES_CBCD_PKCS:
        GlobalCryptMode = DECIPHER;                              // Set DECIPHER
        FileProcessingMode = CRYPT_TDES | CRYPT_CBC | CRYPT_PKCS;
        pszCurrentModeTooltip = szCryptAlgo_3DES_CBCD_PKCS;
        break;
      case ID_CRYPTO_TDES_MAC:
        FileProcessingMode = CRYPT_TDES | CRYPT_MAC;
        pszCurrentModeTooltip = szCryptAlgo_3DES_MAC;
        break;

      // AES
      case ID_CRYPTO_AES_ENCRYPT:
        FileProcessingMode = CRYPT_AES | CRYPT_CBC;
        pszCurrentModeTooltip = szCryptAlgo_AES_ENCRYPT;
        break;
      case ID_CRYPTO_AES_DECIPHER:
        GlobalCryptMode = DECIPHER;                              // Set DECIPHER
        FileProcessingMode = CRYPT_AES | CRYPT_CBC;              
        pszCurrentModeTooltip = szCryptAlgo_AES_DECIPHER;
        break;
      case ID_CRYPTO_AES_ECBENCRYPT:
        FileProcessingMode = CRYPT_AES | CRYPT_ECB;              
        pszCurrentModeTooltip = szCryptAlgo_AES_ECBENCRYPT;
        break;
      case ID_CRYPTO_AES_ECBDECIPHER:
        GlobalCryptMode = DECIPHER;                              // Set DECIPHER
        FileProcessingMode = CRYPT_AES | CRYPT_ECB;              
        pszCurrentModeTooltip = szCryptAlgo_AES_ECBDECIPHER;
        break;
      case ID_CRYPTO_AES_ECBE:
        FileProcessingMode = CRYPT_AES | CRYPT_ECB | CRYPT_ISO;  
        pszCurrentModeTooltip = szCryptAlgo_AES_ECBE;
        break;
      case ID_CRYPTO_AES_ECBD:
        GlobalCryptMode = DECIPHER;                              // Set DECIPHER
        FileProcessingMode = CRYPT_AES | CRYPT_ECB | CRYPT_ISO;  
        pszCurrentModeTooltip = szCryptAlgo_AES_ECBD;
        break;
      case ID_CRYPTO_AES_CBCE:
        FileProcessingMode = CRYPT_AES | CRYPT_CBC | CRYPT_ISO;  
        pszCurrentModeTooltip = szCryptAlgo_AES_CBCE;
        break;
      case ID_CRYPTO_AES_CBCD:
        GlobalCryptMode = DECIPHER;                              // Set DECIPHER
        FileProcessingMode = CRYPT_AES | CRYPT_CBC | CRYPT_ISO;  
        pszCurrentModeTooltip = szCryptAlgo_AES_CBCD;
        break;
      case ID_CRYPTO_AES_ECBE_PKCS:
        FileProcessingMode = CRYPT_AES | CRYPT_ECB | CRYPT_PKCS;
        pszCurrentModeTooltip = szCryptAlgo_AES_ECBE_PKCS;
        break;
      case ID_CRYPTO_AES_ECBD_PKCS:
        GlobalCryptMode = DECIPHER;                              // Set DECIPHER
        FileProcessingMode = CRYPT_AES | CRYPT_ECB | CRYPT_PKCS;
        pszCurrentModeTooltip = szCryptAlgo_AES_ECBD_PKCS;
        break;
      case ID_CRYPTO_AES_CBCE_PKCS:
        FileProcessingMode = CRYPT_AES | CRYPT_CBC | CRYPT_PKCS;
        pszCurrentModeTooltip = szCryptAlgo_AES_CBCE_PKCS;
        break;
      case ID_CRYPTO_AES_CBCD_PKCS:
        GlobalCryptMode = DECIPHER;                              // Set DECIPHER
        FileProcessingMode = CRYPT_AES | CRYPT_CBC | CRYPT_PKCS;
        pszCurrentModeTooltip = szCryptAlgo_AES_CBCD_PKCS;
        break;
      case ID_CRYPTO_AES_MAC:
        FileProcessingMode = CRYPT_AES | CRYPT_MAC;
        pszCurrentModeTooltip = szCryptAlgo_AES_MAC;
        break;

      default:
        if (pszCurrentModeTooltip == szCryptAlgo_CONTINUE)  // Keep button disabled
          SendMessage(hTool, TB_ENABLEBUTTON, ID_TOOLBAR_CRYPT_CONTINUE, FALSE);   
        break;
      } // end switch

    if (pszCurrentModeTooltip == szCryptAlgo_CONTINUE) return;
    
    // Else Append descriptive comment
    StringCbPrintf(_tTTBuf, _tTTBufSize, _T("%s\n%s"),
                 pszCurrentModeTooltip, szCryptAlgo_CONTINUE);

    pszCurrentModeTooltip = _tTTBuf;  // Set the determined text for the tooltip
    } // end if
  } // InitCryptAlgoContinue


//-----------------------------------------------------------------------------
//
//                              DoCryptAlgoContinue
//
//  Only continue with the currently selected Algorithm from Crypto Menu.
//
void DoCryptAlgoContinue(HWND _hwnd)
  {
  // Perform the appropriate command
  PostMessage(hMain, WM_COMMAND, gwCryptContinue, 0);   
  } //DoCryptAlgoContinue


//-----------------------------------------------------------------------------
//
//                         WndProc
//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//  PURPOSE:  Processes messages for the main window.
//
LRESULT CALLBACK WndProc(HWND _hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
  {
  // This keeps the text color as long as the edit field has no focus
  if (msg == WM_CTLCOLOREDIT && textColor == FALSE) 
    return DefWindowProc(_hwnd, msg, wParam, lParam);

  switch(msg)
    {
    //--------------------------------------------------------------------------
    //
    //                        case WM_CREATE
    case WM_CREATE:
      {
      CreateMenuItemIcons(_hwnd);

      // Create toolbar with icon images as buttons 
      hTool = CreateCustomToolbar(_hwnd);    // ha Custom Icons
      //hTool = CreateStdToolBar(_hwnd);     // MS Std Icons (not used)

      // Create quick-info display on toolbar icons  // not needed ??
      //CreateToolTip(_hwnd);                        // not needed ??

      CreateButtonDelim(hTool);

      // Add button: "Toggle Hex-Text display"
      CreateButtonHexText(hTool);

      // Add Dialog Field: "Enter Crypto Key"
      CreateInputDialogKey(hTool);
      // Add button for saving the crypto key
      CreateButtonSetKey(hTool);

      // Add Dialog Field: "Enter Initial Chaining Vector (IV)"
      CreateInputDialogIV(hTool);
      // Add button for saving the IV
      CreateButtonSetIV(hTool);

      // Create a window for text editing
      hEdit = CreateEditControl(_hwnd);

      // Create statusbar at the bottom of the main window
      hStatusbar = CreateStatusBar(_hwnd);

      // Create a quickinfo 'tooltip' for various buttons and dialog fields
      CreateToolTip(hButtonHex,  szTooltipTexthButtonHex,  NULL);   //, TTS_BALLOON (ugly)
      CreateToolTip(hButtonKey,  szTooltipTexthButtonKey,  NULL);   //, TTS_BALLOON
      CreateToolTip(hButtonIV,   szTooltipTexthButtonIV,   NULL);   //, TTS_BALLOON
      CreateToolTip(hKeyTextBox, szTooltipTexthKeyTextBox, NULL);
      CreateToolTip(hIvTextBox,  szTooltipTexthIvTextBox,  NULL);

      // Must be the last (hwndTT=hEdit): Include Icon & Title in this tooltip
      // --> See 'PaintColoredStatusErrorMsg' in haCryptDraw.cpp 'TTM_SETTITLE'
      CreateToolTip(hEdit, szTooltipTexthEdit, NULL);
      // Disable the last hwndTT (=hEdit)
      SendMessage(hwndTT, TTM_ACTIVATE, FALSE, 0);     
      
      dwKeyFileSize = 0;                     // No keyfile
      dwIvFileSize  = 0;                     // No Ivfile

      // Init clear key/IV buffers and text fields for crypto functions
      ClearKeyDialog();
      ClearIcvDialog();

      ControlCryptoToolItems(MF_GRAYED, -1);       // Start up default
      FileProcessingMode = CRYPT_DES | CRYPT_ECB;  //CRYPTMODE_DES_ECB;
      ToolProcessingMode = FileProcessingMode;

      //FileProcessingMode = FILEMODE_TEXT;  // Init window display mode
      UpdateButtons();                       // Default = Text mode
      ShowWindow(hEdit, SW_HIDE);            // Initially hide the Editor text field
      break;
      } // end case WM_CREATE

    //--------------------------------------------------------------------------
    //
    //                          case WM_SIZE
    case WM_SIZE:
      {
      RECT rcTool;
      int iToolHeight;

      RECT rcStatus;
      int iStatusHeight;

      RECT rcClient;
      int iEditHeight;

      // Size toolbar and get height
      hTool = GetDlgItem(_hwnd, IDC_MAIN_TOOL);
      SendMessage(hTool, TB_AUTOSIZE, 0, 0);

      GetWindowRect(hTool, &rcTool);
      iToolHeight = rcTool.bottom - rcTool.top;

      // Size status bar and get height
      hStatusbar = GetDlgItem(_hwnd, IDC_MAIN_STATUS);
      SendMessage(hStatusbar, WM_SIZE, 0, 0);

      GetWindowRect(hStatusbar, &rcStatus);
      iStatusHeight = rcStatus.bottom - rcStatus.top;

      // Calculate remaining height and size for edit
      GetClientRect(_hwnd, &rcClient);

      iEditHeight = rcClient.bottom - iToolHeight - iStatusHeight;

      // Define a small gray border around the text field
      hEdit = GetDlgItem(_hwnd, IDC_MAIN_EDIT);
      SetWindowPos(hEdit, 
                   NULL, 
                   rcClient.left +  7, // Left
                   iToolHeight   +  7, // Top
                   rcClient.right- 14, // Right
                   iEditHeight   - 14, // Bottom
                   SWP_NOZORDER | SWP_DRAWFRAME);
      break;
      }

    //--------------------------------------------------------------------------
    //
    //                        case WM_CONTEXTMENU:
    case WM_CONTEXTMENU:
      {
      RECT rc;
      POINT pt;

      GetClientRect(_hwnd, (LPRECT)&rc); 

      // Get the client coordinates for the mouse click.  
      //pt.x = LOWORD(lParam);   // also OK
      //pt.y = HIWORD(lParam);   // also OK
      GetCursorPos(&pt);

      // Control the context menu 'Key' items (MF_GRAYED or MF_ENABLED);
      if (FileProcessingMode == CRYPT_NONE       ||
          FileProcessingMode == FILEMODE_TEXT    ||
          FileProcessingMode == FILEMODE_TEXTNEW
          )
        ControlContextMenu(MF_GRAYED);
      else
        ControlContextMenu(MF_ENABLED);
        
      // If the mouse click took place inside the client area, 
      // execute the application-defined function 
      // that displays the shortcut menu. 
      //if (PtInRect((LPRECT)&rc, pt))
      HandleContextMenu(_hwnd, pt);
      }
      break;

    case WM_CLOSE:
      if (activeProgbar == TRUE) break; // No WM_COMMANDs if file processing in progress
      DeleteFile(heditTmp);             // Delete 'Hedit.tmp' (no matter if it exists or not)
      DestroyWindow(_hwnd);
      break;

    case WM_DESTROY:
      if (activeProgbar == TRUE) break; // No WM_COMMANDs if file processing in progress
      DeleteFile(heditTmp);             // Delete 'Hedit.tmp' (no matter if it exists or not)
      PostQuitMessage(0);               // Exit haCrypt
      break;

    //--------------------------------------------------------------------------
    //
    //                    case WM_PAINT
    //                    case WM_CTLCOLOREDIT
    //                    case WM_DRAWITEM
    
    case WM_MEASUREITEM: 
      extern void WINAPI OnMeasureItem(HWND, LPMEASUREITEMSTRUCT); 
      OnMeasureItem(_hwnd, (LPMEASUREITEMSTRUCT)lParam); 
      return TRUE; 

//ha//    case WM_DRAWITEM:
//ha//      {
//ha//      extern void WINAPI OnDrawItem(HWND, LPDRAWITEMSTRUCT); 
//ha//      OnDrawItem(_hwnd, (LPDRAWITEMSTRUCT)lParam); 
//ha//      return TRUE; 
//ha//      }

    // All painting occurs here, between BeginPaint() and EndPaint().
    case WM_PAINT:
      PaintWindowGray(_hwnd);  // Just a grayed main window on startup
      //PaintWindowWhite(hEdit); // Ensure a clear white edit display (not needed)
      break;                         // (this wipes out text when window is clipped at desktop edges)

    // Text colors in read-only edit field are handeled here
    case WM_CTLCOLORSTATIC:
    // Text colors in read/write edit field are handeled here
    case WM_CTLCOLOREDIT:
      if ((HWND)lParam == hEdit && textColor != FALSE) // lParam, wParam arrive here
        {
        switch(textColor)
          {
          case T_BLUE:                              // Raw blue color index = 1
            SetTextColor((HDC)wParam, COPY_FGND);   // Blue text color in textfield
            SetBkMode((HDC)wParam, TRANSPARENT);    // Ensure the correct system background
            //SetBkColor((HDC)wParam, ..);          // ..Any background for text in textfield
            break;
          case T_GREEN:                             // Raw green color index = 2        
            SetTextColor((HDC)wParam, INFO_FGND);   // Green text color in textfield
            SetBkMode((HDC)wParam, TRANSPARENT);    // Ensure the correct system background
            break;
          case T_RED:                               // Raw red color index = 3      
            SetTextColor((HDC)wParam, ALERT_FGND);  // Red text color in textfield
            SetBkMode((HDC)wParam, TRANSPARENT);    // Ensure the correct system background
            break;
          } // end Switch
        } // end if
      break;

    // All owner-drawing is intercepted here
    case WM_DRAWITEM:
      {
      extern void WINAPI OnDrawItem(HWND, LPDRAWITEMSTRUCT); 
      OnDrawItem(_hwnd, (LPDRAWITEMSTRUCT)lParam); 

      LPDRAWITEMSTRUCT lpDIS = (LPDRAWITEMSTRUCT)lParam; // Struct arrives here

      if (lpDIS->hwndItem == hStatusbar)
        {
        //typedef struct tagDRAWITEMSTRUCT {
        //  UINT CtlType;
        //  UINT CtlID;
        //  UINT itemID;
        //  UINT itemAction;
        //  UINT itemState;
        //  HWND hwndItem;
        //  HDC hDC;
        //  RECT rcItem;
        //  ULONG_PTR itemData;
        //} DRAWITEMSTRUCT, *PDRAWITEMSTRUCT, *LPDRAWITEMSTRUCT;
        //
        switch(statColor)
          {
          case FGNDWHITE_BGNDBLUE:                    // PaintColoredStatusInfoMsg()
            SetTextColor(lpDIS->hDC, STATUS_FGND);    // White text color in statusbar
            SetBkColor(lpDIS->hDC,   STATUS_BGND);    // Blue background for text in statusbar
            TextOut(lpDIS->hDC, 7, 3, (PTSTR)lpDIS->itemData, wcslen((PTSTR)lpDIS->itemData)); // UNICODE text only.
            break;
          case FGNDWHITE_BGNDRED:                     // PaintColoredStatusErrorMsg()
            SetTextColor(lpDIS->hDC, ERROR_FGND);     // White text color in statusbar
            SetBkColor(lpDIS->hDC,   ERROR_BGND);     // Red background for text in statusbar
            TextOut(lpDIS->hDC, 7, 3, (PTSTR)lpDIS->itemData, wcslen((PTSTR)lpDIS->itemData)); // UNICODE text only.
            break;
          case FGNDGREEN_BGNDTRANS:                   // PaintColoredStatusProgressMsg()
            SetTextColor(lpDIS->hDC, INFO_FGND);      // Green Info text color in statusbar
            SetBkMode(lpDIS->hDC, TRANSPARENT);       // Ensure the correct system background
            TextOut(lpDIS->hDC, 2, 3, (PTSTR)lpDIS->itemData, wcslen((PTSTR)lpDIS->itemData)); // UNICODE text only.
            break;
          case FGNDBLUE_BGNDTRANS:                    // PaintColoredStatusLargeProgressMsg()
            SetTextColor(lpDIS->hDC, COPY_FGND);      // Blue copy text color in statusbar
            SetBkMode(lpDIS->hDC, TRANSPARENT);       // Ensure the correct system background
            TextOut(lpDIS->hDC, 2, 3, (PTSTR)lpDIS->itemData, wcslen((PTSTR)lpDIS->itemData)); // UNICODE text only.
            break;
          case FGNDBLACK_BGNDTRANS:                   // PaintColoredStatusMsg()
            SetTextColor(lpDIS->hDC, STD_FGND);       // Black standard text color in statusbar
            SetBkMode(lpDIS->hDC, TRANSPARENT);       // Ensure the correct system background
            TextOut(lpDIS->hDC, 2, 3, (PTSTR)lpDIS->itemData, wcslen((PTSTR)lpDIS->itemData)); // UNICODE text only.
            break;
          } // end switch
        } // end if (hStatusbar)

      // Owner-drawing the buttons on the toolbar
      //
      // To effectively prevent a drawing chaos and application lock-ups
      //  when fast processing large number (>1500) of smaller multiple files,
      //  we temporarily disable the WM_DRAWITEM service while in multiple file mode.
      //
      else if (msg == WM_DRAWITEM && multiFileFlag == TRUE) // Prevent a drawing chaos
        return DefWindowProc(_hwnd, msg, wParam, lParam);   //  when displaying multiple filenames
      else
        return (DrawItemService(lParam, wParam));           // See haCryptDraw.cpp
      }
      break;  // end case WM_DRAWITEM:

    //--------------------------------------------------------------------------
    //
    //                          case WM_NOTIFY
    case WM_NOTIFY:
      {
      switch (((LPNMHDR)lParam)->code)
        {
        // High-lighting the icon buttons
        case NM_HOVER:
          break;       // Dont know how to do it here, see haCryptDraw.cpp...

        case NM_CUSTOMDRAW:
          return (CustomdDrawService(lParam));   // See haCryptDraw.cpp
          break;

        // Tooltips Info (Text length = 80 chars max)
        // See 'CreateToolTip()' in haCryptWin.cpp
        // LPNMTTDISPINFO pInfo = (LPNMTTDISPINFO)lParam;
        // SendMessage(pInfo->hdr.hwndFrom, TTM_SETMAXTIPWIDTH, 0, 150);
        // wcscpy_s(pInfo->szText, ARRAYSIZE(pInfo->szText), 
        //     L"This\nis a very long text string " \
        //     L"that must be broken into several lines.");
        //
        case TTN_NEEDTEXT:     // Identical: "case TTN_GETDISPINFO:"
          { 
          UINT idButton;
          LPTOOLTIPTEXT lpttt; 

          lpttt = (LPTOOLTIPTEXT)lParam; 
          lpttt->hinst = NULL;
          idButton = lpttt->hdr.idFrom; 

          char ToolTipString[256];

          switch (idButton)   // Display quick-info for toolbar items (TB_ID...)
            {                  
            case ID_FILE_TEXT_NEW:
              lpttt->lpszText = _T(" /TEXT Editor-Mode ");   //ToolTipString; 
              break;
            case ID_FILE_TEXT_OPEN:
              lpttt->lpszText = _T(" Open a text file ");    //ToolTipString; 
              break;
            case ID_FILE_TEXT_SAVEAS:
              lpttt->lpszText = _T(" Save displayed text\n (\\x00 saved as \\x20) "); //ToolTipString; 
              break;

            case ID_TOOLBAR_DES:               
              lpttt->lpszText = szCryptAlgo_DES;            //ToolTipString; 
              break; 
             
            case ID_TOOLBAR_AES:          
              lpttt->lpszText = szCryptAlgo_AES;            //ToolTipString; 
              break;                          
            
            case ID_TOOLBAR_TDES:
              lpttt->lpszText = szCryptAlgo_3DES;           //ToolTipString; 
              break;

            case ID_TOOLBAR_ENCRYPT: 
              lpttt->lpszText = szCryptAlgo_ENCRYPT;        //ToolTipString; 
              break; 
            case ID_TOOLBAR_DECIPHER:         
              lpttt->lpszText = szCryptAlgo_DECIPHER;       //ToolTipString; 
              break;

            case ID_TOOLBAR_MAC:          
              lpttt->lpszText = szCryptAlgo_MAC;            //ToolTipString; 
              break;
            
            case ID_FILE_CRYPT_SAVEAS:                      //ToolTipString;
              lpttt->lpszText = szCryptAlgo_SAVE;
              break;

            case ID_TOOLBAR_CRYPT_CONTINUE:
              lpttt->lpszText = pszCurrentModeTooltip;      //ToolTipString; 
              break;
            } // end switch (idButton)
          break;
          } // end case TTN_NEEDTEXT (Identical: "case TTN_GETDISPINFO:")

        } // end switch
        break;
      } // end case WM_NOTIFY 


    //--------------------------------------------------------------------------
    //
    //                          case WM_COMMAND
    case WM_COMMAND:
      _escFlag = FALSE;           // Discard any pending ESC
      if (activeProgbar == TRUE)  // No WM_COMMANDs if file processing in progress
        {
        if (LOWORD(wParam) != ID_HIDEKEY &&
            LOWORD(wParam) != ID_SHOWKEY)
          break;                   
        }

      InitCryptAlgoContinue(LOWORD(wParam));        // Set FileProcessingMode && Tooltips 
              
      switch(LOWORD(wParam))
        {
        // Button: Dummy delimiter for test only
        case ID_BUTTON_DELIM:                       // Testing ShowWinMouseClick()
          break;                                    // Not needed.

        case ID_KEYBOARD_ESC:                       // ESC pressed on Keyboard
          break;                                    // Not needed.

        // Button: Toggle Hex/Text Display
        case ID_HEX_DISPLAY:
          // Compare the positions MouseClick and Button Hex/Txt
          // If the MouseClick {x;y} are not within the button's rectancle {bottom;right}
          //  then the Mouseclick was a simulated click-event. 
          //  Simulated mouse click-events may not cause any action, but are necessary  
          //  to pop up and show the button images being over-painted by 'CreateGradientBrush'. 
          GetWindowRect(hButtonHex, &rcButton);
          GetCursorPos(&pMouse);
          if ((abs(rcButton.left - pMouse.x) > BUTTON_WIDTH  && KeyboardEntry != VK_RETURN) ||
              (abs(rcButton.top  - pMouse.y) > BUTTON_HEIGHT && KeyboardEntry != VK_RETURN) ||
              (mouseHover == TRUE)) break;

          SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 1, NULL); // Clear possible key/IV display

          _hexMode ^= TRUE;                         // Toggle Hex/Text Display mode
          if (_hexMode)
            {
            SendMessage(hEdit, EM_SETREADONLY, FALSE, 0); // Enable text field for edit
            SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)szHexDisplay);
            Bin2Hex(TRUE);
            SetWindowTextA(hEdit, NULL);           // Init-clear the Text Field
            SetWindowTextA(hEdit, pszCryptFileDisplay); // Change ANSI-text within specified text field
            }
          else
            {
            SendMessage(hEdit, EM_SETREADONLY, FALSE, 0); // Enable text field for edit
            SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)szTextDisplay);
            Bin2Txt();
            SetWindowTextA(hEdit, NULL);            // Init-clear the Text Field
            SetWindowTextA(hEdit, pszCryptFileDisplay); // Change ANSI-text within specified text field
            }
          ShowWinMouseClick(hButtonDelim, 1, 0, 0); // Simulate Mouseclick to fix strange behaviour of hButtonHex ODS_FOCUS?  
          break;

        // Button: Key input Dialog
        case ID_DIALOG_KEY:
          SetWindowText(hMain, szSignonTitle);      // Display signon-text in mainwindow's title field

          // Compare the positions MouseClick and Button Hex/Txt
          // If the MouseClick {x;y} are not within the button's rectancle {bottom;right}
          //  then the Mouseclick was a simulated click-event. 
          //  Simulated mouse click-events may not cause any action, but are necessary  
          //  to pop up and show the button images being over-painted by 'CreateGradientBrush'. 
          GetWindowRect(hButtonKey, &rcButton);
          GetCursorPos(&pMouse);
          if ((abs(rcButton.left - pMouse.x) > BUTTON_WIDTH  && KeyboardEntry != VK_RETURN) ||
              (abs(rcButton.top  - pMouse.y) > BUTTON_HEIGHT && KeyboardEntry != VK_RETURN) ||
              (mouseHover == TRUE)) break;
          KeyboardEntry = FALSE;

          if (dwKeyFileSize > 0)    // Key loaded from file?
            {
            DispayKeyFileHex(_hwnd, szKeyFileIn, 0);
            SetWindowText(_hwnd, szKeyFileName);    // Display filename in mainwindow's title field
            break;
            }

          for (k=0; k<KEY_SIZE_MAX; k++)
            szKeyDialogIn[k] =0;   // Init clear key buffer for crypto functions                    

          // No need to bother if there's no text.
          // If the specified window is an edit control, GetWindowTextLength(HWND)
          //  retrieves the length of the text within the control.
          dwTextLength = GetWindowTextLength(hKeyTextBox); // Get text length
          if (dwTextLength > 0)                            // Any Text at all?
            {
            gwtstat = GetWindowTextA(hKeyTextBox, (LPSTR)szKeyDialogIn, TYPED_KEY_SIZE_MAX+1);   // +1 = NULL-Terminator
            DispayKeyDialogHex(_hwnd, (LPSTR)szKeyDialogIn, 0); // Key-mode: SendDlgItemMessage 1
            }
          else
            {
            SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)szKeySaved);
            DispayKeyDialogHex(_hwnd, (LPSTR)szKeyDialogIn, 0); // Key-mode: SendDlgItemMessage 1 (Needed.)
            // Optional: Overwrite zero key hex display with a default key warning message
            SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)szKeyNull); 
            }
          SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)pszTextKeySaved);
          InitCryptoKeyFromDialog(0);                           // Key-mode: convert for crypto functions
          break;

        // Button: IV input Dialog
        case ID_DIALOG_IV:
          SetWindowText(hMain, szSignonTitle);        // Display signon-text in mainwindow's title field
         
          // Compare the positions MouseClick and Button Hex/Txt
          // If the MouseClick {x;y} are not within the button's rectancle {bottom;right}
          //  then the Mouseclick was a simulated click-event. 
          //  Simulated mouse click-events may not cause any action, but are necessary  
          //  to pop up and show the button images being over-painted by 'CreateGradientBrush'. 
          GetWindowRect(hButtonIV, &rcButton);
          GetCursorPos(&pMouse);
          if ((abs(rcButton.left - pMouse.x) > BUTTON_WIDTH  && KeyboardEntry != VK_RETURN) ||
              (abs(rcButton.top  - pMouse.y) > BUTTON_HEIGHT && KeyboardEntry != VK_RETURN) ||
              (mouseHover == TRUE)) break;
          KeyboardEntry = FALSE;

          if (dwIvFileSize > 0)    // IV loaded from file?
            {
            DispayKeyFileHex(_hwnd, szIvFileIn, 1);
            SetWindowText(_hwnd, szIcvFileName);      // Display filename in mainwindow's title field
            break;
            }

          for (k=0; k<AES_BLOCK_SIZE; k++)  // AES-IV = max size
            szIcvDialogIn[k] =0;            // Init clear IV                    

          // No need to bother if there's no text.
          // If the specified window is an edit control, GetWindowTextLength(HWND)
          //  retrieves the length of the text within the control.
          dwTextLength = GetWindowTextLength(hIvTextBox);
          if (dwTextLength > 0)   // Any Text at all?
            {
            gwtstat = GetWindowTextA(hIvTextBox, (LPSTR)szIcvDialogIn, AES_BLOCK_SIZE+1);  // +1 = NULL-Terminator
            DispayKeyDialogHex(_hwnd, (LPSTR)szIcvDialogIn, 1); // IV-mode: SendDlgItemMessage 1
            }
          else
            {
            SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)szIvSaved);
            DispayKeyDialogHex(_hwnd, (LPSTR)szIcvDialogIn, 1); // Icv-mode: SendDlgItemMessage 1
            }
          SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)szIvSaved);
          InitCryptoKeyFromDialog(1);                           // IV-mode: convert for crypto functions
          break;

        // Context menu choices
        case ID_HIDEKEY:
          if (FileProcessingMode == FILEMODE_TEXT    ||
              FileProcessingMode == FILEMODE_TEXTNEW ||
              FileProcessingMode == CRYPT_NONE) break;
          SendMessage(hKeyTextBox, EM_SETPASSWORDCHAR, (WPARAM)_T('*'), 0);
        ShowWinMouseClick(hKeyTextBox, 1, 0, 0);    // Simulate Mouseclick to make button & dialog appear
        ShowWinMouseClick(hButtonKey,  1, 0, 0);    // Simulate Mouseclick to make button & dialog appear
          RedrawWindow(hTool, &rcToolbar, 0, RDW_ERASE | RDW_INVALIDATE); // Update dialog display (WWIN10 & XP=OK) 
          keyDisplayMode = MF_UNCHECKED;
          // Clean up statusbar from 'paint'
          PaintColoredStatusMsg(szStatusClear);
          SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); 
          if (activeProgbar == FALSE) SendMessage(hStatusbar, SB_SETTEXT, 1, (LPARAM)_T("")); 
          SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)szKeySaved);
          break;

        case ID_SHOWKEY:
          if (FileProcessingMode == FILEMODE_TEXT    ||
              FileProcessingMode == FILEMODE_TEXTNEW ||
              FileProcessingMode == CRYPT_NONE) break;
          SendMessage(hKeyTextBox, EM_SETPASSWORDCHAR, 0, 0);
        ShowWinMouseClick(hKeyTextBox, 1, 0, 0);    // Simulate Mouseclick to make button & dialog appear
        ShowWinMouseClick(hButtonKey,  1, 0, 0);    // Simulate Mouseclick to make button & dialog appear
          RedrawWindow(hTool, &rcToolbar, 0, RDW_ERASE | RDW_INVALIDATE); // Update dialog display (WWIN10 & XP=OK)
          keyDisplayMode = MF_CHECKED;
          if (activeProgbar == FALSE)
            {
            if (dwKeyFileSize > 0)     // Key loaded from file?
              {
              DispayKeyFileHex(_hwnd, szKeyFileIn, 0);
              break;
              }
            DispayKeyDialogHex(_hwnd, (LPSTR)szKeyDialogIn, 0);  // Key-mode: SendDlgItemMessage 0
            SendDlgItemMessage(_hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 0, (LPARAM)szKeySaved);
            }
          break;

        case ID_FANCYTOOLBAR_TOGGLE:
          fancyToolbar ^= MF_CHECKED; // Toggle toolbar design

#ifdef THEME // Change THEME of toolbar under runtime                
          if (fancyToolbar == MF_CHECKED)
            SetWindowTheme(hTool, L"", L"");          // Standard THEME
          else
            SetWindowTheme(hTool, L"Explorer", NULL); // Explorer THEME
#endif                                              
          // Get toolbar rectangle metrics and redraw toolbar
          GetClientRect(hTool, &rcToolbar);
          RedrawWindow(hTool, &rcToolbar, 0, RDW_ERASE | RDW_INVALIDATE);
          break;

        case ID_ESC_ABORT_NOQUERY:
          _escAbortNoQuery ^= MF_CHECKED;
          return 0;
          break;

        case ID_CRYPTO_MFRESULT_BROWSER:
          _multiFileBrowserFlag ^= MF_CHECKED;
          return 0;
          break;

        case ID_CRYPTO_TOGGLE_TEXTEDIT:
          AesEncryptEditedText(ENCRYPT);
          break;
        case ID_CRYPTO_TEST_TEXTEDIT:
          CryptoTestEditedText(ENCRYPT);          
          break;

        case ID_ASCHEX2BIN_TEXTEDIT:
          AscHex2BinEditedText();
          break;

        // Keyfile/IV-file Menu selections
        case ID_KEYFILE_OPEN:
          DoKeyFileOpen(_hwnd, 0);
          break;
        case ID_IVFILE_OPEN:
          DoKeyFileOpen(_hwnd, 1);
          break;

        case ID_CONSOLE_HEDIT_FILEOPEN:  // 'DOS Hedit filename'
        case ID_CONSOLE_HEDIT:           // 'DOS Hedit /?'
        case ID_CONSOLE_HEDIT_CRYPT:     // 'DOS Hedit crypto cmdline'
          // Check integrity  of console application
          if (ConsoleHeditExeVerify() == FALSE) break;
          // Try to rename the file HEDIT.TMP to check if it's used already by HEDIT.EXE
          if (_wrename(heditTmp, heditTmp) != 0 && GetLastError() == ERROR_SHARING_VIOLATION)
            {
            StringCbPrintf(_tDebugBuf, _tDebugbufSize, _T("HEDIT.EXE is already running by another process."));
            CBTCustomMessageBox(NULL, _tDebugBuf, _T(" haCrypt Console DOS HEDIT"), MB_OK, IDI_HACRYPT_ICON);
            break;
            }
          else DeleteFile(heditTmp);     // Delete a possible 'HEDIT.TMP' (no matter if it exists or not)
          CreateConsole(LOWORD(wParam)); // Invoke HEDIT console
          PostQuitMessage(0);            // Exit haCrypt
          break;

        //--------------------------------------------------------------------------
        //
        //                          Help Dialog Boxes
        // Quick instructions 
        case ID_HELP_ABOUT_QUICK:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_QUICK), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;
        case ID_HELP_ABOUT_AESQUICK:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_AESQUICK), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;
        case ID_HELP_ABOUT_RSAQUICK:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_RSAQUICK),  _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;
        
        // Usage
        case ID_HELP_ABOUT_RSA:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_RSA), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;
        case ID_HELP_ABOUT_DES:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_DES), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;
        case ID_HELP_ABOUT_TDES:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_TDES),_hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;
        case ID_HELP_ABOUT_AES:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_AES), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;
        case ID_HELP_ABOUT_CIPH_STEALING:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_CIPH_STEALING), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;
        case ID_HELP_ABOUT_PADDING_ISO:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_PADDING_ISO), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;
        case ID_HELP_ABOUT_PADDING_PKCS:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_PADDING_PKCS),  _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;
        case ID_HELP_ABOUT_MAC:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_MAC), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;
        case ID_HELP_ABOUT_CONSOLE:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_CONSOLE), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;

        // Multiple files
        case ID_HELP_ABOUT_MULTIFILE:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_MULTIFILE), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;

        // Keyfile
        case ID_HELP_ABOUT_KEYFILE:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_KEYFILE), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;

        // Text-field
        case ID_HELP_ABOUT_TEXTFIELD:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_TEXTFIELD), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;

        // Test
        case ID_HELP_ABOUT_TEST:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_TEST),  _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;

        // Version
        case ID_HELP_ABOUT_VERSION:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT_VERSION), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;

        // About
        case ID_HELP_ABOUT:
          _val = DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ABOUT), _hwnd, AboutDlgProc);
          if (_val == _ERR) MessageBox(_hwnd, szDialogFail, szError, MB_ICONERROR | MB_OK);
          break;

        // File Menu 
        case ID_FILE_EXIT:
          FileProcessingMode = FILEMODE_TEXT;
          GlobalFree(pszTextFileIn);          // Exit App: Free allocated memory
          GlobalFree(pszCryptFileIn);           
          GlobalFree(pszCryptFileDisplay);
          PostMessage(_hwnd, WM_CLOSE, 0, 0);
          break;

        case ID_FILE_TEXT_RENAME:
          DoFileRename();
          break;

        //case ID_FILE_TEXT_COPY:         // Deprecated
        //  break;

        case ID_FILE_TEXT_NEW:
          // Alert user that all edited text will be lost
          if (        
              (FileProcessingMode == FILEMODE_TEXTNEW ||
              FileProcessingMode == FILEMODE_TEXT)    &&
              _testMode == FALSE                      &&
              GetWindowTextLength(hEdit) > 0          &&
              CBTMessageBox(NULL, _T("All text will be lost!\nDo you want to clear the text field?"),
                                  _T(" /TEXT - Clearing text field"),
                                  MB_YESNO | MB_ICONWARNING) == IDNO
             )
            {
            PaintColoredStatusMsg(szStatusClear);                        // Clean up statusbar from 'paint'
            if (GetWindowTextLength(hEdit) > EDIT_TEXT_MAXSIZE)
              SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/TEXT (read only)"));
            else SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)_T("/TEXT")); // Show string
            SendMessage(hEdit, EM_SETREADONLY, FALSE, 0);                // Enable text field for edit
            break;                                                       // Keep text field untouched
            } // end if

          FileProcessingMode = FILEMODE_TEXTNEW;     // Set /TEXT
          ToolProcessingMode = FileProcessingMode;   // Save active button
          dwCryptFileSize = 0;                       //ha// Invalidate any pending crypto data
          UpdateButtons();                     
          // Display signon-text in mainwindow's title field
          SetWindowText(_hwnd, szSignonTitle); 
          ControlFileMenu(MF_ENABLED);
          CtrlHideShowWindow(hButtonHex, SW_HIDE);   // Hex not allowed
          ControlCryptoToolItems(MF_ENABLED, FALSE);
          break;
        case ID_FILE_TEXT_OPEN:
          FileProcessingMode = FILEMODE_TEXT;        // Set /TEXT
          ToolProcessingMode = FileProcessingMode;   // Save active button
          UpdateButtons();                                    
          ControlCryptoToolItems(MF_ENABLED, FALSE);
          DoTxtFileOpen(_hwnd);
          ControlFileMenu(MF_ENABLED);
          ShowWinMouseClick(hButtonDelim, 1, 0, 0);  // Simulate Mouseclick to fix strange behaviour of ID_FILE_TEXT_NEW ?  
          ControlCryptoToolItems(MF_ENABLED, FALSE);
          FileProcessingMode = FILEMODE_TEXTNEW;     // Default is edit field window
          break;
        case ID_FILE_TEXT_SAVEAS:                    // .. allow saving crypto hex/txt field
          PaintColoredStatusMsg(szStatusClear);
          SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); 
          DoTxtFileSave(_hwnd);                             
          ShowWinMouseClick(hButtonDelim, 1, 0, 0);  // Simulate Mouseclick to fix strange behaviour of ID_FILE_TEXT_NEW ?  
          break;

        //case WM_ACTIVATE:
        //  ControlFileMenu(MF_ENABLED);  // Initially done in *.rc 'GRAYED'
        //  break;

        // Crypto Menu: DES
        case ID_CRYPTO_DES_ENCRYPT:         
        case ID_CRYPTO_DES_ECBENCRYPT:      
        case ID_CRYPTO_DES_ECBE:      
        case ID_CRYPTO_DES_CBCE:      
        case ID_CRYPTO_DES_ECBE_PKCS:     
        case ID_CRYPTO_DES_CBCE_PKCS:     
        case ID_CRYPTO_DES_MAC:     
        // Crypto Menu: 3DES
        case ID_CRYPTO_TDES_ENCRYPT:          
        case ID_CRYPTO_TDES_ECBENCRYPT:     
        case ID_CRYPTO_TDES_ECBE:     
        case ID_CRYPTO_TDES_CBCE:     
        case ID_CRYPTO_TDES_ECBE_PKCS:      
        case ID_CRYPTO_TDES_CBCE_PKCS:      
        case ID_CRYPTO_TDES_MAC:      
        // Crypto Menu: AES
        case ID_CRYPTO_AES_ENCRYPT:         
        case ID_CRYPTO_AES_ECBENCRYPT:          
        case ID_CRYPTO_AES_ECBE:      
        case ID_CRYPTO_AES_CBCE:      
        case ID_CRYPTO_AES_ECBE_PKCS:     
        case ID_CRYPTO_AES_CBCE_PKCS:     
        case ID_CRYPTO_AES_MAC:                // Button = Enable info in statusbar
          if (_cryptMenuFlag == ID_TOOLBAR_CRYPT_CONTINUE) _cryptMenuFlag = FALSE;
          else _cryptMenuFlag = TRUE;          // Menu = Disable info in statusbar    
          if (UpdateButtons() == FALSE || _testContextFlag == TRUE)
            {
            _testContextFlag = WM_CONTEXTMENU; // Skip if in TEST-MODE (allows easy retry)
            break;                             
            }         
          if (DoBinFileOpen(_hwnd, ENCRYPT) == TRUE) 
            goto caseSaveAs;                   // Allow direct "Save as..."
          break;

        // Crypto Menu: DES
        case ID_CRYPTO_DES_DECIPHER:        
        case ID_CRYPTO_DES_ECBDECIPHER:     
        case ID_CRYPTO_DES_ECBD:      
        case ID_CRYPTO_DES_CBCD:      
        case ID_CRYPTO_DES_ECBD_PKCS:     
        case ID_CRYPTO_DES_CBCD_PKCS:     
        // Crypto Menu: 3DES
        case ID_CRYPTO_TDES_DECIPHER:       
        case ID_CRYPTO_TDES_ECBDECIPHER:      
        case ID_CRYPTO_TDES_ECBD:     
        case ID_CRYPTO_TDES_CBCD:     
        case ID_CRYPTO_TDES_ECBD_PKCS:      
        case ID_CRYPTO_TDES_CBCD_PKCS:      
        // Crypto Menu: AES
        case ID_CRYPTO_AES_DECIPHER:        
        case ID_CRYPTO_AES_ECBDECIPHER:       
        case ID_CRYPTO_AES_ECBD:      
        case ID_CRYPTO_AES_CBCD:      
        case ID_CRYPTO_AES_ECBD_PKCS:     
        case ID_CRYPTO_AES_CBCD_PKCS:          // Button = Enable info in statusbar
          if (_cryptMenuFlag == ID_TOOLBAR_CRYPT_CONTINUE) _cryptMenuFlag = FALSE;
          else _cryptMenuFlag = TRUE;          // Menu = Disable info in statusbar
          if (UpdateButtons() == FALSE || _testContextFlag == TRUE)
            {
            _testContextFlag = WM_CONTEXTMENU; // Skip if in TEST-MODE (allows easy retry)
            break;                             
            }         
          if (DoBinFileOpen(_hwnd, DECIPHER) == TRUE) 
            goto caseSaveAs;                   // Allow direct "Save as..."
          break;                          

        // Crypto Menu: RSA
        case ID_CRYPTO_RSA_GENERATE_KEYS:     // Also saves the RSA key pair 
          if (UpdateButtons() == FALSE) break;         
          WindowsDoAlgorithmRSA();    
          break;                          
        case ID_CRYPTO_RSA_PUTPUBLIC_KEY:     // Deprecated     
        case ID_CRYPTO_RSA_PUTPRIVATE_KEY:    // Deprecated
          break;                              // Deprecated
        case ID_CRYPTO_RSA_GETPUBLIC_KEY:
          if (UpdateButtons() == FALSE) break;         
          DoRsaLoadKey(_hwnd, RSA_MODE_PUBKEYE);
          break;          
        case ID_CRYPTO_RSA_GETPRIVATE_KEY:
          if (UpdateButtons() == FALSE) break;         
          DoRsaLoadKey(_hwnd, RSA_MODE_PRVKEYD);
          break;          
        case ID_CRYPTO_RSA_ENCRYPT:
          if (UpdateButtons() == FALSE) break;         
          DoRsaEncrypt(_hwnd);
          break;          
        case ID_CRYPTO_RSA_DECIPHER:
          if (UpdateButtons() == FALSE) break;         
          DoRsaDecipher(_hwnd);
          break;
        case ID_CRYPTO_RSA_GEN_RNDKEY128:
          if (UpdateButtons() == FALSE) break;         
          DoRsaGenRandomKey(_hwnd, 128);      // 128 bit
          break;                            
        case ID_CRYPTO_RSA_GEN_RNDKEY256:
          if (UpdateButtons() == FALSE) break;         
          DoRsaGenRandomKey(_hwnd, 256);      // 256 bit
          break;                            

        // Toolbar icon selection buttons 'DES, AES, 3DES'
        case ID_TOOLBAR_DES:
          _cryptMenuFlag = FALSE;                      // Enable info in statusbar
          FileProcessingMode = CRYPT_DES | CRYPT_ECB;
          ToolProcessingMode = FileProcessingMode;     // Save active button
          ControlCryptoToolItems(MF_ENABLED, TRUE);
          toolButtonFlag = TRUE;                       // Force status message 'szStatusInfoECB/CBC'
          UpdateButtons();
          break;                          
        case ID_TOOLBAR_AES:          
          _cryptMenuFlag = FALSE;                      // Enable info in statusbar
          FileProcessingMode = CRYPT_AES | CRYPT_CBC;
          ToolProcessingMode = FileProcessingMode;     // Save active button
          ControlCryptoToolItems(MF_ENABLED, TRUE);
          toolButtonFlag = TRUE;                       // Force status message 'szStatusInfoECB/CBC'
          UpdateButtons();
          break;                          
        case ID_TOOLBAR_TDES:         
          _cryptMenuFlag = FALSE;                      // Enable info in statusbar
          FileProcessingMode = CRYPT_TDES | CRYPT_CBC;
          ToolProcessingMode = FileProcessingMode;     // Save active button
          ControlCryptoToolItems(MF_ENABLED, TRUE);
          toolButtonFlag = TRUE;                       // Force status message 'szStatusInfoECB/CBC'
          UpdateButtons();
          break;                          

        // Toolbar icon push button '/Encrypt'
        case ID_TOOLBAR_ENCRYPT:      
          _cryptMenuFlag = FALSE;                      // Enable info in statusbar
            FileProcessingMode = ToolProcessingMode;   // Correlate to active button    
          if (UpdateButtons() == FALSE) break;
          DoBinFileOpen(_hwnd, ENCRYPT); 
          break;                          

        // Toolbar icon push button  '/Decipher'
        case ID_TOOLBAR_DECIPHER:
          _cryptMenuFlag = FALSE;                      // Enable info in statusbar
            FileProcessingMode = ToolProcessingMode;   // Correlate to active button    
          if (UpdateButtons() == FALSE) break;
          DoBinFileOpen(_hwnd, DECIPHER); 
          break;                          

        // Toolbar icon push button '/MAC'
        case ID_TOOLBAR_MAC:
          _cryptMenuFlag = FALSE;                      // Enable info in statusbar
          FileProcessingMode = (ToolProcessingMode & ~CRYPT_ECB) | CRYPT_MAC; // Correlate to active button    
          if (UpdateButtons() == FALSE) break;
          DoBinFileOpen(_hwnd, ENCRYPT); 
          break;
                                    
        // Crypto Menu item / Toolbar icon push button: 'Save encrypted/deciphered data' (all modes)
        case ID_FILE_CRYPT_SAVEAS:                     // ToolTip button;
        case ID_FILE_CRYPT_DES_SAVEAS:                 // Menu items
        case ID_FILE_CRYPT_AES_SAVEAS:
        case ID_FILE_CRYPT_TDES_SAVEAS:
//---------
caseSaveAs:  // GOTO Label (the easiest solution at this point)
//---------
          if (FileProcessingMode == FILEMODE_TEXT    ||            
              FileProcessingMode == FILEMODE_TEXTNEW ||
              FileProcessingMode == CRYPT_NONE) break; // No Cryptfile to store       
          PaintColoredStatusMsg(szStatusClear);
          SendMessage(hStatusbar, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT); 
          DoBinFileSave(_hwnd);           
          break;                          

        // Toolbar icon push button (recoursive)
        case ID_TOOLBAR_CRYPT_CONTINUE:
          _cryptMenuFlag = ID_TOOLBAR_CRYPT_CONTINUE;  // Force info in statusbar
          DoCryptAlgoContinue(_hwnd);                  // Continue w/ last used crypto mode 
          break;                          
        } // end switch
      break; // end case WM_COMMAND:

    default:
      return DefWindowProc(_hwnd, msg, wParam, lParam);
    } // end switch(msg)

  UpdateWindow(_hwnd);
  return 0;
  } // WndProc

//-----------------------------------------------------------------------------
//
//                       SetUpWindowClass
//
// Remove window structure from WinMain and put into function
//
bool SetUpWindowClass()
  {
  // Setup the Window structure
  WNDCLASSEX wcex;                          // Structure for the window class
  wcex.cbSize        = sizeof(WNDCLASSEX);  // This structure's size
  wcex.style         = 0;                   // Additional elements of the window class
  wcex.lpfnWndProc   = WndProc;             // Behavior of the window. See "LRESULT CALLBACK WndProc" function
  wcex.cbClsExtra    = 0;                   // No extra bytes after the window class
  wcex.cbWndExtra    = 0;                   // Structure for the window instance
  wcex.hInstance     = GetModuleHandle(NULL);              // Handle to the application instance.
  wcex.hIcon         = (HICON)LoadImage(GetModuleHandle(NULL),
                        MAKEINTRESOURCE(IDI_HACRYPT_ICON), // Custom icon (if NULL, system provides a default icon.)
                        IMAGE_ICON, 16, 16, 0);            // Default icon: wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION)
  wcex.hCursor       = LoadCursor(NULL, IDC_ARROW);        // Handle to cursor class
  wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);           // Add color as the background of the window
  wcex.lpszMenuName  = MAKEINTRESOURCE(IDR_MAINMENU);      // Menu
  wcex.lpszClassName = (LPCWSTR)szWindowClass;             // String that identifies the window class
  wcex.hIconSm       = (HICON)LoadImage(GetModuleHandle(NULL),
                        MAKEINTRESOURCE(IDI_HACRYPT_ICON), // Custom icon (if NULL, system provides a default icon.)
                        IMAGE_ICON, 16, 16, 0);            // Default icon: wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION)

  // Register the window class, and if it fails quit the program 
  if (!RegisterClassEx(&wcex))
    {
    MessageBox(NULL, szRegistrationFail, szError, MB_ICONEXCLAMATION | MB_OK);
    return FALSE;    // Failure, error return.
    }
  else return TRUE;  // Registration succeded.
  } // SetUpWindowClass


//-----------------------------------------------------------------------------
//--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort
//--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort
//
//                           CheckEscape
//
// Thread function.
//   Esc will be handled always in another thread.
//   Immediate exit can be undesirable on some cases.
//
DWORD WINAPI CheckEscape(LPVOID lpParam)   // Thread function
  {
  _escFlag = FALSE; // Initialization 
  while (1)
    {
    // Waste some time, and continue waiting for ESC-key pressed
    while (GetAsyncKeyState(VK_ESCAPE) == 0) Sleep(100);

    // Indicate the outside world that the ESC-key has been pressed. 
    _escFlag = TRUE;
    //while (GetAsyncKeyState(VK_ESCAPE) != 0) ;  // Not needed
    } // endless while (1)
  return 0;    // Dummy return (never executed)
  } // CheckEscape

//-----------------------------------------------------------------------------
//
//                           CheckEscapeAbort
//
// Here we allow to abort time consuming operations by pressing the ESC key.
// Used this to interrupt the progressbar when reading very lengthy files,
// and allow to abort the process while resuming the program.
//
BOOL CheckEscapeAbort()
  {
  if (_escFlag == TRUE)        // Asynchronuous event via thread function
    {
    DoEvents();                // Necessary for some obscure reason
    if (_escAbortNoQuery == MF_UNCHECKED)
      DialogBox(g_hInst, MAKEINTRESOURCE(IDD_HACRYPT_ESC), hMain, DialogProcMultiFile);
    else _valAQ = A_YES;       // Abort current file read without query popup

    if (_valAQ == A_YES)       // _valAQ must be global/extern
      {
      DestroyWindow(hProgBar); // Remove-clear Progressbar  'Loading file'
      activeProgbar = FALSE;   // Progressbar de-activated
      PaintColoredStatusInfoMsg(szEscapeAbort); // Display "ESC Abort" message
      _escAbort = TRUE;
      return(TRUE);            // Abort-return
      }
    else
      {
      // Discard all pending ESC (if any) in keybuffer
      while (GetAsyncKeyState(VK_ESCAPE) != 0) ;
      _escFlag = FALSE;        // Reset any pending ESC-Abort condition
      _escAbort = FALSE;
      return(FALSE);           // Continue-return
      }
    } // end if (_escFlag)

  else return(FALSE);          // Continue-return
  } // CheckEscapeAbort
//
//--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort
//--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort--ESC Abort
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
//
//                            WinMain
//
int consoleMenuFlag, consoleMenuToggle = FALSE;  // Hedit.EXE surveillance flags

int WINAPI WinMain(
    _In_     HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_     LPSTR     lpCmdLine,
    _In_     int       nCmdShow)

  {
  HWND hwnd;
  MSG msg;

  g_hInst = hInstance; // Save our hInstance global g_.. for later

  // Build the signon string using buffer overun safety
  StringCbCat(szSignonTitle, sizeof(szSignonTitle), BuildVersion);

  //----------------------------------------------------
  // typedef struct tagINITCOMMONCONTROLSEX {           |
  //   DWORD dwSize;                                    |
  //   DWORD dwICC;                                     |
  // } INITCOMMONCONTROLSEX, *LPINITCOMMONCONTROLSEX;   |
  // Syntax:                                            |
  // BOOL InitCommonControlsEx(                         |
  //  const INITCOMMONCONTROLSEX *picce);               |
  //                                                    |
  //INITCOMMONCONTROLSEX iccex;                       //|
  //iccex.dwICC  = ICC_WIN95_CLASSES;                 //|
  //iccex.dwSize = sizeof(INITCOMMONCONTROLSEX);      //|
  //InitCommonControlsEx(&iccex);                     //|
  //InitCommonControls(); // Comctl32.dll < V6.0        |
  InitCommonControls();   // VS C++ 2010 compatible     |
  //----------------------------------------------------

  // Registering the Window Class
  // Provided window class registration structure as function
  if (SetUpWindowClass() == FALSE) return (0);

  // Step 2: Creating the Main Window
  // Main Window parameters
  //  szWindowClass: The name of the application
  //  szTitle: The text that appears in the title bar
  //  WS_OVERLAPPEDWINDOW | .. : The type of window to create
  //  CW_USEDEFAULT, CW_USEDEFAULT: Initial position (x, y)
  //  905, 320: Initial size (width, height) Windows XP VS 2010
  //  915, 322: Initial size (width, height) Windows 10 VS 2019
  //  NULL: The parent of this window
  //  NULL: This application does not have a menu bar
  //  hInstance: The first parameter from WinMain
  //  NULL: Not used in this application
  //
  // Disable resizing the window using the following style:
  // Fix Size = '((WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME) & ~WS_MAXIMIZEBOX)'
  hwnd = CreateWindowEx(
    0,          // WS_EX_CLIENTEDGE, Optional window styles. Can be set to 0
    szWindowClass,
    szSignonTitle,
    ((WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME) & ~WS_MAXIMIZEBOX) | WS_CLIPCHILDREN,    
    CW_USEDEFAULT, CW_USEDEFAULT, MAINWINDOW_WIDTH, MAINWINDOW_HEIGHT,
    NULL,
    NULL,
    hInstance,
    NULL);

  if (!hwnd)
    {
    MessageBox(NULL, szCreationFail, szError, MB_ICONEXCLAMATION | MB_OK);
    return 0;
    }
  hMain = hwnd;  // Publish Main hwnd handle for access in subfunctions

  // Make the window visible on the screen
  // The parameters to ShowWindow explained:
  // hWnd: the value returned from CreateWindow
  // nCmdShow: the fourth parameter from WinMain
  ShowWindow(hwnd, nCmdShow);
  UpdateWindow(hwnd);

  // Create a thread for handling the ESC key
  CreateThread(NULL, 0, CheckEscape,NULL, 0, NULL);

  // Get 'heditExe' path (directory of 'haCrypt.exe' where 'hedit.exe' must reside)
  // Initialize console paths and commandline
  GetHomeDirectory();                                       

  // Just to draw a fancy border around the dialog fileds when mouse hovers
  SetWindowSubclass(hKeyTextBox, SubclassprocButton, SUBCLASSBUTTON, 0);
  SetWindowSubclass(hIvTextBox,  SubclassprocButton, SUBCLASSBUTTON, 0);

  // Fancy colored buttons 
  SetWindowSubclass(hButtonHex,  SubclassprocButton, SUBCLASSBUTTON, 0);
  SetWindowSubclass(hButtonKey,  SubclassprocButton, SUBCLASSBUTTON, 0);
  SetWindowSubclass(hButtonIV,   SubclassprocButton, SUBCLASSBUTTON, 0);

  // The Main Message Loop will run until GetMessage() returns 0
  while(GetMessage(&msg, NULL, 0, 0) > 0)                   // Ensure to break also if return = -1
    {
    // Continuously checked. Immediate Response when Hedit.exe is moved/renamed/deleted 
    hMenu = GetMenu(hwnd);                                  // Mainmenu 0, 1, 2, 3, ..
    if (consoleMenuFlag = PathFileExists(heditExe))         // Checking for 'Hedit.exe' file existence
      EnableMenuItem(hMenu, 2, MF_BYPOSITION | MF_ENABLED); // Allow Console Menu
    else
      EnableMenuItem(hMenu, 2, MF_BYPOSITION | MF_GRAYED);  // Disable Console if no Hedit.exe
    if (consoleMenuFlag != consoleMenuToggle)
      {
      DrawMenuBar(hwnd);                                    // Only redraw if file existance changed,
      consoleMenuToggle = consoleMenuFlag;                  //  to prevent flicker on mouse moves. 
      }

    //-----------------------------------------------------------------------------
    //
    // Special keyboard input keycode capturing and handling (ENTER and (Alt+<xxx>)
    //
    // Messages (msg.message) - WM_KEYDOWN, WM_SYSKEYDOWN, WM_SYSKEYUP, WM_CHAR 
    //
    // Example: The combination ALT + P would generate:
    //  WM_SYSKEYDOWN: VK_MENU
    //  WM_SYSKEYDOWN: 0x50
    //  WM_SYSCHAR: 'p'
    //  WM_SYSKEYUP: 0x50
    //  WM_SYSCHAR: VK_MENU
    //
    switch(msg.message)
      {  
      case WM_KEYDOWN:
        // Intercept and handle any key, if pressed while in edit-field
        if (FileProcessingMode != FILEMODE_TEXTNEW)     // If not in /TEXT mode
          SendMessage(hEdit, EM_SETREADONLY, TRUE, 0);  //  global disable text field for edit

        // Intercept and handle the CR <Enter>, no matter which control has focus
        if (msg.wParam == VK_RETURN)
          {
          KeyboardEntry = VK_RETURN;      // Flag that <Enter> key has been pressed 
          //SendDlgItemMessage(hwnd, IDC_MAIN_STATUS, SB_SETTEXT, 1, (LPARAM)_T("KEY = CR captured")); // Test only
          //WndProc(hwnd, WM_COMMAND, MYMSG_DOSOMETHING, 0);                                           // Test only

          // Check which control has Keyboard-focus
          hKeyboard = GetFocus();         // Get the handle of the input field where Enter-key was pressed
          if (hKeyboard == hIvTextBox)    // Check if user focused on IV
            {                             
            dwIvFileSize = 0;             // Clear any IV-file input
            PostMessage(hwnd, WM_COMMAND, ID_DIALOG_IV, 0);    // Perform the appropriate command
            }
          if (hKeyboard == hKeyTextBox)   // Check if user focused on Key                     
            {
            dwKeyFileSize = 0;            // Clear any Keyfile input
            PostMessage(hwnd, WM_COMMAND, ID_DIALOG_KEY, 0);   // Perform the appropriate command
            }
          }

        else if (msg.wParam == VK_ESCAPE) // Not Implemented -- TEST ONLY -- TEST ONLY -- TEST ONLY
          // ESCAPE: Abort current Operation - Default button focus is MB_DEFBUTTON2 ('Cancel')'
          PostMessage(hwnd, WM_COMMAND, ID_KEYBOARD_ESC, 0); // Perform the appropriate command
        break; // end case WM_KEYDOWN

      case WM_KEYUP:
        break;

      // The virtual-key code for the <Alt>-key is named VK_MENU for historical reasons.                       
      case WM_SYSKEYDOWN:
        // Alt+<xxx> pressed on keypad
        break;

      case WM_SYSKEYUP:
//ha//        {
//ha////------------------------------------------
//ha//int LeftAltKeyDown=0, SyskeyCharCode; // Not Implemented ...
//ha//int altCharCount=0;
//ha//TCHAR altchar[3];
//ha//TCHAR altCharDec;
//ha//TCHAR _keypadBuf[KEY_SIZE_MAX];      // Keypad buffer (max key length for AES = 256 bits)
//ha//int kj=0, ki=0;;                     // Keypad buf index
//ha////------------------------------------------
//ha//        if (msg.wParam == VK_MENU) break;
//ha//        if (altCharCount == 0) altchar[0] = (TCHAR)msg.wParam;
//ha//        if (altCharCount == 1) altchar[1] = (TCHAR)msg.wParam;
//ha//        if (altCharCount == 2) altchar[2] = (TCHAR)msg.wParam;
//ha//        altCharCount++;
//ha//        if (altCharCount == 3)
//ha//          { 
//ha//          altCharDec = (((altchar[0] & 0x0F)*10) + (altchar[1] & 0x0F))*10 + (altchar[2] & 0x0F);
//ha//          if (altCharDec > 255) altCharDec = 255;
//ha//          altCharCount = 0;
//ha//          altchar[0] =0;      
//ha//          altchar[1] =0;  
//ha//          altchar[2] =0;
//ha//          }
        break;

      case WM_CHAR:                        // Normal keys (= NULL prefix)
//ha//        if (LeftAltKeyDown == 1)
//ha//          { 
//ha//          msg.wParam = '*';
//ha//          _keypadBuf[ki++] = altCharDec;
//ha//          LeftAltKeyDown = 0;
//ha//          }
//ha//        else ki++;  
        break;

      case WM_SYSCHAR:
        break;
      } // end switch(msg.message)

    //-------------------------------------------------------------------------
    //
    //                      Windows Message Dispatcher
    //
    // if (!IsDialogMessage(hDlgFileExist, &msg))  // For Modeless Dialog only
    //
      {
      TranslateMessage(&msg); // Translate virtual-key messages into character messages
      DispatchMessage(&msg);  // Send message to WindowProcedure
      }
    } // end while

  return (int)msg.wParam;
  } // WinMain

//-----------------------------------------------------------------------------

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//MessageBoxA(NULL, "STOP", "STOP 1", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "rcButton.left = %d, pMouse.x = %d\nKeyboardEntry = %08X\nrcButton.left - pMouse.x = %d [BUTTON_WIDTH = %d]\npMouse.x - rcButton.left = %d",
//ha//        rcButton.left, pMouse.x, KeyboardEntry,rcButton.left - pMouse.x,BUTTON_WIDTH,pMouse.x - rcButton.left);
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG stop A", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(__DebugBuf, "%08X %08X %08X %08X %08X %08X %08X %08X ",
//ha//                  (UINT)szKeyDialogIn[0],(UINT)szKeyDialogIn[1],(UINT)szKeyDialogIn[2],(UINT)szKeyDialogIn[3],
//ha//                  (UINT)szKeyDialogIn[4],(UINT)szKeyDialogIn[5],(UINT)szKeyDialogIn[6],(UINT)szKeyDialogIn[7]); 
//ha//MessageBoxA(NULL, __DebugBuf, "DEBUG szKeyDialogIn 2", MB_OK);
//ha////MessageBoxA(NULL, szKeyDialogIn, "DEBUG DES ECB _keybuf", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
//ha//                  (UCHAR)asciiIcvblock[0],(UCHAR)asciiIcvblock[1],
//ha//                  (UCHAR)asciiIcvblock[2],(UCHAR)asciiIcvblock[3],
//ha//                  (UCHAR)asciiIcvblock[4],(UCHAR)asciiIcvblock[5],
//ha//                  (UCHAR)asciiIcvblock[6],(UCHAR)asciiIcvblock[7], 
//ha//                  (UCHAR)asciiIcvblock[8],(UCHAR)asciiIcvblock[9],
//ha//                  (UCHAR)asciiIcvblock[10],(UCHAR)asciiIcvblock[11],
//ha//                  (UCHAR)asciiIcvblock[12],(UCHAR)asciiIcvblock[13],
//ha//                  (UCHAR)asciiIcvblock[14],(UCHAR)asciiIcvblock[15]); 
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG DES ECB asciiIcvblock", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "%X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X ",
//ha//                  _uniBlock[0], _uniBlock[1], _uniBlock[2], _uniBlock[3],
//ha//                  _uniBlock[4], _uniBlock[5], (UCHAR)_uniBlock[6], (UCHAR)_uniBlock[7], 
//ha//                  _uniBlock[8], _uniBlock[9], _uniBlock[10],_uniBlock[11], 
//ha//                  _uniBlock[12],_uniBlock[13],_uniBlock[14],_uniBlock[15]); 
//ha//MessageBoxA(NULL, DebugBuf, "DEBUG DES ECB szKeyTextSaved", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "szKeyDialogIn[ 0]= %08X %08X %08X %08X\nszKeyDialogIn[ 4]= %08X %08X %08X %08X\n"
//ha//                  "szKeyDialogIn[ 8]= %08X %08X %08X %08X\nszKeyDialogIn[12]= %08X %08X %08X %08X\n"
//ha//                  "szKeyDialogIn[16]= %08X %08X %08X %08X\nszKeyDialogIn[20]= %08X %08X %08X %08X\n"
//ha//                  "szKeyDialogIn[23]= %08X %08X %08X %08X\nszKeyDialogIn[28]= %08X %08X %08X %08X\n"
//ha//                  "szKeyDialogIn=%s",
//ha//                 (UINT)szKeyDialogIn[0],  (UINT)szKeyDialogIn[1], 
//ha//                 (UINT)szKeyDialogIn[2],  (UINT)szKeyDialogIn[3],
//ha//                 (UINT)szKeyDialogIn[4],  (UINT)szKeyDialogIn[5], 
//ha//                 (UINT)szKeyDialogIn[6],  (UINT)szKeyDialogIn[7],
//ha//                 (UINT)szKeyDialogIn[8],  (UINT)szKeyDialogIn[9], 
//ha//                 (UINT)szKeyDialogIn[10], (UINT)szKeyDialogIn[11],
//ha//                 (UINT)szKeyDialogIn[12], (UINT)szKeyDialogIn[13],
//ha//                 (UINT)szKeyDialogIn[14], (UINT)szKeyDialogIn[15],
//ha//                 (UINT)szKeyDialogIn[16], (UINT)szKeyDialogIn[17], 
//ha//                 (UINT)szKeyDialogIn[18], (UINT)szKeyDialogIn[19],
//ha//                 (UINT)szKeyDialogIn[20], (UINT)szKeyDialogIn[21], 
//ha//                 (UINT)szKeyDialogIn[22], (UINT)szKeyDialogIn[23],
//ha//                 (UINT)szKeyDialogIn[24], (UINT)szKeyDialogIn[25], 
//ha//                 (UINT)szKeyDialogIn[26], (UINT)szKeyDialogIn[27],
//ha//                 (UINT)szKeyDialogIn[28], (UINT)szKeyDialogIn[29],
//ha//                 (UINT)szKeyDialogIn[30], (UINT)szKeyDialogIn[31], (char *)&szKeyDialogIn[0]);
//ha//MessageBoxA(NULL, DebugBuf, "haCryptMain- InitCryptoKeyFromDialog (2)", MB_OK); // Show MAC bytes
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//
//ha//  for (k=0; k<KEY_SIZE_MAX; k++) DebugBuf[k] = 0;
//ha//  for (k=0; k<KEY_SIZE_MAX; k++) KeyDialog_In[k] = 0;
//ha//
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf,"%s", (char *)&szKeyDialogIn[0]);
//ha//MessageBoxA(NULL, DebugBuf, "haCryptMain- InitCryptoKeyFromDialog (3)", MB_OK); // Show MAC bytes
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "KeyDialog_In[ 0]= %08X %08X %08X %08X\nKeyDialog_In[ 4]= %08X %08X %08X %08X\n"
//ha//                  "KeyDialog_In[ 8]= %08X %08X %08X %08X\nKeyDialog_In[12]= %08X %08X %08X %08X\n"
//ha//                  "KeyDialog_In[16]= %08X %08X %08X %08X\nKeyDialog_In[20]= %08X %08X %08X %08X\n"
//ha//                  "KeyDialog_In[23]= %08X %08X %08X %08X\nKeyDialog_In[28]= %08X %08X %08X %08X\n"
//ha//                  "KeyDialog_In=%s",
//ha//                 KeyDialog_In[0],  KeyDialog_In[1], 
//ha//                 KeyDialog_In[2],  KeyDialog_In[3],
//ha//                 KeyDialog_In[4],  KeyDialog_In[5], 
//ha//                 KeyDialog_In[6],  KeyDialog_In[7],
//ha//                 KeyDialog_In[8],  KeyDialog_In[9], 
//ha//                 KeyDialog_In[10], KeyDialog_In[11],
//ha//                 KeyDialog_In[12], KeyDialog_In[13],
//ha//                 KeyDialog_In[14], KeyDialog_In[15],
//ha//                 KeyDialog_In[16], KeyDialog_In[17], 
//ha//                 KeyDialog_In[18], KeyDialog_In[19],
//ha//                 KeyDialog_In[20], KeyDialog_In[21], 
//ha//                 KeyDialog_In[22], KeyDialog_In[23],
//ha//                 KeyDialog_In[24], KeyDialog_In[25], 
//ha//                 KeyDialog_In[26], KeyDialog_In[27],
//ha//                 KeyDialog_In[28], KeyDialog_In[29],
//ha//                 KeyDialog_In[30], KeyDialog_In[31], KeyDialog_In);
//ha//MessageBoxA(NULL, DebugBuf, "haCryptMain- InitCryptoKeyFromDialog (2)", MB_OK); // Show MAC bytes
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//sprintf(DebugBuf, "szKeyDialogIn[ 0]= %08X %08X %08X %08X\nszKeyDialogIn[ 4]= %08X %08X %08X %08X\n"
//ha//                  "szKeyDialogIn[ 8]= %08X %08X %08X %08X\nszKeyDialogIn[12]= %08X %08X %08X %08X\n"
//ha//                  "szKeyDialogIn[16]= %08X %08X %08X %08X\nszKeyDialogIn[20]= %08X %08X %08X %08X\n"
//ha//                  "szKeyDialogIn[23]= %08X %08X %08X %08X\nszKeyDialogIn[28]= %08X %08X %08X %08X\n"
//ha//                  "szKeyDialogIn=%s",
//ha//                 (UINT)szKeyDialogIn[0],  (UINT)szKeyDialogIn[1], 
//ha//                 (UINT)szKeyDialogIn[2],  (UINT)szKeyDialogIn[3],
//ha//                 (UINT)szKeyDialogIn[4],  (UINT)szKeyDialogIn[5], 
//ha//                 (UINT)szKeyDialogIn[6],  (UINT)szKeyDialogIn[7],
//ha//                 (UINT)szKeyDialogIn[8],  (UINT)szKeyDialogIn[9], 
//ha//                 (UINT)szKeyDialogIn[10], (UINT)szKeyDialogIn[11],
//ha//                 (UINT)szKeyDialogIn[12], (UINT)szKeyDialogIn[13],
//ha//                 (UINT)szKeyDialogIn[14], (UINT)szKeyDialogIn[15],
//ha//                 (UINT)szKeyDialogIn[16], (UINT)szKeyDialogIn[17], 
//ha//                 (UINT)szKeyDialogIn[18], (UINT)szKeyDialogIn[19],
//ha//                 (UINT)szKeyDialogIn[20], (UINT)szKeyDialogIn[21], 
//ha//                 (UINT)szKeyDialogIn[22], (UINT)szKeyDialogIn[23],
//ha//                 (UINT)szKeyDialogIn[24], (UINT)szKeyDialogIn[25], 
//ha//                 (UINT)szKeyDialogIn[26], (UINT)szKeyDialogIn[27],
//ha//                 (UINT)szKeyDialogIn[28], (UINT)szKeyDialogIn[29],
//ha//                 (UINT)szKeyDialogIn[30], (UINT)szKeyDialogIn[31], (char *)&szKeyDialogIn[0]);
//ha//MessageBoxA(NULL, DebugBuf, "haCryptMain- InitCryptoKeyFromDialog (2)", MB_OK); // Show MAC bytes
//ha////ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---

//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---
//ha//MessageBoxA(NULL, "DEBUG _escFlag", "DEBUG STOP 1", MB_OK);
//ha////---DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG------DEBUG---


