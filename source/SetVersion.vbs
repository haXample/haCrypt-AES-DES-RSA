' haCrypt - Crypto tool for DES, AES, TDEA and RSA.
' SetVersion.vbs VB-Script
' (c)2022 by helmut altmann

' This program is free software; you can redistribute it and/or modify
' it under the terms of the GNU General Public License as published by
' the Free Software Foundation; either version 2 of the License, or
' (at your option) any later version.
'
' This program is distributed in the hope that it will be useful,
' but WITHOUT ANY WARRANTY; without even the implied warranty of
' MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
' GNU General Public License for more details.
'
' You should have received a copy of the GNU General Public License
' along with this program; see the file COPYING.  If not, write to
' the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
' Boston, MA 02111-1307, USA.

' This will create the module 'haCryptBuildTime.cpp' providing the
' Build-version information for haCrypt.exe. 
' Must run before (create .CPP) executing the NMAKE build targets.

' This will overwrite the actual build date & time version (if desired).
' Must run before (create .CPP) and after the build (timestamp *.EXE).

'**************************************************
Dim bldDay, bldMonth, bldYear, bldFileDate        '|
                                                  '|
bldDay = Day(Date)                                '|
If bldDay < 10 Then                               '|
    bldDay = "0" & bldDay     ' Need leading zero '|
End If                                            '|
                                                  '|
bldMonth = Month(Date)                            '|
If bldMonth < 10 Then                             '|
    bldMonth = "0" & bldMonth ' Need leading zero '|
End If                                            '|
                                                  '|
bldYear = Year(Date)                              '|
'**************************************************

'---------------------------------------------------------------
' Change Modification of file timestamp (with-VB-Script)       '|
'                                                              '|
Dim tfVer, tfCpp                                               '|
                                                               '|
Const FolderPath  = "C:\TEMP600\__" ' = "I:\TEMP600\__\_\_"    '|
                                                               '|
bldFileTime = "14:10"                ' = Build Version (1.4.1) '|
bldVersion = Split(bldFileTime, ":") ' bldVersion(0) = 14      '|
                                     ' bldVersion(1) = 10      '|
                                                               '|
' Constuct the release version string (=formatted time)        '|
VersionString = Left(bldVersion(0), 1) & "." & _                   
               Right(bldVersion(0), 1) & "." & _               
               Left(bldVersion(1), 1)                          '|
'ha'WScript.Echo VersionString                                 '|
                                                               '|
' Current system date from above                               '|
bldFileDate = bldDay & "." & bldMonth & "." & bldYear          '|
'ha'bldFileDate   = "10.03.2023"                               '|
'ha'WScript.Echo bldFileDate                                   '|
                                                               '|
filenameVer = FolderPath & "\haCryptBuildTime.ver"             '|
filenameCpp = FolderPath & "\haCryptBuildTime.cpp"             '|
                                                               '|
Set fso       = CreateObject("Scripting.FileSystemObject")     '|
Set objShell  = CreateObject("Shell.Application")              '|
Set objWShell = WScript.CreateObject("WScript.Shell")          '|
Set objArgs   = WScript.Arguments                              '|
                                                               '|
'  Wscript.Echo objArgs.Count                                  '|
'  Wscript.Echo objArgs(0)                                     '|
If objArgs.Count <> 1 Then                                     '|
  WScript.Echo "ERROR: Wrong number of arguments."             '|
  WScript.Quit                 ' Abort to System.              '|
End If                                                         '|
                                                               '|
If objArgs(0) = "INIT" Then    ' Create .VER                   '|
  Set tfVer    = fso.CreateTextFile(filenameVer, True)         '|
  Set tfCpp    = fso.CreateTextFile(filenameCpp, True)         '|
  Call CreateFileBuildVer()                                    '|
                                                               '|
ElseIf objArgs(0) = "64" Then  ' Timestamp *.EXE               '|
  Call SetTimeStamp("haCrypt64.exe")                           '|
  printf_VersionString()                                       '|
                                                               '|
ElseIf objArgs(0) = "64Q" Then                                 '|
  Call SetTimeStamp("haCryptQuick64.exe")                      '|
  printf_VersionString()                                       '|
                                                               '|
ElseIf objArgs(0) = "32" Then                                  '|
  Call SetTimeStamp("haCrypt.exe")                             '|
  Call SetTimeStamp("haCrypt_XP.exe")                          '|
  printf_VersionString()                                       '|
                                                               '|
ElseIf objArgs(0) = "32Q" Then                                 '|
  Call SetTimeStamp("haCryptQuick_XP.exe")                     '|
  printf_VersionString()                                       '|
                                                               '|
ElseIf objArgs(0) = "32STD" Then                               '|
  Call SetTimeStamp("haCryptSTD_XP.exe")                       '|
  printf_VersionString()                                       '|
                                                               '|
Else                                                           '|
 WScript.Echo "ERROR: "&"'"& objArgs(0) &"'"&" not supported." '|
 WScript.Quit                  ' Abort to System.              '|
                                                               '|
End If ' End if objArgs(0)                                     '|
                                                               '|
Sub SetTimeStamp(FileName)                                     '|
  Set objFolder = objShell.NameSpace(FolderPath)               '|
  Set objFolderItem = objFolder.ParseName(FileName)            '|
  objFolderItem.ModifyDate = bldFileDate & " " & bldFileTime   '|
End Sub                                                        '|
                                                               '|
Sub CreateFileBuildVer()                                       '|
  tfVer.WriteLine(bldFileDate)                                 '|
  tfVer.WriteLine(bldFileTime)                                 '|
  tfVer.Close                                                  '|
                                                               '|
  ' Create a C++ Source module  providing the Build Time-Stamp '|
  call CreateFileCpp()  ' Create .CPP (a C++ Source module)    '|
End Sub                                                        '|
'---------------------------------------------------------------

Function printf_VersionString()
If InStr(LCase(WScript.FullName), "cscript.exe") <> 0 Then
    WScript.StdOut.WriteLine vbTab & "BuildVersion " & _
                             VersionString 
   End If
End Function
 
' ha 'Function ForceConsole()
' ha '    If InStr(LCase(WScript.FullName), vbsInterpreter) = 0 Then
' ha '        objWShell.Run vbsInterpreter & " //NoLogo " & Chr(34) & WScript.ScriptFullName & Chr(34)
' ha '        WScript.Quit
' ha '    End If
' ha 'End Function
 
'---------------------------------------------------------------
'
'                 CreateFileCpp()
' 
' Example: Two input lines from Date & Time:
' 22.04.2022       |  07.07.2022
' 13:55            |  10:02
' = (7E6224.1355)  |  = (7E677.1002)
'
' // Build a string showing date and time formatted as a version string.
' // Return the version string in a C++ source module as function
' //
' dwRet = StringCchPrintf(lpszString, dwSize, TEXT("Build: %03X%d%d.%02d%02d%02d"),
'                         stLocal.wYear, stLocal.wMonth, stLocal.wDay,
'                         stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
'
Sub CreateFileCpp()
  BuildDateTime = fso.OpenTextFile(filenameVer).ReadAll
  ' The input text lines are splitted line-by-line:
  BuildVersion = Split(BuildDateTime, vbCrLf)
  'WScript.Echo BuildVersion(0) 
  'WScript.Echo BuildVersion(1) 
  'WScript.Echo Hex(Mid(BuildVersion(0), 7, 4)) 'Hex(2022) 

  tfCpp.WriteLine("// haCryptBuildTime.cpp - C++ auto-generated source file.")
  tfCpp.WriteLine("// (c)2022 by helmut altmann")
  tfCpp.WriteLine("// Script: SetVersion.vbs")
  tfCpp.WriteLine()
  tfCpp.WriteLine("#include <windows.h>")
  tfCpp.WriteLine("#include <tchar.h>")
  tfCpp.WriteLine("#include <strsafe.h>")

  tfCpp.WriteLine()
  tfCpp.WriteLine("int wYear   = " & Mid(BuildVersion(0), 7, 4) &";") 
 
  ' Handle illegal octal values like 08, 09 (just discard leading zeros)
  If Mid(BuildVersion(0), 4, 1) = "0" Then
     tfCpp.WriteLine("int wMonth  = " & Mid(BuildVersion(0), 5, 1) &";") 
  Else
     tfCpp.WriteLine("int wMonth  = " & Mid(BuildVersion(0), 4, 2) &";") 
  End If

  If Left(BuildVersion(0), 1) = "0" Then
     tfCpp.WriteLine("int wDay    = " & Mid(BuildVersion(0), 2, 1) &";") 
  Else
     tfCpp.WriteLine("int wDay    = " & Left(BuildVersion(0), 2) &";") 
  End If

  If Mid(BuildVersion(1), 1, 1) = "0" Then
     tfCpp.WriteLine("int wHour   = " & Mid(BuildVersion(1), 2, 1) &";") 
  Else
     tfCpp.WriteLine("int wHour   = " & Mid(BuildVersion(1), 1, 2) &";") 
  End If

  If Mid(BuildVersion(1), 4, 1) = "0" Then
     tfCpp.WriteLine("int wMinute = " & Mid(BuildVersion(1), 5, 1) &";") 
  Else
     tfCpp.WriteLine("int wMinute = " & Right(BuildVersion(1), 2) &";") 
  End If

  tfCpp.WriteLine("TCHAR* BuildVersion = _T(""" & "" & VersionString & """);")

  tfCpp.WriteLine()
  tfCpp.WriteLine("BOOL GetBuildTime(TCHAR* szFileName, LPTSTR lpszString, DWORD dwSize)")
  tfCpp.WriteLine("  {")

  tfCpp.WriteLine("  StringCchPrintf(lpszString, dwSize, TEXT(""Build: %03X%d%d.%02d%02d""),")
  tfCpp.WriteLine("                  wYear, wMonth, wDay,")
  tfCpp.WriteLine("                  wHour, wMinute);")
  tfCpp.WriteLine("  return(TRUE);")
  tfCpp.WriteLine("  } // GetBuildTime")
  tfCpp.Close
End Sub
'---------------------------------------------------------------

' End VB-Script

