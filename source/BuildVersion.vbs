' haCrypt - Crypto tool for DES, AES, TDEA and RSA.
' BuildVersion.vbs VB-Script
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

'---------------------------------------------------------------
'                                                              
Dim tfCpp                                              
                                                               
Const FolderPath = "C:\TEMP600\__"                     
''ha''Const FolderPath = "I:\TEMP600\__\_\_"                           
                                                               
filenameVer = FolderPath & "\haCryptBuildTime.ver"             
filenameCpp = FolderPath & "\haCryptBuildTime.cpp"             
                                                               
Set fso      = CreateObject("Scripting.FileSystemObject")      
Set tfCpp    = fso.CreateTextFile(filenameCpp, True)           
                                                               
Set WshShell = WScript.CreateObject("WScript.Shell")
           
call CreateFileCpp()  ' Create .CPP (a C++ Source module)      

'---------------------------------------------------------------
'
'                 CreateFileCpp()
' 
' Two input lines from Date & Time:
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
  tfCpp.WriteLine("// Script: BuildVersion.vbs")
  tfCpp.WriteLine()
  tfCpp.WriteLine("#include <windows.h>")
  tfCpp.WriteLine("#include <tchar.h>")
  tfCpp.WriteLine("#include <strsafe.h>")

  ' Constuct the development version string (=Date & Time)
  VersionString = BuildVersion(0) & " " & BuildVersion(1)                  

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

