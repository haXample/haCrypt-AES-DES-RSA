// haCryptBuildTime.cpp - C++ auto-generated source file.
// (c)2022 by helmut altmann
// Script: SetVersion.vbs

#include <windows.h>
#include <tchar.h>
#include <strsafe.h>

int wYear   = 2023;
int wMonth  = 12;
int wDay    = 24;
int wHour   = 14;
int wMinute = 10;
TCHAR* BuildVersion = _T("1.4.1");

BOOL GetBuildTime(TCHAR* szFileName, LPTSTR lpszString, DWORD dwSize)
  {
  StringCchPrintf(lpszString, dwSize, TEXT("Build: %03X%d%d.%02d%02d"),
                  wYear, wMonth, wDay,
                  wHour, wMinute);
  return(TRUE);
  } // GetBuildTime
