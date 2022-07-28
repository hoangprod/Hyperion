#pragma once

PPEB	 GetCurrentPeb_();
UINT_PTR GetCurrentImageBase();

UINT_PTR FindReadGadgetFromByfron();
UINT_PTR FindWriteGadgetFromByfron();
UINT_PTR FindCallGadgetFromByfron();

UINT_PTR GetFunctionAddress(const wchar_t* Module, const char* functionName);

bool INT_ComparePattern(char* szSource, const char* szPattern, const char* szMask);
char* INT_PatternScan(char* pData, UINT_PTR RegionSize, const char* szPattern, const char* szMask, int Len);
char* PatternScanUnsafe(UINT_PTR pStart, UINT_PTR RegionSize, const char* szPattern, const char* szMask);


void DifMemoryInfo(MEMORY_BASIC_INFORMATION i1, MEMORY_BASIC_INFORMATION i2);

MEMORY_BASIC_INFORMATION VirtualQueryAddress(UINT_PTR Address);

