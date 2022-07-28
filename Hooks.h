#pragma once


bool InitiateHooks();

ULONG NTAPI h_ZwQueryVirtualMemory  (HANDLE Handle, PVOID BaseAddress, ULONG Class, MEMORY_BASIC_INFORMATION* MemoryInfo, SIZE_T MemoryInformationLength, SIZE* ReturnLength);
ULONG NTAPI h_ZwProtectVirtualMemory(HANDLE Handle, PVOID* BaseAddress, SIZE_T* Size, DWORD Protect, DWORD* OldProtect);