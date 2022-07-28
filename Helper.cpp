#include "pch.h"
#include "Helper.h"


PPEB GetCurrentPeb_()
{
    return (PPEB)__readgsqword(0x60);
}

UINT_PTR GetCurrentImageBase()
{
    return (UINT_PTR)GetCurrentPeb_()->ImageBaseAddress;
}


bool INT_ComparePattern(char* szSource, const char* szPattern, const char* szMask)
{
    for (; *szMask; ++szSource, ++szPattern, ++szMask)
        if (*szMask == 'x' && *szSource != *szPattern)
            return false;

    return true;
}

char* INT_PatternScan(char* pData, UINT_PTR RegionSize, const char* szPattern, const char* szMask, int Len)
{
    for (UINT i = 0; i != RegionSize - Len; ++i, ++pData)
        if (INT_ComparePattern(pData, szPattern, szMask))
            return pData;
    return nullptr;
}


char* PatternScanUnsafe(UINT_PTR pStart, UINT_PTR RegionSize, const char* szPattern, const char* szMask)
{
    char* pCurrent = (char*)pStart;
    auto Len = lstrlenA(szMask);

    if (Len > RegionSize)
        return 0;

    return INT_PatternScan(pCurrent, RegionSize, szPattern, szMask, Len);
}


void DifMemoryInfo(MEMORY_BASIC_INFORMATION i1, MEMORY_BASIC_INFORMATION i2)
{
    Ulog("BaseAddress:\t%p - %p", i1.BaseAddress, i2.BaseAddress);
    Ulog("AllocationBase:\t%p - %p", i1.AllocationBase, i2.AllocationBase);
    Ulog("AllocationProtect:\t%lx - %lx", i1.AllocationProtect, i2.AllocationProtect);
    Ulog("PartitionId:\t\t%lx - %lx", i1.PartitionId, i2.PartitionId);
    Ulog("RegionSize:\t\t%llx - %llx", i1.RegionSize, i2.RegionSize);
    Ulog("State:\t\t%lx - %lx", i1.State, i2.State);
    Ulog("Protect:\t\t%lx - %lx", i1.Protect, i2.Protect);
    Ulog("Type:\t\t%lx - %lx\n", i1.Type, i2.Type);
}

MEMORY_BASIC_INFORMATION VirtualQueryAddress(UINT_PTR Address)
{
    MEMORY_BASIC_INFORMATION Info = {};

    if (!VirtualQuery((PVOID)Address, &Info, sizeof(Info)))
    {
        Ulog("VirtualQuery Failed with error (%lx).", GetLastError());

        return Info;
    }

    return Info;
}

UINT_PTR GetFunctionAddress(const wchar_t* Module, const char* functionName)
{
    auto hModule = GetModuleHandle(Module);

    if (!hModule)
    {
        Ulog("Could not find loader.dll");
        return 0;
    }

    return (UINT_PTR)GetProcAddress(hModule, functionName);
}

UINT_PTR FindReadGadgetFromByfron()
{
    auto BaseAddress = GetModuleHandle(L"loader.dll");

    if (!BaseAddress)
    {
        Ulog("Could not find Loader.dll");
        return false;
    }

    auto DosHeader = (PIMAGE_DOS_HEADER)((uintptr_t)BaseAddress);
    //Get NT Header
    auto NTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)DosHeader->e_lfanew + (uintptr_t)BaseAddress);
    //Get Current Image Size
    auto ImageSize = NTHeader->OptionalHeader.SizeOfImage;

    auto Result = PatternScanUnsafe((UINT_PTR)BaseAddress, ImageSize, "\x8a\x01\xc3", "xxx");

    if (Result)
    {
        Ulog("Found Necessary Read Gadget");
        return (UINT_PTR)Result;
    }

    return 0;
}

UINT_PTR FindWriteGadgetFromByfron()
{
    auto BaseAddress = GetModuleHandle(L"loader.dll");

    if (!BaseAddress)
    {
        Ulog("Could not find Loader.dll");
        return false;
    }

    auto DosHeader = (PIMAGE_DOS_HEADER)((uintptr_t)BaseAddress);
    //Get NT Header
    auto NTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)DosHeader->e_lfanew + (uintptr_t)BaseAddress);
    //Get Current Image Size
    auto ImageSize = NTHeader->OptionalHeader.SizeOfImage;

    auto Result = PatternScanUnsafe((UINT_PTR)BaseAddress, ImageSize, "\x88\x0a\xc3", "xxx");

    if (Result)
    {
        Ulog("Found Necessary Write Gadget");
        return (UINT_PTR)Result;
    }

    return 0;
}

UINT_PTR FindCallGadgetFromByfron()
{
    auto BaseAddress = GetModuleHandle(L"loader.dll");

    if (!BaseAddress)
    {
        Ulog("Could not find Loader.dll");
        return false;
    }

    auto DosHeader = (PIMAGE_DOS_HEADER)((uintptr_t)BaseAddress);
    //Get NT Header
    auto NTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)DosHeader->e_lfanew + (uintptr_t)BaseAddress);
    //Get Current Image Size
    auto ImageSize = NTHeader->OptionalHeader.SizeOfImage;

    auto Result = PatternScanUnsafe((UINT_PTR)BaseAddress, ImageSize, "\xff\x23\x01", "xxx");

    if (Result)
    {
        Ulog("Found Necessary Call Gadget @ %p", Result);
        return (UINT_PTR)Result;
    }

    return 0;
}
