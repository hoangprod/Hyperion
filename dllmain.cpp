// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "VEH.h"
#include "Hooks.h"
#include "Helper.h"
#include "Syscalls.h"
#include "Spoofcall.h"


typedef void(*fn_WriteByte)(const char byte, UINT_PTR address);
fn_WriteByte writebyteGadget = 0;

typedef unsigned char(*fn_ReadByte)(char* Address);
fn_ReadByte readbyteGadget = 0;

BYTE SpoofRead(char* address)
{
    __try
    {
        return readbyteGadget(address);
    }
    __except (true) {}
}

VOID SpoofWrite(const char * byte, size_t size, UINT_PTR address)
{
    __try
    {
        for (size_t i = 0; i < size; i++)
        {
            return writebyteGadget(byte[i], address + i);
        }
    }
    __except (true) {}
}




bool DumpGame()
{
    auto BaseAddress = GetCurrentImageBase();

    if (!BaseAddress)
    {
        Ulog("Could not find Process' Base Address.");
        return false;
    }

    Ulog("Process Base Address: %llx", BaseAddress);

    readbyteGadget = (fn_ReadByte)FindReadGadgetFromByfron();

    if (!readbyteGadget)
    {
        Ulog("Could not find necessary Gadget...");
        return false;
    }

    //Get DOS Header
    auto DosHeader = (PIMAGE_DOS_HEADER)(BaseAddress);
    //Get NT Header
    auto NTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)DosHeader->e_lfanew + BaseAddress);
    //Get Current Image Size
    auto ImageSize = NTHeader->OptionalHeader.SizeOfImage;

    char* AllocatedMem = (char*)VirtualAlloc(0, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!AllocatedMem)
    {
        Ulog("Could not allocate memory to hold the dump.");
        return false;
    }

    for (size_t i = 0; i < ImageSize; i++)
    {
        AllocatedMem[i] = SpoofRead((char*)((UINT_PTR)BaseAddress + i));
    }

    //Get DOS Header of our Allocated Dump
    auto DosHeaderNew = (PIMAGE_DOS_HEADER)((uintptr_t)AllocatedMem);
    //Get NT Header of our Allocated Dump
    auto NtHeaderNew = (PIMAGE_NT_HEADERS)((uintptr_t)DosHeaderNew->e_lfanew + (uintptr_t)AllocatedMem);

    //Get Section Header of our Allocated Dump
    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaderNew);

    //Iterate through each section and fix size and address
    for (int i = 0; i < NtHeaderNew->FileHeader.NumberOfSections; i++, SectionHeader++)
    {
        SectionHeader->SizeOfRawData = SectionHeader->Misc.VirtualSize;
        SectionHeader->PointerToRawData = SectionHeader->VirtualAddress;
    }

    char FileNameT[MAX_PATH] = {};
    // Get current process file name
    //
    GetModuleFileNameA(0, FileNameT, MAX_PATH);

    char FileName[MAX_PATH] = {};
    sprintf_s(FileName, "%s_dump.exe", FileNameT);
    Ulog("Dumped the Game To Path: %s", FileName);

    // Write our dumped and fixed executable to a file
    // 
    std::ofstream Dump(FileName, std::ios::binary);
    Dump.write((char*)AllocatedMem, ImageSize);
    Dump.close();

    return true;
}


bool RestoreKiUserExceptionDispatcher()
{
    auto NtDll = (PVOID)GetModuleHandle(L"ntdll.dll");

    if (!NtDll)
    {
        Ulog("Could not find NtDll");
        return false;
    }

    GameBaseAddress = GetCurrentImageBase();

    if (!GameBaseAddress)
    {
        Ulog("Could not find Process' Base Address.");
        return false;
    }

    gadGetJumpTrampoline = (PVOID)FindCallGadgetFromByfron();

    if (!gadGetJumpTrampoline)
    {
        Ulog("Could not find Call Gadget");
        return false;
    }

    readbyteGadget = (fn_ReadByte)FindReadGadgetFromByfron();

    if (!readbyteGadget)
    {
        Ulog("Could not find necessary Gadget...");
        return false;
    }

    for (size_t i = 0x1000; i < 0x2000; i++)
    {
        SpoofRead((char*)(GameBaseAddress + i));
    }

    DWORD Old = 0;
    SIZE_T Size = 10;

    auto pKiUserExceptionDispatcher = (PVOID)(GameBaseAddress + 0x1000); //(PVOID)((UINT_PTR)NtDll + 0x09FDA0);

    ULONG Status = Syscall<ULONG>(0x50, GetCurrentProcess(), &pKiUserExceptionDispatcher, &Size, 0x80, &Old);
    
    if (Status != 0)
    {
        Ulog("Failed to Syscall VirtualProtect due to error %lx", Status);
        return false;
    }

    auto InfoPre = VirtualQueryAddress((UINT_PTR)pKiUserExceptionDispatcher);

    Ulog("Writing Hello to %p", pKiUserExceptionDispatcher);

    memcpy(pKiUserExceptionDispatcher, "Hello", 6);

    auto InfoPost = VirtualQueryAddress((UINT_PTR)pKiUserExceptionDispatcher);

    DifMemoryInfo(InfoPre, InfoPost);

    Status = Syscall<ULONG>(0x50, GetCurrentProcess(), &pKiUserExceptionDispatcher, &Size, 0x80, &Old);

    if (Status != 0)
    {
        Ulog("Failed to Syscall RE-VirtualProtect due to error %lx", Status);
        return false;
    }

    auto InfoPost2= VirtualQueryAddress((UINT_PTR)pKiUserExceptionDispatcher);

    DifMemoryInfo(InfoPost, InfoPost2);

    Ulog("Restored pKiUserExceptionDispatcher @ %p", pKiUserExceptionDispatcher);

    return true;
}


void Welcome()
{
    FILE* fp; AllocConsole();
    freopen_s(&fp, "CONOUT$", "w", stdout);

    Ulog("Hello Byfron!");
    Ulog("Release by ByfronHomeworkGroup#7550");
    Ulog("Contact for Discord Add!");

    InitiateHooks();

    AddVectoredExceptionHandler(true, LeoHandler);

    RestoreKiUserExceptionDispatcher();
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Welcome();
        return true;
        // DumpGame();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

