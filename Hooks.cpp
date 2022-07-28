#include "pch.h"
#include "Syscalls.h"
#include "Helper.h"
#include "Hooks.h"


const UCHAR HkpDetour[] = {
	0xff, 0x25, 0x00, 0x00, 0x00, 0x00
};

BOOL PlaceAbsoluteJump(UINT_PTR From, UINT_PTR To)
{
	memcpy((PVOID)From, HkpDetour, sizeof HkpDetour);
	memcpy((PVOID)(From + sizeof HkpDetour), &To, sizeof To);


	return true;
}



ULONG h_ZwQueryVirtualMemory(HANDLE Handle, PVOID BaseAddress, ULONG Class, MEMORY_BASIC_INFORMATION* MemoryInfo, SIZE_T MemoryInformationLength, SIZE* ReturnLength)
{
	ULONG Status = Syscall<ULONG>(0x23, Handle, BaseAddress, Class, MemoryInfo, MemoryInformationLength, ReturnLength);
	
	__try
	{
		if (Class == 0)
		{
			Ulog("BaseAddress:\t%p", MemoryInfo->BaseAddress);
			Ulog("AllocationBase:\t%p", MemoryInfo->AllocationBase);
			Ulog("AllocationProtect:\t%lx", MemoryInfo->AllocationProtect);
			Ulog("RegionSize:\t\t%llx", MemoryInfo->RegionSize);
			Ulog("State:\t\t%lx", MemoryInfo->State);
			Ulog("Protect:\t\t%lx", MemoryInfo->Protect);
			Ulog("Type:\t\t%lx", MemoryInfo->Type);

			if (MemoryInfo->Protect == 0x40)
			{
				Ulog("Spoofing %lx to 0x4", MemoryInfo->Protect);
				MemoryInfo->Protect = 0x4;
			}

			printf("\n\n");
		}
		else
		{
			Ulog("[Query] Class %lx", Class);
		}

	}
	__except (TRUE) {};


	return Status;
}

ULONG h_ZwProtectVirtualMemory(HANDLE Handle, PVOID* BaseAddress, SIZE_T* Size, DWORD Protect, DWORD* OldProtect)
{
	__try
	{
		if (Protect == 1)
			Protect = 4;

		ULONG Status = Syscall<ULONG>(0x50, Handle, BaseAddress, Size, Protect, OldProtect);

		Ulog("[Protect] %p Size (%llx) Protect (%lx) - from %p", *BaseAddress, *Size, Protect, _ReturnAddress());

		return Status;
	}
	__except (TRUE) {};

	return 0;
}




bool InitiateHooks()
{
	auto ModuleBase = GetModuleHandle(L"loader.dll");

	if (!ModuleBase)
	{
		Ulog("Could not find Loader.dll");
		return false;
	}

	*(UINT_PTR*)((UINT_PTR)ModuleBase + 0xef5e8) = (UINT_PTR)h_ZwProtectVirtualMemory;
	*(UINT_PTR*)((UINT_PTR)ModuleBase + 0xef7f8) = (UINT_PTR)h_ZwQueryVirtualMemory;



	return true;
}