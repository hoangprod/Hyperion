#include "pch.h"
#include "VEH.h"




LONG WINAPI LeoHandler(EXCEPTION_POINTERS* pExceptionInfo)
{

	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		Ulog("1) Exception (%lx) at (%p) from RIP (%llx)", pExceptionInfo->ExceptionRecord->ExceptionCode,
			pExceptionInfo->ExceptionRecord->ExceptionAddress,
			pExceptionInfo->ContextRecord->Rip);

		Sleep(1000000);
	}

	return EXCEPTION_CONTINUE_SEARCH; //Keep going down the exception handling list to find the right handler IF it is not PAGE_GUARD nor SINGLE_STEP
}
