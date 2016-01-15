// test_module.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"

BOOL APIENTRY DllMain( HMODULE hModule, DWORD dwReason, LPVOID lpReserved )
{
	if( dwReason == DLL_PROCESS_ATTACH )
	{
		MessageBoxA( 0, "Injected", "Success", MB_OK );
	}

    return TRUE;
}