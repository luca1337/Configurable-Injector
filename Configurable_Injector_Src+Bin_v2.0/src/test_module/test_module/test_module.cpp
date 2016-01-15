// test_module.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include <stdio.h>

DWORD WINAPI lpThreadTest( LPVOID lpParam )
{
	printf( "Testing Floating point support [%f]\n", 1.2938f );
	printf( "Testing Import Address [0x%X]\n", ( DWORD )MessageBoxA );

	MessageBoxA( 0, "Code Injected Successfully!", "Success", MB_OK );

	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD dwReason, LPVOID lpReserved )
{
	if( dwReason == DLL_PROCESS_ATTACH )
	{
		CreateThread( 0, 0, lpThreadTest, 0, 0, 0 );
	}

    return TRUE;
}