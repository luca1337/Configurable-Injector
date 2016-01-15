// utility_public.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include <windows.h>
#include "CRemoteCode.h"

#ifdef UNICODE
#undef UNICODE
#endif

#include <Tlhelp32.h>
#include <Psapi.h>
#include <wtsapi32.h>

#pragma comment( lib, "Advapi32.lib" )
#pragma comment( lib, "Psapi.lib" )
#pragma comment( lib, "Wtsapi32.lib" )

FARPROC GetRemoteProcAddress( HANDLE hProcess, char *szModuleName, char *szProcName );
HMODULE GetRemoteModuleHandle( char *szModuleName, HANDLE hProcess, bool bUsePath );
HANDLE GetProcessByName( char *szName );
BOOL GetDebugPrivileges( void );

extern "C" __declspec( dllexport ) bool __cdecl RequestDebugPrivs()
{
	return (GetDebugPrivileges() == TRUE);
}

extern "C" __declspec( dllexport ) bool __cdecl InjectLibrary( wchar_t *szLibrary, HANDLE *hProcess )
{
	if( !szLibrary || !hProcess )
		return false;

	HANDLE hProcessHandle = *hProcess;

	if( hProcessHandle == INVALID_HANDLE_VALUE )
		return false;

	FARPROC fpRemoteProcAddressLoadLibrary = GetRemoteProcAddress( hProcessHandle, "kernel32.dll", "LoadLibraryExW" );

	if( fpRemoteProcAddressLoadLibrary == (FARPROC)0 )
		return false;

	CRemoteCode remote( hProcessHandle );

	remote.PushUNICODEString( szLibrary );

	remote.PushInt( 0 );

	remote.PushInt( LOAD_IGNORE_CODE_AUTHZ_LEVEL );

	remote.PushCall( CCONV_STDCALL, fpRemoteProcAddressLoadLibrary );

	remote_thread_buffer_t rtb = remote.AssembleRemoteThreadBuffer();

	if( remote.ExecuteRemoteThreadBuffer( rtb ) == false )
	{
		return false;
	}

	return true;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved )
{
	DisableThreadLibraryCalls( hModule );

    return TRUE;
}

FARPROC GetRemoteProcAddress( HANDLE hProcess, char *szModuleName, char *szProcName )
{
	HMODULE hLocalModule = GetModuleHandleA( szModuleName );

	if( hLocalModule == false )
		return (FARPROC)0;

	FARPROC fpLocal = GetProcAddress( hLocalModule, szProcName );

	if( fpLocal == (FARPROC)0 )
		return (FARPROC)0;

	DWORD dwOffset = (DWORD)fpLocal - (DWORD)hLocalModule;

	HMODULE hRemoteModuleHandle = GetRemoteModuleHandle( szModuleName, hProcess, false );

	if( hRemoteModuleHandle == (HMODULE)0 )
		return (FARPROC)0;

	return (FARPROC)((DWORD)hRemoteModuleHandle + dwOffset);
}

HMODULE GetRemoteModuleHandle( char *szModuleName, HANDLE hProcess, bool bUsePath )
{
	HANDLE tlh = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetProcessId( hProcess ) );

	MODULEENTRY32 modEntry;
	
	modEntry.dwSize = sizeof( MODULEENTRY32 );

	Module32First( tlh, &modEntry );
	do
	{
		string comp;
		comp.clear();

		if(bUsePath){ comp = modEntry.szExePath; } else { comp = modEntry.szModule; }

		if( !strcmp( szModuleName, comp.c_str() ) )
		{
			CloseHandle( tlh );

			return modEntry.hModule;
		}
	}
	while(Module32Next( tlh, &modEntry ) );

	CloseHandle( tlh );

	return NULL;
}

HANDLE GetProcessByName( char *szName )
{
	DWORD dwProcessCount = 0;
	PWTS_PROCESS_INFO pProcessInfo;

	BOOL bWTSEnum = WTSEnumerateProcesses( WTS_CURRENT_SERVER_HANDLE, 0, 1, &pProcessInfo, &dwProcessCount );

	if( bWTSEnum == FALSE || dwProcessCount == 0 )
	{
		HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

		if( hSnapshot == INVALID_HANDLE_VALUE )
		{
			return INVALID_HANDLE_VALUE;
		}

		PROCESSENTRY32 pe32;
		
		BOOL bOK = Process32First( hSnapshot, &pe32 );

		while( bOK )
		{
			if( strstr( pe32.szExeFile, szName ) )
			{
				HANDLE hProcessRet = OpenProcess( 
					PROCESS_QUERY_INFORMATION |   // Required by Alpha
					PROCESS_CREATE_THREAD     |   // For CreateRemoteThread
					PROCESS_VM_OPERATION      |   // For VirtualAllocEx/VirtualFreeEx
					PROCESS_VM_WRITE,             // For WriteProcessMemory
					FALSE, pe32.th32ProcessID );

				if( hProcessRet == INVALID_HANDLE_VALUE )
				{
					return INVALID_HANDLE_VALUE;
				}

				return hProcessRet;
			}

			bOK = Process32Next( hSnapshot, &pe32 );
		}

		CloseHandle( hSnapshot );
	}

	for( DWORD dwCurrent = 0; dwCurrent < dwProcessCount; dwCurrent++ )
	{
		if( strstr( pProcessInfo[dwCurrent].pProcessName, szName ) )
		{
			return OpenProcess( PROCESS_ALL_ACCESS, FALSE, pProcessInfo[dwCurrent].ProcessId );
		}
	}

	return INVALID_HANDLE_VALUE;
}

bool SetPrivilege( HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege )
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if(!LookupPrivilegeValue( NULL, lpszPrivilege, &luid )) 
		return false;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious);
	
	if (GetLastError() != ERROR_SUCCESS) 
		return false;

	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;
	
	if (bEnablePrivilege) 
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	else
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);

	AdjustTokenPrivileges( hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL );
	
	if (GetLastError() != ERROR_SUCCESS) 
		return false;

	return true;
}

BOOL GetDebugPrivileges( void )
{
	HANDLE hToken;

	bool bOK = false;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
		{
			CloseHandle( hToken );
			
			return TRUE;
		}

		CloseHandle( hToken );
	}

	return FALSE;
}
