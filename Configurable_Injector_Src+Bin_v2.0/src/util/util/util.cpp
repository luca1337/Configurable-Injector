#include "stdafx.h"
#include <windows.h>
#include "util.h"

arch_type_t GetProcessArch( CNTLoader *pLoader, char *szProcessName );

void __cdecl debugProc( string shout )
{
//	gApp.AddToLogFile( "Shout: %s", shout.c_str() );
}

DLLEXPORT void* ProcessUtility( int Opcode, void *Parameters )
{
	CNTLoader NTLoader;

	NTLoader.RegisterDebugProc( debugProc );

	switch( Opcode )
	{
	case OP_GetProcessArchitecture:
		{
			FParams_GetProcessArchitecture *pParams = 
				reinterpret_cast<FParams_GetProcessArchitecture *>( Parameters );

			if( pParams == NULL )
				return NULL;

			NTLoader.SetProcess( pParams->hProcess );

			int *iReturn = new int;

			*iReturn = GetProcessArch( &NTLoader, pParams->ProcessModuleName );

			return iReturn;
		}
	case OP_RequestDebugPrivledges:
		{
			bool *bReturn = new bool;

			*bReturn = (GetDebugPrivileges() == TRUE) ? true : false;

			return bReturn;
		}
	case OP_InjectModuleWithByteArray:
		{
			bool *bReturn = new bool;

			*bReturn = false;

			FParams_InjectModuleWithByteArray *pParams = 
				reinterpret_cast<FParams_InjectModuleWithByteArray *>( Parameters );

			if( pParams == NULL )
				return NULL;

			NTLoader.SetProcess( pParams->hProcess );

			if( NTLoader.LoadModuleFromMemory( pParams->BaseOfModule, pParams->SizeOfModule ) == NULL )
			{
				return NULL;
			}

			return bReturn;
		}
	case OP_InjectModuleFileToMemory:
		{
			bool *bReturn = new bool;

			*bReturn = false;

			FParams_InjectModuleFileToMemory *pParams = 
				reinterpret_cast<FParams_InjectModuleFileToMemory *>( Parameters );

			if( pParams == NULL )
				return bReturn;

			if( pParams->hProcess == INVALID_HANDLE_VALUE || pParams->File == NULL )
			{
				*bReturn = false;
			}

			NTLoader.SetProcess( pParams->hProcess );

			if( NTLoader.LoadModuleByNameIntoMemoryW( pParams->File ) )
			{
				*bReturn = true;
			}

			return bReturn;
		}
	case OP_InjectModuleFile:
		{
			bool *bReturn = new bool;

			*bReturn = false;

			FParams_InjectModuleFile *pParams =
				reinterpret_cast<FParams_InjectModuleFile *>( Parameters );

			if( pParams == NULL )
			{
				return bReturn;
			}

			if( pParams->hProcess == INVALID_HANDLE_VALUE || pParams->File == NULL )
			{
				return bReturn;
			}

			NTLoader.SetProcess( pParams->hProcess );
			
			if( NTLoader.LoadModuleByNameW( pParams->File ) )
			{
				*bReturn = true;
			}

			return bReturn;
		}
	}

	return NULL;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD dwReason, LPVOID lpReserved )
{
	if( dwReason == DLL_PROCESS_ATTACH )
	{
		gApp.BaseUponModule( hModule );
	}

    return TRUE;
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

	if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
	{
		if( !SetPrivilege( hToken, SE_DEBUG_NAME, TRUE ) )
		{
			gApp.AddToLogFile( "GetDebugPrivileges: SetPrivilege error" );
		}
		else
		{
			bOK = true;
		}

		CloseHandle( hToken );
	}
	else
	{
		gApp.AddToLogFile( "GetDebugPrivileges: OpenProcessToken error" );
	}

	return bOK;
}

arch_type_t GetProcessArch( CNTLoader *pLoader, char *szProcessName )
{
	if( pLoader == NULL )
		return ARCH_XUNKNOWN;

	HMODULE hProcessModule = pLoader->GetRemoteModuleHandleA( szProcessName );

	if( hProcessModule == NULL )
		return ARCH_XUNKNOWN;

	BYTE ToPEHeader = 0;

	BOOL bRead1 = ReadProcessMemory( pLoader->GetProcess(), (LPVOID)((DWORD)hProcessModule + 0x3C), &ToPEHeader, sizeof( BYTE ), NULL );

	if( bRead1 == FALSE )
	{
		return ARCH_XUNKNOWN;
	}

	BOOL bRead2 = ReadProcessMemory( pLoader->GetProcess(), (LPVOID)((DWORD)hProcessModule + ( ToPEHeader + 0x4 ) ), &ToPEHeader, sizeof( BYTE ), NULL );

	if( bRead2 == FALSE )
	{
		return ARCH_XUNKNOWN;
	}

	if( ToPEHeader == 0x64 )
	{
		return ARCH_X64;
	}

	return ARCH_X86;
}