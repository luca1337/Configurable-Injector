/*
Copyright (c) 2009, guidtech.net
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the guidtech.net nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY guidtech.net ''AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL guidtech.net BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "stdafx.h"
#include "CNTLoader.h"

#ifdef UNICODE
#undef UNICODE
#endif

#include <Tlhelp32.h>
#include <Psapi.h>

#pragma comment( lib, "Psapi.lib" )

HMODULE CNTLoader::LoadModuleByNameA( char *szString )
{
	wchar_t szModule[ MAX_PATH ] = { 0 };

	mbstowcs( szModule, szString, MAX_PATH );

	DebugShout( "[LoadModuleByNameA] ( %S <- %s )", szModule, szString );

	return LoadModuleByNameW( szModule );
}

HMODULE CNTLoader::LoadModuleByNameW( wchar_t *szString )
{
	HMODULE hCheck = GetRemoteModuleHandleW( szString );

	if( hCheck )
	{
		//Already exists!

		return hCheck;
	}

	if( szString == NULL )
	{
		DebugShout( "[LoadModuleByNameW] szString is NULL" );

		return NULL;
	}

	FARPROC fpRemote = GetRemoteProcAddress( "kernel32.dll", "LoadLibraryW" );

	if( fpRemote == NULL )
	{
		DebugShout( "[LoadModuleByNameW] LoadLibraryW Resolve Failure" );

		return NULL;
	}

	DebugShout( "[LoadModuleByNameW] LoadLibraryW = 0x%X", fpRemote );

	PushUNICODEString( szString );

	PushCall( CCONV_STDCALL, fpRemote );

	remote_thread_buffer_t rtb = AssembleRemoteThreadBuffer();

	if( ExecuteRemoteThreadBuffer( rtb ) == false )
	{
		DebugShout( "[LoadModuleByNameW] ExecuteRemoteThreadBuffer failed" );

		return NULL;
	}

	DebugShout( "[LoadModuleByNameW] ExecuteRemoteThreadBuffer succeeded" );

	return GetRemoteModuleHandleW( szString );
}

HMODULE CNTLoader::LoadModuleByNameIntoMemoryA( char *szString )
{
	if( m_hProcess == INVALID_HANDLE_VALUE )
		return NULL;

	HANDLE hFile = CreateFileA( 
		szString, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

	if( hFile == INVALID_HANDLE_VALUE )
	{
		DebugShout( "[LoadModuleByNameIntoMemoryA] Call to CreateFileA failed!" );

		return NULL;
	}

	DebugShout( "[LoadModuleByNameIntoMemoryA] CreateFileA Succeeded!" );

	UINT uiSize = NULL, uiBytes = NULL;

	if( GetFileAttributesA( szString ) & FILE_ATTRIBUTE_COMPRESSED )
	{
		uiSize = GetCompressedFileSizeA( szString, NULL );
	}
	else
	{
		uiSize = GetFileSize( hFile, NULL );
	}

	if( uiSize == NULL )
	{
		DebugShout( "[LoadModuleByNameIntoMemoryA] Filesize is NULL" );

		return NULL;
	}

	DebugShout( "[LoadModuleByNameIntoMemoryA] Filesize [0x%X]", uiSize );

	unsigned char *pucAllocatedBinary = new unsigned char[ uiSize ];
	
	BOOL bReadFileReturn = ReadFile( hFile, pucAllocatedBinary, uiSize, (LPDWORD)&uiBytes, FALSE );

	CloseHandle( hFile );

	if( bReadFileReturn == FALSE )
	{
		DebugShout( "[LoadModuleByNameIntoMemoryA] Call to ReadFile failed!" );

		delete[] pucAllocatedBinary;

		return NULL;
	}

	DebugShout( "[LoadModuleByNameIntoMemoryA] ReadFile Succeeded!" );

	HMODULE hReturn = LoadModuleFromMemory( ( unsigned long )pucAllocatedBinary, uiSize );

	delete[] pucAllocatedBinary;

	return hReturn;
}

HMODULE CNTLoader::LoadModuleByNameIntoMemoryW( wchar_t *szString )
{
	char szANSIString[ MAX_PATH ] = { 0 };

	wcstombs( szANSIString, szString, MAX_PATH );

	DebugShout( "[LoadModuleByNameIntoMemoryW]( %S -> %s )",
		szString, szANSIString );

	return LoadModuleByNameIntoMemoryA( szANSIString );
}

HMODULE CNTLoader::LoadModuleFromMemory( unsigned long BaseAddress, unsigned long SizeOfModule )
{
	if( m_hProcess == INVALID_HANDLE_VALUE )
		return NULL;

	while( this->LoadModuleByNameA( "USER32.DLL" ) == NULL )
		Sleep( 10 );

	IMAGE_DOS_HEADER *pDos = ToDOSHeader((HMODULE)BaseAddress);
	IMAGE_NT_HEADERS *pNTh = ToNTHeaders((HMODULE)BaseAddress);

	if( !pDos || !pNTh )
	{
		DebugShout( "[LoadModuleFromMemory] Failed to get module essiential data (NT and DOS headers)" );

		return NULL;
	}

	DebugShout( "[LoadModuleFromMemory] Got essiential data!" );

	IMAGE_IMPORT_DESCRIPTOR *pImageImportDesc = (IMAGE_IMPORT_DESCRIPTOR *)GetPtrFromRVA( 
		( DWORD )( pNTh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress ), pNTh, (BYTE *)BaseAddress );

	if( pNTh->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size )
	{
		if( FixImports( (void *)BaseAddress, pNTh, pImageImportDesc ) == false )
		{
			DebugShout( "[LoadModuleFromMemory] Failed to fix imports!" );

			return NULL;
		}
	}

	DebugShout( "[LoadModuleFromMemory] Fixed Imports" );

	PVOID pvModuleBaseAddress = CommitMemory( ( void* )BaseAddress, SizeOfModule );

	if( pvModuleBaseAddress == NULL )
	{
		DebugShout( "[LoadModuleFromMemory] Failed to allocate module space!" );

		return NULL;
	}

	DebugShout( "[LoadModuleFromMemory] Module Base: 0x%X", pvModuleBaseAddress );

	IMAGE_BASE_RELOCATION *pBaseRelocation = (IMAGE_BASE_RELOCATION *)GetPtrFromRVA(
		( DWORD )( pNTh->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress ), pNTh, (BYTE *)BaseAddress );

	if( pNTh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size )
	{
		if( FixRelocs( (void *)BaseAddress, pvModuleBaseAddress, 
			pNTh, pBaseRelocation, pNTh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size ) == false )
		{
			DebugShout( "[LoadModuleFromMemory] Failed to fix relocations!" );

			return NULL;
		}
	}

	DebugShout( "[LoadModuleFromMemory] Fixed Relocations" );

	if( MapSections( pvModuleBaseAddress, (void *)BaseAddress, pNTh ) == false )
	{
		DebugShout( "[LoadModuleFromMemory] Failed to map sections" );

		return NULL;
	}

	DebugShout( "[LoadModuleFromMemory] Mapped Sections" );

	unsigned long ulPointerToCall = (unsigned long)((DWORD_PTR)pvModuleBaseAddress + (DWORD_PTR)pNTh->OptionalHeader.AddressOfEntryPoint);

	DebugShout( "[LoadModuleFromMemory] Module Entry Point: 0x%X", ulPointerToCall );

	PushInt( ( int )pvModuleBaseAddress );
	PushInt( DLL_PROCESS_ATTACH );
	PushInt( 0 );
	PushCall( CCONV_STDCALL, ( FARPROC )ulPointerToCall );

	remote_thread_buffer_t RemoteThreadBuffer = AssembleRemoteThreadBuffer();

	if( ExecuteRemoteThreadBuffer( RemoteThreadBuffer ) == false )
	{
		DebugShout( "[LoadModuleFromMemory] Failed to execute remote thread buffer" );

		return NULL;
	}

	DebugShout( "[LoadModuleFromMemory] Executed the remote thread buffer successfully" );

	return ( HMODULE )pvModuleBaseAddress;
}

HMODULE CNTLoader::GetRemoteModuleHandleA( const char *szModule )
{
	DebugShout( "[GetRemoteModuleHandle] Looking for Module [%s]", szModule );

	HANDLE tlh = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetProcessId( GetProcess() ) );

	MODULEENTRY32 modEntry;
	
	modEntry.dwSize = sizeof( MODULEENTRY32 );

	Module32First( tlh, &modEntry );
	do
	{
		DebugShout( "[GetRemoteModuleHandle] Passing [%s]", modEntry.szModule );

		if( _stricmp( szModule, modEntry.szModule ) == 0 )
		{
			DebugShout( "[GetRemoteModuleHandle] Found Match For [%s][%s][0x%X]", 
				szModule, modEntry.szModule, modEntry.hModule );

			CloseHandle( tlh );

			return modEntry.hModule;
		}
	}
	while( Module32Next( tlh, &modEntry ) );

	DebugShout( "[GetRemoteModuleHandle] Failed to find module [%s]", szModule );

	CloseHandle( tlh );

	return NULL;
}

HMODULE CNTLoader::GetRemoteModuleHandleW( const wchar_t *szModule )
{
	char pszModule[ MAX_PATH ] = { 0 };

	wcstombs( pszModule, szModule, MAX_PATH );

	return GetRemoteModuleHandleA( pszModule );
}

FARPROC CNTLoader::GetRemoteProcAddress( const char *szModule, const char *szFunction )
{
	unsigned long LocalModule	= ( unsigned long )GetModuleHandleA( szModule );
	unsigned long LocalCommon	= ( unsigned long )GetProcAddress( ( HMODULE )LocalModule, szFunction );
	unsigned long RemoteModule	= ( unsigned long )GetRemoteModuleHandleA( szModule );

	if( LocalModule == 0 || LocalCommon == 0 || RemoteModule == 0 )
	{
		return 0;
	}
	
	return ( FARPROC )( ( LocalCommon - LocalModule ) + RemoteModule );
}

BOOL CNTLoader::GetMemoryValue( void *Address, void *Buffer, int Size )
{
	if( ReadProcessMemory( GetProcess(), Address, Buffer, ( SIZE_T )Size, NULL ) == FALSE )
		return FALSE;

	return TRUE;
}

PIMAGE_DOS_HEADER CNTLoader::ToDOSHeader( HMODULE hModule )
{
	IMAGE_DOS_HEADER *pDOS = reinterpret_cast<PIMAGE_DOS_HEADER>( hModule );

	if( !pDOS )
		return NULL;

	if( pDOS->e_magic != IMAGE_DOS_SIGNATURE )
		return NULL;

	if( pDOS->e_lfanew >= 0x10000000 )
		return NULL;

	return pDOS;
}

PIMAGE_NT_HEADERS CNTLoader::ToNTHeaders( HMODULE hModule )
{
	HMODULE hNTDll = GetModuleHandleA( "ntdll.dll" );

	if( hNTDll )
	{
		RtlImageNtHeader_t pRtlImageNtHeader = (RtlImageNtHeader_t)GetProcAddress( hNTDll, "RtlImageNtHeader" );
		
		if( pRtlImageNtHeader )
		{
			PVOID pModule = reinterpret_cast<PVOID>( hModule );

			return pRtlImageNtHeader( pModule );
		}
	}

	IMAGE_DOS_HEADER* pDOS = ToDOSHeader( hModule );

	DWORD dwModule = reinterpret_cast<DWORD>( hModule );

	IMAGE_NT_HEADERS *pNT = (IMAGE_NT_HEADERS *)(dwModule + pDOS->e_lfanew);

	if( pNT->Signature != IMAGE_NT_SIGNATURE )
		return NULL;

	return pNT;
}

PIMAGE_SECTION_HEADER CNTLoader::GetEnclosingSectionHeader( DWORD rva, PIMAGE_NT_HEADERS pNTHeader )
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION( pNTHeader );

	unsigned int i;
   
	for ( i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++ )
	{
		DWORD size = section->Misc.VirtualSize;

		if( size == NULL )
		{
			size = section->SizeOfRawData;
		}

		if( ( rva >= section->VirtualAddress ) && ( rva < ( section->VirtualAddress + size ) ) )
		{
			return section;
		}
	}

	return NULL;
}

LPVOID CNTLoader::GetPtrFromRVA( DWORD rva, IMAGE_NT_HEADERS *pNTHeader, PBYTE imageBase )
{
	PIMAGE_SECTION_HEADER pSectionHdr;

	INT delta;
      
	pSectionHdr = GetEnclosingSectionHeader( rva, pNTHeader );

	if ( !pSectionHdr )
		return 0;
 
	delta = (INT)(pSectionHdr->VirtualAddress-pSectionHdr->PointerToRawData);

	return (PVOID) ( imageBase + rva - delta );
}

bool CNTLoader::FixImports( void *base, IMAGE_NT_HEADERS *ntHd, IMAGE_IMPORT_DESCRIPTOR *impDesc )
{
	for( ; !IsBadReadPtr( impDesc, sizeof( impDesc ) ) && impDesc->Name; impDesc++ )
	{
		CHAR *pszDllModuleName = (CHAR *)GetPtrFromRVA( ( DWORD )impDesc->Name, ntHd, (BYTE *)base );

		if( pszDllModuleName == NULL )
		{
			DebugShout( "[FixImports] No Name for [Unknown Library]" );

			return false;
		}

		DebugShout( "[FixImports] Running Fix For [%s]", pszDllModuleName );

		HMODULE hRemoteModuleLib = GetRemoteModuleHandleA( pszDllModuleName );

		if( hRemoteModuleLib == NULL )
		{
			hRemoteModuleLib = LoadModuleByNameA( pszDllModuleName );

			if( hRemoteModuleLib == NULL )
			{
				DebugShout( "[FixImports] No Library for [%s]", pszDllModuleName );

				return false;
			}
		}

		DebugShout( "[FixImports] Library for [%s][0x%X]", pszDllModuleName, hRemoteModuleLib );

		IMAGE_THUNK_DATA *itd = ( IMAGE_THUNK_DATA * )GetPtrFromRVA( ( DWORD )impDesc->FirstThunk, ntHd, (BYTE *)base );

		if( !itd )
		{
			DebugShout( "[FixImports] No IMAGE_THUNK_DATA for [%s]", pszDllModuleName );

			return false;
		}

		DebugShout( "[FixImports] IMAGE_THUNK_DATA for [%s] success", pszDllModuleName );

		for( ; itd->u1.AddressOfData != 0; itd++ )
		{
			IMAGE_IMPORT_BY_NAME *iibn = (IMAGE_IMPORT_BY_NAME *)GetPtrFromRVA( ( DWORD )itd->u1.AddressOfData, ntHd, (BYTE *)base ); 

			if( iibn == NULL )
			{
				DebugShout( "[FixImports] No IMAGE_IMPORT_BY_NAME for [0x%X]", itd->u1.AddressOfData );

				return false;
			}

			DebugShout( "[FixImports] IMAGE_IMPORT_BY_NAME for [0x%X] Success", itd->u1.AddressOfData );

			CHAR *pszImportName = (CHAR *)iibn->Name;

			if( pszImportName == NULL )
			{
				DebugShout( "[FixImports] No Import Name for [0x%X]", itd->u1.AddressOfData );

				return false;
			}

			DebugShout( "[FixImports] Import Name for [%s][0x%X]", pszImportName, itd->u1.AddressOfData );

			FARPROC fpRemoteProcAddress = GetRemoteProcAddress( pszDllModuleName, pszImportName );
			
			if( fpRemoteProcAddress == NULL )
			{
				DebugShout( "[FixImports] No Import Address for [%s]", pszImportName );

				return false;
			}

			DebugShout( "[FixImports] Import Address for [%s][0x%X]", pszImportName, fpRemoteProcAddress );

			itd->u1.Function = ( DWORD )fpRemoteProcAddress;
		}
	}

	return true;
}

bool CNTLoader::FixRelocs( void *base, void *rBase, IMAGE_NT_HEADERS *ntHd, IMAGE_BASE_RELOCATION *reloc, unsigned int size )
{
   unsigned long ImageBase = ntHd->OptionalHeader.ImageBase;

   unsigned int nBytes = 0;

   unsigned long delta = MakeDelta(unsigned long, rBase, ImageBase);

   while(1)
   {
		unsigned long *locBase = (unsigned long *)GetPtrFromRVA((DWORD)(reloc->VirtualAddress), ntHd, (PBYTE)base);
		unsigned int numRelocs = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		if(nBytes >= size)
			break;

		unsigned short *locData = MakePtr(unsigned short *, reloc, sizeof(IMAGE_BASE_RELOCATION));
		
		for(unsigned int i = 0; i < numRelocs; i++)
		{       
			if(((*locData >> 12) & IMAGE_REL_BASED_HIGHLOW))
				*MakePtr(unsigned long *, locBase, (*locData & 0x0FFF)) += delta;

			locData++;
		}

		nBytes += reloc->SizeOfBlock;
		reloc = (IMAGE_BASE_RELOCATION *)locData;
	}

	return true;
}

bool CNTLoader::MapSections( void *moduleBase, void *dllBin, IMAGE_NT_HEADERS *ntHd )
{
	IMAGE_SECTION_HEADER *header = IMAGE_FIRST_SECTION(ntHd);
	unsigned int nBytes = 0;
	unsigned int virtualSize = 0;
	unsigned int n = 0;

	for(unsigned int i = 0; ntHd->FileHeader.NumberOfSections; i++)
	{
		if( nBytes >= ntHd->OptionalHeader.SizeOfImage )
			break;

		WriteProcessMemory( GetProcess(),
			MakePtr(LPVOID, moduleBase, header->VirtualAddress),
			MakePtr(LPCVOID, dllBin, header->PointerToRawData),
			header->SizeOfRawData,
			(LPDWORD)&n);

		virtualSize = header->VirtualAddress;
		
		header++;

		virtualSize = header->VirtualAddress - virtualSize;

		nBytes += virtualSize;


		MEMORY_BASIC_INFORMATION mbi;

		VirtualQueryEx( GetProcess(), MakePtr( LPVOID, moduleBase, header->VirtualAddress ), &mbi, sizeof( mbi ) );

		VirtualProtectEx( GetProcess(), mbi.BaseAddress, mbi.RegionSize, header->Characteristics & 0x00FFFFFF, NULL );

		FlushInstructionCache( GetProcess(), mbi.BaseAddress, mbi.RegionSize );
   }

   return true;
}

FARPROC CNTLoader::ResolveModuleStub( const char *pszFunction )
{
	HANDLE hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetProcessId( GetProcess() ) );

	if( hSnap == INVALID_HANDLE_VALUE )
		return NULL;

	MODULEENTRY32 me32;

	me32.dwSize = sizeof( MODULEENTRY32 );

	Module32First( hSnap, &me32 );

	do
	{
		FARPROC fpRemoteProc = GetRemoteProcAddress( me32.szModule, pszFunction );

		if( fpRemoteProc )
		{
			DebugShout( "[ResolveModuleStub] Stub Resolved [%s][%s]", me32.szModule, pszFunction );

			CloseHandle( hSnap );

			return fpRemoteProc;
		}

	} while( Module32Next( hSnap, &me32 ) );

	CloseHandle( hSnap );

	DebugShout( "[ResolveModuleStub] Stub NOT Resolved [%s]", pszFunction );

	return NULL;
}

bool CNTLoader::GetRemoteDOSHeader( HMODULE hRemoteModule, IMAGE_DOS_HEADER *DOSHeader )
{
	if( hRemoteModule == NULL || DOSHeader == NULL ) return false;

	memset( DOSHeader, 0, sizeof( IMAGE_DOS_HEADER ) );

	if( GetMemoryValue( ( void* )hRemoteModule, DOSHeader, sizeof( IMAGE_DOS_HEADER ) ) == FALSE )
		return false;

	if( DOSHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return false;

	if( DOSHeader->e_lfanew >= 0x10000000 )
		return false;

	return true;
}

bool CNTLoader::GetRemoteNTHeaders( HMODULE hRemoteModule, IMAGE_NT_HEADERS *NTHeaders )
{
	if( hRemoteModule == NULL || NTHeaders == NULL ) return false;

	memset( NTHeaders, 0, sizeof( IMAGE_NT_HEADERS ) );

	IMAGE_DOS_HEADER DOSHeader;

	if( GetRemoteDOSHeader( hRemoteModule, &DOSHeader ) == false )
		return false;

	DWORD *dwNTHeaders = (DWORD *)( ( DWORD )hRemoteModule + DOSHeader.e_lfanew );

	if( GetMemoryValue( dwNTHeaders, NTHeaders, sizeof( IMAGE_NT_HEADERS ) ) == FALSE )
		return false;

	if( NTHeaders->Signature != IMAGE_NT_SIGNATURE )
		return false;

	return true;
}

bool CNTLoader::GetRemoteModuleExportDirectory( HMODULE hRemoteModule, IMAGE_EXPORT_DIRECTORY *ExportDirectory )
{
	if( ExportDirectory == NULL || hRemoteModule == NULL ) return false;

	memset( ExportDirectory, 0, sizeof( IMAGE_EXPORT_DIRECTORY ) );

	unsigned char *ucAllocatedPEHeader = new unsigned char[ 0x1000 ];

	if( GetMemoryValue( ( void* )hRemoteModule, ucAllocatedPEHeader, 0x1000 ) )
	{
		IMAGE_DOS_HEADER *pExternalDos = ToDOSHeader( ( HMODULE )ucAllocatedPEHeader );
		IMAGE_NT_HEADERS *pExrernalNts = ToNTHeaders( ( HMODULE )ucAllocatedPEHeader );

		if( pExternalDos && pExrernalNts )
		{
			IMAGE_SECTION_HEADER* pImageSectionHeader = ( IMAGE_SECTION_HEADER* )( ucAllocatedPEHeader + pExternalDos->e_lfanew + sizeof( IMAGE_NT_HEADERS ) );

			for( int i = 0; i < pExrernalNts->FileHeader.NumberOfSections; i++, pImageSectionHeader++ )
			{
				if( pImageSectionHeader == NULL )
					continue;

//				DebugShout( "[GetRemoteModuleExportDirectory] Section Name Currently [%s]", ( CHAR* )pImageSectionHeader->Name );

				if( _stricmp( ( CHAR* )pImageSectionHeader->Name, ".edata" ) == 0 )
				{
//					DebugShout( "[GetRemoteModuleExportDirectory] .edata section found!" );

					if( GetMemoryValue( ( void* )pImageSectionHeader->VirtualAddress, ExportDirectory, sizeof( IMAGE_EXPORT_DIRECTORY ) ) == FALSE )
						continue;

					delete[] ucAllocatedPEHeader;

					return true;
				}
			}

			DWORD dwEATAddress = pExrernalNts->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;

			if( dwEATAddress )
			{
				if( GetMemoryValue( ( void* )( ( DWORD )hRemoteModule + dwEATAddress ), ExportDirectory, sizeof( IMAGE_EXPORT_DIRECTORY ) ) )
				{
//					DebugShout( "[GetRemoteModuleExportDirectory] Used Optional Header" );

					delete[] ucAllocatedPEHeader;

					return true;
				}
			}
		}
	}

	delete[] ucAllocatedPEHeader;

	return false;
}

bool CNTLoader::GetRemoteModuleSectionSizeInformation( HMODULE hRemoteModule, CHAR *pszSection, int *BaseOfSection, int *SizeOfSection )
{
	if( hRemoteModule == NULL || pszSection == NULL || BaseOfSection == NULL || SizeOfSection == NULL ) return false;

	unsigned char *ucAllocatedPEHeader = new unsigned char[ 0x1000 ];
	
	if( ucAllocatedPEHeader == NULL )
		return false;

	if( GetMemoryValue( ( void* )hRemoteModule, ucAllocatedPEHeader, 0x1000 ) == false )
	{
		delete[] ucAllocatedPEHeader;

		return false;
	}

	IMAGE_DOS_HEADER *pExternalDos = ToDOSHeader( ( HMODULE )ucAllocatedPEHeader );
	IMAGE_NT_HEADERS *pExrernalNts = ToNTHeaders( ( HMODULE )ucAllocatedPEHeader );

	if( pExternalDos == NULL || pExrernalNts == NULL )
	{
		delete[] ucAllocatedPEHeader;

		return false;
	}

	IMAGE_SECTION_HEADER* pImageSectionHeader = ( IMAGE_SECTION_HEADER* )( ucAllocatedPEHeader + pExternalDos->e_lfanew + sizeof( IMAGE_NT_HEADERS ) );

	bool bReturnValue = false;

	for( int i = 0; i < pExrernalNts->FileHeader.NumberOfSections; i++, pImageSectionHeader++ )
	{
		if( pImageSectionHeader == NULL )
			continue;

		if( _stricmp( ( CHAR* )pImageSectionHeader->Name, pszSection ) == 0 )
		{
			*BaseOfSection = ( ( int )hRemoteModule + pImageSectionHeader->PointerToRawData );
			*SizeOfSection = ( *BaseOfSection + pImageSectionHeader->SizeOfRawData );

			bReturnValue = true;

			break;
		}
	}

	delete[] ucAllocatedPEHeader;

	return bReturnValue;
}