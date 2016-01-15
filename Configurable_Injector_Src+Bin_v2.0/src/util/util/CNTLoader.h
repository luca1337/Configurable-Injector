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

#include <windows.h>
#include <winnt.h>

#ifndef _CNTLOADER_H_
#define _CNTLOADER_H_

#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))
#define MakeDelta(cast, x, y) (cast) ( (DWORD_PTR)(x) - (DWORD_PTR)(y))

typedef PIMAGE_NT_HEADERS (NTAPI *RtlImageNtHeader_t)( PVOID ModuleAddress );

class CNTLoader : public CRemoteCode
{
public:

	HMODULE						LoadModuleByNameA( char *szString );
	HMODULE						LoadModuleByNameW( wchar_t *szString );
	HMODULE						LoadModuleByNameIntoMemoryA( char *szString );
	HMODULE						LoadModuleByNameIntoMemoryW( wchar_t *szString );
	HMODULE						LoadModuleFromMemory( unsigned long BaseAddress, unsigned long SizeOfModule );

public:

	HMODULE						GetRemoteModuleHandleA( const char *szModule );
	HMODULE						GetRemoteModuleHandleW( const wchar_t *szModule );
	FARPROC						GetRemoteProcAddress( const char *szModule, const char *szFunction );
	BOOL						GetMemoryValue( void *Address, void *Buffer, int Size );

private:

	PIMAGE_DOS_HEADER NTAPI		ToDOSHeader( HMODULE hModule );
	PIMAGE_NT_HEADERS NTAPI		ToNTHeaders( HMODULE hModule );
	PIMAGE_SECTION_HEADER		GetEnclosingSectionHeader( DWORD rva, PIMAGE_NT_HEADERS pNTHeader );
	LPVOID						GetPtrFromRVA( DWORD rva, IMAGE_NT_HEADERS *pNTHeader, PBYTE imageBase );
	bool						FixImports( void *base, IMAGE_NT_HEADERS *ntHd, IMAGE_IMPORT_DESCRIPTOR *impDesc );
	bool						FixRelocs( void *base, void *rBase, IMAGE_NT_HEADERS *ntHd, IMAGE_BASE_RELOCATION *reloc, unsigned int size );
	bool						MapSections( void *moduleBase, void *dllBin, IMAGE_NT_HEADERS *ntHd );
	FARPROC						ResolveModuleStub( const char *pszFunction );

private:

	bool						GetRemoteDOSHeader( HMODULE hRemoteModule, IMAGE_DOS_HEADER *DOSHeader );
	bool						GetRemoteNTHeaders( HMODULE hRemoteModule, IMAGE_NT_HEADERS *NTHeaders );
	bool						GetRemoteModuleSectionHeader( HMODULE hRemoteModule, char *pszSectionName, IMAGE_SECTION_HEADER *SectionHeader );
	bool						GetRemoteModuleExportDirectory( HMODULE hRemoteModule, IMAGE_EXPORT_DIRECTORY *ExportDirectory );
	bool						GetRemoteModuleSectionSizeInformation( HMODULE hRemoteModule, CHAR *pszSection, int *BaseOfSection, int *SizeOfSection );
};

#endif