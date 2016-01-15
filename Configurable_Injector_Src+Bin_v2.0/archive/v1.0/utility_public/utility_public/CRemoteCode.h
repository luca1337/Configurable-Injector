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
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include "X86.h"

using namespace std;

typedef void (__cdecl *DebugShout_t)( string shout );

//these are the only types supported at the moment
typedef enum {
	CCONV_CDECL					= 0,
	CCONV_STDCALL				= 1,
	CCONV_THISCALL				= 2,
	CCONV_FASTCALL				= 3
} calling_convention_t;

//
typedef enum {
	PARAMETER_TYPE_INT			= 0,
	PARAMETER_TYPE_BOOL			= 1,
	PARAMETER_TYPE_SHORT		= 2,
	PARAMETER_TYPE_FLOAT		= 3,
	PARAMETER_TYPE_BYTE			= 4,
	PARAMETER_TYPE_POINTER		= 5,
	PARAMETER_TYPE_STRING		= 6,
	PARAMETER_TYPE_WSTRING		= 7
} parameter_type_t;

//
typedef struct {
	parameter_type_t			ptype;
	void*						pparam;
} parameter_info_t;

//
typedef struct {
	calling_convention_t		cconv;
	vector<parameter_info_t>	params;
	unsigned long				calladdress;
} invoke_info_t;

//
typedef vector<unsigned char>	remote_thread_buffer_t;
typedef vector<DebugShout_t>	debug_proc_list_t;

class CRemoteCode
{
public:

	CRemoteCode( HANDLE hProcess );

	void					RegisterDebugProc( DebugShout_t proc );

	void					PushParameter( parameter_type_t param_type, void *param );
	
	void					PushInt( int i );
	void					PushBool( bool b );
	void					PushShort( short s );
	void					PushFloat( float f );
	void					PushByte( unsigned char uc );
	void					PushPointer( void *ptr );
	void					PushANSIString( char *szString );
	void					PushUNICODEString( wchar_t *szString );

	void					PushCall( calling_convention_t cconv, FARPROC CallAddress );

	remote_thread_buffer_t	AssembleRemoteThreadBuffer();

	bool					ExecuteRemoteThreadBuffer( remote_thread_buffer_t thread_data, bool async = true );

	void					DebugShoutBufferHex();
	void					DebugPrintThreadToFile( string file );

	void*					CommitMemory( void *data, size_t size_of_data );
	void*					RemoteAllocateMemory( unsigned long size );
	void					RemoteFreeMemory( void *address, unsigned long size );

	string					CallingConventionToString( calling_convention_t cconv );
	string					ParameterTypeToString( parameter_type_t type );

private:

	void					AddByteToBuffer( unsigned char in );
	void					AddLongToBuffer( unsigned long in );
	void					PushAllParameters( bool right_to_left = true );
	void					DebugShout( const char *szShout, ... );

	HANDLE					m_hProcess;
	invoke_info_t			m_CurrentInvokeInfo;
	remote_thread_buffer_t	m_CurrentRemoteThreadBuffer;
	debug_proc_list_t		m_DebugProcList;
};