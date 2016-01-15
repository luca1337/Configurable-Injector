#include "stdafx.h"
#include <windows.h>
#include "AppTools.h"

cAppTools gApp;

string cAppTools::GetDirectoryFile( string file )
{
	string path = dlldir;
	path += file;
	return path;
}

void __cdecl cAppTools::AddToLogFile( char *szLog, ... )
{
	FILE * fp;
	
	va_list va_alist;
	
	time_t current_time;
	
	struct tm * current_tm;
	
	char logbuf[ 1024 ] = { 0 };

	time (&current_time);
	
	current_tm = localtime (&current_time);

	sprintf (logbuf, "[ %02d:%02d:%02d ] ", current_tm->tm_hour, current_tm->tm_min, current_tm->tm_sec);

	va_start( va_alist, szLog );
	
	_vsnprintf( logbuf + strlen( logbuf ), sizeof( logbuf ) - strlen( logbuf ), szLog, va_alist );
	
	va_end( va_alist );

	if ( ( fp = fopen ( GetDirectoryFile( "util.log" ).c_str(), "a" ) ) != NULL )
	{
		fprintf( fp, "%s\n", logbuf );

		fclose( fp );
	}
}

void cAppTools::BaseUponModule( HMODULE hModule )
{
	m_hSelf = hModule;

	char dd[ MAX_PATH ];

  	GetModuleFileNameA( hModule, dd, MAX_PATH );

	//MessageBoxA( 0, dd, "ONE", MB_OK );

	dlldir = GetToLast(string(dd), "\\");
	dlldir += string("\\");
}

void cAppTools::MessageBox( string Message, string Caption )
{
	MessageBoxA( 0, Message.c_str(), Caption.c_str(), MB_OK );
}

string cAppTools::GetFileExtension( string file )
{
	return GetAfterLast( file, "." );
}

string cAppTools::GetAfterLast( string haystack, string needle )
{
	return haystack.substr( haystack.find_last_of( needle ) + needle.length() );
}

string cAppTools::GetToLast( string haystack, string needle )
{
	return haystack.substr( 0, haystack.find_last_of( needle ) );
}

bool cAppTools::bDataCompare( const BYTE* pData, const BYTE* bMask, const char* szMask )
{
    for( ; *szMask; ++szMask, ++pData, ++bMask )
	{
        if( *szMask == 'x' && *pData != *bMask ) 
		{
            return false;
		}
	}
    return ( *szMask ) == NULL;
}

DWORD cAppTools::FindPattern( DWORD dwAddress, DWORD dwLen, char *szbMask, char* szMask )
{
	if( strlen( szbMask ) != strlen( szMask ) )
	{
		AddToLogFile( "Error in mask( 0x%X, 0x%X, %s, %s )( Length mismatch )",
			dwAddress, dwLen, szbMask, szMask );
	}

    for( DWORD i=0; i < dwLen; i++ )
	{
		if( bDataCompare( ( BYTE* )( dwAddress + i ), (BYTE *)szbMask, szMask) )
		{
			return ( DWORD )( dwAddress + i );
		}
	}
    return 0;
}