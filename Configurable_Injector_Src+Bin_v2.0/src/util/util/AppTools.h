#include <windows.h>
#include <time.h>
#include <fstream>
using namespace std;

#ifndef C_APPTOOLS
#define C_APPTOOLS

#ifdef MessageBox
#undef MessageBox
#endif

class cAppTools
{
public:
	string		GetDirectoryFile( string file );
	void		__cdecl AddToLogFile( char *szLog, ... );
	void		BaseUponModule( HMODULE hModule );
	void		MessageBox( string Message, string Caption );

	string		GetFileExtension( string file );
	string		GetAfterLast( string haystack, string needle );
	string		GetToLast( string haystack, string needle );
	
	DWORD		FindPattern( DWORD dwAddress, DWORD dwLen, char *szbMask, char* szMask );

	ofstream	ofile;
	string		dlldir;
	HMODULE		m_hSelf;

private:

	bool bDataCompare( const BYTE* pData, const BYTE* bMask, const char* szMask );
};

#define VAR_NAME( x ) #x
#define LOG_OFFSET( y ) gApp.AddToLogFile( "%s = 0x%X", #y, y );
#define LOG_VARIABLE( y ) gApp.AddToLogFile( "%s (0x%X)", #y, y );

#endif

extern cAppTools gApp;