#ifndef _PARAMETERS_H_
#define _PARAMETERS_H_

#include <windows.h>

#define OP_GetProcessArchitecture		0
#define OP_RequestDebugPrivledges		1
#define OP_InjectModuleWithByteArray	2
#define OP_InjectModuleFileToMemory		3
#define OP_InjectModuleFile				4

typedef struct {
	HANDLE			hProcess;
	char*			ProcessModuleName;
} FParams_GetProcessArchitecture;

typedef struct {
} FParams_RequestDebugPrivledges;

typedef struct {
	HANDLE			hProcess;
	unsigned long	BaseOfModule;
	unsigned long	SizeOfModule;
} FParams_InjectModuleWithByteArray;

typedef struct {
	HANDLE			hProcess;
	wchar_t*		File;
} FParams_InjectModuleFileToMemory;

typedef struct {
	HANDLE			hProcess;
	wchar_t*		File;
} FParams_InjectModuleFile;

#endif