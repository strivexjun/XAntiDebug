/*******************************************************************
*  Copyright(c) 2017-2017 Company Name
*  All rights reserved.
*
*  文件名称: XAntiDebug.cpp
*  简要描述: 主要反调试逻辑实现
*
*  创建日期: 2017年11月3日 21:46:27
*  作者:	     Xjun
*  说明:	     终极反调试
*
*  修改日期: \
*  作者: \
*  说明: \
******************************************************************/

#include "XAntiDebug.h"

using namespace wow64ext;

//
//禁止目录重定向
//
BOOL safeWow64DisableDirectory(PVOID &arg)
{
	typedef BOOL WINAPI fntype_Wow64DisableWow64FsRedirection(PVOID *OldValue);
	auto pfnWow64DisableWow64FsRedirection = (fntype_Wow64DisableWow64FsRedirection*)\
		GetProcAddress(GetModuleHandleA("kernel32.dll"), "Wow64DisableWow64FsRedirection");

	if (pfnWow64DisableWow64FsRedirection) {

		(*pfnWow64DisableWow64FsRedirection)(&arg);
		return TRUE;
	}
	else {
		return FALSE;
	}
}

//
//恢复目录重定向
//
BOOL safeWow64ReverDirectory(PVOID &arg)
{
	typedef BOOL WINAPI fntype_Wow64RevertWow64FsRedirection(PVOID *OldValue);
	auto pfnWow64RevertWow64FsRedirection = (fntype_Wow64RevertWow64FsRedirection*) \
		GetProcAddress(GetModuleHandleA("kernel32.dll"), "Wow64RevertWow64FsRedirection");

	if (pfnWow64RevertWow64FsRedirection) {

		(*pfnWow64RevertWow64FsRedirection)(&arg);
		return TRUE;
	}
	else {
		return FALSE;
	}
}

//
// 安全的取得真实系统信息
//
VOID SafeGetNativeSystemInfo(__out LPSYSTEM_INFO lpSystemInfo)
{
	if (NULL == lpSystemInfo)    return;
	typedef VOID(WINAPI *LPFN_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
	LPFN_GetNativeSystemInfo fnGetNativeSystemInfo = (LPFN_GetNativeSystemInfo)GetProcAddress(GetModuleHandleA("kernel32"), "GetNativeSystemInfo");;
	if (NULL != fnGetNativeSystemInfo)
	{
		fnGetNativeSystemInfo(lpSystemInfo);
	}
	else
	{
		GetSystemInfo(lpSystemInfo);
	}
}

//
// 获取操作系统位数
//
int GetSystemBits()
{
	SYSTEM_INFO si;
	SafeGetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
	{
		return 64;
	}
	return 32;
}



#ifdef _WIN64
#define GetProcAddress64 GetProcAddress
#define GetModuleHandle64 GetModuleHandle
#define getMem64(a,b,c) memcpy(a,b,c)
#endif // !_WIN64

//
//终极反调试初始化
//
XAD_STATUS XAntiDebug::initialize()
{

	if (GetSystemBits() == 64)
	{
		_isX64 = TRUE;
#ifndef _WIN64
		//InitWow64ext();
#endif // !_WIN64

	}

	// 获取ntapi地址
	if (_isX64)
	{
		_MyQueryInfomationProcess  = (DWORD64)Wow64GetProcAddress64(Wow64GetModuleHandle64(XAD_NTDLL), "ZwQueryInformationProcess");
		if (_MyQueryInfomationProcess == NULL)
		{
			return XAD_ERROR_NTAPI;
		}
		_MyQueryInfomationProcess -= (DWORD64)Wow64GetModuleHandle64(XAD_NTDLL);
	}
	else
	{
		_MyQueryInfomationProcess = (DWORD)GetProcAddress(GetModuleHandleW(XAD_NTDLL), "ZwQueryInformationProcess");
		if (_MyQueryInfomationProcess == NULL)
		{
			return XAD_ERROR_NTAPI;
		}
		_MyQueryInfomationProcess -= (DWORD)GetModuleHandleW(XAD_NTDLL);
	}


	// rva to raw
	DWORD	fileOffset = 0;
	if (_isX64)
	{
		unsigned char pehead[XAD_PEHAD];
		getMem64(pehead, (DWORD64)Wow64GetModuleHandle64(XAD_NTDLL), XAD_PEHAD);

		PIMAGE_DOS_HEADER	pDosHead = (PIMAGE_DOS_HEADER)pehead;
		if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE)
			return XAD_ERROR_FILEOFFSET;
	
		PIMAGE_NT_HEADERS64	pNtHead = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pDosHead + pDosHead->e_lfanew);
		if (pNtHead->Signature != IMAGE_NT_SIGNATURE)
			return XAD_ERROR_FILEOFFSET;

		PIMAGE_SECTION_HEADER	pSection = (PIMAGE_SECTION_HEADER)\
			(sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + pNtHead->FileHeader.SizeOfOptionalHeader + (ULONG_PTR)pNtHead);

		for (int i = 0; i < pNtHead->FileHeader.NumberOfSections; i++)
		{
			if (pSection->VirtualAddress <= _MyQueryInfomationProcess &&
				_MyQueryInfomationProcess <= (pSection->VirtualAddress + pSection->Misc.VirtualSize))
			{
				break;
			}
			pSection++;
		}
		fileOffset = (DWORD)(_MyQueryInfomationProcess - pSection->VirtualAddress + pSection->PointerToRawData);
	}
	else // else 32bit 
	{

		PIMAGE_DOS_HEADER	pDosHead = (PIMAGE_DOS_HEADER)GetModuleHandleW(XAD_NTDLL);
		if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE)
			return XAD_ERROR_FILEOFFSET;

		PIMAGE_NT_HEADERS	pNtHead = (PIMAGE_NT_HEADERS)((char*)pDosHead + pDosHead->e_lfanew);
		if (pNtHead->Signature != IMAGE_NT_SIGNATURE)
			return XAD_ERROR_FILEOFFSET;

		PIMAGE_SECTION_HEADER	pSection = (PIMAGE_SECTION_HEADER)\
			(sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + pNtHead->FileHeader.SizeOfOptionalHeader + (ULONG_PTR)pNtHead);
		for (int i = 0; i < pNtHead->FileHeader.NumberOfSections; i++)
		{
			if (pSection->VirtualAddress <= _MyQueryInfomationProcess &&
				_MyQueryInfomationProcess <= (pSection->VirtualAddress + pSection->Misc.VirtualSize))
			{
				break;
			}
			pSection++;
		}
		fileOffset = (DWORD)(_MyQueryInfomationProcess - pSection->VirtualAddress + pSection->PointerToRawData);
	}
	if (fileOffset == 0)
	{
		return XAD_ERROR_FILEOFFSET;
	}

	// get ssdt index from ntll file offset
	unsigned char opcode[64];
	DWORD readd;
	wchar_t sysDir[MAX_PATH] = { 0 };
	GetSystemDirectoryW(sysDir, MAX_PATH);
	wcscat_s(sysDir, L"\\");
	wcscat_s(sysDir,XAD_NTDLL);

#ifndef _WIN64
	//disable wow64 redirect the directory
	if (_isX64)
		safeWow64DisableDirectory(_wow64FsReDirectory);
#endif 

	HANDLE	hFile = CreateFileW(sysDir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return XAD_ERROR_OPENNTDLL;
	}
	SetFilePointer(hFile, fileOffset, NULL, FILE_CURRENT);
	ReadFile(hFile, opcode, 64, &readd, NULL);
	CloseHandle(hFile);

	ldasm_data  ld;
	unsigned char *pEip = opcode;
	int			len;
	while (TRUE)
	{
		len = ldasm(pEip, &ld, _isX64);
		if (len == 5 && pEip[0] == 0xB8) // mov eax,xxxxxx
		{
			_eax = *(DWORD*)(&pEip[1]);
			break;
		}
		pEip += len;
	}

#ifndef _WIN64
	//restore wow64 redirect the directory
	if (_isX64)
		safeWow64ReverDirectory(_wow64FsReDirectory);
#endif 

	// alloc memory page and write syscall opcode
	unsigned char shellSysCall32[] = {
		0xB8, 0x0, 0x0, 0x0, 0x0,	// mov eax,NtQueryInformationProcess
		0xE8, 0x3, 0x0, 0x0, 0x0,	// call sysentry
		0xC2, 0x14, 0x0,			// ret 0x14
									// sysenter:
		0x8B, 0xD4,					// mov edx,esp
		0x0F, 0x34,					// sysenter
		0xC3						// retn
	};

	unsigned char shellSysCall64[] = {
		0xB8, 0x0, 0x0, 0x0, 0x0,	// mov eax,NtQueryInformationProcess
		0x4C, 0x8B, 0xD1,			// mov r10,rcx
		0x0F, 0x05,					// syscall
		0xC3						// retn
	};
	_executePage = VirtualAllocEx((HANDLE)-1, 0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (_executePage == NULL)
	{
		return XAD_ERROR_ALLOCMEM;
	}

	unsigned int	random;
	ULONG_PTR		pSysCall;

	srand(GetTickCount());
	unsigned char *pRandChar = (unsigned char *)_executePage;
	for (int i = 0; i < 0x1000; i++)
	{
		pRandChar[i] = LOBYTE(rand());
	}
	random = rand() % 0x800 + 0x100;

	//copy ssdt index to opcode
	memcpy(&shellSysCall32[1], &_eax, 4);
	memcpy(&shellSysCall64[1], &_eax, 4);

	// random write opcode to page address
	pSysCall = (ULONG_PTR)_executePage + random;
	
	// copy 32 bit opcode
	pfnSyscall32 = (fn_SysCall32)pSysCall;
	memcpy((void*)pSysCall, shellSysCall32, sizeof(shellSysCall32));
	pSysCall += sizeof(shellSysCall32);

	//copy 64 bit opcode
	pfnSyscall64 = (fn_SysCall64)pSysCall;
	memcpy((void*)pSysCall, shellSysCall64, sizeof(shellSysCall64));

	_crc32 = crc32(_executePage, 0x1000); // first 


	return XAD_OK;
}

//
//终极反调试检测
//
BOOL XAntiDebug::isDebuging()
{

	if (IsDebuggerPresent())
	{
		return TRUE;
	}

	//////////////////////////////////////////////////////////////////////////
	BOOL	debuging = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuging);
	if (debuging)
	{
		return TRUE;
	}
	
	//////////////////////////////////////////////////////////////////////////
	__try{
		CloseHandle((HANDLE)0xDEADC0DE);
	}
	__except (EXCEPTION_EXECUTE_HANDLER){
		return TRUE;
	}
	
	//////////////////////////////////////////////////////////////////////////
	if (_isX64) // 64bit
	{
		DWORD64		processInformation;
		DWORD64		returnLength;
		DWORD64		status;

#ifndef _WIN64
		status = Wow64Call64(pfnSyscall64, 5,
			(DWORD64)-1,   //handle
			(DWORD64)0x1E, // processObjectHandle
			(DWORD64)&processInformation,
			(DWORD64)8,
			(DWORD64)&returnLength);
#else
		status = pfnSyscall64(
			(HANDLE)-1,
			(DWORD64)0x1E,
			(PVOID)&processInformation,
			(DWORD)8,
			(PDWORD64)&returnLength);
#endif // !_WIN64

		

		if (status != 0xC0000353) //STATUS_PORT_NOT_SET 
		{
			return TRUE;
		}
		if (status == 0xC0000353 && processInformation != 0)
		{
			return TRUE;
		}


		// checksum execute page crc32
		if (crc32(_executePage,0x1000) != _crc32)
		{
			return TRUE;
		}

		//利用内核二次覆盖的BUG来检测反调试，在利用这个漏洞之前计算一遍页面CRC
		DWORD64		bugCheck;
#ifndef _WIN64
		status = Wow64Call64(pfnSyscall64, 5,
			(DWORD64)-1,
			(DWORD64)0x1E,
			(DWORD64)&bugCheck,
			(DWORD64)8,
			(DWORD64)&bugCheck);
#else
		status = pfnSyscall64(
			(HANDLE)-1,
			(DWORD64)0x1E,
			(PVOID)&bugCheck,
			(DWORD)8,
			(PDWORD64)&bugCheck);
#endif // !_WIN64

		if (status == 0xC0000353 && bugCheck != 8)
		{
			return TRUE;
		}

	}
	else // 32bit
	{
		DWORD		processInformation;
		DWORD		returnLength;
		DWORD		status;

		status = pfnSyscall32(
			(HANDLE)-1,
			(DWORD)0x1E,
			&processInformation,
			(DWORD)4,
			&returnLength);

		if (status != 0xC0000353) //STATUS_PORT_NOT_SET 
		{
			return TRUE;
		}
		if (status == 0xC0000353 && processInformation != 0)
		{
			return TRUE;
		}

		// checksum execute page crc32
		if (crc32(_executePage, 0x1000) != _crc32)
		{
			return TRUE;
		}

		//利用内核二次覆盖的BUG来检测反调试，在利用这个漏洞之前计算一遍页面CRC
		DWORD		bugCheck;
		status = pfnSyscall32(
			(HANDLE)-1,
			(DWORD)0x1E,
			&bugCheck,
			(DWORD)4,
			&bugCheck);
		if (status == 0xC0000353 && bugCheck != 4)
		{
			return TRUE;
		}
	}

	return FALSE;
}


XAntiDebug::XAntiDebug()
{

}

XAntiDebug::~XAntiDebug()
{
	if (_executePage != NULL)
	{
		VirtualFreeEx((HANDLE)-1, _executePage, 0, MEM_RELEASE);
	}

}