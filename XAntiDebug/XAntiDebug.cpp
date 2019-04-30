//Author:Xjun

#include "XAntiDebug.h"

/*
 *	禁止目录重定向
 */
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

/*
 *	恢复目录重定向
 */
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

/*
 *	安全取得系统真实信息
 */
VOID SafeGetNativeSystemInfo(__out LPSYSTEM_INFO lpSystemInfo)
{
	if (NULL == lpSystemInfo)    return;
	typedef VOID(WINAPI *LPFN_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
	LPFN_GetNativeSystemInfo fnGetNativeSystemInfo = \
		(LPFN_GetNativeSystemInfo)GetProcAddress(GetModuleHandleA("kernel32"), "GetNativeSystemInfo");

	if (NULL != fnGetNativeSystemInfo)
	{
		fnGetNativeSystemInfo(lpSystemInfo);
	}
	else
	{
		GetSystemInfo(lpSystemInfo);
	}
}


/*
 *	触发异常，用于检测硬件断点
 */
volatile void __stdcall HardwareBreakpointRoutine(PVOID xAntiDbgClass)
{
	__debugbreak();
	return;
}

/*
 *	VECTORED_EXCEPTION_HANDLER
 */
LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
	//
	// 命中硬件断点，说明是
	//
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
	{
#ifdef _WIN64
		XAntiDebug *antiDbg = (XAntiDebug*)pExceptionInfo->ContextRecord->Rcx;
		if (pExceptionInfo->ContextRecord->Dr0 != 0 ||
			pExceptionInfo->ContextRecord->Dr1 != 0 ||
			pExceptionInfo->ContextRecord->Dr2 != 0 ||
			pExceptionInfo->ContextRecord->Dr3 != 0)
		{
			antiDbg->_isSetHWBP = TRUE;

			//
			// 顺便把你的硬件断点给清理掉
			//
			pExceptionInfo->ContextRecord->Dr0 = 0;
			pExceptionInfo->ContextRecord->Dr1 = 0;
			pExceptionInfo->ContextRecord->Dr2 = 0;
			pExceptionInfo->ContextRecord->Dr3 = 0;
		}

		//
		// 继续执行 int3 opcode len = 1
		//
		pExceptionInfo->ContextRecord->Rip = pExceptionInfo->ContextRecord->Rip + 1;
#else
		XAntiDebug *antiDbg = (XAntiDebug *)(*(DWORD*)(pExceptionInfo->ContextRecord->Esp + 4));
		if (pExceptionInfo->ContextRecord->Dr0 != 0 ||
			pExceptionInfo->ContextRecord->Dr1 != 0 ||
			pExceptionInfo->ContextRecord->Dr2 != 0 ||
			pExceptionInfo->ContextRecord->Dr3 != 0)
		{
			antiDbg->_isSetHWBP = TRUE;

			//
			// 顺便把你的硬件断点给清理掉
			//
			pExceptionInfo->ContextRecord->Dr0 = 0;
			pExceptionInfo->ContextRecord->Dr1 = 0;
			pExceptionInfo->ContextRecord->Dr2 = 0;
			pExceptionInfo->ContextRecord->Dr3 = 0;
		}

		//
		// 继续执行 int3 opcode len = 1
		//
		pExceptionInfo->ContextRecord->Eip = pExceptionInfo->ContextRecord->Eip + 1;
#endif

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}


//////////////////////////////////////////////////////////////////////////

#ifdef _WIN64
#define GetProcAddress64         GetProcAddress
#define GetModuleHandle64        GetModuleHandleW
#define getMem64(dest,src,size)  memcpy(dest,src,size)
#endif

#define XAD_NTDLL                L"ntdll.dll"
#define XAD_PAGESIZE             (0x1000)
#define XAD_MAXOPCODE            (0x64)

/*
 *	构造函数
 */
XAntiDebug::XAntiDebug(HMODULE moduleHandle, DWORD flags)
{
	//
	// 初始化私有变量
	//
	_initialized = FALSE;
	_isArch64 = FALSE;
	_isWow64 = FALSE;
	_isWow64FsReDriectory = FALSE;
	_pagePtr = 0;
	_pageSize = 0;
	_pageCrc32 = 0;
	_pfnSyscall32 = NULL;
	_pfnSyscall64 = NULL;
	_isLoadStrongOD = FALSE;
	_isSetHWBP = FALSE;

	_moduleHandle = moduleHandle;
	_flags = flags;

	SYSTEM_INFO si;
	RTL_OSVERSIONINFOW	osVer;
	SafeGetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
	{
		_isArch64 = TRUE;
	}

	typedef LONG(__stdcall *fnRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);
	fnRtlGetVersion pRtlGetVersion = (fnRtlGetVersion)GetProcAddress(GetModuleHandle(L"ntdll"), "RtlGetVersion");

	if (pRtlGetVersion)
	{
		pRtlGetVersion(&osVer);
	}

	_major = osVer.dwMajorVersion;
	_minor = osVer.dwMinorVersion;

	IsWow64Process((HANDLE)-1, &_isWow64);

	if (_isArch64 && _isWow64)
	{
		_isWow64FsReDriectory = TRUE;
	}

	_pageSize = si.dwPageSize;

	//
	// ThreadHideFromDebugger
	//
	typedef NTSTATUS(NTAPI* fnNtSetInformationThread)(
		_In_ HANDLE ThreadHandle,
		_In_ DWORD_PTR ThreadInformationClass,
		_In_ PVOID ThreadInformation,
		_In_ ULONG ThreadInformationLength
		);

	fnNtSetInformationThread pfnNtSetInformationThread = \
		(fnNtSetInformationThread)GetProcAddress(GetModuleHandleW(XAD_NTDLL), "NtSetInformationThread");
	if (pfnNtSetInformationThread)
	{
#ifndef _DEBUG
		LONG status;

		pfnNtSetInformationThread((HANDLE)-2, 0x11, NULL, NULL);

		//
		// StrongOD 驱动处理不当
		//
		status = pfnNtSetInformationThread((HANDLE)-2, 0x11, (PVOID)sizeof(PVOID), sizeof(PVOID));
		if (status == 0)
		{
			_isLoadStrongOD = TRUE;
		}
#endif
	}
}

/*
 *	析构函数
 */
XAntiDebug::~XAntiDebug()
{
	if (_pagePtr)
	{
		VirtualFreeEx((HANDLE)-1, reinterpret_cast<LPVOID>(_pagePtr), 0, MEM_RELEASE);
	}
}

/*
 *	反调试初始化
 */
XAD_STATUS XAntiDebug::XAD_Initialize()
{
	//
	// 防止重复初始化，造成内存泄漏
	//
	if (_initialized)
	{
		return XAD_OK;
	}

	if ((_flags & FLAG_CHECKSUM_NTOSKRNL) && _major >= 6 && _minor >= 1)
	{
		//
		//检测正在运行的NTOS文件路径. 因NT函数枚举出来的路径是CHAR，这里都用CHAR
		//

		typedef LONG(WINAPI* fnZwQuerySystemInformation)(
			LONG_PTR SystemInformationClass,
			PVOID SystemInformation,
			ULONG SystemInformationLength,
			PULONG ReturnLength
			);

		CHAR	sysDir[MAX_PATH];
		DWORD	MySystemModuleInformation = 11;

		LONG	status;
		ULONG	systemModuleSize = 0;
		PVOID	systemModuleBuf;

		fnZwQuerySystemInformation pfnZwQuerySystemInformation;

		GetSystemDirectoryA(sysDir, MAX_PATH);
		pfnZwQuerySystemInformation = \
			(fnZwQuerySystemInformation)GetProcAddress(GetModuleHandleW(XAD_NTDLL), "ZwQuerySystemInformation");
		if (!pfnZwQuerySystemInformation)
		{
			return XAD_ERROR_OPENNTOS;
		}

		pfnZwQuerySystemInformation(MySystemModuleInformation, NULL, NULL, &systemModuleSize);
		if (systemModuleSize == 0)
		{
			return XAD_ERROR_OPENNTOS;
		}

		systemModuleBuf = calloc(1, systemModuleSize);
		status = pfnZwQuerySystemInformation(MySystemModuleInformation, systemModuleBuf, systemModuleSize, &systemModuleSize);
		if (status != 0) //STATUS_SUCCESS
		{
			return XAD_ERROR_OPENNTOS;
		}

		//
		// 这里是系统模块链表 第一个就是ntos的路径，从这里取得文件名
		//
		char *src = (char*)systemModuleBuf;
		char *match = "\\SystemRoot\\system32\\";
		size_t	matchLen = strlen(match);
		for (size_t i = 0; i < (systemModuleSize - matchLen); i++, src++)
		{
			if (strncmp(src, match, matchLen) == 0)
			{
				break;
			}
		}
		src = PathFindFileNameA(src);
		strcpy(_ntosPath, sysDir);
		strcat(_ntosPath, "\\");
		strcat(_ntosPath, src);
		free(systemModuleBuf);
	}

	if (_flags & FLAG_CHECKSUM_CODESECTION)
	{
		PIMAGE_DOS_HEADER	dosHead;
		PIMAGE_NT_HEADERS	ntHead;
		PIMAGE_SECTION_HEADER secHead;
		CODE_CRC32	codeSection;

		if (IsBadReadPtr(_moduleHandle, sizeof(void*)) == 0)
		{
			dosHead = (PIMAGE_DOS_HEADER)_moduleHandle;

			if (dosHead == NULL || dosHead->e_magic != IMAGE_DOS_SIGNATURE)
			{
				return XAD_ERROR_MODULEHANDLE;
			}

			ntHead = ImageNtHeader(dosHead);
			if (ntHead == NULL || ntHead->Signature != IMAGE_NT_SIGNATURE)
			{
				return XAD_ERROR_MODULEHANDLE;
			}

			secHead = IMAGE_FIRST_SECTION(ntHead);
			_codeCrc32.clear();

			for (size_t Index = 0; Index < ntHead->FileHeader.NumberOfSections; Index++)
			{
				//
				//可读、不可写的区段默认全部校验
				//

				if ((secHead->Characteristics & IMAGE_SCN_MEM_READ) &&
					!(secHead->Characteristics & IMAGE_SCN_MEM_WRITE))
				{
					codeSection.m_va = (PVOID)((DWORD_PTR)_moduleHandle + secHead->VirtualAddress);
					codeSection.m_size = secHead->Misc.VirtualSize;
					codeSection.m_crc32 = crc32(codeSection.m_va, codeSection.m_size);
					_codeCrc32.push_back(codeSection);
				}
				secHead++;
			}
		}

	}

	if (_flags & FLAG_DETECT_DEBUGGER)
	{
		if (_isArch64)
		{
			//
			// 首先获取 ZwQueryInformationProcess函数地址
			//
#ifndef _WIN64
			InitWow64Ext();
#endif
			_MyQueryInfomationProcess = (DWORD64)GetProcAddress64(GetModuleHandle64(XAD_NTDLL), "ZwQueryInformationProcess");
			if (_MyQueryInfomationProcess == NULL)
			{
				return XAD_ERROR_NTAPI;
			}
			_MyQueryInfomationProcess -= (DWORD64)GetModuleHandle64(XAD_NTDLL);
		}
		else
		{
#ifndef _WIN64
			_MyQueryInfomationProcess = (DWORD)GetProcAddress(GetModuleHandleW(XAD_NTDLL), "ZwQueryInformationProcess");
			if (_MyQueryInfomationProcess == NULL)
			{
				return XAD_ERROR_NTAPI;
			}
			_MyQueryInfomationProcess -= (DWORD)GetModuleHandleW(XAD_NTDLL);
#else
			__debugbreak();
#endif
		}

		//
		//从 ntdll 虚拟地址转换到实际文件偏移数据
		//
		DWORD	fileOffset = 0;
		if (_isArch64)
		{
			unsigned char pehead[XAD_PAGESIZE];
			getMem64(pehead, GetModuleHandle64(XAD_NTDLL), XAD_PAGESIZE);

			PIMAGE_DOS_HEADER	pDosHead = (PIMAGE_DOS_HEADER)pehead;
			if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE)
				return XAD_ERROR_FILEOFFSET;

			PIMAGE_NT_HEADERS64	pNtHead = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pDosHead + pDosHead->e_lfanew);
			if (pNtHead->Signature != IMAGE_NT_SIGNATURE)
				return XAD_ERROR_FILEOFFSET;

			PIMAGE_SECTION_HEADER	pSection = (PIMAGE_SECTION_HEADER)\
				(sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + pNtHead->FileHeader.SizeOfOptionalHeader + (ULONG_PTR)pNtHead);

			for (size_t i = 0; i < pNtHead->FileHeader.NumberOfSections; i++)
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
		else
		{
			PIMAGE_DOS_HEADER	pDosHead = (PIMAGE_DOS_HEADER)GetModuleHandleW(XAD_NTDLL);
			if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE)
				return XAD_ERROR_FILEOFFSET;

			PIMAGE_NT_HEADERS	pNtHead = (PIMAGE_NT_HEADERS)((char*)pDosHead + pDosHead->e_lfanew);
			if (pNtHead->Signature != IMAGE_NT_SIGNATURE)
				return XAD_ERROR_FILEOFFSET;

			PIMAGE_SECTION_HEADER	pSection = (PIMAGE_SECTION_HEADER)\
				(sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + pNtHead->FileHeader.SizeOfOptionalHeader + (ULONG_PTR)pNtHead);
			for (size_t i = 0; i < pNtHead->FileHeader.NumberOfSections; i++)
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

		//
		// 读ntdll文件，使用ldasm反汇编函数头部，得出SSDT Index
		//
#ifndef _WIN64
		PVOID _wow64FsReDirectory;
#endif
		unsigned char opcode[XAD_MAXOPCODE];
		DWORD readd;
		TCHAR sysDir[MAX_PATH] = { 0 };
		HANDLE hFile;
		GetSystemDirectory(sysDir, MAX_PATH);
		_tcscat(sysDir, _T("\\ntdll.dll"));

#ifndef _WIN64
		if (_isWow64FsReDriectory)
			safeWow64DisableDirectory(_wow64FsReDirectory);
#endif 

		hFile = CreateFile(sysDir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			return XAD_ERROR_OPENNTDLL;
		}
		SetFilePointer(hFile, fileOffset, NULL, FILE_CURRENT);
		ReadFile(hFile, opcode, XAD_MAXOPCODE, &readd, NULL);
		CloseHandle(hFile);

		ldasm_data ld;
		unsigned char *pEip = opcode;
		size_t len;
		while (TRUE)
		{
			len = ldasm(pEip, &ld, _isArch64);
			if (len == 5 && pEip[0] == 0xB8) // mov eax,xxxxxx
			{
				_eax = *(DWORD*)(&pEip[1]);
				break;
			}
			pEip += len;
		}

#ifndef _WIN64
		if (_isWow64FsReDriectory)
			safeWow64ReverDirectory(_wow64FsReDirectory);
#endif 

		//
		// 申请内存，组合shellcode，直接调用syscall
		//
		unsigned char shellSysCall32[] = {
			0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,NtQueryInformationProcess
			0xE8, 0x3, 0x0, 0x0, 0x0,   // call sysentry
			0xC2, 0x14, 0x0,            // ret 0x14
			// sysenter:
			0x8B, 0xD4,                 // mov edx,esp
			0x0F, 0x34,                 // sysenter
			0xC3                        // retn
		};

		unsigned char shellSysCall64[] = {
			0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,NtQueryInformationProcess
			0x4C, 0x8B, 0xD1,           // mov r10,rcx
			0x0F, 0x05,                 // syscall
			0xC3                        // retn
		};
		_pagePtr = VirtualAllocEx((HANDLE)-1, 0, _pageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (_pagePtr == NULL)
		{
			return XAD_ERROR_ALLOCMEM;
		}

		size_t random;
		ULONG_PTR pSysCall;

		srand(GetTickCount());
		unsigned char *pRandChar = (unsigned char *)_pagePtr;
		for (size_t i = 0; i < _pageSize; i++)
		{
			pRandChar[i] = LOBYTE(rand());
		}

		//
		// 把代码随机拷贝在页内存当中，要检查内存页边界，防止崩溃
		//
		random = rand() % (_pageSize - (sizeof(shellSysCall32) + sizeof(shellSysCall64)));

		memcpy(&shellSysCall32[1], &_eax, 4);
		memcpy(&shellSysCall64[1], &_eax, 4);

		pSysCall = (ULONG_PTR)_pagePtr + random;

		_pfnSyscall32 = (fn_SysCall32)pSysCall;
		memcpy((void*)pSysCall, shellSysCall32, sizeof(shellSysCall32));
		pSysCall += sizeof(shellSysCall32);

		_pfnSyscall64 = (fn_SysCall64)pSysCall;
		memcpy((void*)pSysCall, shellSysCall64, sizeof(shellSysCall64));

		_pageCrc32 = crc32(_pagePtr, _pageSize);

		return XAD_OK;

	}

	if (_flags & FLAG_DETECT_HARDWAREBREAKPOINT)
	{
		// 不需要初始化
		;
	}

	return XAD_OK;
}

/*
 *	执行检测
 */
BOOL XAntiDebug::XAD_ExecuteDetect()
{
	BOOL       result = FALSE;

	if ((_flags & FLAG_CHECKSUM_NTOSKRNL) && _major >= 6 && _minor >= 1)
	{
		WCHAR	pwszSourceFile[MAX_PATH];
		SHAnsiToUnicode(_ntosPath, pwszSourceFile, MAX_PATH);

		// https://docs.microsoft.com/zh-cn/windows/desktop/SecCrypto/example-c-program--verifying-the-signature-of-a-pe-file
		LONG lStatus;

		// Initialize the WINTRUST_FILE_INFO structure.

		WINTRUST_FILE_INFO FileData;
		memset(&FileData, 0, sizeof(FileData));
		FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
		FileData.pcwszFilePath = pwszSourceFile;
		FileData.hFile = NULL;
		FileData.pgKnownSubject = NULL;

		/*
		WVTPolicyGUID specifies the policy to apply on the file
		WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

		1) The certificate used to sign the file chains up to a root
		certificate located in the trusted root certificate store. This
		implies that the identity of the publisher has been verified by
		a certification authority.

		2) In cases where user interface is displayed (which this example
		does not do), WinVerifyTrust will check for whether the
		end entity certificate is stored in the trusted publisher store,
		implying that the user trusts content from this publisher.

		3) The end entity certificate has sufficient permission to sign
		code, as indicated by the presence of a code signing EKU or no
		EKU.
		*/

		GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		WINTRUST_DATA WinTrustData;

		// Initialize the WinVerifyTrust input data structure.

		// Default all fields to 0.
		memset(&WinTrustData, 0, sizeof(WinTrustData));

		WinTrustData.cbStruct = sizeof(WinTrustData);

		// Use default code signing EKU.
		WinTrustData.pPolicyCallbackData = NULL;

		// No data to pass to SIP.
		WinTrustData.pSIPClientData = NULL;

		// Disable WVT UI.
		WinTrustData.dwUIChoice = WTD_UI_NONE;

		// No revocation checking.
		WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

		// Verify an embedded signature on a file.
		WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

		// Verify action.
		WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

		// Verification sets this value.
		WinTrustData.hWVTStateData = NULL;

		// Not used.
		WinTrustData.pwszURLReference = NULL;

		// This is not applicable if there is no UI because it changes 
		// the UI to accommodate running applications instead of 
		// installing applications.
		WinTrustData.dwUIContext = 0;

		// Set pFile.
		WinTrustData.pFile = &FileData;

		// WinVerifyTrust verifies signatures as specified by the GUID 
		// and Wintrust_Data.
		lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

		// Any hWVTStateData must be released by a call with close.
		WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
		if (lStatus != ERROR_SUCCESS)
		{
			return TRUE;
		}
	}

	if (_flags & FLAG_CHECKSUM_CODESECTION)
	{
		for (size_t i = 0; i < _codeCrc32.size(); i++)
		{
			if (crc32(_codeCrc32[i].m_va, _codeCrc32[i].m_size) != _codeCrc32[i].m_crc32)
			{
				return TRUE;
			}
		}
	}

	if (_flags & FLAG_DETECT_DEBUGGER)
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
			CloseHandle(ULongToHandle(0xDEADC0DE));
		}
		__except (EXCEPTION_EXECUTE_HANDLER){
			return TRUE;
		}

		//////////////////////////////////////////////////////////////////////////
		typedef enum _MYOBJECT_INFORMATION_CLASS
		{
			ObjectBasicInformation, // OBJECT_BASIC_INFORMATION
			ObjectNameInformation, // OBJECT_NAME_INFORMATION
			ObjectTypeInformation, // OBJECT_TYPE_INFORMATION
			ObjectTypesInformation, // OBJECT_TYPES_INFORMATION
			ObjectHandleFlagInformation, // OBJECT_HANDLE_FLAG_INFORMATION
			ObjectSessionInformation,
			ObjectSessionObjectInformation,
			MaxObjectInfoClass
		} MYOBJECT_INFORMATION_CLASS;

		typedef struct _MYOBJECT_HANDLE_FLAG_INFORMATION
		{
			BOOLEAN Inherit;
			BOOLEAN ProtectFromClose;
		} MYOBJECT_HANDLE_FLAG_INFORMATION, *PMYOBJECT_HANDLE_FLAG_INFORMATION;

		typedef NTSTATUS(WINAPI *fnNtSetInformationObject)(
			_In_ HANDLE Handle,
			_In_ MYOBJECT_INFORMATION_CLASS ObjectInformationClass,
			_In_ PVOID ObjectInformation,
			_In_ ULONG ObjectInformationLength
			);

		HANDLE processHandle1, processHandle2;
		fnNtSetInformationObject pfnNtSetInformationObject = \
			(fnNtSetInformationObject)GetProcAddress(GetModuleHandleW(XAD_NTDLL), "ZwSetInformationObject");
		MYOBJECT_HANDLE_FLAG_INFORMATION objInfo = { 0 };
		objInfo.Inherit = false;
		objInfo.ProtectFromClose = true;

		__try{
			processHandle1 = GetCurrentProcess();
			DuplicateHandle(processHandle1, processHandle1, processHandle1, &processHandle2, 0, FALSE, 0);
			pfnNtSetInformationObject(processHandle2, ObjectHandleFlagInformation, &objInfo, sizeof(objInfo));
			DuplicateHandle(processHandle1, processHandle2, processHandle1, &processHandle2, 0, FALSE, DUPLICATE_CLOSE_SOURCE);

		}
		__except (EXCEPTION_EXECUTE_HANDLER){
			return TRUE;
		}

		//////////////////////////////////////////////////////////////////////////
		if (_isLoadStrongOD)
		{
			return TRUE;
		}

		//////////////////////////////////////////////////////////////////////////
		if (_isArch64)
		{
			DWORD64		processInformation;
			DWORD64		returnLength;
			DWORD64		status;

#ifndef _WIN64
			status = X64Call(
				(DWORD64)_pfnSyscall64,
				5,
				(DWORD64)-1,
				(DWORD64)0x1E,
				(DWORD64)&processInformation,
				(DWORD64)8,
				(DWORD64)&returnLength);
#else
			status = _pfnSyscall64(
				(DWORD64)-1,
				(DWORD64)0x1E,
				(PDWORD64)&processInformation,
				(DWORD64)8,
				(PDWORD64)&returnLength);
#endif

			if (status != 0xC0000353) //STATUS_PORT_NOT_SET 
			{
				return TRUE;
			}
			if (status == 0xC0000353 && processInformation != 0)
			{
				return TRUE;
			}

			//
			// 利用内核二次覆盖的BUG来检测反调试，在利用这个漏洞之前计算一遍页面CRC
			//
			if (crc32(_pagePtr, _pageSize) != _pageCrc32)
			{
				return TRUE;
			}

			DWORD64		bugCheck;
#ifndef _WIN64
			status = X64Call(
				(DWORD64)_pfnSyscall64,
				5,
				(DWORD64)-1,
				(DWORD64)0x1E,
				(DWORD64)&bugCheck,
				(DWORD64)8,
				(DWORD64)&bugCheck);
#else
			status = _pfnSyscall64(
				(DWORD64)-1,
				(DWORD64)0x1E,
				(PDWORD64)&bugCheck,
				(DWORD64)8,
				(PDWORD64)&bugCheck);
#endif 
			if (status == 0xC0000353 && bugCheck != 8)
			{
				return TRUE;
			}
		}
		else
		{
			DWORD		processInformation;
			DWORD		returnLength;
			DWORD		status;

			status = _pfnSyscall32(
				(DWORD)-1,
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

			//
			// 利用内核二次覆盖的BUG来检测反调试，在利用这个漏洞之前计算一遍页面CRC
			//
			if (crc32(_pagePtr, _pageSize) != _pageCrc32)
			{
				return TRUE;
			}

			DWORD		bugCheck;
			status = _pfnSyscall32(
				(DWORD)-1,
				(DWORD)0x1E,
				&bugCheck,
				(DWORD)4,
				&bugCheck);
			if (status == 0xC0000353 && bugCheck != 4)
			{
				return TRUE;
			}
		}
	}

	if (_flags & FLAG_DETECT_HARDWAREBREAKPOINT)
	{
		//
		// 方法1
		//
		CONTEXT	ctx = { 0 };
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (GetThreadContext((HANDLE)-2, &ctx))
		{
			if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
			{
				return TRUE;
			}
		}

		//
		// 方法2
		//

		AddVectoredExceptionHandler(0, VectoredExceptionHandler);

		typedef void(__stdcall *fnMakeException)(PVOID lparam);
		fnMakeException pfnMakeException = (fnMakeException)HardwareBreakpointRoutine;
		pfnMakeException(this);

		RemoveVectoredExceptionHandler(VectoredExceptionHandler);

		if (_isSetHWBP)
		{
			return TRUE;
		}
	}

	return FALSE;
}