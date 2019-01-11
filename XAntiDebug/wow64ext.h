/**
*
* WOW64Ext Library
*
* Copyright (c) 2014 ReWolf
* http://blog.rewolf.pl/
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published
* by the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*/


#pragma once
#include "sdkext.h"


#ifdef _WIN64
#error Cannot compile in 64-bit environment!
#endif

#ifdef _WINDLL
#   define wow64ext_api __cdecl
#   define wow64ext_pub extern"C" __declspec(dllexport)
#else
#   define wow64ext_api __cdecl
#   define wow64ext_pub extern"C"
#endif


namespace wow64ext
{

    using namespace sdkext;
    
    wow64ext_pub auto wow64ext_api Wow64CopyMemory64(
        _Out_bytecap_(aBytes)   PVOID64 aDst,
        _In_bytecount_(aBytes)  PVOID64 aSrc,
        _In_                    UINT64  aBytes
    )->VOID;

    wow64ext_pub auto wow64ext_api Wow64CompareMemory64(
        _In_bytecount_(aBytes)  PVOID64 aDst,
        _In_bytecount_(aBytes)  PVOID64 aSrc,
        _In_                    UINT64  aBytes
    )->bool;

    wow64ext_pub auto wow64ext_api Wow64Call64(
        _In_                    PVOID64 aFunc,
        _In_                    int     aArgsCount,
        _In_opt_                ...     /*Args*/
    )->UINT64;

    wow64ext_pub auto wow64ext_api ZwWow64CurrentTeb64(
    )->PVOID64 /*TEB64*/;

    wow64ext_pub auto wow64ext_api ZwWow64CurrentPeb64(
    )->PVOID64 /*PEB64*/;
    
    wow64ext_pub auto wow64ext_api Wow64GetModuleHandle64(
        _In_                    LPCWSTR aModuleName
    )->PVOID64;

    wow64ext_pub auto wow64ext_api Wow64GetNtdll64(
    )->PVOID64;

    wow64ext_pub auto wow64ext_api Wow64GetLdrGetProcedureAddress64(
    )->PVOID64;

    wow64ext_pub auto wow64ext_api Wow64GetProcAddress64(
        _In_                    PVOID64 aModule,
        _In_                    LPCSTR  aProcName
    )->PVOID64;

    wow64ext_pub auto wow64ext_api Wow64SetLastErrorFromNtStatus(
        NTSTATUS    aStatus
    )->NTSTATUS;

}

namespace wow64ext
{

    wow64ext_pub NTSTATUS wow64ext_api NtWow64QueryVirtualMemory64(
        _In_                HANDLE64    aProcessHandle,
        _In_                PVOID64     aBaseAddress,
        _In_ MEMORY_INFORMATION_CLASS   aMemoryInformationClass,
        _Out_writes_bytes_(aMemoryInformationBytes) PVOID aMemoryInformation,
        _In_                UINT64      aMemoryInformationBytes,
        _Out_opt_           PUINT64     aReturnLength
    );

    wow64ext_pub NTSTATUS wow64ext_api NtWow64AllocateVirtualMemory64(
        _In_                HANDLE64    aProcessHandle,
        _In_bytecount_(*aRegionSize) PVOID64* aBaseAddress,
        _In_                UINT64      aZeroBits,
        _Inout_             PUINT64     aRegionSize,
        _In_                UINT32      aAllocationType,
        _In_                UINT32      aProtect
    );

    wow64ext_pub NTSTATUS wow64ext_api NtWow64FreeVirtualMemory64(
        _In_                HANDLE64    aProcessHandle,
        _Inout_             PVOID64*    aBaseAddress,
        _Inout_             PUINT64     aRegionSize,
        _In_                UINT32       aFreeType
    );

    wow64ext_pub NTSTATUS wow64ext_api NtWow64ProtectVirtualMemory64(
        _In_                HANDLE64    aProcessHandle,
        _Inout_             PVOID64 *   aBaseAddress,
        _Inout_             PUINT64     aRegionSize,
        _In_                UINT32      aNewProtect,
        _Out_               PUINT32     aOldProtect
    );

    wow64ext_pub NTSTATUS wow64ext_api NtWow64ReadVirtualMemory64(
        _In_                HANDLE64    aProcessHandle,
        _In_opt_            PVOID64     aBaseAddress,
        _Out_writes_bytes_(aBufferSize) PVOID aBuffer,
        _In_                UINT64      aBufferSize,
        _Out_opt_           PUINT64     aNumberOfBytesRead
    );

    wow64ext_pub NTSTATUS wow64ext_api NtWow64WriteVirtualMemory64(
        _In_                HANDLE64    aProcessHandle,
        _In_opt_            PVOID64     aBaseAddress,
        _In_reads_bytes_(aBufferSize)   PVOID aBuffer,
        _In_                UINT64      aBufferSize,
        _Out_opt_           PUINT64     aNumberOfBytesWritten
    );

    wow64ext_pub NTSTATUS wow64ext_api NtWow64FlushInstructionCache64(
        _In_                HANDLE64    aProcessHandle,
        _In_opt_            PVOID64     aBaseAddress,
        _In_                UINT64      aLength
    );

    wow64ext_pub NTSTATUS wow64ext_api NtWow64MapViewOfSection64(
        _In_                HANDLE64        aSectionHandle,
        _In_                HANDLE64        aProcessHandle,
        _Inout_bytecap_(*aViewSize) PVOID64 * aBaseAddress,
        _In_                UINT64          aZeroBits,
        _In_                UINT64          aCommitSize,
        _Inout_opt_         PLARGE_INTEGER  aSectionOffset,
        _Inout_             PUINT64         aViewSize,
        _In_                SECTION_INHERIT aInheritDisposition,
        _In_                UINT32          aAllocationType,
        _In_                UINT32          aWin32Protect
    );

    wow64ext_pub NTSTATUS wow64ext_api NtWow64UnmapViewOfSection64(
        _In_                HANDLE64    aProcessHandle,
        _In_opt_            PVOID64     aBaseAddress
    );

    wow64ext_pub NTSTATUS wow64ext_api NtWow64GetContextThread64(
        _In_                HANDLE64    aThreadHandle,
        _Out_               PCONTEXT64  aThreadContext
    );

    wow64ext_pub NTSTATUS wow64ext_api NtWow64SetContextThread64(
        _In_                HANDLE64    aThreadHandle,
        _In_                PCONTEXT64  aThreadContext
    );

    wow64ext_pub NTSTATUS wow64ext_api NtWow64QueryInformationProcess64(
        _In_                HANDLE64                    aProcessHandle,
        _In_                PROCESSINFOCLASS            aProcessInformationClass,
        _Out_writes_bytes_(aProcessInformationBytes) PVOID aProcessInformation,
        _In_                UINT32                      aProcessInformationBytes,
        _Out_opt_           PUINT32                     aReturnLength
    );

    wow64ext_pub UINT64  wow64ext_api Wow64VirtualQueryEx64(
        _In_                HANDLE64                    aProcess,
        _In_                PVOID64                     aBaseAddress,
        _Out_               PMEMORY_BASIC_INFORMATION   aBuffer,
        _In_                UINT64                      aBytes
    );

    wow64ext_pub PVOID64 wow64ext_api Wow64VirtualAllocEx64(
        _In_                HANDLE64    aProcess,
        _In_opt_            PVOID64     aBaseAddress,
        _In_                UINT64      aSize,
        _In_                UINT32      aAllocationType,
        _In_                UINT32      aProtect
    );

    wow64ext_pub BOOL    wow64ext_api Wow64VirtualFreeEx64(
        _In_                HANDLE64    aProcess,
        _In_                PVOID64     aBaseAddress,
        _In_                UINT64      aSize,
        _In_                UINT32      aFreeType
    );

    wow64ext_pub BOOL    wow64ext_api Wow64VirtualProtectEx64(
        _In_                HANDLE64    aProcess,
        _In_                PVOID64     aBaseAddress,
        _In_                UINT64      aSize,
        _In_                UINT32      aNewProtect,
        _Out_               PUINT32     aOldProtect
    );

    wow64ext_pub BOOL    wow64ext_api Wow64ReadProcessMemory64(
        _In_                HANDLE64    aProcess,
        _In_                PVOID64     aBaseAddress,
        _Out_               PVOID       aBuffer,
        _In_                UINT64      aSize,
        _Out_               PUINT64     aNumberOfBytesRead
    );

    wow64ext_pub BOOL    wow64ext_api Wow64WriteProcessMemory64(
        _In_                HANDLE64    aProcess,
        _In_                PVOID64     aBaseAddress,
        _In_                PVOID       aBuffer,
        _In_                UINT64      aSize,
        _Out_               PUINT64     aNumberOfBytesWritten
    );

    wow64ext_pub BOOL    wow64ext_api Wow64GetThreadContext64(
        _In_                HANDLE64    aThread,
        _Out_               PCONTEXT64  aContext
    );

    wow64ext_pub BOOL    wow64ext_api Wow64SetThreadContext64(
        _In_                HANDLE64    aThread,
        _In_                PCONTEXT64  aContext
    );

}
