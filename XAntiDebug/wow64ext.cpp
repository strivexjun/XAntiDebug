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


#include <windows.h>
#include "wow64ext.h"
#include "_wow64ext.inl"

#ifndef STATUS_SUCCESS
#   define STATUS_SUCCESS           ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_NOT_SUPPORTED
#   define STATUS_NOT_SUPPORTED     ((NTSTATUS)0xC00000BBL)
#endif


void* __cdecl operator new[](size_t aSize)
{
    if (0 == aSize)
        aSize = 1;

    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, aSize);
}

void __cdecl operator delete[](void* aPtr)
{
    if (nullptr == aPtr)
        return;

    HeapFree(GetProcessHeap(), 0, aPtr);
}


namespace wow64ext
{

    static auto IsWow64Mode()
        -> bool
    {
        auto vWow64Mode = FALSE;
        return (IsWow64Process(GetCurrentProcess(), &vWow64Mode) && !!vWow64Mode);
    }
    bool Wow64Mode = IsWow64Mode();

    wow64ext_pub auto wow64ext_api Wow64CopyMemory64(
        _Out_bytecap_(aBytes)   PVOID64 aDst,
        _In_bytecount_(aBytes)  PVOID64 aSrc,
        _In_                    UINT64  aBytes
    ) -> VOID
    {
        if (!Wow64Mode)
        {
            return;
        }
        
        if (nullptr == aDst ||
            nullptr == aSrc ||
            0       == aBytes)
        {
            return;
        }

        Reg64 vDst      = { (UINT64)aDst    };
        Reg64 vSrc      = { (UINT64)aSrc    };
        Reg64 vBytes    = { (UINT64)aBytes  };

        __asm
        {
            X64Start();

            ;// below code is compiled as x86 inline asm, but it is executed as x64 code
            ;// that's why it need sometimes REX_W() macro, right column contains detailed
            ;// transcription how it will be interpreted by CPU

            push   edi                      ;// push     rdi
            push   esi                      ;// push     rsi
                                            ;//
      REX_W mov    edi, vDst.dw[0]          ;// mov      rdi, dword ptr [vDst]
      REX_W mov    esi, vSrc.dw[0]          ;// mov      rsi, qword ptr [vSrc]
      REX_W mov    ecx, vBytes.dw[0]        ;// mov      ecx, dword ptr [vBytes]
                                            ;//
      REX_W mov    eax, ecx                 ;// mov      rax, rcx
      REX_W and    eax, 3                   ;// and      rax, 3
      REX_W shr    ecx, 2                   ;// shr      rcx, 2
                                            ;//
            rep    movsd                    ;// rep movs dword ptr [rdi], dword ptr [rsi]
                                            ;//
      REX_W test   eax, eax                 ;// test     rax, rax
            je     _move_0                  ;// je       _move_0
      REX_W cmp    eax, 1                   ;// cmp      rax, 1
            je     _move_1                  ;// je       _move_1
                                            ;//
            movsw                           ;// movs     word ptr [rdi], word ptr [rsi]
      REX_W cmp    eax, 2                   ;// cmp      eax, 2
            je     _move_0                  ;// je       _move_0
                                            ;//
        _move_1:                            ;//
            movsb                           ;// movs     byte ptr [rdi], byte ptr [rsi]
                                            ;//
        _move_0:                            ;//
            pop    esi                      ;// pop      rsi
            pop    edi                      ;// pop      rdi

            X64End();
        }
    }

    wow64ext_pub auto wow64ext_api Wow64CompareMemory64(
        _In_bytecount_(aBytes)  PVOID64 aBuffer1,
        _In_bytecount_(aBytes)  PVOID64 aBuffer2,
        _In_                    UINT64  aBytes
    )->bool
    {
        if (!Wow64Mode)
        {
            return false;
        }

        if (nullptr == aBuffer1 ||
            nullptr == aBuffer2 ||
            0       == aBytes)
        {
            return false;
        }

        bool  vResult   = false;
        Reg64 vBuffer1  = { (UINT64)aBuffer1 };
        Reg64 vBuffer2  = { (UINT64)aBuffer2 };
        Reg64 vBytes    = { (UINT64)aBytes   };
        
        __asm
        {
            X64Start();

            ;// below code is compiled as x86 inline asm, but it is executed as x64 code
            ;// that's why it need sometimes REX_W() macro, right column contains detailed
            ;// transcription how it will be interpreted by CPU

            push   edi                      ;// push      rdi
            push   esi                      ;// push      rsi
                                            ;//           
      REX_W mov    edi, vBuffer1.dw[0]      ;// mov       rdi, dword ptr [vSource1]
      REX_W mov    esi, vBuffer2.dw[0]      ;// mov       rsi, qword ptr [vSource2]
      REX_W mov    ecx, vBytes.dw[0]        ;// mov       ecx, dword ptr [vLength]
                                            ;//           
      REX_W mov    eax, ecx                 ;// mov       rax, rcx
      REX_W and    eax, 3                   ;// and       rax, 3
      REX_W shr    ecx, 2                   ;// shr       rcx, 2
                                            ;// 
            repe   cmpsd                    ;// repe cmps dword ptr [rsi], dword ptr [rdi]
            jnz    _ret_false               ;// jnz       _ret_false
                                            ;// 
      REX_W test   eax, eax                 ;// test      rax, rax
            je     _move_0                  ;// je        _move_0
      REX_W cmp    eax, 1                   ;// cmp       rax, 1
            je     _move_1                  ;// je        _move_1
                                            ;// 
            cmpsw                           ;// cmps      word ptr [rsi], word ptr [rdi]
            jnz    _ret_false               ;// jnz       _ret_false
      REX_W cmp    eax, 2                   ;// cmp       rax, 2
            je     _move_0                  ;// je        _move_0
                                            ;// 
        _move_1:                            ;// 
            cmpsb                           ;// cmps      byte ptr [rsi], byte ptr [rdi]
            jnz    _ret_false               ;// jnz       _ret_false
                                            ;// 
        _move_0:                            ;// 
            mov    vResult, 1               ;// mov       byte ptr [result], 1
                                            ;// 
        _ret_false:                         ;// 
            pop    esi                      ;// pop      rsi
            pop    edi                      ;// pop      rdi

            X64End();
        }

        return vResult;
    }

    wow64ext_pub auto wow64ext_api Wow64Call64(
        _In_                    PVOID64 aFunc,
        _In_                    int     aArgsCount,
        _In_opt_                ...     /*Args*/
    )->UINT64
    {
        if (!Wow64Mode)
        {
            return (UINT64)0xC00000BBL; /*STATUS_NOT_SUPPORTED*/
        }

        va_list vArgs;
        va_start(vArgs, aArgsCount);

        Reg64 vRcx  = { (aArgsCount > 0) ? aArgsCount--, va_arg(vArgs, UINT64) : 0 };
        Reg64 vRdx  = { (aArgsCount > 0) ? aArgsCount--, va_arg(vArgs, UINT64) : 0 };
        Reg64 vR8   = { (aArgsCount > 0) ? aArgsCount--, va_arg(vArgs, UINT64) : 0 };
        Reg64 vR9   = { (aArgsCount > 0) ? aArgsCount--, va_arg(vArgs, UINT64) : 0 };
        Reg64 vRax  = { 0 };

        Reg64 vFunc         = { (UINT64)aFunc };
        Reg64 vRestArgs     = { (UINT64)(PVOID64)&va_arg(vArgs, UINT64) };
        Reg64 vArgsCount    = { (UINT64)aArgsCount };
        
        UINT32 vBackEsp = 0;
        UINT16 vBackFs  = 0;

        __asm
        {

            ;// reset FS segment, to properly handle RFG
            mov    vBackFs, fs;
            mov    eax, 0x2B;
            mov    fs, ax;

            ;// keep original esp in vBackEsp variable
            mov    vBackEsp, esp;

            ;// align esp to 0x10, without aligned stack some syscalls may return errors !
            ;// (actually, for syscalls it is sufficient to align to 8, but SSE opcodes 
            ;// requires 0x10 alignment), it will be further adjusted according to the
            ;// number of arguments above 4
            and    esp, 0xFFFFFFF0;

            X64Start();

            ;// below code is compiled as x86 inline asm, but it is executed as x64 code
            ;// that's why it need sometimes REX_W() macro, right column contains detailed
            ;// transcription how it will be interpreted by CPU

            ;// fill first four arguments
      REX_W mov    ecx, vRcx.dw[0]              ;// mov     rcx, qword ptr [vRcx]
      REX_W mov    edx, vRdx.dw[0]              ;// mov     rdx, qword ptr [vRdx]
            push   vR8.dw[0]                    ;// push    qword ptr [vR8]
            X64Pop(_R8)                         ;// pop     r8
            push   vR9.dw[0]                    ;// push    qword ptr [vR9]
            X64Pop(_R9)                         ;// pop     r9
                                                ;//
      REX_W mov    eax, vArgsCount.dw[0]        ;// mov     rax, qword ptr [vArgsCount]
                                                ;// 
                                                ;// final stack adjustment, according to the    ;//
                                                ;// number of arguments above 4                 ;// 
            test   al, 1                        ;// test    al, 1
            jnz    _no_adjust                   ;// jnz     _no_adjust
            sub    esp, 8                       ;// sub     rsp, 8
        _no_adjust:                             ;//
                                                ;// 
            push   edi                          ;// push    rdi
      REX_W mov    edi, vRestArgs.dw[0]         ;// mov     rdi, qword ptr [vRestArgs]
                                                ;// 
                                                ;// put rest of arguments on the stack          ;// 
      REX_W test   eax, eax                     ;// test    rax, rax
            jz     _ls_e                        ;// je      _ls_e
      REX_W lea    edi, dword ptr[edi + 8 * eax - 8];// lea     rdi, [rdi + rax*8 - 8]
                                                ;// 
        _ls:                                    ;// 
      REX_W test   eax, eax                     ;// test    rax, rax
            jz     _ls_e                        ;// je      _ls_e
            push   dword ptr[edi]               ;// push    qword ptr [rdi]
      REX_W sub    edi, 8                       ;// sub     rdi, 8
      REX_W sub    eax, 1                       ;// sub     rax, 1
            jmp    _ls                          ;// jmp     _ls
        _ls_e:                                  ;// 
                                                ;// 
                                                ;// create stack space for spilling registers   ;// 
            REX_W sub    esp, 0x20              ;// sub     rsp, 20h
                                                ;// 
            #pragma warning(suppress: 4409)
            call   aFunc                        ;// call    qword ptr [func]
                                                ;// 
            ;// cleanup stack                   ;// 
      REX_W mov    ecx, vArgsCount.dw[0]        ;// mov     rcx, qword ptr [vArgsCount]
      REX_W lea    esp, dword ptr[esp + 8 * ecx + 0x20];// lea     rsp, [rsp + rcx*8 + 20h]
                                                ;// 
            pop    edi                          ;// pop     rdi
                                                ;// 
            ;// set return value                ;// 
      REX_W mov    vRax.dw[0], eax              ;// mov     qword ptr [vRax], rax

            X64End();

            mov    ax, ds;
            mov    ss, ax;
            mov    esp, vBackEsp;

            ;// restore FS segment
            mov    ax, vBackFs;
            mov    fs, ax;
        }

        return vRax.v;
    }

    wow64ext_pub auto wow64ext_api ZwWow64CurrentTeb64(
    )->PVOID64 /*TEB64*/
    {
        if (!Wow64Mode)
        {
            return nullptr;
        }

        Reg64 vTeb64{};

        // R12 register should always contain pointer to TEB64 in WoW64 processes
        // below pop will pop QWORD from stack, as we're in x64 mode now

        X64Start();
        X64Push(_R12);
        __asm pop vTeb64.dw[0];
        X64End();

        return (PVOID64)vTeb64.v;
    }

    wow64ext_pub auto wow64ext_api ZwWow64CurrentPeb64(
    )->PVOID64 /*PEB64*/
    {
        if (!Wow64Mode)
        {
            return nullptr;
        }

        auto vTeb = TEB64();
        Wow64CopyMemory64(&vTeb, ZwWow64CurrentTeb64(), sizeof(vTeb));

        return vTeb.ProcessEnvironmentBlock;
    }

    wow64ext_pub auto wow64ext_api Wow64GetModuleHandle64(
        _In_                    LPCWSTR aModuleName
    )->PVOID64
    {
        if (!Wow64Mode)
        {
            return nullptr;
        }

        PEB64 vPeb{};
        Wow64CopyMemory64(&vPeb, ZwWow64CurrentPeb64(), sizeof(vPeb));

        PEB_LDR_DATA64 vLdr{};
        Wow64CopyMemory64(&vLdr, vPeb.Ldr, sizeof(vLdr));

        LDR_DATA_TABLE_ENTRY64 vEntry{};
        vEntry.InLoadOrderLinks.Flink = vLdr.InLoadOrderModuleList.Flink;
        auto vEndEntry = (PVOID64)((UINT64)vPeb.Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList));

        PVOID64 vDllBase = nullptr;
        do
        {
            Wow64CopyMemory64(&vEntry, vEntry.InLoadOrderLinks.Flink, sizeof(LDR_DATA_TABLE_ENTRY64));

            auto vDllName = (wchar_t*)new UINT8[vEntry.BaseDllName.MaximumLength + sizeof(UNICODE_NULL)]{};
            if (nullptr == vDllName)
            {
                break;
            }
            Wow64CopyMemory64(vDllName, vEntry.BaseDllName.Buffer, vEntry.BaseDllName.Length);

            if (0 == _wcsicmp(aModuleName, vDllName))
            {
                delete[](UINT8*)vDllName, vDllName = nullptr;

                vDllBase = vEntry.DllBase;
                break;
            }
            delete[](UINT8*)vDllName, vDllName = nullptr;

        } while (vEntry.InLoadOrderLinks.Flink != vEndEntry);

        return vDllBase;
    }

    wow64ext_pub auto wow64ext_api Wow64GetNtdll64(
    )->PVOID64
    {
        static PVOID64 sNtdll64 = nullptr;
        if (sNtdll64) 
        {
            return sNtdll64;
        }

        sNtdll64 = Wow64GetModuleHandle64(L"ntdll.dll");
        return sNtdll64;
    }

    wow64ext_pub auto wow64ext_api Wow64GetLdrGetProcedureAddress64(
    )->PVOID64
    {
        static PVOID64 sLdrGetProcedureAddress64 = nullptr;
        if (sLdrGetProcedureAddress64)
        {
            return sLdrGetProcedureAddress64;
        }

        UINT32* vAddressRvaArray    = nullptr;
        UINT32* vNameRvaArray       = nullptr;
        UINT16* vOrdinalsArray      = nullptr;
        for (;;)
        {
            PVOID64 vDllBase = Wow64GetNtdll64();
            if (nullptr == vDllBase)
            {
                break;
            }

            IMAGE_DOS_HEADER vDosHeader{};
            Wow64CopyMemory64(&vDosHeader, vDllBase, sizeof(vDosHeader));

            IMAGE_NT_HEADERS64 vNtHeader{};
            Wow64CopyMemory64(
                &vNtHeader,
                (PVOID64)((UINT64)vDllBase + vDosHeader.e_lfanew),
                sizeof(vNtHeader));

            auto& vExportDataDirectory = vNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (0 == vExportDataDirectory.VirtualAddress)
            {
                break;
            }

            IMAGE_EXPORT_DIRECTORY vExportDirectory{};
            Wow64CopyMemory64(&vExportDirectory, (PVOID64)((UINT64)vDllBase + vExportDataDirectory.VirtualAddress), sizeof(vExportDirectory));

            vAddressRvaArray = new UINT32[vExportDirectory.NumberOfFunctions]{};
            if (nullptr == vAddressRvaArray)
            {
                break;
            }
            Wow64CopyMemory64(vAddressRvaArray, (PVOID64)((UINT64)vDllBase + vExportDirectory.AddressOfFunctions), sizeof(UINT32) * (UINT64)vExportDirectory.NumberOfFunctions);

            vNameRvaArray = new UINT32[vExportDirectory.NumberOfNames]{};
            if (nullptr == vNameRvaArray)
            {
                break;
            }
            Wow64CopyMemory64(vNameRvaArray, (PVOID64)((UINT64)vDllBase + vExportDirectory.AddressOfNames), sizeof(UINT32) * (UINT64)vExportDirectory.NumberOfNames);

            vOrdinalsArray = new UINT16[vExportDirectory.NumberOfFunctions]{};
            if (nullptr == vOrdinalsArray)
            {
                break;
            }
            Wow64CopyMemory64(vOrdinalsArray, (PVOID64)((UINT64)vDllBase + vExportDirectory.AddressOfNameOrdinals), sizeof(UINT16) * (UINT64)vExportDirectory.NumberOfFunctions);

            for (auto i = 0u; i < vExportDirectory.NumberOfNames; ++i)
            {
                if (Wow64CompareMemory64(
                    (PVOID64)"LdrGetProcedureAddress",
                    (PVOID64)((UINT64)vDllBase + vNameRvaArray[i]),
                    sizeof("LdrGetProcedureAddress")))
                {
                    sLdrGetProcedureAddress64 = (PVOID64)((UINT64)vDllBase + vAddressRvaArray[vOrdinalsArray[i]]);
                    break;
                }
            }

            break;
        }
        delete[] vAddressRvaArray   , vAddressRvaArray  = nullptr;
        delete[] vNameRvaArray      , vNameRvaArray     = nullptr;
        delete[] vOrdinalsArray     , vOrdinalsArray    = nullptr;

        return sLdrGetProcedureAddress64;
    }

    wow64ext_pub auto wow64ext_api Wow64GetProcAddress64(
        _In_                    PVOID64 aModule,
        _In_                    LPCSTR  aProcName
    )->PVOID64
    {
        if (nullptr == aModule)
        {
            return nullptr;
        }

        PVOID64 vLdrGetProcedureAddress = Wow64GetLdrGetProcedureAddress64();
        if (nullptr == vLdrGetProcedureAddress)
        {
            return nullptr;
        }

        ANSI_STRING64 vRoutineName{};
        vRoutineName.Buffer = const_cast<LPSTR>(aProcName);
        vRoutineName.Length = (UINT16)(sizeof(char) * strlen(aProcName));
        vRoutineName.MaximumLength = (UINT16)(vRoutineName.Length + sizeof(ANSI_NULL));

        PVOID64 vRoutine = nullptr;
        auto vStatus = Wow64Call64(vLdrGetProcedureAddress, 4,
            (UINT64)aModule,
            (UINT64)&vRoutineName,
            (UINT64)0,
            (UINT64)&vRoutine);

        return Wow64SetLastErrorFromNtStatus((NTSTATUS)vStatus), vRoutine;
    }

    wow64ext_pub auto wow64ext_api Wow64SetLastErrorFromNtStatus(
        NTSTATUS    aStatus
    )->NTSTATUS
    {
        using $RtlSetLastWin32ErrorAndNtStatusFromNtStatus          = void(WINAPI*)(NTSTATUS);
        static auto sRtlSetLastWin32ErrorAndNtStatusFromNtStatus    = ($RtlSetLastWin32ErrorAndNtStatusFromNtStatus)nullptr;

        if (sRtlSetLastWin32ErrorAndNtStatusFromNtStatus)
        {
            return sRtlSetLastWin32ErrorAndNtStatusFromNtStatus(aStatus), aStatus;
        }

        auto vModule = GetModuleHandleA("ntdll.dll");
        if (nullptr == vModule)
        {
            return aStatus;
        }

        sRtlSetLastWin32ErrorAndNtStatusFromNtStatus = ($RtlSetLastWin32ErrorAndNtStatusFromNtStatus)GetProcAddress(
            vModule, "RtlSetLastWin32ErrorAndNtStatusFromNtStatus");
        if (nullptr == sRtlSetLastWin32ErrorAndNtStatusFromNtStatus)
        {
            return aStatus;
        }

        return sRtlSetLastWin32ErrorAndNtStatusFromNtStatus(aStatus), aStatus;
    }
    
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
    )
    {
        NTSTATUS vStatus = STATUS_SUCCESS;

        for (;;)
        {
            if (nullptr == aBaseAddress)
            {
                vStatus = STATUS_INVALID_PARAMETER;
                break;
            }

            PVOID64 sNtQueryVirtualMemory = nullptr;
            if (nullptr == sNtQueryVirtualMemory)
            {
                auto vModule = Wow64GetNtdll64();
                if (nullptr == vModule)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                sNtQueryVirtualMemory = Wow64GetProcAddress64(vModule, "NtQueryVirtualMemory");
                if (nullptr == sNtQueryVirtualMemory)
                {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            vStatus = (NTSTATUS)Wow64Call64(sNtQueryVirtualMemory, 6,
                (UINT64)aProcessHandle,
                (UINT64)aBaseAddress,
                (UINT64)aMemoryInformationClass,
                (UINT64)aMemoryInformation,
                (UINT64)aMemoryInformationBytes,
                (UINT64)aReturnLength);

            break;
        }

        return Wow64SetLastErrorFromNtStatus(vStatus);
    }

    wow64ext_pub NTSTATUS wow64ext_api NtWow64AllocateVirtualMemory64(
        _In_                HANDLE64    aProcessHandle,
        _In_bytecount_(*aRegionSize) PVOID64* aBaseAddress,
        _In_                UINT64      aZeroBits,
        _Inout_             PUINT64     aRegionSize,
        _In_                UINT32      aAllocationType,
        _In_                UINT32      aProtect
    )
    {
        NTSTATUS vStatus = STATUS_SUCCESS;

        for (;;)
        {
            if (nullptr == aBaseAddress)
            {
                vStatus = STATUS_INVALID_PARAMETER;
                break;
            }

            PVOID64 sNtAllocateVirtualMemory = nullptr;
            if (nullptr == sNtAllocateVirtualMemory)
            {
                auto vModule = Wow64GetNtdll64();
                if (nullptr == vModule)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                sNtAllocateVirtualMemory = Wow64GetProcAddress64(vModule, "NtAllocateVirtualMemory");
                if (nullptr == sNtAllocateVirtualMemory)
                {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            vStatus = (NTSTATUS)Wow64Call64(sNtAllocateVirtualMemory, 6,
                (UINT64)aProcessHandle,
                (UINT64)aBaseAddress,
                (UINT64)aZeroBits,
                (UINT64)aRegionSize,
                (UINT64)aAllocationType,
                (UINT64)aProtect);

            break;
        }

        return Wow64SetLastErrorFromNtStatus(vStatus);
    }

    wow64ext_pub NTSTATUS wow64ext_api NtWow64FreeVirtualMemory64(
        _In_                HANDLE64    aProcessHandle,
        _Inout_             PVOID64*    aBaseAddress,
        _Inout_             PUINT64     aRegionSize,
        _In_                UINT32      aFreeType
    )
    {
        NTSTATUS vStatus = STATUS_SUCCESS;

        for (;;)
        {
            if (nullptr == aBaseAddress)
            {
                vStatus = STATUS_INVALID_PARAMETER;
                break;
            }

            PVOID64 sNtFreeVirtualMemory = nullptr;
            if (nullptr == sNtFreeVirtualMemory)
            {
                auto vModule = Wow64GetNtdll64();
                if (nullptr == vModule)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                sNtFreeVirtualMemory = Wow64GetProcAddress64(vModule, "NtFreeVirtualMemory");
                if (nullptr == sNtFreeVirtualMemory)
                {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            vStatus = (NTSTATUS)Wow64Call64(sNtFreeVirtualMemory, 4,
                (UINT64)aProcessHandle,
                (UINT64)aBaseAddress,
                (UINT64)aRegionSize,
                (UINT64)aFreeType);

            break;
        }

        return Wow64SetLastErrorFromNtStatus(vStatus);
    }

    wow64ext_pub NTSTATUS wow64ext_api NtWow64ProtectVirtualMemory64(
        _In_                HANDLE64    aProcessHandle,
        _Inout_             PVOID64 *   aBaseAddress,
        _Inout_             PUINT64     aRegionSize,
        _In_                UINT32      aNewProtect,
        _Out_               PUINT32     aOldProtect
    )
    {
        NTSTATUS vStatus = STATUS_SUCCESS;

        for (;;)
        {
            if (nullptr == aBaseAddress)
            {
                vStatus = STATUS_INVALID_PARAMETER;
                break;
            }

            PVOID64 sNtProtectVirtualMemory = nullptr;
            if (nullptr == sNtProtectVirtualMemory)
            {
                auto vModule = Wow64GetNtdll64();
                if (nullptr == vModule)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                sNtProtectVirtualMemory = Wow64GetProcAddress64(vModule, "NtProtectVirtualMemory");
                if (nullptr == sNtProtectVirtualMemory)
                {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            vStatus = (NTSTATUS)Wow64Call64(sNtProtectVirtualMemory, 5,
                (UINT64)aProcessHandle,
                (UINT64)aBaseAddress,
                (UINT64)aRegionSize,
                (UINT64)aNewProtect,
                (UINT64)aOldProtect);

            break;
        }

        return Wow64SetLastErrorFromNtStatus(vStatus);
    }

    wow64ext_pub NTSTATUS wow64ext_api NtWow64ReadVirtualMemory64(
        _In_                HANDLE64    aProcessHandle,
        _In_opt_            PVOID64     aBaseAddress,
        _Out_writes_bytes_(aBufferSize) PVOID aBuffer,
        _In_                UINT64      aBufferSize,
        _Out_opt_           PUINT64     aNumberOfBytesRead
    )
    {
        NTSTATUS vStatus = STATUS_SUCCESS;

        for (;;)
        {
            if (aNumberOfBytesRead) *aNumberOfBytesRead = 0;

            if (nullptr == aBaseAddress)
            {
                vStatus = STATUS_INVALID_PARAMETER;
                break;
            }

            PVOID64 sNtReadVirtualMemory = nullptr;
            if (nullptr == sNtReadVirtualMemory)
            {
                auto vModule = Wow64GetNtdll64();
                if (nullptr == vModule)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                sNtReadVirtualMemory = Wow64GetProcAddress64(vModule, "NtReadVirtualMemory");
                if (nullptr == sNtReadVirtualMemory)
                {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            vStatus = (NTSTATUS)Wow64Call64(sNtReadVirtualMemory, 5,
                (UINT64)aProcessHandle,
                (UINT64)aBaseAddress,
                (UINT64)aBuffer,
                (UINT64)aBufferSize,
                (UINT64)aNumberOfBytesRead);

            break;
        }

        return Wow64SetLastErrorFromNtStatus(vStatus);
    }

    wow64ext_pub NTSTATUS wow64ext_api NtWow64WriteVirtualMemory64(
        _In_                HANDLE64    aProcessHandle,
        _In_opt_            PVOID64     aBaseAddress,
        _In_reads_bytes_(aBufferSize)   PVOID aBuffer,
        _In_                UINT64      aBufferSize,
        _Out_opt_           PUINT64     aNumberOfBytesWritten
    )
    {
        NTSTATUS vStatus = STATUS_SUCCESS;

        for (;;)
        {
            if(aNumberOfBytesWritten) *aNumberOfBytesWritten = 0;

            if (nullptr == aBaseAddress)
            {
                vStatus = STATUS_INVALID_PARAMETER;
                break;
            }

            PVOID64 sNtWriteVirtualMemory = nullptr;
            if (nullptr == sNtWriteVirtualMemory)
            {
                auto vModule = Wow64GetNtdll64();
                if (nullptr == vModule)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                sNtWriteVirtualMemory = Wow64GetProcAddress64(vModule, "NtWriteVirtualMemory");
                if (nullptr == sNtWriteVirtualMemory)
                {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            vStatus = (NTSTATUS)Wow64Call64(sNtWriteVirtualMemory, 5,
                (UINT64)aProcessHandle,
                (UINT64)aBaseAddress,
                (UINT64)aBuffer,
                (UINT64)aBufferSize,
                (UINT64)aNumberOfBytesWritten);

            break;
        }

        return Wow64SetLastErrorFromNtStatus(vStatus);
    }

    wow64ext_pub NTSTATUS wow64ext_api NtWow64FlushInstructionCache64(
        _In_                HANDLE64    aProcessHandle,
        _In_opt_            PVOID64     aBaseAddress,
        _In_                UINT64      aLength
    )
    {
        NTSTATUS vStatus = STATUS_SUCCESS;

        for (;;)
        {
            PVOID64 sNtFlushInstructionCache = nullptr;
            if (nullptr == sNtFlushInstructionCache)
            {
                auto vModule = Wow64GetNtdll64();
                if (nullptr == vModule)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                sNtFlushInstructionCache = Wow64GetProcAddress64(vModule, "NtFlushInstructionCache");
                if (nullptr == sNtFlushInstructionCache)
                {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            vStatus = (NTSTATUS)Wow64Call64(sNtFlushInstructionCache, 3,
                (UINT64)aProcessHandle,
                (UINT64)aBaseAddress,
                (UINT64)aLength);

            break;
        }

        return Wow64SetLastErrorFromNtStatus(vStatus);
    }

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
    )
    {
        NTSTATUS vStatus = STATUS_SUCCESS;

        for (;;)
        {
            PVOID64 sNtMapViewOfSection = nullptr;
            if (nullptr == sNtMapViewOfSection)
            {
                auto vModule = Wow64GetNtdll64();
                if (nullptr == vModule)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                sNtMapViewOfSection = Wow64GetProcAddress64(vModule, "NtMapViewOfSection");
                if (nullptr == sNtMapViewOfSection)
                {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            vStatus = (NTSTATUS)Wow64Call64(sNtMapViewOfSection, 10,
                (UINT64)aSectionHandle,
                (UINT64)aProcessHandle,
                (UINT64)aBaseAddress,
                (UINT64)aZeroBits,
                (UINT64)aCommitSize,
                (UINT64)aSectionOffset,
                (UINT64)aViewSize,
                (UINT64)aInheritDisposition,
                (UINT64)aAllocationType,
                (UINT64)aWin32Protect);

            break;
        }

        return Wow64SetLastErrorFromNtStatus(vStatus);
    }

    wow64ext_pub NTSTATUS wow64ext_api NtWow64UnmapViewOfSection64(
        _In_                HANDLE64    aProcessHandle,
        _In_opt_            PVOID64     aBaseAddress
    )
    {
        NTSTATUS vStatus = STATUS_SUCCESS;

        for (;;)
        {
            PVOID64 sNtUnmapViewOfSection = nullptr;
            if (nullptr == sNtUnmapViewOfSection)
            {
                auto vModule = Wow64GetNtdll64();
                if (nullptr == vModule)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                sNtUnmapViewOfSection = Wow64GetProcAddress64(vModule, "NtUnmapViewOfSection");
                if (nullptr == sNtUnmapViewOfSection)
                {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            vStatus = (NTSTATUS)Wow64Call64(sNtUnmapViewOfSection, 2,
                (UINT64)aProcessHandle,
                (UINT64)aBaseAddress);

            break;
        }

        return Wow64SetLastErrorFromNtStatus(vStatus);
    }

    wow64ext_pub NTSTATUS wow64ext_api NtWow64GetContextThread64(
        _In_                HANDLE64    aThreadHandle,
        _Out_               PCONTEXT64  aThreadContext
    )
    {
        NTSTATUS vStatus = STATUS_SUCCESS;

        for (;;)
        {
            PVOID64 sNtGetContextThread = nullptr;
            if (nullptr == sNtGetContextThread)
            {
                auto vModule = Wow64GetNtdll64();
                if (nullptr == vModule)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                sNtGetContextThread = Wow64GetProcAddress64(vModule, "NtGetContextThread");
                if (nullptr == sNtGetContextThread)
                {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            vStatus = (NTSTATUS)Wow64Call64(sNtGetContextThread, 2,
                (UINT64)aThreadHandle,
                (UINT64)aThreadContext);

            break;
        }

        return Wow64SetLastErrorFromNtStatus(vStatus);
    }

    wow64ext_pub NTSTATUS wow64ext_api NtWow64SetContextThread64(
        _In_                HANDLE64    aThreadHandle,
        _In_                PCONTEXT64  aThreadContext
    )
    {
        NTSTATUS vStatus = STATUS_SUCCESS;

        for (;;)
        {
            PVOID64 sNtSetContextThread = nullptr;
            if (nullptr == sNtSetContextThread)
            {
                auto vModule = Wow64GetNtdll64();
                if (nullptr == vModule)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                sNtSetContextThread = Wow64GetProcAddress64(vModule, "NtSetContextThread");
                if (nullptr == sNtSetContextThread)
                {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            vStatus = (NTSTATUS)Wow64Call64(sNtSetContextThread, 2,
                (UINT64)aThreadHandle,
                (UINT64)aThreadContext);

            break;
        }

        return Wow64SetLastErrorFromNtStatus(vStatus);
    }

    wow64ext_pub NTSTATUS wow64ext_api NtWow64QueryInformationProcess64(
        _In_                HANDLE64                    aProcessHandle,
        _In_                PROCESSINFOCLASS            aProcessInformationClass,
        _Out_writes_bytes_(aProcessInformationBytes) PVOID aProcessInformation,
        _In_                UINT32                      aProcessInformationBytes,
        _Out_opt_           PUINT32                     aReturnLength
    )
    {
        NTSTATUS vStatus = STATUS_SUCCESS;

        for (;;)
        {
            PVOID64 sNtQueryInformationProcess = nullptr;
            if (nullptr == sNtQueryInformationProcess)
            {
                auto vModule = Wow64GetNtdll64();
                if (nullptr == vModule)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                sNtQueryInformationProcess = Wow64GetProcAddress64(vModule, "NtQueryInformationProcess");
                if (nullptr == sNtQueryInformationProcess)
                {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            vStatus = (NTSTATUS)Wow64Call64(sNtQueryInformationProcess, 5,
                (UINT64)aProcessHandle,
                (UINT64)aProcessInformationClass,
                (UINT64)aProcessInformation,
                (UINT64)aProcessInformationBytes,
                (UINT64)aReturnLength);

            break;
        }

        return Wow64SetLastErrorFromNtStatus(vStatus);
    }

    wow64ext_pub UINT64  wow64ext_api Wow64VirtualQueryEx64(
        _In_                HANDLE64                    aProcess,
        _In_                PVOID64                     aBaseAddress,
        _Out_               PMEMORY_BASIC_INFORMATION   aBuffer,
        _In_                UINT64                      aBytes
    )
    {
        UINT64 vReturnBytes = 0;
        if (!NT_SUCCESS(NtWow64QueryVirtualMemory64(
            aProcess, aBaseAddress, MemoryBasicInformation, aBuffer, aBytes, &vReturnBytes)))
        {
            return 0;
        }

        return vReturnBytes;
    }

    wow64ext_pub PVOID64 wow64ext_api Wow64VirtualAllocEx64(
        _In_                HANDLE64    aProcess,
        _In_opt_            PVOID64     aBaseAddress,
        _In_                UINT64      aSize,
        _In_                UINT32      aAllocationType,
        _In_                UINT32      aProtect
    )
    {
        PVOID64 vBaseAddress    = aBaseAddress;
        UINT64  vRegionSize     = aSize;
        if (!NT_SUCCESS(NtWow64AllocateVirtualMemory64(
            aProcess, &vBaseAddress, 0, &vRegionSize, aAllocationType, aProtect)))
        {
            return nullptr;
        }

        return vBaseAddress;
    }

    wow64ext_pub BOOL    wow64ext_api Wow64VirtualFreeEx64(
        _In_                HANDLE64    aProcess,
        _In_                PVOID64     aBaseAddress,
        _In_                UINT64      aSize,
        _In_                UINT32      aFreeType
    )
    {
        PVOID64 vBaseAddress    = aBaseAddress;
        UINT64  vRegionSize     = aSize;
        if (!NT_SUCCESS(NtWow64FreeVirtualMemory64(
            aProcess, &vBaseAddress, &vRegionSize, aFreeType)))
        {
            return FALSE;
        }

        return TRUE;
    }

    wow64ext_pub BOOL    wow64ext_api Wow64VirtualProtectEx64(
        _In_                HANDLE64    aProcess,
        _In_                PVOID64     aBaseAddress,
        _In_                UINT64      aSize,
        _In_                UINT32      aNewProtect,
        _Out_               PUINT32     aOldProtect
    )
    {
        PVOID64 vBaseAddress    = aBaseAddress;
        UINT64  vRegionSize     = aSize;
        if (!NT_SUCCESS(NtWow64ProtectVirtualMemory64(
            aProcess, &vBaseAddress, &vRegionSize, aNewProtect, aOldProtect)))
        {
            return FALSE;
        }

        return TRUE;
    }

    wow64ext_pub BOOL    wow64ext_api Wow64ReadProcessMemory64(
        _In_                HANDLE64    aProcess,
        _In_                PVOID64     aBaseAddress,
        _Out_               PVOID       aBuffer,
        _In_                UINT64      aSize,
        _Out_               PUINT64     aNumberOfBytesRead
    )
    {
        if (!NT_SUCCESS(NtWow64ReadVirtualMemory64(
            aProcess, aBaseAddress, aBuffer, aSize, aNumberOfBytesRead)))
        {
            return FALSE;
        }

        return TRUE;
    }

    wow64ext_pub BOOL    wow64ext_api Wow64WriteProcessMemory64(
        _In_                HANDLE64    aProcess,
        _In_                PVOID64     aBaseAddress,
        _In_                PVOID       aBuffer,
        _In_                UINT64      aSize,
        _Out_               PUINT64     aNumberOfBytesWritten
    )
    {
        if (!NT_SUCCESS(NtWow64WriteVirtualMemory64(
            aProcess, aBaseAddress, aBuffer, aSize, aNumberOfBytesWritten)))
        {
            return FALSE;
        }

        return TRUE;
    }

    wow64ext_pub BOOL    wow64ext_api Wow64GetThreadContext64(
        _In_                HANDLE64    aThread,
        _Out_               PCONTEXT64  aContext
    )
    {
        if (!NT_SUCCESS(NtWow64GetContextThread64(aThread, aContext)))
        {
            return FALSE;
        }

        return TRUE;
    }

    wow64ext_pub BOOL    wow64ext_api Wow64SetThreadContext64(
        _In_                HANDLE64    aThread,
        _In_                PCONTEXT64  aContext
    )
    {
        if (!NT_SUCCESS(NtWow64SetContextThread64(aThread, aContext)))
        {
            return FALSE;
        }

        return TRUE;
    }
}
