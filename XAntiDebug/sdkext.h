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
#include <winternl.h>
//#include <ntexapi.h>



#pragma warning(push)
#pragma warning(disable: 4201)
namespace sdkext
{

#pragma region Basic Type
    using PVOID     = void *;
    using PVOID32   = void * __ptr32;
    using PVOID64   = void * __ptr64;

    using HANDLE    = PVOID;
    using HANDLE32  = PVOID32;
    using HANDLE64  = PVOID64;

    struct CLIENT_ID64
    {
        HANDLE64    UniqueProcess;
        HANDLE64    UniqueThread;
    };

    struct LIST_ENTRY64
    {
        PVOID64     Flink;
        PVOID64     Blink;
    };

    typedef struct X_STRING64
    {
        UINT16      Length;
        UINT16      MaximumLength;
        PVOID64     Buffer;
    }ANSI_STRING64, *PANSI_STRING64, UNICODE_STRING64, *PUNICODE_STRING64;

    struct CURDIR64
    {
        X_STRING64  DosPath;
        HANDLE64    Handle;
    };
#pragma endregion


#pragma region CONTEXT
    enum Context64Flags : long
    {
        CONTEXT_ARCH                = 0x00100000L,

        CONTEXT64_CONTROL           = (CONTEXT_ARCH | 0x00000001L),
        CONTEXT64_INTEGER           = (CONTEXT_ARCH | 0x00000002L),
        CONTEXT64_SEGMENTS          = (CONTEXT_ARCH | 0x00000004L),
        CONTEXT64_FLOATING_POINT    = (CONTEXT_ARCH | 0x00000008L),
        CONTEXT64_DEBUG_REGISTERS   = (CONTEXT_ARCH | 0x00000010L),

        CONTEXT64_FULL      = (CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT),
        CONTEXT64_ALL       = (CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS),

        CONTEXT64_XSTATE    = (CONTEXT_ARCH | 0x00000040L),
    };


    typedef struct DECLSPEC_ALIGN(16) XSAVE_FORMAT64 {
        UINT16  ControlWord;
        UINT16  StatusWord;
        UINT8   TagWord;
        UINT8   Reserved1;
        UINT16  ErrorOpcode;
        UINT32  ErrorOffset;
        UINT16  ErrorSelector;
        UINT16  Reserved2;
        UINT32  DataOffset;
        UINT16  DataSelector;
        UINT16  Reserved3;
        UINT32  MxCsr;
        UINT32  MxCsr_Mask;
        M128A   FloatRegisters[8];
        M128A   XmmRegisters[16];
        UINT8   Reserved4[96];

    }*PXSAVE_FORMAT64;
    typedef XSAVE_FORMAT64 XMM_SAVE_AREA64, *PXMM_SAVE_AREA64;


    typedef struct DECLSPEC_ALIGN(16) CONTEXT64 {

        //
        // Register parameter home addresses.
        //
        // N.B. These fields are for convience - they could be used to extend the
        //      context record in the future.
        //

        UINT64 P1Home;
        UINT64 P2Home;
        UINT64 P3Home;
        UINT64 P4Home;
        UINT64 P5Home;
        UINT64 P6Home;

        //
        // Control flags.
        //

        UINT32 ContextFlags;
        UINT32 MxCsr;

        //
        // Segment Registers and processor flags.
        //

        UINT16 SegCs;
        UINT16 SegDs;
        UINT16 SegEs;
        UINT16 SegFs;
        UINT16 SegGs;
        UINT16 SegSs;
        UINT32 EFlags;

        //
        // Debug registers
        //

        UINT64 Dr0;
        UINT64 Dr1;
        UINT64 Dr2;
        UINT64 Dr3;
        UINT64 Dr6;
        UINT64 Dr7;

        //
        // Integer registers.
        //

        UINT64 Rax;
        UINT64 Rcx;
        UINT64 Rdx;
        UINT64 Rbx;
        UINT64 Rsp;
        UINT64 Rbp;
        UINT64 Rsi;
        UINT64 Rdi;
        UINT64 R8;
        UINT64 R9;
        UINT64 R10;
        UINT64 R11;
        UINT64 R12;
        UINT64 R13;
        UINT64 R14;
        UINT64 R15;

        //
        // Program counter.
        //

        UINT64 Rip;

        //
        // Floating point state.
        //

        union {
            XMM_SAVE_AREA64 FltSave;
            struct {
                M128A Header[2];
                M128A Legacy[8];
                M128A Xmm0;
                M128A Xmm1;
                M128A Xmm2;
                M128A Xmm3;
                M128A Xmm4;
                M128A Xmm5;
                M128A Xmm6;
                M128A Xmm7;
                M128A Xmm8;
                M128A Xmm9;
                M128A Xmm10;
                M128A Xmm11;
                M128A Xmm12;
                M128A Xmm13;
                M128A Xmm14;
                M128A Xmm15;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;

        //
        // Vector registers.
        //

        M128A  VectorRegister[26];
        UINT64 VectorControl;

        //
        // Special debug control registers.
        //

        UINT64 DebugControl;
        UINT64 LastBranchToRip;
        UINT64 LastBranchFromRip;
        UINT64 LastExceptionToRip;
        UINT64 LastExceptionFromRip;
    }*PCONTEXT64;
#pragma endregion


#pragma region TEB
    typedef struct NT_TIB64
    {
        PVOID64     ExceptionList;          // PEXCEPTION_REGISTRATION_RECORD
        PVOID64     StackBase;
        PVOID64     StackLimit;
        PVOID64     SubSystemTib;
        union
        {
            PVOID64 FiberData;
            UINT32  Version;
        };
        PVOID64     ArbitraryUserPointer;
        PVOID64     Self;                   // PNT_TIB64
    }*PNT_TIB64;

    typedef struct TEB64
    {
        NT_TIB64    NtTib;
        PVOID64     EnvironmentPointer;
        CLIENT_ID64 ClientId;
        HANDLE64    ActiveRpcHandle;
        PVOID64     ThreadLocalStoragePointer;
        PVOID64     ProcessEnvironmentBlock; // PPEB64
        UINT32      LastErrorValue;
        UINT32      CountOfOwnedCriticalSections;
        HANDLE64    CsrClientThread;
        PVOID64     Win32ThreadInfo;
        //rest of the structure is not defined for now, as it is not needed
    }*PTEB64;
    static_assert(offsetof(TEB64, ProcessEnvironmentBlock) == 0x0060);
#pragma endregion


#pragma region PEB
    typedef struct LDR_DATA_TABLE_ENTRY64
    {
        LIST_ENTRY64    InLoadOrderLinks;
        LIST_ENTRY64    InMemoryOrderLinks;
        LIST_ENTRY64    InInitializationOrderLinks;

        PVOID64         DllBase;
        PVOID64         EntryPoint;
        UINT32          SizeOfImage;

        UNICODE_STRING64    FullDllName;
        UNICODE_STRING64    BaseDllName;

        union
        {
            UINT32      Flags;
            struct
            {
                UINT32  PackagedBinary : 1;
                UINT32  MarkedForRemoval : 1;
                UINT32  ImageDll : 1;
                UINT32  LoadNotificationsSent : 1;
                UINT32  TelemetryEntryProcessed : 1;
                UINT32  ProcessStaticImport : 1;
                UINT32  InLegacyLists : 1;
                UINT32  InIndexes : 1;
                UINT32  ShimDll : 1;
                UINT32  InExceptionTable : 1;
                UINT32  ReservedFlags1 : 2;
                UINT32  LoadInProgress : 1;
                UINT32  LoadConfigProcessed : 1;
                UINT32  EntryProcessed : 1;
                UINT32  ProtectDelayLoad : 1;
                UINT32  ReservedFlags3 : 2;
                UINT32  DontCallForThreads : 1;
                UINT32  ProcessAttachCalled : 1;
                UINT32  ProcessAttachFailed : 1;
                UINT32  CorDeferredValidate : 1;
                UINT32  CorImage : 1;
                UINT32  DontRelocate : 1;
                UINT32  CorILOnly : 1;
                UINT32  ReservedFlags5 : 3;
                UINT32  Redirected : 1;
                UINT32  ReservedFlags6 : 2;
                UINT32  CompatDatabaseProcessed : 1;
            };
        };

        UINT16          LoadCount;
        UINT16          TlsIndex;

        LIST_ENTRY64    HashLinks;

        union
        {
            UINT32      TimeDateStamp;
            PVOID64     LoadedImports;
        };

        PVOID64         EntryPointActivationContext;
        HANDLE64        Lock;
        PVOID64         DdagNode;
        LIST_ENTRY64    NodeModuleLink;
        PVOID64         LoadContext;
        PVOID64         ParentDllBase;
        PVOID64         SwitchBackContext;
    }*PLDR_DATA_TABLE_ENTRY64;
    static_assert(offsetof(LDR_DATA_TABLE_ENTRY64, DllBase      ) == 0x0030);
    static_assert(offsetof(LDR_DATA_TABLE_ENTRY64, EntryPoint   ) == 0x0038);
    static_assert(offsetof(LDR_DATA_TABLE_ENTRY64, FullDllName  ) == 0x0048);

    typedef struct PEB_LDR_DATA64
    {
        UINT32          Length;
        UINT8           Initialized;
        HANDLE64        SsHandle;
        LIST_ENTRY64    InLoadOrderModuleList;  // LDR_DATA_TABLE_ENTRY
        LIST_ENTRY64    InMemoryOrderModuleList;
        LIST_ENTRY64    InInitializationOrderModuleList;
        PVOID64         EntryInProgress;
        UINT8           ShutdownInProgress;
        HANDLE64        ShutdownThreadId;
    }*PPEB_LDR_DATA64;
    static_assert(offsetof(PEB_LDR_DATA64, InLoadOrderModuleList) == 0x0010);

    typedef struct RTL_USER_PROCESS_PARAMETERS64
    {
        DWORD       MaximumLength;
        DWORD       Length;
        DWORD       Flags;
        DWORD       DebugFlags;
        HANDLE64    ConsoleHandle;
        DWORD       ConsoleFlags;
        HANDLE64    StandardInput;
        HANDLE64    StandardOutput;
        HANDLE64    StandardError;
        CURDIR64    CurrentDirectory;
        UNICODE_STRING64 DllPath;
        UNICODE_STRING64 ImagePathName;
        UNICODE_STRING64 CommandLine;
    }*PRTL_USER_PROCESS_PARAMETERS64;
    static_assert(offsetof(RTL_USER_PROCESS_PARAMETERS64, DllPath) == 0x0050);

    typedef struct PEB64
    {
        enum : UINT32
        {
            GdiHandleBufferSize32   = 34,
            GdiHandleBufferSize64   = 60,
            GdiHandleBufferSize     = (sizeof(SIZE_T) == sizeof(UINT32) ? GdiHandleBufferSize32 : GdiHandleBufferSize64),

            FlsMaximumAvailable     = 128,
            TlsMinimumAvailable     = 64,
            TlsExpansionSlots       = 1024,
        };

        UINT8   InheritedAddressSpace;
        UINT8   ReadImageFileExecOptions;
        UINT8   BeingDebugged;
        union
        {
            UINT8       BitField;
            struct
            {
                UINT8   ImageUsesLargePages : 1;
                UINT8   IsProtectedProcess : 1;
                UINT8   IsImageDynamicallyRelocated : 1;
                UINT8   SkipPatchingUser32Forwarders : 1;
                UINT8   IsPackagedProcess : 1;
                UINT8   IsAppContainer : 1;
                UINT8   IsProtectedProcessLight : 1;
                UINT8   IsLongPathAwareProcess : 1;
            };
        };
        PVOID64     Mutant;
        PVOID64     ImageBaseAddress;
        PVOID64     Ldr;                                // PPEB_LDR_DATA64
        PVOID64     ProcessParameters;                  // PRTL_USER_PROCESS_PARAMETERS64
        PVOID64     SubSystemData;
        HANDLE64    ProcessHeap;
        HANDLE64    FastPebLock;
        PVOID64     AtlThunkSListPtr;
        PVOID64     IFEOKey;
        union
        {
            UINT32      CrossProcessFlags;
            struct
            {
                UINT32  ProcessInJob : 1;
                UINT32  ProcessInitializing : 1;
                UINT32  ProcessUsingVEH : 1;
                UINT32  ProcessUsingVCH : 1;
                UINT32  ProcessUsingFTH : 1;
                UINT32  ProcessPreviouslyThrottled : 1;
                UINT32  ProcessCurrentlyThrottled : 1;
                UINT32  ReservedBits0 : 25;
            };
        };
        union
        {
            PVOID64     KernelCallbackTable;
            PVOID64     UserSharedInfoPtr;
        };
        UINT32          SystemReserved[1];
        UINT32          AtlThunkSListPtr32;
        PVOID64         ApiSetMap;
        UINT32          TlsExpansionCounter;
        PVOID64         TlsBitmap;
        UINT32          TlsBitmapBits[2];
        PVOID64         ReadOnlySharedMemoryBase;
        PVOID64         HotpatchInformation;
        PVOID64         ReadOnlyStaticServerData;
        PVOID64         AnsiCodePageData;
        PVOID64         OemCodePageData;
        PVOID64         UnicodeCaseTableData;
        UINT32          NumberOfProcessors;
        UINT32          NtGlobalFlag;
        LARGE_INTEGER   CriticalSectionTimeout;
        UINT64          HeapSegmentReserve;             // SIZE_T
        UINT64          HeapSegmentCommit;              // SIZE_T
        UINT64          HeapDeCommitTotalFreeThreshold; // SIZE_T
        UINT64          HeapDeCommitFreeBlockThreshold; // SIZE_T
        UINT32          NumberOfHeaps;
        UINT32          MaximumNumberOfHeaps;
        PVOID64         ProcessHeaps;
        PVOID64         GdiSharedHandleTable;
        PVOID64         ProcessStarterHelper;
        UINT32          GdiDCAttributeList;
        PVOID64         LoaderLock;
        UINT32          OSMajorVersion;
        UINT32          OSMinorVersion;
        UINT16          OSBuildNumber;
        UINT16          OSCSDVersion;
        UINT32          OSPlatformId;
        UINT32          ImageSubsystem;
        UINT32          ImageSubsystemMajorVersion;
        UINT32          ImageSubsystemMinorVersion;
        UINT64          ActiveProcessAffinityMask;      // SIZE_T
        UINT32          GdiHandleBuffer[GdiHandleBufferSize];
        PVOID64         PostProcessInitRoutine;
        PVOID64         TlsExpansionBitmap;
        UINT32          TlsExpansionBitmapBits[32];
        UINT32          SessionId;
        ULARGE_INTEGER  AppCompatFlags;
        ULARGE_INTEGER  AppCompatFlagsUser;
        PVOID64         pShimData;
        PVOID64         AppCompatInfo;
        UNICODE_STRING64 CSDVersion;
        PVOID64         ActivationContextData;
        PVOID64         ProcessAssemblyStorageMap;
        PVOID64         SystemDefaultActivationContextData;
        PVOID64         SystemAssemblyStorageMap;
        UINT64          MinimumStackCommit;             // SIZE_T
        PVOID64         FlsCallback;
        LIST_ENTRY64    FlsListHead;
        PVOID64         FlsBitmap;
        UINT32          FlsBitmapBits[FlsMaximumAvailable / (sizeof(UINT32) * 8)];
        UINT32          FlsHighIndex;
        PVOID64         WerRegistrationData;
        PVOID64         WerShipAssertPtr;
        PVOID64         ContextData;
        PVOID64         ImageHeaderHash;
        union
        {
            UINT32      TracingFlags;
            struct
            {
                UINT32  HeapTracingEnabled : 1;
                UINT32  CritSecTracingEnabled : 1;
                UINT32  LibLoaderTracingEnabled : 1;
                UINT32  SpareTracingBits : 29;
            };
        };
        UINT64          CsrServerReadOnlySharedMemoryBase;
        PVOID64         TppWorkerpListLock;
        LIST_ENTRY64    TppWorkerpList;
        PVOID64         WaitOnAddressHashTable[128];
        PVOID64         TelemetryCoverageHeader;        // REDSTONE3
        UINT32          CloudFileFlags;
        UINT32          CloudFileDiagFlags;             // REDSTONE4
        UINT8           PlaceholderCompatibilityMode;
        UINT8           PlaceholderCompatibilityModeReserved[7];
    }*PPEB64;
    static_assert(offsetof(PEB64, ImageBaseAddress  ) == 0x0010);
    static_assert(offsetof(PEB64, Ldr               ) == 0x0018);
    static_assert(offsetof(PEB64, ProcessParameters ) == 0x0020);
#pragma endregion


#pragma region Memory
    enum MEMORY_INFORMATION_CLASS
    {
        MemoryBasicInformation,             // MEMORY_BASIC_INFORMATION
        MemoryWorkingSetInformation,        // MEMORY_WORKING_SET_INFORMATION
        MemoryMappedFilenameInformation,    // UNICODE_STRING
        MemoryRegionInformation,            // MEMORY_REGION_INFORMATION
        MemoryWorkingSetExInformation,      // MEMORY_WORKING_SET_EX_INFORMATION
        MemorySharedCommitInformation,      // MEMORY_SHARED_COMMIT_INFORMATION
        MemoryImageInformation,             // MEMORY_IMAGE_INFORMATION
        MemoryRegionInformationEx,
        MemoryPrivilegedBasicInformation,
        MemoryEnclaveImageInformation,      // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
        MemoryBasicInformationCapped
    };
#pragma endregion


#pragma region Section
    typedef enum SECTION_INHERIT
    {
        ViewShare = 1,
        ViewUnmap = 2
    }*PSECTION_INHERIT;
#pragma endregion


}
#pragma warning(pop)

using sdkext::PVOID;
using sdkext::PVOID32;
using sdkext::PVOID64;

using sdkext::HANDLE;
using sdkext::HANDLE32;
using sdkext::HANDLE64;
