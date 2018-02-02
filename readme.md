# VMProtect 3.x Anti-debug Method Improved

## Quick summary:

- IsDebuggerPresent
- CheckRemoteDebuggerPresent
- CloseHandle(0xDEADC0DE)
- ZwQueryInformationProcess(ProcessDebugObjectHandle), called correctly 
- crc32 check on direct syscall
- ZwQueryInformationProcess(ProcessDebugObjectHandle), called with ReturnLength == ProcessInformationClass