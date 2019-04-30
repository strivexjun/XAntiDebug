# Introduction
##  VMProtect 3.x Anti-debug Method Improved

# Feature
-  Checksum ntoskrnl File
-  Checksum Code Section
-  Anti Debugger
-  Anti HardwareBreakpoint

# How use
> example.cpp
```cpp
	XAD_STATUS		status;
	XAntiDebug		antiDbg(GetModuleHandle(NULL), FLAG_FULLON);
	BOOL			result;

	//
	// 在程序最早的时候初始化 如 WinMain 或 DllMain
	//
	status = antiDbg.XAD_Initialize();
	if (status != XAD_OK)
	{
		printf("initialize error. %d\n", status);
		return 0;
	}

	//
	// 调用检测
	//

	for (;;)
	{
		result = antiDbg.XAD_ExecuteDetect();
		printf("result = %s\n", result ? "true" : "false");

		getchar();
	}

	return 0;

```

# Support
 xp-win10 and x86/x64