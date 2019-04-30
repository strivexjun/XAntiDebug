// example.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>

#include "XAntiDebug/XAntiDebug.h"


int _tmain(int argc, _TCHAR* argv[])
{
	//
	// 推荐使用 FLAG_DETECT_DEBUGGER | FLAG_DETECT_HARDWAREBREAKPOINT,如果你对原理不熟悉的，不要用其他的
	//

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
}

