#include <stdio.h>

#include "XAntiDebug/XAntiDebug.h"

int main()
{
	XAD_STATUS		status;
	XAntiDebug		dbg;

	status = dbg.initialize();
	if (status != XAD_OK)
	{
		printf("initialize error. code= %d\n", status);

		switch (status)
		{
		case XAD_ERROR_NTAPI:
		{
			puts("get ntapi address fail.");
			break;
		}
		case XAD_ERROR_OPENNTDLL:
		{
			puts("open ntdll file fail.");
			break;
		}
		case XAD_ERROR_FILEOFFSET:
		{
			puts("calculate ntdll file offset fail.");
			break;
		}
		case XAD_ERROR_ALLOCMEM:
		{
			puts("alloc memory fail.");
			break;

		}
		default:
			break;
		}
		return 0;
	}

	if (dbg.isDebuging())
		puts("debuging...");
	else
		puts("ok");

	system("pause");

}