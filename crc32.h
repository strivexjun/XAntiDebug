#if !defined(__crc32cr_table_h__)
#define __crc32cr_table_h__

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


unsigned int crc32(const void *buffer, unsigned int len);

BOOL CRC32File(LPCTSTR lpszFileName, unsigned char digest[16]);

#endif
