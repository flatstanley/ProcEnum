
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winioctl.h>
#include "..\ProcEnum\Public.h"

WCHAR* G_DevicePath = L"\\\\.\\ProcEnum";

int __cdecl
main(
	_In_ int argc,
	_In_reads_(argc) char* argv[]
)
{
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	HANDLE hDevice = INVALID_HANDLE_VALUE;
	BOOL result = TRUE;

	hDevice = CreateFile(L"\\\\.\\ProcEnum",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("Failed to open [%ws]. Error %d\n", G_DevicePath, GetLastError());
		result = FALSE;
		goto exit;
	}

	printf("Opened [%ws] successfully\n", G_DevicePath);


	DWORD retBytes = 0;
	DWORD lastError;
	DWORD procDescCount = 0;
	DWORD outputBufferSize = 0;
	PUCHAR pOutputBuffer = NULL;
	do
	{
		procDescCount += 4;
		outputBufferSize = sizeof(PROCESS_DESC_LIST::procDescCount) + sizeof(PROCESS_DESC) * procDescCount;

		if (pOutputBuffer)
			delete[] pOutputBuffer;
		pOutputBuffer = new UCHAR[outputBufferSize];

		if (pOutputBuffer == NULL)
			break;

		result = DeviceIoControl(
			hDevice,
			IOCTL_PROCENUM_GET_PROCESS_LIST,
			NULL,
			0,
			pOutputBuffer,
			outputBufferSize,
			&retBytes,
			NULL);
		lastError = GetLastError();
		printf("IOCTL_PROCENUM_GET_PROCESS_LIST: procDescCount %d result %d retBytes %d lastError %d\n", procDescCount, result, retBytes, lastError);

	}
	while (!result && lastError == ERROR_INSUFFICIENT_BUFFER);
	
	if (result)
	{
		PPROCESS_DESC_LIST pProcessDescList = (PPROCESS_DESC_LIST)pOutputBuffer;
		printf("IOCTL_PROCENUM_GET_PROCESS_LIST: procDescCount %d\n", pProcessDescList->procDescCount);
		for (ULONG i = 0; i < pProcessDescList->procDescCount; i++)
		{
			printf("%u: %p: [%S]\n", i, pProcessDescList->ProcessDesc[i].ProcessId, pProcessDescList->ProcessDesc[i].ImageFileName);
		}

	}

	if (pOutputBuffer)
		delete[] pOutputBuffer;

	if (!result)
	{
		CloseHandle(hDevice);
		return GetLastError();
	}

exit:


	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}

	return ((result == TRUE) ? 0 : 1);

}