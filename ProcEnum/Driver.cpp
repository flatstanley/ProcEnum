#include <ntddk.h>
#include <wdf.h>

#include "Public.h"

extern "C" {
	NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING);
	DRIVER_INITIALIZE DriverEntry;

EVT_WDF_DRIVER_DEVICE_ADD ProcEnumEvtDeviceAdd;
EVT_WDF_DRIVER_UNLOAD    ProcEnumEvtDriverUnload;

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL ProcEnumEvtIoDeviceControl;
}

//TODO: replace with a hash table to speed up lookups:
LIST_ENTRY ProcListHead;
KSPIN_LOCK ProcListLock;
volatile LONG ProcListCount = 0;

typedef struct _PROCESS_ENTRY  {
	LIST_ENTRY listEntry;
	HANDLE ProcessId;
	WCHAR ImageFileName[MAXIMUM_FILENAME_LENGTH + 1];
} PROCESS_ENTRY, *PPROCESS_ENTRY;


void ProcessNotifyRoutine(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo);

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT     DriverObject,
	_In_ PUNICODE_STRING    RegistryPath
)
{
	NTSTATUS status = STATUS_SUCCESS;

	WDF_DRIVER_CONFIG config;

	KdPrint(("ProcEnum: DriverEntry\n"));

	//DbgBreakPoint();

	WDF_DRIVER_CONFIG_INIT(&config, ProcEnumEvtDeviceAdd);

	config.EvtDriverUnload = ProcEnumEvtDriverUnload;

	status = WdfDriverCreate(DriverObject,
		RegistryPath,
		WDF_NO_OBJECT_ATTRIBUTES,
		&config,
		WDF_NO_HANDLE
	);

	if (!NT_SUCCESS(status))
		return status;


	KeInitializeSpinLock(&ProcListLock);
	InitializeListHead(&ProcListHead);

	// TODO: figure out a way of getting the processes that are *already* loaded (?)

	status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutine, false);

	return status;
}

VOID
ProcEnumEvtDriverUnload(
	WDFDRIVER Driver
)
{
	UNREFERENCED_PARAMETER(Driver);

	KdPrint(("ProcEnum: ProcEnumEvtDriverUnload\n"));

	PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutine, true);
}

NTSTATUS
ProcEnumEvtDeviceAdd(
	_In_    WDFDRIVER       Driver,
	_Inout_ PWDFDEVICE_INIT DeviceInit
)
{
	UNREFERENCED_PARAMETER(Driver);

	NTSTATUS status;

	WDFDEVICE hDevice;

	KdPrint(("ProcEnum: ProcEnumEvtDeviceAdd\n"));

	// Create the device object
	status = WdfDeviceCreate(&DeviceInit,
		WDF_NO_OBJECT_ATTRIBUTES,
		&hDevice
	);
	if (!NT_SUCCESS(status))
		return status;

	WDF_IO_QUEUE_CONFIG  ioQueueConfig;
	WDFQUEUE  hQueue;
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
		&ioQueueConfig,
		WdfIoQueueDispatchSequential
	);

	ioQueueConfig.EvtIoDeviceControl = &ProcEnumEvtIoDeviceControl;

	status = WdfIoQueueCreate(hDevice, &ioQueueConfig, WDF_NO_OBJECT_ATTRIBUTES, &hQueue);
	if (!NT_SUCCESS(status))
		return status;

	DECLARE_CONST_UNICODE_STRING(MySymbolicLinkName, L"\\??\\ProcEnum");
	status = WdfDeviceCreateSymbolicLink(hDevice, &MySymbolicLinkName);
	if (!NT_SUCCESS(status))
		return status;

	return status;
}

VOID
ProcEnumEvtIoDeviceControl(
	_In_ WDFQUEUE Queue,
	_In_ WDFREQUEST Request,
	_In_ size_t OutputBufferLength,
	_In_ size_t InputBufferLength,
	_In_ ULONG IoControlCode)
{
	UNREFERENCED_PARAMETER(Queue);
	UNREFERENCED_PARAMETER(Request);
	UNREFERENCED_PARAMETER(InputBufferLength);
	
	NTSTATUS status = STATUS_SUCCESS;
	ULONG_PTR information = 0;

	switch (IoControlCode)
	{
	case IOCTL_PROCENUM_GET_PROCESS_LIST:
	{
		ULONG requiredLen = sizeof(PROCESS_DESC_LIST::procDescCount) + ProcListCount * sizeof(PROCESS_DESC);
		ULONG bufferDescCount = ((ULONG)OutputBufferLength - sizeof(PROCESS_DESC_LIST::procDescCount)) / sizeof(PROCESS_DESC);

		KdPrint(("ProcEnum: IOCTL_PROCENUM_GET_PROCESS_LIST: OutputBufferLength %u bufferDescCount &u requiredLen %u\n", OutputBufferLength, bufferDescCount, requiredLen));

		if (OutputBufferLength < requiredLen)
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		WDFMEMORY memory;
		status = WdfRequestRetrieveOutputMemory(Request, &memory);
		if (!NT_SUCCESS(status))
			break;
		size_t outputLen;
		PPROCESS_DESC_LIST pProcDescList = (PPROCESS_DESC_LIST) WdfMemoryGetBuffer(memory, &outputLen);
		if (pProcDescList == NULL || outputLen < OutputBufferLength)	// sanity check
		{
			status = STATUS_INVALID_ADDRESS;	//??
			break;
		}

		pProcDescList->procDescCount = 0;
		KIRQL irql;
		KeAcquireSpinLock(&ProcListLock, &irql);

		PLIST_ENTRY pEntry = ProcListHead.Flink;
		ULONG& i = pProcDescList->procDescCount;
		for (i = 0; i < bufferDescCount; i++)
		{
			PPROCESS_ENTRY pProcessEntry = (PPROCESS_ENTRY)CONTAINING_RECORD(pEntry, PROCESS_ENTRY, listEntry);

			pProcDescList->ProcessDesc[i].ProcessId = pProcessEntry->ProcessId;

			size_t lenToCopy = min(sizeof(PROCESS_DESC::ImageFileName), sizeof(PROCESS_ENTRY::ImageFileName));
			memcpy(pProcDescList->ProcessDesc[i].ImageFileName, pProcessEntry->ImageFileName, lenToCopy);
			pProcDescList->ProcessDesc[i].ImageFileName[sizeof(pProcDescList->ProcessDesc[i].ImageFileName) - 1] = 0;


			KdPrint(("ProcEnum: IOCTL_PROCENUM_GET_PROCESS_LIST: ProcessId %p\n", pProcessEntry->ProcessId));

			pEntry = pEntry->Flink;
			if (pEntry == &ProcListHead)
				break;
		}

		KeReleaseSpinLock(&ProcListLock, irql);

		information = sizeof(PROCESS_DESC_LIST::procDescCount) + pProcDescList->procDescCount * sizeof(PROCESS_DESC);

		status = STATUS_SUCCESS;
		break;
	}

	default:    
		status = STATUS_NOT_SUPPORTED;
		break;
	}
	
	if (status != STATUS_PENDING)
		WdfRequestCompleteWithInformation(Request, status, information);

}


void ProcessNotifyRoutine(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
)
{

	KdPrint(("ProcEnum: ProcessNotifyRoutine: Process %p ProcessId %p CreateInfo %p\n", Process, ProcessId, CreateInfo));

	if (CreateInfo)
	{
		PPROCESS_ENTRY pProcessDesc = (PPROCESS_ENTRY) ExAllocatePool(NonPagedPool, sizeof(PROCESS_ENTRY));
		if (pProcessDesc == NULL)
			return;
		pProcessDesc->ProcessId = ProcessId;

		size_t lenToCopy = min(CreateInfo->ImageFileName->Length, sizeof(pProcessDesc->ImageFileName)-1);
		memcpy(pProcessDesc->ImageFileName, CreateInfo->ImageFileName->Buffer, lenToCopy);
		pProcessDesc->ImageFileName[lenToCopy/sizeof(WCHAR)] = 0;

		ExInterlockedInsertTailList(&ProcListHead, &pProcessDesc->listEntry, &ProcListLock);
		InterlockedIncrement(&ProcListCount);
		KdPrint(("ProcEnum: ProcessNotifyRoutine Added ProcessId %p ProcListCount %u\n", ProcessId, ProcListCount));
	}
	else
	{
		KIRQL irql;
		KeAcquireSpinLock(&ProcListLock, &irql);

		PLIST_ENTRY pEntry = ProcListHead.Flink;

		while(pEntry != &ProcListHead)
		{
			PPROCESS_ENTRY pProcessEnt;
			pProcessEnt = (PPROCESS_ENTRY)CONTAINING_RECORD(pEntry, PROCESS_ENTRY, listEntry);

			if (pProcessEnt->ProcessId == ProcessId)
			{
				InterlockedDecrement(&ProcListCount);
				RemoveEntryList(&pProcessEnt->listEntry);

				KdPrint(("ProcEnum: ProcessNotifyRoutine Removed ProcessId %p ProcListCount %u\n", ProcessId, ProcListCount));

				ExFreePool(pProcessEnt);
				break;
			}

			pEntry = pEntry->Flink;
		}

		KeReleaseSpinLock(&ProcListLock, irql);
	}
}
