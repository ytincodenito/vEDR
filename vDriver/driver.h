#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>


typedef PVOID(*fnLoadLibraryExA)(
	LPCSTR lpLibFileName,
	HANDLE hFile,
	ULONG dwFlag
	);

typedef struct _INJECTION_DATA // _SIRIFEF_INJECTION_DATA in article
{
	BOOLEAN Executing;
	PEPROCESS Process;
	PETHREAD Ethread;
	KEVENT Event;
	WORK_QUEUE_ITEM WorkItem;
	ULONG ProcessId;
} INJECTION_DATA, * P_INJECTION_DATA;

typedef struct GET_ADDRESS
{
	PVOID Kernel32dll;
	fnLoadLibraryExA pvLoadLibraryExA;
}GET_ADDRESS, * PGET_ADDRESS;

// Define undocumented structures
typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
}KAPC_ENVIRONMENT, * PKAPC_ENVIRONMENT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID KKERNEL_ROUTINE(
	PRKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
);

typedef KKERNEL_ROUTINE(NTAPI* PKKERNEL_ROUTINE);

typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(
	PRKAPC Apc
	);

void KeInitializeApc(
	PRKAPC Apc,
	PRKTHREAD Thread,
	KAPC_ENVIRONMENT Environment,
	PKKERNEL_ROUTINE KernelRoutine,
	PKRUNDOWN_ROUTINE RundownRoutine,
	PKNORMAL_ROUTINE NormalRoutine,
	KPROCESSOR_MODE ProcessorMode,
	PVOID NormalContext
);

BOOLEAN KeInsertQueueApc(
	PRKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment
);