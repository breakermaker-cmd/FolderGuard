#include <fltKernel.h>
#include <ntifs.h>
#include "comm.h"

#define POOL_TAG_COMM 'mCfG'

typedef struct _NOTIFY_WORK_ITEM {
	WORK_QUEUE_ITEM WorkItem;
	UNICODE_STRING Path;
	CHAR ProcName[16];
	ULONG Pid;
} NOTIFY_WORK_ITEM, * PNOTIFY_WORK_ITEM;

namespace FolderGuard {

	namespace Comm {

		static HANDLE g_sectionHandle = nullptr;
		static PVOID g_sectionBase = nullptr;
		static FolderGuardNotifyData* g_notifyData = nullptr;
		static KSPIN_LOCK g_commLock;
		static volatile LONG g_activeWorkItems = 0;
		static volatile BOOLEAN g_shutdownRequested = FALSE;

		VOID NotifyWorkRoutine(_In_ PVOID Context) {
			PNOTIFY_WORK_ITEM workItem = (PNOTIFY_WORK_ITEM)Context;
			KIRQL oldIrql;

			KeAcquireSpinLock(&g_commLock, &oldIrql);

			if (g_notifyData && !g_shutdownRequested) {
				g_notifyData->pid = workItem->Pid;
				g_notifyData->pathLen = workItem->Path.Length;
				RtlCopyMemory(g_notifyData->procName, workItem->ProcName, sizeof(g_notifyData->procName));

				PWCHAR pathDst = (PWCHAR)((PUCHAR)g_notifyData + sizeof(FolderGuardNotifyData));
				ULONG pathBytes = (workItem->Path.Length < (PAGE_SIZE - sizeof(FolderGuardNotifyData)))
					? workItem->Path.Length
					: (PAGE_SIZE - sizeof(FolderGuardNotifyData));

				g_notifyData->pathLen = (USHORT)pathBytes;
				RtlCopyMemory(pathDst, workItem->Path.Buffer, pathBytes);

				KeMemoryBarrier();
				*(volatile ULONG*)&g_notifyData->ready = 1;
			}

			KeReleaseSpinLock(&g_commLock, oldIrql);

			if (workItem->Path.Buffer) {
				ExFreePoolWithTag(workItem->Path.Buffer, POOL_TAG_COMM);
			}
			ExFreePoolWithTag(workItem, POOL_TAG_COMM);

			InterlockedDecrement(&g_activeWorkItems);
		}

		NTSTATUS Init() {
			KeInitializeSpinLock(&g_commLock);
			g_activeWorkItems = 0;
			g_shutdownRequested = FALSE;

			OBJECT_ATTRIBUTES oa;
			UNICODE_STRING sectionName;
			RtlInitUnicodeString(&sectionName, FG_SECTION_NAME);

			SECURITY_DESCRIPTOR sd;
			RtlZeroMemory(&sd, sizeof(sd));
			RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
			RtlSetDaclSecurityDescriptor(&sd, TRUE, nullptr, FALSE);

			InitializeObjectAttributes(&oa, &sectionName, OBJ_CASE_INSENSITIVE, nullptr, &sd);

			LARGE_INTEGER maxSize;
			maxSize.QuadPart = PAGE_SIZE;

			NTSTATUS status = ZwCreateSection(&g_sectionHandle,
				SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY,
				&oa,
				&maxSize,
				PAGE_READWRITE,
				SEC_COMMIT,
				nullptr);

			if (!NT_SUCCESS(status)) {
				DbgPrint("[FolderGuard] Comm: ZwCreateSection failed 0x%08X\n", status);
				return status;
			}

			SIZE_T viewSize = PAGE_SIZE;
			status = ZwMapViewOfSection(g_sectionHandle,
				ZwCurrentProcess(),
				&g_sectionBase,
				0,
				0,
				nullptr,
				&viewSize,
				ViewUnmap,
				0,
				PAGE_READWRITE);

			if (!NT_SUCCESS(status)) {
				ZwClose(g_sectionHandle);
				g_sectionHandle = nullptr;
				DbgPrint("[FolderGuard] Comm: ZwMapViewOfSection failed 0x%08X\n", status);
				return status;
			}

			g_notifyData = (FolderGuardNotifyData*)g_sectionBase;
			RtlZeroMemory(g_notifyData, sizeof(FolderGuardNotifyData));
			DbgPrint("[FolderGuard] Comm: Section shared at %p\n", g_sectionBase);
			return STATUS_SUCCESS;
		}

		VOID Cleanup() {
			KIRQL oldIrql;
			LARGE_INTEGER interval;

			//PREVENT NEW WORK ITEMS FROM PROCESSING
			g_shutdownRequested = TRUE;

			interval.QuadPart = -10000000LL; // 1 second in 100ns units
			for (int i = 0; i < 10; i++) {
				if (g_activeWorkItems == 0)
					break;
				KeDelayExecutionThread(KernelMode, FALSE, &interval);
				DbgPrint("[FolderGuard] Comm: Waiting for %ld work items to complete...\n", g_activeWorkItems);
			}

			KeAcquireSpinLock(&g_commLock, &oldIrql);

			if (g_sectionBase) {
				ZwUnmapViewOfSection(ZwCurrentProcess(), g_sectionBase);
				g_sectionBase = nullptr;
				g_notifyData = nullptr;
			}

			KeReleaseSpinLock(&g_commLock, oldIrql);

			if (g_sectionHandle) {
				ZwClose(g_sectionHandle);
				g_sectionHandle = nullptr;
			}

			if (g_activeWorkItems > 0) {
				DbgPrint("[FolderGuard] Comm: Warning - %ld work items still active after cleanup\n", g_activeWorkItems);
			}
		}

		VOID NotifyBlock(_In_ PUNICODE_STRING path, _In_opt_ const CHAR* procNameAnsi, _In_ ULONG pid) {
			if (!path || !path->Buffer || path->Length == 0)
				return;

			if (g_shutdownRequested)
				return;

			PNOTIFY_WORK_ITEM workItem = (PNOTIFY_WORK_ITEM)ExAllocatePoolWithTag(
				NonPagedPool, sizeof(NOTIFY_WORK_ITEM), POOL_TAG_COMM);
			if (!workItem) return;

			RtlZeroMemory(workItem, sizeof(NOTIFY_WORK_ITEM));
			workItem->Pid = pid;

			if (procNameAnsi) {
				// KEEP THIS - BOUNDS CHECKING.
				ULONG copyLen = 0;
				while (copyLen < (sizeof(workItem->ProcName) - 1) && procNameAnsi[copyLen] != '\0') {
					workItem->ProcName[copyLen] = procNameAnsi[copyLen];
					copyLen++;
				}
				workItem->ProcName[copyLen] = '\0';
			}
			else {
				workItem->ProcName[0] = '\0';
			}

			workItem->Path.Length = path->Length;
			workItem->Path.MaximumLength = path->Length;
			workItem->Path.Buffer = (PWCHAR)ExAllocatePoolWithTag(
				NonPagedPool, path->Length, POOL_TAG_COMM);

			if (!workItem->Path.Buffer) {
				ExFreePoolWithTag(workItem, POOL_TAG_COMM);
				return;
			}

			RtlCopyMemory(workItem->Path.Buffer, path->Buffer, path->Length);

			InterlockedIncrement(&g_activeWorkItems);

			ExInitializeWorkItem(&workItem->WorkItem, NotifyWorkRoutine, workItem);
			ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);
		}

	}

}