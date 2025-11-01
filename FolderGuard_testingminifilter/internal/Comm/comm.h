#pragma once

#include <fltKernel.h>

#define FG_SECTION_NAME L"\\BaseNamedObjects\\FolderGuardNotify"

#pragma pack(push, 1)
struct FolderGuardNotifyData {
	ULONG pid;
	ULONG pathLen; // bytes, UNICODE
	CHAR procName[64]; // ANSI, null-terminated
	// WCHAR path[pathLen/2] follows
	ULONG ready; // 0=empty, 1=data ready
};
#pragma pack(pop)

namespace FolderGuard {

	namespace Comm {

		NTSTATUS Init();
		VOID Cleanup();
		VOID NotifyBlock(_In_ PUNICODE_STRING path, _In_opt_ const CHAR* procNameAnsi, _In_ ULONG pid);

	}

}

