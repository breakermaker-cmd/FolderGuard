#include <fltKernel.h>
#include <ntimage.h>
#include <ntifs.h>
#include <bcrypt.h>
#include "process.h"

#pragma warning(push)
#pragma warning(disable: 4100) 
#pragma warning(disable: 4201) 

extern "C" {
	NTKERNELAPI PSTR PsGetProcessImageFileName(_In_ PEPROCESS Process);
	NTKERNELAPI PPEB PsGetProcessPeb(_In_ PEPROCESS Process);
	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(_In_ PEPROCESS Process);
	NTKERNELAPI NTSTATUS NTAPI ZwQueryInformationProcess(
		_In_ HANDLE ProcessHandle,
		_In_ PROCESSINFOCLASS ProcessInformationClass,
		_Out_ PVOID ProcessInformation,
		_In_ ULONG ProcessInformationLength,
		_Out_opt_ PULONG ReturnLength
	);
}
#ifndef FG_DEBUG
#define FG_DEBUG 0
#endif

#define FG_LOG(fmt, ...) do { if (FG_DEBUG) { DbgPrint(fmt, __VA_ARGS__); } } while (0)

static const wchar_t* FG_OB_ALTITUDE = L"385701";

typedef enum _SIGNATURE_LEVEL {
	SIG_LEVEL_UNCHECKED = 0,
	SIG_LEVEL_UNSIGNED = 1,
	SIG_LEVEL_ENTERPRISE = 2,
	SIG_LEVEL_CUSTOM_1 = 3,
	SIG_LEVEL_AUTHENTICODE = 4,
	SIG_LEVEL_CUSTOM_2 = 5,
	SIG_LEVEL_STORE = 6,
	SIG_LEVEL_CUSTOM_3 = 7,
	SIG_LEVEL_ANTIMALWARE = 8,
	SIG_LEVEL_MICROSOFT = 9,
	SIG_LEVEL_CUSTOM_4 = 10,
	SIG_LEVEL_CUSTOM_5 = 11,
	SIG_LEVEL_DYNAMIC_CODEGEN = 12,
	SIG_LEVEL_WINDOWS = 13,
	SIG_LEVEL_CUSTOM_7 = 14,
	SIG_LEVEL_WINDOWS_TCB = 15,
	SIG_LEVEL_CUSTOM_6 = 16
} SIGNATURE_LEVEL, * PSIGNATURE_LEVEL;

typedef struct _PS_PROTECTION {
	union {
		UCHAR Level;
		struct {
			UCHAR Type : 3;
			UCHAR Audit : 1;
			UCHAR Signer : 4;
		} s;
	} u;
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _PROCESS_SIGNATURE_INFORMATION {
	PS_PROTECTION Protection;
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
	UCHAR Reserved;
} PROCESS_SIGNATURE_INFORMATION, * PPROCESS_SIGNATURE_INFORMATION;

#define ProcessSignatureInformation ((PROCESSINFOCLASS)75)
#define PROCESS_QUERY_INFORMATION 0x0400
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

namespace FolderGuard {
	namespace Process {

		BOOLEAN IsProcessProtected(PEPROCESS process) {
			if (!process) return FALSE;

            HANDLE hProcess = nullptr;
            NTSTATUS status = ObOpenObjectByPointer(
				process,
				OBJ_KERNEL_HANDLE,
				nullptr,
                PROCESS_QUERY_LIMITED_INFORMATION,
				*PsProcessType,
				KernelMode,
				&hProcess
			);

			if (!NT_SUCCESS(status)) return FALSE;

			PROCESS_SIGNATURE_INFORMATION sigInfo = { 0 };
			ULONG returnLength = 0;

			status = ZwQueryInformationProcess(
				hProcess,
				ProcessSignatureInformation,
				&sigInfo,
				sizeof(sigInfo),
				&returnLength
			);

			ZwClose(hProcess);

			if (!NT_SUCCESS(status)) return FALSE;

			return (sigInfo.SignatureLevel >= SIG_LEVEL_MICROSOFT);
		}

		BOOLEAN IsSystemProcess(PEPROCESS process) {
			if (!process) return FALSE;

			if (PsGetProcessId(process) == (HANDLE)4) return TRUE;

			const CHAR* image = PsGetProcessImageFileName(process);
			if (!image) return FALSE;

			if (!_stricmp(image, "System") ||
				!_stricmp(image, "smss.exe") ||
				!_stricmp(image, "csrss.exe") ||
				!_stricmp(image, "wininit.exe") ||
				!_stricmp(image, "services.exe") ||
				!_stricmp(image, "lsass.exe") ||
				!_stricmp(image, "winlogon.exe"))
				return TRUE;

			return FALSE;
		}

		BOOLEAN IsKnownTrustedProcess(PEPROCESS process) {
			const CHAR* image = PsGetProcessImageFileName(process);
			if (!image) return FALSE;

			if (!_stricmp(image, "chrome.exe") || !_stricmp(image, "msedge.exe") ||
				!_stricmp(image, "brave.exe") || !_stricmp(image, "firefox.exe") ||
				!_stricmp(image, "opera.exe") || !_stricmp(image, "vivaldi.exe") ||
				!_stricmp(image, "yandex.exe") || !_stricmp(image, "discord.exe") ||
				!_stricmp(image, "telegram.exe") || !_stricmp(image, "explorer.exe") ||
				!_stricmp(image, "ShellExperienceHost.exe") || !_stricmp(image, "RuntimeBroker.exe"))
				return TRUE;

			return FALSE;
		}

		BOOLEAN IsAllowed(PEPROCESS process) {
			if (!process) return FALSE;

			if (IsSystemProcess(process))
				return TRUE;

			if (IsKnownTrustedProcess(process))
				return TRUE;

			if (IsProcessProtected(process))
				return TRUE;

			PACCESS_TOKEN token = PsReferencePrimaryToken(process);
			if (token) {
				BOOLEAN isAdmin = SeTokenIsAdmin(token);
				PsDereferencePrimaryToken(token);

				if (isAdmin) {
                    // idk what to do here
				}
			}

			return FALSE;
		}

	}
}

#pragma warning(pop)