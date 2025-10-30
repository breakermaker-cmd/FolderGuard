#include <fltKernel.h>
#include <ntstrsafe.h>

#include "paths.h"

#define POOL_TAG 'tPMM'

namespace FolderGuard {

	namespace Paths {

		struct ProtectedPath {
			UNICODE_STRING Path;
			PVOID Buffer;
		};

		constexpr ULONG MAX_PROTECTED_PATHS = 128;
		static ProtectedPath gProtectedPaths[MAX_PROTECTED_PATHS] = { 0 };
		static ULONG gProtectedPathCount = 0;
		static ERESOURCE gPathsLock;

		void Init() {
			ExInitializeResourceLite(&gPathsLock);
		}

		void Cleanup() {
			ExEnterCriticalRegionAndAcquireResourceExclusive(&gPathsLock);
			for (ULONG i = 0; i < gProtectedPathCount; i++) {
				if (gProtectedPaths[i].Buffer)
					ExFreePoolWithTag(gProtectedPaths[i].Buffer, POOL_TAG);
				gProtectedPaths[i].Buffer = nullptr;
				RtlZeroMemory(&gProtectedPaths[i].Path, sizeof(UNICODE_STRING));
			}
			gProtectedPathCount = 0;
			ExReleaseResourceAndLeaveCriticalRegion(&gPathsLock);
			ExDeleteResourceLite(&gPathsLock);
		}

		void Add(const WCHAR* path) {
			if (!path || gProtectedPathCount >= MAX_PROTECTED_PATHS) return;

			SIZE_T pathLen = wcslen(path);
			if (pathLen == 0) return;

			ExEnterCriticalRegionAndAcquireResourceShared(&gPathsLock);
			for (ULONG i = 0; i < gProtectedPathCount; i++) {
				if (gProtectedPaths[i].Buffer && _wcsicmp((PWSTR)gProtectedPaths[i].Buffer, path) == 0) {
					ExReleaseResourceAndLeaveCriticalRegion(&gPathsLock);
					return;
				}
			}
			ExReleaseResourceAndLeaveCriticalRegion(&gPathsLock);

			PVOID buffer = ExAllocatePoolZero(NonPagedPool, (pathLen + 1) * sizeof(WCHAR), POOL_TAG);
			if (!buffer) return;
			RtlCopyMemory(buffer, path, pathLen * sizeof(WCHAR));

			ExEnterCriticalRegionAndAcquireResourceExclusive(&gPathsLock);
			gProtectedPaths[gProtectedPathCount].Buffer = buffer;
			RtlInitUnicodeString(&gProtectedPaths[gProtectedPathCount].Path, (PCWSTR)buffer);
			gProtectedPathCount++;
			ExReleaseResourceAndLeaveCriticalRegion(&gPathsLock);
		}

		BOOLEAN IsProtected(PUNICODE_STRING filePath) {
			if (!filePath || !filePath->Buffer || filePath->Length == 0) return FALSE;

			BOOLEAN result = FALSE;
			ExEnterCriticalRegionAndAcquireResourceShared(&gPathsLock);
			for (ULONG i = 0; i < gProtectedPathCount; i++) {
				if (gProtectedPaths[i].Path.Length == 0) continue;

				UNICODE_STRING upperFile = { 0 }, upperProtected = { 0 };
				if (NT_SUCCESS(RtlUpcaseUnicodeString(&upperFile, filePath, TRUE)) &&
					NT_SUCCESS(RtlUpcaseUnicodeString(&upperProtected, &gProtectedPaths[i].Path, TRUE))) {

					ULONG fileLen = upperFile.Length / sizeof(WCHAR), protLen = upperProtected.Length / sizeof(WCHAR);
					if (protLen <= fileLen) {
						for (ULONG j = 0; j <= fileLen - protLen; j++) {
							if (RtlCompareMemory(&upperFile.Buffer[j], upperProtected.Buffer, upperProtected.Length) == upperProtected.Length) {
								result = TRUE;
								break;
							}
						}
					}

					RtlFreeUnicodeString(&upperProtected);
				}
				RtlFreeUnicodeString(&upperFile);
				if (result) break;
			}
			ExReleaseResourceAndLeaveCriticalRegion(&gPathsLock);
			return result;
		}

		void DiscoverDefaultPaths() {
			Add(L"\\Google\\Chrome\\User Data");
			Add(L"\\Microsoft\\Edge\\User Data");
			Add(L"\\BraveSoftware\\Brave-Browser\\User Data");
			Add(L"\\Opera Software\\Opera Stable");
			Add(L"\\Vivaldi\\User Data");
			Add(L"\\Yandex\\YandexBrowser\\User Data");
			Add(L"\\Mozilla\\Firefox\\Profiles");

			Add(L"\\AppData\\Roaming\\Discord");
			Add(L"\\AppData\\Roaming\\Telegram Desktop");
		}

	}

}


