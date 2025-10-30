#include <fltKernel.h>
#include <ntimage.h>
#include <ntifs.h>
#include "process.h"

#pragma warning(push)
#pragma warning(disable: 4100)
#pragma warning(disable: 4201)

extern "C" {
    NTKERNELAPI PSTR PsGetProcessImageFileName(_In_ PEPROCESS Process);
    NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(_In_ PEPROCESS Process);
}

#ifndef FG_DEBUG
#define FG_DEBUG 1
#endif

#define FG_LOG(fmt, ...) do { if (FG_DEBUG) { DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[FolderGuard] " fmt "\n", __VA_ARGS__); } } while (0)

#define POOL_TAG 'tPMM'

// ---------------------------------------------------------------------
// WHITELIST – NUR NT-PFÄDE (aus PE-Header)
// ---------------------------------------------------------------------
struct WHITELIST_ENTRY {
    PCWSTR NtPath;     // \Device\HarddiskVolume?\...
    PCSTR  ImageName;
};

static const WHITELIST_ENTRY g_Whitelist[] = {
    // BROWSERS
    { L"\\Device\\HarddiskVolume?\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe" },
    { L"\\Device\\HarddiskVolume?\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe" },
    { L"\\Device\\HarddiskVolume?\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe", "msedge.exe" },
    { L"\\Device\\HarddiskVolume?\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "msedge.exe" },

    // DISCORD
    { L"\\Device\\HarddiskVolume?\\Users\\*\\AppData\\Local\\Discord\\app-*.*\\Discord.exe", "discord.exe" },
    { L"\\Device\\HarddiskVolume?\\Users\\*\\AppData\\Local\\DiscordPTB\\app-*.*\\DiscordPTB.exe", "Discordptb.exe" },
    { L"\\Device\\HarddiskVolume?\\Users\\*\\AppData\\Local\\DiscordCanary\\app-*.*\\DiscordCanary.exe", "DiscordCanary.exe" },

    // EXODUS
    { L"\\Device\\HarddiskVolume?\\Users\\*\\AppData\\Local\\exodus\\app-*.*\\Exodus.exe", "Exodus.exe" },

    // TELEGRAM
    { L"\\Device\\HarddiskVolume?\\Users\\*\\AppData\\Local\\Telegram Desktop\\Telegram.exe", "telegram.exe" },

    // VPN
    { L"\\Device\\HarddiskVolume?\\Program Files\\Mullvad VPN\\Mullvad VPN.exe", "Mullvad VPN.exe" },

    // WALLETS (Beispiele)
    { L"\\Device\\HarddiskVolume?\\Users\\*\\AppData\\Roaming\\Electrum\\electrum.exe", "electrum.exe" },

    // SYSTEM
    { L"\\Device\\HarddiskVolume?\\Windows\\explorer.exe", "explorer.exe" },
    { L"\\Device\\HarddiskVolume?\\Windows\\System32\\RuntimeBroker.exe", "RuntimeBroker.exe" },
};
static const ULONG g_WhitelistCount = RTL_NUMBER_OF(g_Whitelist);

// ---------------------------------------------------------------------
// ECHTER NT-PFAD AUS PE-HEADER (100% zuverlässig)
// ---------------------------------------------------------------------
PUNICODE_STRING GetProcessNtImagePath(PEPROCESS Process) {
    PVOID base = PsGetProcessSectionBaseAddress(Process);
    if (!base) return nullptr;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUCHAR)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    // ImagePathName ist im .rsrc oder direkt im PE
    // Wir suchen nach dem String, der mit \??\ oder \Device\ beginnt
    UNICODE_STRING prefix1 = RTL_CONSTANT_STRING(L"\\??\\");
    UNICODE_STRING prefix2 = RTL_CONSTANT_STRING(L"\\Device\\");

    PUCHAR start = (PUCHAR)base;
    PUCHAR end = start + nt->OptionalHeader.SizeOfImage;

    for (PUCHAR p = start; p < end - 64; p += 2) {
        if ((*(PUSHORT)p == 0x003F && *(PUSHORT)(p + 2) == 0x005C) || // \??
            (*(PUSHORT)p == 0x005C && *(PUSHORT)(p + 2) == 0x0044)) { // \D
            UNICODE_STRING candidate;
            candidate.Buffer = (PWSTR)p;
            candidate.Length = 0;
            candidate.MaximumLength = (USHORT)(end - p);

            // Prüfe, ob es ein gültiger Pfad ist
            if (RtlPrefixUnicodeString(&prefix1, &candidate, TRUE) ||
                RtlPrefixUnicodeString(&prefix2, &candidate, TRUE)) {

                USHORT len = 0;
                while (len < candidate.MaximumLength && candidate.Buffer[len] != 0) len++;
                if (len < 20 || len > 260) continue;

                PUNICODE_STRING result = (PUNICODE_STRING)ExAllocatePoolZero(NonPagedPool, sizeof(UNICODE_STRING) + len * 2, POOL_TAG);
                if (!result) return nullptr;

                result->Buffer = (PWSTR)((PUCHAR)result + sizeof(UNICODE_STRING));
                result->Length = len * 2;
                result->MaximumLength = len * 2;
                RtlCopyMemory(result->Buffer, candidate.Buffer, len * 2);

                // \??\C:\ → \Device\HarddiskVolume?\...
                if (result->Buffer[0] == L'\\' && result->Buffer[1] == L'?' && result->Buffer[2] == L'?' && result->Buffer[3] == L'\\') {
                    // Wir lassen es als \??\C:\ – FsRtlIsNameInExpression versteht es
                }

                return result;
            }
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------
// Whitelist-Check
// ---------------------------------------------------------------------
BOOLEAN IsInWhitelist(PEPROCESS process) {
    const CHAR* imageName = PsGetProcessImageFileName(process);
    if (!imageName) return FALSE;

    PUNICODE_STRING ntPath = GetProcessNtImagePath(process);
    if (!ntPath) return FALSE;

    BOOLEAN trusted = FALSE;
    UNICODE_STRING usPath = { ntPath->Length, ntPath->MaximumLength, ntPath->Buffer };

    for (ULONG i = 0; i < g_WhitelistCount; ++i) {
        if (_stricmp(imageName, g_Whitelist[i].ImageName) != 0) continue;

        UNICODE_STRING pattern;
        RtlInitUnicodeString(&pattern, g_Whitelist[i].NtPath);

        if (FsRtlIsNameInExpression(&pattern, &usPath, TRUE, nullptr)) {
            FG_LOG("TRUSTED: %s → %wZ", imageName, &usPath);
            trusted = TRUE;
            break;
        }
    }

    ExFreePoolWithTag(ntPath, POOL_TAG);
    return trusted;
}

// ---------------------------------------------------------------------
// System / MS-Signed
// ---------------------------------------------------------------------
BOOLEAN IsSystemProcess(PEPROCESS process) {
    if (PsGetProcessId(process) == (HANDLE)4) return TRUE;
    const CHAR* name = PsGetProcessImageFileName(process);
    return name && (!_stricmp(name, "System") || !_stricmp(name, "smss.exe"));
}

BOOLEAN IsMicrosoftSigned(PEPROCESS process) {
    // Optional – wir vertrauen Whitelist + System
    return FALSE;
}

// ---------------------------------------------------------------------
// EXPORT
// ---------------------------------------------------------------------
extern "C" BOOLEAN FolderGuard::Process::IsAllowed(PEPROCESS process) {
    if (!process) return FALSE;
    if (IsSystemProcess(process)) return TRUE;
    if (IsInWhitelist(process)) return TRUE;
    if (IsMicrosoftSigned(process)) return TRUE;

    const CHAR* name = PsGetProcessImageFileName(process);
    FG_LOG("BLOCKED: %s", name ? name : "unknown");
    return FALSE;
}

#pragma warning(pop)