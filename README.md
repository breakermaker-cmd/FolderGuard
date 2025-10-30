# FolderGuard

**FolderGuard** is a Windows file system minifilter driver designed to protect sensitive user data from untrusted processes.

---

## Overview

FolderGuard monitors and controls access to configured sensitive paths, ensuring that only trusted processes can read, write, or delete protected data.

**Key features:**

* Blocks destructive or suspicious operations (create, overwrite, delete, raw-disk access) on protected paths unless the process is trusted.
* Uses a **trust model** combining:

  * Windows system processes
  * A small allowlist of known safe processes (e.g., browsers, shell)
  * Code integrity/signature checks
* Emits **kernel debug logs (DbgPrint)** for every allow/deny decision, enabling analysis and fine-tuning.

---

## How It Works (High-Level)

* FolderGuard hooks into the Windows file system via **minifilter callbacks** for operations like `IRP_MJ_CREATE`, `WRITE`, and `SET_INFORMATION`.
* The **Paths module** maintains an in-memory list of protected path prefixes.
* The **Process module** evaluates whether the calling process is trusted.
* If a process attempts an operation on a protected path and is not trusted, the driver **denies the request** with `STATUS_ACCESS_DENIED` and logs the decision.

---

## Current Scope & Notes

* Protects common **data-stealing targets** (browser profiles, messaging app data). Paths can be modified in `internal/Paths/paths.cpp`.
* Designed to be **conservative**: avoids blocking system or legitimate applications by default, but prevents obvious bypass attempts (e.g., delete-on-close or backup-intent on protected files).
* **User-mode notifications are currently disabled**; all decisions are visible via kernel logs.
* Requires **Test Signing or a production certificate** to load on modern Windows builds (Secure Boot prevents unsigned drivers).
* **Note:** If anyone wants to create a user-mode communicator (KM ↔️ UM), I’d really appreciate it... that way, we could notify the user without relying on DbgPrint.

---

## Driver Setup Instructions

1. **Enable Test Signing** (or disable Secure Boot temporarily if necessary) and **temporarily disable antivirus**.

   ```cmd
   bcdedit /set testsigning on
   ```

   Reboot.

   > If you cannot enable test signing via BCDEdit: enter BIOS/UEFI during boot (DEL/F2) and temporarily **disable Secure Boot**.

2. **Build the driver** in **Release x64 mode**.

3. **Copy the driver** to the system directory:

   ```text
   C:\Windows\System32\drivers\FolderGuard.sys
   ```

4. **Configure the minifilter instance** in an elevated Command Prompt:

   ```cmd
   reg add "HKLM\SYSTEM\CurrentControlSet\Services\FolderGuard\Instances" /v DefaultInstance /t REG_SZ /d "FolderGuard Instance" /f
   reg add "HKLM\SYSTEM\CurrentControlSet\Services\FolderGuard\Instances\FolderGuard Instance" /v Altitude /t REG_SZ /d "370000" /f
   reg add "HKLM\SYSTEM\CurrentControlSet\Services\FolderGuard\Instances\FolderGuard Instance" /v Flags /t REG_DWORD /d 0 /f
   ```

5. **Load the driver**:

   ```cmd
   fltmc load FolderGuard
   ```

6. **Unload the driver** when done:

   ```cmd
   fltmc unload FolderGuard
   ```

---

## Additional Notes

* The **service name** is `FolderGuard` (not the filename). Ensure the INF/service install matches this name.
* Use **VM snapshots** or backups when testing, as kernel crashes may occur.
- for the love of me use DebugView
