#include <fltKernel.h>
#include <ntstrsafe.h>

#include "internal/Paths/paths.h"
#include "internal/Process/process.h"
#include "internal/Callbacks/callbacks.h"
#include "internal/Comm/comm.h"

PFLT_FILTER gFilterHandle = nullptr;

namespace FolderGuard {

    namespace Driver {

        NTSTATUS Unload(FLT_FILTER_UNLOAD_FLAGS Flags) {
            UNREFERENCED_PARAMETER(Flags);
            DbgPrint("[FolderGuard] Unloading minifilter\n");
            FolderGuard::Comm::Cleanup();
            Paths::Cleanup();
            if (gFilterHandle) FltUnregisterFilter(gFilterHandle);
            gFilterHandle = nullptr;
            return STATUS_SUCCESS;
        }

        NTSTATUS Entry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
            UNREFERENCED_PARAMETER(RegistryPath);
            DbgPrint("[FolderGuard] Loading minifilter\n");

            Paths::Init();
            Paths::DiscoverDefaultPaths();

            NTSTATUS status = FolderGuard::Comm::Init();
            if (!NT_SUCCESS(status)) {
                Paths::Cleanup();
                return status;
            }

            FLT_OPERATION_REGISTRATION CallbacksArray[] = {
                { IRP_MJ_CREATE, 0, Callbacks::PreOperation, nullptr },
                { IRP_MJ_OPERATION_END }
            };

            FLT_REGISTRATION FilterRegistration = {
                sizeof(FLT_REGISTRATION),
                FLT_REGISTRATION_VERSION,
                0,
                nullptr,
                CallbacksArray,
                Unload,
                nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr
            };

            status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
            if (!NT_SUCCESS(status)) {
                Paths::Cleanup();
                return status;
            }


            status = FltStartFiltering(gFilterHandle);
            if (!NT_SUCCESS(status)) {
                FltUnregisterFilter(gFilterHandle);
                gFilterHandle = nullptr;
                Paths::Cleanup();
                return status;
            }

            return STATUS_SUCCESS;
        }

    } 

}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    return FolderGuard::Driver::Entry(DriverObject, RegistryPath);
}
