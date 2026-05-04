#include "driver.h"

// External declarations for functions defined in ntifs.h or driver.c
extern NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTKERNELAPI VOID ObMakeTemporaryObject(_In_ PVOID Object);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);

// ------------------------------------------------------------
// DKOM: Remove this driver from PsLoadedModuleList
// Uses MmGetSystemRoutineAddress to resolve the exported symbol
// then unlinks our entry from the doubly-linked list.
// IRQL must be raised to DPC level to prevent list corruption.
// ------------------------------------------------------------
NTSTATUS hiding_remove_from_loaded_modules(VOID) {
    UNICODE_STRING routine_name;
    RtlInitUnicodeString(&routine_name, L"PsLoadedModuleList");

    PLIST_ENTRY ps_loaded_module_list = (PLIST_ENTRY)MmGetSystemRoutineAddress(&routine_name);
    if (!ps_loaded_module_list) return STATUS_NOT_FOUND;

    PUINT8 our_base = (PUINT8)DriverEntry;

    // Raise IRQL to DPC level to prevent list modification during traversal
    KIRQL old_irql = KeRaiseIrqlToDpcLevel();

    PLIST_ENTRY entry = ps_loaded_module_list->Flink;
    while (entry != ps_loaded_module_list) {
        // KLDR_DATA_TABLE_ENTRY: DllBase at offset 0x30, SizeOfImage at offset 0x40 on x64
        PUINT8 module_base = *(PUINT8*)((PUINT8)entry + 0x30);

        if (module_base) {
            UINT32 size_of_image = *(UINT32*)((PUINT8)entry + 0x40);

            if (our_base >= module_base && our_base < module_base + size_of_image) {
                // Found ourselves — unlink from list
                PLIST_ENTRY blink = entry->Blink;
                PLIST_ENTRY flink = entry->Flink;
                flink->Blink = blink;
                blink->Flink = flink;

                // Null out our links to prevent dangling pointers
                entry->Flink = entry;
                entry->Blink = entry;

                KeLowerIrql(old_irql);
                return STATUS_SUCCESS;
            }
        }

        entry = entry->Flink;
    }

    KeLowerIrql(old_irql);
    return STATUS_NOT_FOUND;
}

// ------------------------------------------------------------
// Clear the driver name from the driver object
// ------------------------------------------------------------
NTSTATUS hiding_clear_driver_name(VOID) {
    if (g_driver.device_object && g_driver.device_object->DriverObject) {
        PDRIVER_OBJECT drv = g_driver.device_object->DriverObject;
        if (drv->DriverName.Buffer && drv->DriverName.MaximumLength > 0) {
            RtlZeroMemory(drv->DriverName.Buffer, drv->DriverName.MaximumLength);
            drv->DriverName.Length = 0;
        }
    }
    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// Hide device object from \Device\ directory
// Uses ObMakeTemporaryObject to remove the name from Object Manager namespace.
// The device remains functional via its symbolic link.
// ------------------------------------------------------------
NTSTATUS hiding_hide_device_object(VOID) {
    if (!g_driver.device_object) return STATUS_SUCCESS;

    // ObMakeTemporaryObject removes the permanent name entry from the Object Manager,
    // making the device invisible to directory enumeration (\Device\ listing).
    // The device itself remains alive (referenced by the driver and symlink).
    ObMakeTemporaryObject((PVOID)g_driver.device_object);

    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// Self-delete the service registry entry
// Removes HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
// ------------------------------------------------------------
NTSTATUS hiding_delete_service_registry(VOID) {
    NTSTATUS status;
    HANDLE key_handle = NULL;
    UNICODE_STRING key_path;
    OBJECT_ATTRIBUTES obj_attr;

    RtlInitUnicodeString(&key_path,
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services");
    InitializeObjectAttributes(&obj_attr, &key_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenKey(&key_handle, KEY_READ, &obj_attr);
    if (!NT_SUCCESS(status)) return status;

    ULONG index = 0;
    ULONG result_len = 0;
    PKEY_BASIC_INFORMATION key_info = NULL;
    ULONG buf_size = 4096;

    key_info = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(PagedPool, buf_size, 'lmDR');
    if (!key_info) {
        ZwClose(key_handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    while (TRUE) {
        status = ZwEnumerateKey(key_handle, index, KeyBasicInformation,
            key_info, buf_size, &result_len);
        if (!NT_SUCCESS(status)) break;

        if (key_info->NameLength >= 3 * sizeof(WCHAR) &&
            key_info->Name[0] == L'l' &&
            key_info->Name[1] == L'm' &&
            key_info->Name[2] == L'_') {

            UNICODE_STRING subkey_name;
            subkey_name.Buffer = key_info->Name;
            subkey_name.Length = (USHORT)key_info->NameLength;
            subkey_name.MaximumLength = (USHORT)key_info->NameLength;

            HANDLE subkey_handle = NULL;
            OBJECT_ATTRIBUTES subkey_attr;
            InitializeObjectAttributes(&subkey_attr, &subkey_name,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, key_handle, NULL);

            status = ZwOpenKey(&subkey_handle, DELETE, &subkey_attr);
            if (NT_SUCCESS(status)) {
                ZwDeleteKey(subkey_handle);
                ZwClose(subkey_handle);
            }
            break;
        }

        index++;
    }

    ExFreePoolWithTag(key_info, 'lmDR');
    ZwClose(key_handle);
    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// Process protection: ObRegisterCallbacks pre-operation callback
// Strips dangerous access rights from other processes targeting our protected process.
// Uses spinlock for thread-safe access to g_driver.protected_process.
// ------------------------------------------------------------
static OB_PREOP_CALLBACK_STATUS protection_pre_callback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Only handle handle creation/duplication
    if (Info->Operation != OB_OPERATION_HANDLE_CREATE &&
        Info->Operation != OB_OPERATION_HANDLE_DUPLICATE) {
        return OB_PREOP_SUCCESS;
    }

    // Get the target object
    PEPROCESS target = (PEPROCESS)Info->Object;
    if (!target) return OB_PREOP_SUCCESS;

    // Thread-safe read of protected_process
    KIRQL old_irql;
    KeAcquireSpinLock(&g_driver.ob_lock, &old_irql);
    PEPROCESS protected = g_driver.protected_process;
    KeReleaseSpinLock(&g_driver.ob_lock, old_irql);

    // Check if target is our protected process
    if (!protected || target != protected) {
        return OB_PREOP_SUCCESS;
    }

    // Don't restrict our own driver process
    if (PsGetCurrentProcess() == protected) {
        return OB_PREOP_SUCCESS;
    }

    // Strip dangerous access rights via the proper struct
    if (Info->Parameters) {
        if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
            Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_PROTECT_MASK;
        } else {
            Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_PROTECT_MASK;
        }
    }

    return OB_PREOP_SUCCESS;
}

// ------------------------------------------------------------
// CMD_PROTECT_PROCESS: Register process protection callback
// Uses spinlock to protect concurrent access to protected_process.
// ------------------------------------------------------------
NTSTATUS handle_protect_process(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len) {
    UNREFERENCED_PARAMETER(output);
    UNREFERENCED_PARAMETER(output_len);

    if (input_len < sizeof(CmdProtectProcess)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    CmdProtectProcess* req = (CmdProtectProcess*)input;

    // If disabling, clean up existing callback
    if (req->enable == 0) {
        KIRQL old_irql;
        KeAcquireSpinLock(&g_driver.ob_lock, &old_irql);

        if (g_driver.protection_callback_handle) {
            ObUnRegisterCallbacks(g_driver.protection_callback_handle);
            g_driver.protection_callback_handle = NULL;
        }
        if (g_driver.protected_process) {
            ObDereferenceObject(g_driver.protected_process);
            g_driver.protected_process = NULL;
        }

        KeReleaseSpinLock(&g_driver.ob_lock, old_irql);
        return STATUS_SUCCESS;
    }

    // Enable protection: look up target process
    PEPROCESS target_process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)req->process_id, &target_process);
    if (!NT_SUCCESS(status)) return status;

    // Replace existing callback under spinlock
    KIRQL old_irql;
    KeAcquireSpinLock(&g_driver.ob_lock, &old_irql);

    if (g_driver.protection_callback_handle) {
        ObUnRegisterCallbacks(g_driver.protection_callback_handle);
        g_driver.protection_callback_handle = NULL;
    }
    if (g_driver.protected_process) {
        ObDereferenceObject(g_driver.protected_process);
        g_driver.protected_process = NULL;
    }

    // Build callback registration with Win10+ types
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"321400.000");

    OB_OPERATION_REGISTRATION op_reg = {0};
    op_reg.ObjectType = PsProcessType;
    op_reg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    op_reg.PreOperation = protection_pre_callback;
    op_reg.PostOperation = NULL;

    OB_CALLBACK_REGISTRATION reg = {0};
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 1;
    reg.Altitude = altitude;
    reg.RegistrationContext = NULL;
    reg.OperationRegistration = &op_reg;

    status = ObRegisterCallbacks(&reg, &g_driver.protection_callback_handle);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(target_process);
        KeReleaseSpinLock(&g_driver.ob_lock, old_irql);
        return status;
    }

    g_driver.protected_process = target_process;
    KeReleaseSpinLock(&g_driver.ob_lock, old_irql);

    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// CMD_CR3_ENABLE: Cache DirectoryTableBase for CR3 shenanigan detection
// ------------------------------------------------------------
NTSTATUS handle_cr3_enable(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len) {
    UNREFERENCED_PARAMETER(output);
    UNREFERENCED_PARAMETER(output_len);

    if (input_len < sizeof(UINT32)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    UINT32 pid = *(UINT32*)input;

    if (g_driver.cr3_active && g_driver.cr3_cached_process) {
        ObDereferenceObject(g_driver.cr3_cached_process);
        g_driver.cr3_active = FALSE;
        g_driver.cr3_cached_process = NULL;
    }

    PEPROCESS target = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &target);
    if (!NT_SUCCESS(status)) return status;

    ULONG_PTR dtb = *(ULONG_PTR*)((PUINT8)target + EPROCESS_DTB_OFFSET);

    g_driver.cr3_cached_process = target;
    g_driver.cr3_cached_pid = pid;
    g_driver.cr3_expected_dtb = dtb;
    g_driver.cr3_active = TRUE;

    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// CMD_CR3_DISABLE: Disable CR3 shenanigan detection
// ------------------------------------------------------------
NTSTATUS handle_cr3_disable(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len) {
    UNREFERENCED_PARAMETER(input);
    UNREFERENCED_PARAMETER(input_len);
    UNREFERENCED_PARAMETER(output);
    UNREFERENCED_PARAMETER(output_len);

    if (g_driver.cr3_active && g_driver.cr3_cached_process) {
        ObDereferenceObject(g_driver.cr3_cached_process);
    }

    g_driver.cr3_active = FALSE;
    g_driver.cr3_cached_process = NULL;
    g_driver.cr3_cached_pid = 0;
    g_driver.cr3_expected_dtb = 0;

    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// CR3 verification helper (called from dispatch_ioctl)
// Checks if the cached process's DTB has been tampered with.
// ------------------------------------------------------------
NTSTATUS verify_cr3_cache(VOID) {
    if (!g_driver.cr3_active || !g_driver.cr3_cached_process) {
        return STATUS_SUCCESS;
    }

    ULONG_PTR current_dtb = *(ULONG_PTR*)((PUINT8)g_driver.cr3_cached_process + EPROCESS_DTB_OFFSET);
    if (current_dtb != g_driver.cr3_expected_dtb) {
        DbgPrint("[LouisMod] CR3 tampering detected! PID=%u: expected=0x%llX actual=0x%llX\n",
            g_driver.cr3_cached_pid,
            (ULONGLONG)g_driver.cr3_expected_dtb,
            (ULONGLONG)current_dtb);
        g_driver.cr3_expected_dtb = current_dtb;
    }

    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// MmUnloadedDrivers cleanup
// Removes our driver entry from the unloaded driver list to prevent
// detection via scanning of recently unloaded drivers.
// ------------------------------------------------------------
NTSTATUS hiding_cleanup_unloaded_drivers(VOID) {
    // MmUnloadedDrivers is an array of UNICODE_STRING or ULONG_PTR (Win10 2004+)
    // in ntoskrnl's .data section. We scan for known unloaded driver names
    // matching our device name pattern and zero them out.

    // Find ntoskrnl base
    UNICODE_STRING routine_name;
    RtlInitUnicodeString(&routine_name, L"MmGetSystemRoutineAddress");
    PUINT8 mm_gsra = (PUINT8)MmGetSystemRoutineAddress(&routine_name);
    if (!mm_gsra) return STATUS_NOT_FOUND;

    // Get ntoskrnl base from the function address
    PUINT8 kernel_base = mm_gsra;
    for (LONG_PTR i = -0x2000; i < 0; i += 0x1000) {
        if (*(USHORT*)(kernel_base + i) == IMAGE_DOS_SIGNATURE) {
            kernel_base = kernel_base + i;
            break;
        }
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)kernel_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_NOT_FOUND;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(kernel_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return STATUS_NOT_FOUND;

    // Walk sections to find .data
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    PUINT8 data_start = NULL;
    SIZE_T data_size = 0;

    for (UINT16 i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char sec_name[9] = {0};
        RtlCopyMemory(sec_name, sections[i].Name, 8);
        if (RtlCompareMemory(sec_name, ".data", 5) == 5) {
            data_start = kernel_base + sections[i].VirtualAddress;
            data_size = sections[i].Misc.VirtualSize;
            break;
        }
    }

    if (!data_start || data_size < 1024) return STATUS_NOT_FOUND;

    // Temporarily disable write protection (CR0.WP)
    ULONG_PTR cr0 = __readcr0();
    __writecr0(cr0 & ~((ULONG_PTR)0x10000)); // Clear WP bit

    // Scan .data section for our service name pattern (lm_*)
    // We search for UNICODE_STRING structures pointing to unloaded driver names
    SIZE_T scan_end = data_size - sizeof(UNICODE_STRING);
    for (SIZE_T offset = 0; offset < scan_end; offset += sizeof(PVOID)) {
        PUNICODE_STRING us = (PUNICODE_STRING)(data_start + offset);

        // Sanity check: Length should be reasonable for a driver name
        if (us->Length < 6 * sizeof(WCHAR) || us->Length > 128 * sizeof(WCHAR)) continue;
        if (us->MaximumLength < us->Length || us->MaximumLength > 256 * sizeof(WCHAR)) continue;

        // Check if Buffer points within the kernel address range
        if (!us->Buffer || (ULONG_PTR)us->Buffer < 0xFFFFF00000000000ULL) continue;

        __try {
            if (us->Length >= 3 * sizeof(WCHAR) &&
                us->Buffer[0] == L'l' &&
                us->Buffer[1] == L'm' &&
                us->Buffer[2] == L'_') {

                // Found our entry — zero it out
                RtlZeroMemory(us->Buffer, us->MaximumLength);
                us->Length = 0;
                us->Buffer = NULL;
                us->MaximumLength = 0;

                DbgPrint("[LouisMod] Cleaned up MmUnloadedDrivers entry\n");
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Skip invalid entries
            continue;
        }
    }

    // Restore write protection
    __writecr0(cr0);

    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// PiDDBCacheTable cleanup (stub — skipped on Win10+ due to PatchGuard)
// On Win10 1607+, PiDDBCacheTable is deprecated and protected by PG.
// On older builds, we could remove our entry from the AVL table.
// ------------------------------------------------------------
NTSTATUS hiding_cleanup_piddb_cache(VOID) {
    // PiDDBCacheTable is deprecated on Win10 1607+. The code integrity
    // subsystem uses different mechanisms for tracking driver hashes.
    // Modifying CI structures on PG-enabled systems causes bugcheck 0x109.
    //
    // Since our primary target is Win10/11, we skip this step.
    // Self-deletion of the service registry is sufficient for hiding
    // from most detection methods on modern Windows.

    DbgPrint("[LouisMod] PiDDBCacheTable cleanup: skipped (Win10+, PG-protected)\n");
    return STATUS_SUCCESS;
}
