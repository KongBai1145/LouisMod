#include "driver.h"

DRIVER_GLOBALS g_driver = {0};

// ------------------------------------------------------------
// IOCTL dispatch (forward declaration)
// ------------------------------------------------------------
NTSTATUS dispatch_ioctl(PDEVICE_OBJECT device_obj, PIRP irp);

// ------------------------------------------------------------
// Random device name generation using processor timestamp
// Generates: \Device\lm_<16 hex chars>
// ------------------------------------------------------------
static WCHAR g_device_name_buf[64] = {0};
static WCHAR g_symlink_name_buf[64] = {0};

static NTSTATUS generate_random_names(VOID) {
    static const WCHAR dev_prefix[] = L"\\Device\\lm_";
    static const WCHAR sym_prefix[] = L"\\GLOBAL??\\Global\\lm_";
    static const WCHAR hex[] = L"0123456789abcdef";

    // Mix multiple entropy sources for better randomness
    LARGE_INTEGER system_time;
    KeQuerySystemTime(&system_time);
    UINT64 timestamp = __rdtsc();
    UINT64 time_entropy = (UINT64)system_time.QuadPart;

    // LCG mixing
    UINT64 mixed = timestamp ^ time_entropy;
    mixed = mixed * 6364136223846793005ULL + 1442695040888963407ULL;
    mixed ^= (mixed >> 31);

    // Build device name: \Device\lm_<16 hex>
    UINT32 dev_prefix_len = (UINT32)(sizeof(dev_prefix) / sizeof(WCHAR) - 1);
    RtlCopyMemory(g_device_name_buf, dev_prefix, dev_prefix_len * sizeof(WCHAR));
    for (int i = 0; i < 16; i++) {
        g_device_name_buf[dev_prefix_len + i] = hex[(mixed >> (i * 4)) & 0xF];
    }
    g_device_name_buf[dev_prefix_len + 16] = L'\0';

    // Build symlink name: \GLOBAL??\Global\lm_<16 hex>
    UINT32 sym_prefix_len = (UINT32)(sizeof(sym_prefix) / sizeof(WCHAR) - 1);
    RtlCopyMemory(g_symlink_name_buf, sym_prefix, sym_prefix_len * sizeof(WCHAR));
    for (int i = 0; i < 16; i++) {
        g_symlink_name_buf[sym_prefix_len + i] = hex[(mixed >> (i * 4)) & 0xF];
    }
    g_symlink_name_buf[sym_prefix_len + 16] = L'\0';

    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// Store device name in registry for Rust-side discovery
// ------------------------------------------------------------
static NTSTATUS store_device_name_in_registry(VOID) {
    NTSTATUS status;
    HANDLE key_handle = NULL;
    UNICODE_STRING key_path;
    UNICODE_STRING value_name;
    OBJECT_ATTRIBUTES obj_attr;

    RtlInitUnicodeString(&key_path, LOUISMOD_REGISTRY_PATH);
    InitializeObjectAttributes(&obj_attr, &key_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    ULONG disposition = 0;
    status = ZwCreateKey(&key_handle, KEY_WRITE, &obj_attr, 0, NULL,
        REG_OPTION_VOLATILE, &disposition);
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&value_name, LOUISMOD_REGISTRY_VALUE);
    UINT32 name_bytes = (UINT32)((wcslen(g_driver.device_name) + 1) * sizeof(WCHAR));

    status = ZwSetValueKey(key_handle, &value_name, 0, REG_SZ,
        g_driver.device_name, name_bytes);

    ZwClose(key_handle);
    return status;
}

// ------------------------------------------------------------
// Create / Close
// ------------------------------------------------------------
static NTSTATUS dispatch_create(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS dispatch_close(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// Unload
// ------------------------------------------------------------
static VOID driver_unload(PDRIVER_OBJECT driver_obj) {
    UNREFERENCED_PARAMETER(driver_obj);

    // Clean up process protection callbacks
    if (g_driver.protection_callback_handle) {
        ObUnRegisterCallbacks(g_driver.protection_callback_handle);
        g_driver.protection_callback_handle = NULL;
    }
    if (g_driver.protected_process) {
        ObDereferenceObject(g_driver.protected_process);
        g_driver.protected_process = NULL;
    }

    // Clean up CR3 cache
    if (g_driver.cr3_active && g_driver.cr3_cached_process) {
        ObDereferenceObject(g_driver.cr3_cached_process);
        g_driver.cr3_active = FALSE;
        g_driver.cr3_cached_process = NULL;
    }

    if (g_driver.hiding_active) {
        return; // don't touch device/symlink if we've unlinked ourselves
    }

    UNICODE_STRING symlink;
    RtlInitUnicodeString(&symlink, g_driver.symlink_name);
    IoDeleteSymbolicLink(&symlink);

    if (g_driver.device_object) {
        IoDeleteDevice(g_driver.device_object);
    }
}

// ------------------------------------------------------------
// Resolve NtUserSendInput from win32kbase.sys
// by walking PsLoadedModuleList and parsing PE export table.
// Must be called AFTER win32kbase.sys is loaded (session init).
// ------------------------------------------------------------
NTSTATUS resolve_win32kbase_functions(VOID) {
    UNICODE_STRING routine_name;
    RtlInitUnicodeString(&routine_name, L"PsLoadedModuleList");

    PLIST_ENTRY ps_loaded_module_list = (PLIST_ENTRY)MmGetSystemRoutineAddress(&routine_name);
    if (!ps_loaded_module_list) return STATUS_NOT_FOUND;

    UNICODE_STRING target_name;
    RtlInitUnicodeString(&target_name, L"win32kbase.sys");

    PLIST_ENTRY entry = ps_loaded_module_list->Flink;
    while (entry != ps_loaded_module_list) {
        PUINT8 dll_base = *(PUINT8*)((PUINT8)entry + 0x30);
        if (!dll_base) { entry = entry->Flink; continue; }

        // BaseDllName is at offset 0x58 from KLDR_DATA_TABLE_ENTRY
        UNICODE_STRING* base_name = (UNICODE_STRING*)((PUINT8)entry + 0x58);

        if (RtlCompareUnicodeString(base_name, &target_name, TRUE) == 0) {
            // Found win32kbase.sys — parse its PE exports
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_base;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) break;

            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dll_base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) break;

            IMAGE_DATA_DIRECTORY export_dir =
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (export_dir.VirtualAddress == 0 || export_dir.Size == 0) break;

            PIMAGE_EXPORT_DIRECTORY exports =
                (PIMAGE_EXPORT_DIRECTORY)(dll_base + export_dir.VirtualAddress);

            DWORD* name_table = (DWORD*)(dll_base + exports->AddressOfNames);
            WORD* ordinal_table = (WORD*)(dll_base + exports->AddressOfNameOrdinals);
            DWORD* func_table = (DWORD*)(dll_base + exports->AddressOfFunctions);

            // Search for NtUserSendInput by name
            for (DWORD i = 0; i < exports->NumberOfNames; i++) {
                char* func_name = (char*)(dll_base + name_table[i]);
                if (RtlCompareMemory(func_name, "NtUserSendInput", 15) == 15 &&
                    func_name[15] == '\0') {

                    DWORD func_rva = func_table[ordinal_table[i]];

                    // Skip forwarded exports (RVA inside export section)
                    if (func_rva >= export_dir.VirtualAddress &&
                        func_rva < export_dir.VirtualAddress + export_dir.Size) {
                        DbgPrint("[LouisMod] NtUserSendInput is a forwarded export, skipping\n");
                        break;
                    }

                    g_driver.fn_send_input =
                        (NtUserSendInput_t)(dll_base + func_rva);
                    DbgPrint("[LouisMod] NtUserSendInput resolved at 0x%llX\n",
                        (ULONGLONG)(ULONG_PTR)g_driver.fn_send_input);
                    return STATUS_SUCCESS;
                }
            }
            break; // win32kbase.sys found but NtUserSendInput not in exports
        }

        entry = entry->Flink;
    }

    return STATUS_NOT_FOUND;
}

// ------------------------------------------------------------
// Ensure input injection functions are resolved (deferred).
// Called from input handlers on first invocation.
// ------------------------------------------------------------
NTSTATUS ensure_input_resolved(VOID) {
    if (g_driver.fn_send_input) {
        return STATUS_SUCCESS;
    }

    // Don't retry if already attempted and failed
    if (g_driver.win32kbase_checked) {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS status = resolve_win32kbase_functions();
    g_driver.win32kbase_checked = TRUE;

    if (!NT_SUCCESS(status)) {
        DbgPrint("[LouisMod] Failed to resolve NtUserSendInput: 0x%08X\n", status);
    }

    return status;
}

// ------------------------------------------------------------
// DriverEntry
// ------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);
    UNICODE_STRING device_name;
    UNICODE_STRING symlink_name;
    NTSTATUS status;

    // Generate random device name for stealth
    generate_random_names();
    KeInitializeSpinLock(&g_driver.ob_lock);
    wcscpy_s(g_driver.device_name, 64, g_device_name_buf);
    wcscpy_s(g_driver.symlink_name, 64, g_symlink_name_buf);

    RtlInitUnicodeString(&device_name, g_driver.device_name);
    RtlInitUnicodeString(&symlink_name, g_driver.symlink_name);

    status = IoCreateDevice(
        driver_obj,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &g_driver.device_object
    );
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&symlink_name, &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_driver.device_object);
        g_driver.device_object = NULL;
        return status;
    }

    driver_obj->MajorFunction[IRP_MJ_CREATE] = dispatch_create;
    driver_obj->MajorFunction[IRP_MJ_CLOSE] = dispatch_close;
    driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_ioctl;
    driver_obj->DriverUnload = driver_unload;

    // Store device name in registry so Rust side can discover it
    status = store_device_name_in_registry();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[LouisMod] Warning: failed to store device name in registry: 0x%08X\n", status);
    }

    // Phase 5: Apply stealth measures
    // 1. Hide from PsLoadedModuleList (DKOM)
    hiding_remove_from_loaded_modules();

    // 2. Clear driver name from driver object
    hiding_clear_driver_name();

    // 3. Hide device object from directory listing
    hiding_hide_device_object();

    // 4. Self-delete service registry entry
    hiding_delete_service_registry();

    // 5. Clean up MmUnloadedDrivers to remove our traces
    hiding_cleanup_unloaded_drivers();

    // 6. Attempt PiDDBCacheTable cleanup (may be skipped on Win10+ with PG)
    hiding_cleanup_piddb_cache();

    g_driver.hiding_active = TRUE;

    return STATUS_SUCCESS;
}
