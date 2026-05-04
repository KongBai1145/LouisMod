#include "driver.h"

// ------------------------------------------------------------
// Type definitions for kernel-mode process/module enumeration.
// These user-mode types are not available via ntddk.h.
// ------------------------------------------------------------

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

// PROCESS_BASIC_INFORMATION and ProcessBasicInformation are already defined in ntddk.h

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PEB_LDR_DATA* Ldr;
} PEB;

// ------------------------------------------------------------
// Process list via ZwQuerySystemInformation
// ------------------------------------------------------------
NTSTATUS handle_process_list(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len) {
    UNREFERENCED_PARAMETER(input);
    UNREFERENCED_PARAMETER(input_len);

    NTSTATUS status;
    ULONG buf_size = 256 * 1024; // 256KB initial
    PSYSTEM_PROCESS_INFORMATION spi = NULL;

    // Query required size first
    ULONG actual_size = 0;
    ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &actual_size);
    if (actual_size > 0) buf_size = actual_size + 65536;

    spi = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(PagedPool, buf_size, 'lmDR');
    if (!spi) return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(SystemProcessInformation, spi, buf_size, &actual_size);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(spi, 'lmDR');
        return status;
    }

    // Count processes and calculate output size
    UINT32 count = 0;
    PSYSTEM_PROCESS_INFORMATION current = spi;
    while (TRUE) {
        count++;
        if (current->NextEntryOffset == 0) break;
        current = (PSYSTEM_PROCESS_INFORMATION)((PUINT8)current + current->NextEntryOffset);
    }

    UINT32 out_size = sizeof(UINT32) + count * sizeof(ProcessEntry);
    PUINT8 reply = (PUINT8)ExAllocatePoolWithTag(PagedPool, out_size, 'lmDR');
    if (!reply) {
        ExFreePoolWithTag(spi, 'lmDR');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *(UINT32*)reply = count;
    ProcessEntry* entries = (ProcessEntry*)(reply + sizeof(UINT32));

    UINT32 idx = 0;
    current = spi;
    while (idx < count) {
        entries[idx].process_id = (UINT32)(ULONG_PTR)current->UniqueProcessId;

        // Copy process name (up to PROCESS_NAME_MAX chars)
        RtlZeroMemory(entries[idx].name, sizeof(entries[idx].name));
        if (current->ImageName.Buffer && current->ImageName.Length > 0) {
            UINT32 copy_len = min(current->ImageName.Length, (sizeof(entries[idx].name) - sizeof(WCHAR)));
            RtlCopyMemory(entries[idx].name, current->ImageName.Buffer, copy_len);
        }

        idx++;
        if (current->NextEntryOffset == 0) break;
        current = (PSYSTEM_PROCESS_INFORMATION)((PUINT8)current + current->NextEntryOffset);
    }

    ExFreePoolWithTag(spi, 'lmDR');
    *output = reply;
    *output_len = out_size;
    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// Module list via PEB traversal
// ------------------------------------------------------------
NTSTATUS handle_module_list(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len) {
    if (input_len < sizeof(CmdModuleListReq)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    CmdModuleListReq* req = (CmdModuleListReq*)input;
    PEPROCESS target_process = NULL;
    NTSTATUS status;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->process_id, &target_process);
    if (!NT_SUCCESS(status)) return status;

    // Get PEB address
    PROCESS_BASIC_INFORMATION pbi;
    ULONG ret_len = 0;
    status = ZwQueryInformationProcess(
        target_process,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &ret_len
    );
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(target_process);
        return status;
    }

    if (!pbi.PebBaseAddress) {
        ObDereferenceObject(target_process);
        return STATUS_UNSUCCESSFUL;
    }

    // Read PEB LDR from target process
    SIZE_T read = 0;

    // Read Peb->Ldr pointer
    UINT64 ldr_ptr = 0;
    __try {
        status = MmCopyVirtualMemory(
            target_process,
            (PUINT8)pbi.PebBaseAddress + FIELD_OFFSET(PEB, Ldr),
            PsGetCurrentProcess(),
            &ldr_ptr,
            sizeof(ldr_ptr),
            KernelMode,
            &read
        );
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }
    if (!NT_SUCCESS(status) || !ldr_ptr) {
        ObDereferenceObject(target_process);
        return status;
    }

    // Read InLoadOrderModuleList.Flink from LDR
    LIST_ENTRY ldr_list_head = {0};
    __try {
        status = MmCopyVirtualMemory(
            target_process,
            (PUINT8)ldr_ptr + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList),
            PsGetCurrentProcess(),
            &ldr_list_head,
            sizeof(ldr_list_head),
            KernelMode,
            &read
        );
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(target_process);
        return status;
    }

    // Walk the module list (cap at 256 modules)
    // We read LIST_ENTRY from target process space and use CONTAINING_RECORD
    // with target-space addresses to correctly locate each LDR_DATA_TABLE_ENTRY.
    UINT32 max_modules = 256;
    UINT32 out_size = sizeof(UINT32) + max_modules * sizeof(ModuleEntry);
    PUINT8 reply = (PUINT8)ExAllocatePoolWithTag(PagedPool, out_size, 'lmDR');
    if (!reply) {
        ObDereferenceObject(target_process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UINT32 mod_count = 0;
    ModuleEntry* entries = (ModuleEntry*)(reply + sizeof(UINT32));

    // The head address within the target process's PEB_LDR_DATA
    PUINT8 head_addr_in_target = (PUINT8)ldr_ptr + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList);

    // Start from the first module (Flink of the head)
    PLIST_ENTRY current_flink = ldr_list_head.Flink;

    while (mod_count < max_modules) {
        // Check if we've wrapped back to the list head
        if ((PUINT8)current_flink == head_addr_in_target) break;

        // Read the LIST_ENTRY at current_flink from target process
        LIST_ENTRY current_entry = {0};
        __try {
            status = MmCopyVirtualMemory(
                target_process,
                current_flink,
                PsGetCurrentProcess(),
                &current_entry,
                sizeof(LIST_ENTRY),
                KernelMode,
                &read
            );
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_ACCESS_VIOLATION;
        }
        if (!NT_SUCCESS(status)) break;

        // Compute the LDR_DATA_TABLE_ENTRY address in the target:
        // current_flink points to the InLoadOrderLinks field within the entry
        LDR_DATA_TABLE_ENTRY entry = {0};
        PUINT8 entry_addr = (PUINT8)current_flink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        __try {
            status = MmCopyVirtualMemory(
                target_process,
                entry_addr,
                PsGetCurrentProcess(),
                &entry,
                sizeof(entry),
                KernelMode,
                &read
            );
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_ACCESS_VIOLATION;
        }
        if (!NT_SUCCESS(status)) break;

        entries[mod_count].base_address = (UINT64)(ULONG_PTR)entry.DllBase;
        entries[mod_count].module_size = (UINT64)entry.SizeOfImage;

        RtlZeroMemory(entries[mod_count].name, sizeof(entries[mod_count].name));
        if (entry.FullDllName.Buffer && entry.FullDllName.Length > 0) {
            UINT32 copy_len = min(entry.FullDllName.Length,
                (sizeof(entries[mod_count].name) - sizeof(WCHAR)));
            RtlCopyMemory(entries[mod_count].name, entry.FullDllName.Buffer, copy_len);
        }

        mod_count++;

        // Move to the next module via the current entry's Flink
        current_flink = current_entry.Flink;
    }

    ObDereferenceObject(target_process);

    *(UINT32*)reply = mod_count;
    *output = reply;
    *output_len = sizeof(UINT32) + mod_count * sizeof(ModuleEntry);
    return STATUS_SUCCESS;
}
