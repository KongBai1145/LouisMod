#include "driver.h"

NTSTATUS handle_read_memory(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len) {
    if (input_len < sizeof(CmdReadMemoryReq)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    CmdReadMemoryReq* req = (CmdReadMemoryReq*)input;
    PEPROCESS target_process = NULL;
    NTSTATUS status;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->process_id, &target_process);
    if (!NT_SUCCESS(status)) return status;

    // Allocate output buffer for the read data
    PUINT8 buf = (PUINT8)ExAllocatePoolWithTag(NonPagedPool, req->size, 'lmDR');
    if (!buf) {
        ObDereferenceObject(target_process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SIZE_T read_bytes = 0;
    __try {
        status = MmCopyVirtualMemory(
            target_process,
            (PVOID)(ULONG_PTR)req->address,
            PsGetCurrentProcess(),
            buf,
            req->size,
            KernelMode,
            &read_bytes
        );
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }

    ObDereferenceObject(target_process);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, 'lmDR');
        return status;
    }

    *output = buf;
    *output_len = (UINT32)read_bytes;
    return STATUS_SUCCESS;
}

NTSTATUS handle_write_memory(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len) {
    if (input_len < sizeof(CmdWriteMemoryReq)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    CmdWriteMemoryReq* req = (CmdWriteMemoryReq*)input;
    PUINT8 data = input + sizeof(CmdWriteMemoryReq);
    UINT32 data_len = input_len - sizeof(CmdWriteMemoryReq);

    if (data_len < req->size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PEPROCESS target_process = NULL;
    NTSTATUS status;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->process_id, &target_process);
    if (!NT_SUCCESS(status)) return status;

    SIZE_T written_bytes = 0;
    __try {
        status = MmCopyVirtualMemory(
            PsGetCurrentProcess(),
            data,
            target_process,
            (PVOID)(ULONG_PTR)req->address,
            req->size,
            KernelMode,
            &written_bytes
        );
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }

    ObDereferenceObject(target_process);

    if (!NT_SUCCESS(status)) return status;

    // Return bytes written as a simple UINT32
    PUINT8 reply = (PUINT8)ExAllocatePoolWithTag(NonPagedPool, sizeof(UINT32), 'lmDR');
    if (!reply) return STATUS_INSUFFICIENT_RESOURCES;

    *(UINT32*)reply = (UINT32)written_bytes;
    *output = reply;
    *output_len = sizeof(UINT32);
    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// Batch read: multiple memory reads in a single IOCTL
// Entries are processed sequentially; EPROCESS is cached per-PID within the batch.
// ------------------------------------------------------------
NTSTATUS handle_batch_read(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len) {
    if (input_len < sizeof(UINT32)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    UINT32 n_entries = *(UINT32*)input;
    if (n_entries == 0 || n_entries > BATCH_MAX_ENTRIES) {
        return STATUS_INVALID_PARAMETER;
    }

    UINT32 needed = sizeof(UINT32) + n_entries * sizeof(CmdBatchReadEntry);
    if (input_len < needed) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    CmdBatchReadEntry* entries = (CmdBatchReadEntry*)(input + sizeof(UINT32));

    // Calculate max output size: count + per-entry (NTSTATUS + data_size + data)
    UINT32 total_data = 0;
    for (UINT32 i = 0; i < n_entries; i++) {
        UINT32 entry_size = entries[i].size;
        if (entry_size > BATCH_MAX_ENTRY_SIZE) entry_size = BATCH_MAX_ENTRY_SIZE;
        total_data += entry_size;
    }
    UINT32 out_size = sizeof(UINT32) +
        n_entries * (sizeof(NTSTATUS) + sizeof(UINT32)) + total_data;

    PUINT8 reply = (PUINT8)ExAllocatePoolWithTag(NonPagedPool, out_size, 'lmDR');
    if (!reply) return STATUS_INSUFFICIENT_RESOURCES;

    *(UINT32*)reply = n_entries;
    PUINT8 wp = reply + sizeof(UINT32); // write pointer

    // Per-batch EPROCESS cache (avoids redundant lookups for same PID)
    PEPROCESS cached_eprocess = NULL;
    UINT32 cached_pid = 0;
    BOOLEAN has_cache = FALSE;

    for (UINT32 i = 0; i < n_entries; i++) {
        NTSTATUS entry_status;
        PEPROCESS target;
        UINT32 read_size = entries[i].size;
        if (read_size > BATCH_MAX_ENTRY_SIZE) read_size = BATCH_MAX_ENTRY_SIZE;

        if (has_cache && entries[i].process_id == cached_pid) {
            target = cached_eprocess;
            entry_status = STATUS_SUCCESS;
        } else {
            if (has_cache) {
                ObDereferenceObject(cached_eprocess);
                has_cache = FALSE;
            }
            entry_status = PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)entries[i].process_id, &target);
            if (NT_SUCCESS(entry_status)) {
                cached_eprocess = target;
                cached_pid = entries[i].process_id;
                has_cache = TRUE;
            }
        }

        if (!NT_SUCCESS(entry_status)) {
            *(NTSTATUS*)wp = entry_status;
            wp += sizeof(NTSTATUS);
            *(UINT32*)wp = 0;
            wp += sizeof(UINT32);
            continue;
        }

        PUINT8 buf = (PUINT8)ExAllocatePoolWithTag(NonPagedPool, read_size, 'lmDR');
        if (!buf) {
            *(NTSTATUS*)wp = STATUS_INSUFFICIENT_RESOURCES;
            wp += sizeof(NTSTATUS);
            *(UINT32*)wp = 0;
            wp += sizeof(UINT32);
            continue;
        }

        SIZE_T read_bytes = 0;
        __try {
            entry_status = MmCopyVirtualMemory(
                target,
                (PVOID)(ULONG_PTR)entries[i].address,
                PsGetCurrentProcess(),
                buf,
                read_size,
                KernelMode,
                &read_bytes
            );
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            entry_status = STATUS_ACCESS_VIOLATION;
            read_bytes = 0;
        }

        *(NTSTATUS*)wp = entry_status;
        wp += sizeof(NTSTATUS);

        UINT32 actual = (UINT32)read_bytes;
        *(UINT32*)wp = actual;
        wp += sizeof(UINT32);

        if (actual > 0) {
            RtlCopyMemory(wp, buf, actual);
            wp += actual;
        }

        ExFreePoolWithTag(buf, 'lmDR');
    }

    if (has_cache) {
        ObDereferenceObject(cached_eprocess);
    }

    *output = reply;
    *output_len = (UINT32)(wp - reply);
    return STATUS_SUCCESS;
}
