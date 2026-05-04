#include "driver.h"

NTSTATUS dispatch_ioctl(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    UINT32 info = 0;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    UINT32 code = stack->Parameters.DeviceIoControl.IoControlCode;
    PUINT8 inbuf = (PUINT8)irp->AssociatedIrp.SystemBuffer;
    UINT32 inlen = stack->Parameters.DeviceIoControl.InputBufferLength;
    PUINT8 outbuf = (PUINT8)irp->AssociatedIrp.SystemBuffer;
    UINT32 outlen = stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (code != IOCTL_LOUISMOD_COMMAND) {
        irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // Minimum: command_id(4) + xor_key(4)
    if (inlen < WIRE_HEADER_SIZE) {
        irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Parse wire header
    // Verify CR3 cache integrity if active (before processing any command)
    if (g_driver.cr3_active) {
        verify_cr3_cache();
    }
    UINT32 command_id = *(UINT32*)&inbuf[0];
    UINT32 xor_key = *(UINT32*)&inbuf[4];
    PUINT8 payload = inbuf + WIRE_HEADER_SIZE;
    UINT32 payload_len = inlen - WIRE_HEADER_SIZE;

    // Decrypt payload in-place
    xor_payload(payload, payload_len, xor_key);

    // Dispatch to handler
    PUINT8 reply_payload = NULL;
    UINT32 reply_len = 0;

    switch (command_id) {
    case CMD_INIT:
        status = handle_init(payload, payload_len, &reply_payload, &reply_len);
        break;
    case CMD_PROCESS_LIST:
        status = handle_process_list(payload, payload_len, &reply_payload, &reply_len);
        break;
    case CMD_MODULE_LIST:
        status = handle_module_list(payload, payload_len, &reply_payload, &reply_len);
        break;
    case CMD_READ_MEMORY:
        status = handle_read_memory(payload, payload_len, &reply_payload, &reply_len);
        break;
    case CMD_WRITE_MEMORY:
        status = handle_write_memory(payload, payload_len, &reply_payload, &reply_len);
        break;
    case CMD_MOUSE_INPUT:
        status = handle_mouse_input(payload, payload_len, &reply_payload, &reply_len);
        break;
    case CMD_KEYBOARD_INPUT:
        status = handle_keyboard_input(payload, payload_len, &reply_payload, &reply_len);
        break;
    case CMD_PROTECT_PROCESS:
        status = handle_protect_process(payload, payload_len, &reply_payload, &reply_len);
        break;
    case CMD_CR3_ENABLE:
        status = handle_cr3_enable(payload, payload_len, &reply_payload, &reply_len);
        break;
    case CMD_CR3_DISABLE:
        status = handle_cr3_disable(payload, payload_len, &reply_payload, &reply_len);
        break;
    case CMD_BATCH_READ:
        status = handle_batch_read(payload, payload_len, &reply_payload, &reply_len);
        break;
    default:
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }

    // Build response: status(4) + xor_key(4) + encrypted_reply
    UINT32 resp_header = WIRE_HEADER_SIZE; // 8 bytes: status + xor_key
    UINT32 total_needed = resp_header + reply_len;

    if (total_needed <= outlen && reply_payload != NULL) {
        // Write response header
        *(NTSTATUS*)&outbuf[0] = status;
        *(UINT32*)&outbuf[4] = xor_key;

        // Copy reply payload and encrypt
        if (reply_len > 0) {
            RtlCopyMemory(outbuf + resp_header, reply_payload, reply_len);
            xor_payload(outbuf + resp_header, reply_len, xor_key);
        }

        info = total_needed;
        status = STATUS_SUCCESS;
    }
    else if (reply_payload == NULL && NT_SUCCESS(status)) {
        // No payload but success — still write header
        *(NTSTATUS*)&outbuf[0] = status;
        *(UINT32*)&outbuf[4] = xor_key;
        info = resp_header;
        status = STATUS_SUCCESS;
    }
    else {
        // Buffer too small or handler failed
        *(NTSTATUS*)&outbuf[0] = status;
        *(UINT32*)&outbuf[4] = xor_key;
        info = resp_header;
    }

    // Free reply payload if allocated by handler
    if (reply_payload && reply_payload != payload) {
        ExFreePoolWithTag(reply_payload, 'lmDR');
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
