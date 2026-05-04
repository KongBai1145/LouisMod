#include "driver.h"

NTSTATUS handle_init(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len) {
    UNREFERENCED_PARAMETER(input);
    UNREFERENCED_PARAMETER(input_len);

    PUINT8 reply = (PUINT8)ExAllocatePoolWithTag(NonPagedPool, sizeof(CmdInitReply), 'lmDR');
    if (!reply) return STATUS_INSUFFICIENT_RESOURCES;

    CmdInitReply* init = (CmdInitReply*)reply;
    init->protocol_version = LOUISMOD_PROTOCOL_VERSION;
    init->driver_major = LOUISMOD_DRIVER_MAJOR;
    init->driver_minor = LOUISMOD_DRIVER_MINOR;

    // Feature flags — all capabilities enabled
    init->features = 0;
    init->features |= FEATURE_PROCESS_LIST;
    init->features |= FEATURE_PROCESS_MODULES;
    init->features |= FEATURE_MEMORY_READ;
    init->features |= FEATURE_MEMORY_WRITE;
    init->features |= FEATURE_INPUT_MOUSE;
    init->features |= FEATURE_INPUT_KEYBOARD;
    init->features |= FEATURE_CR3;

    *output = reply;
    *output_len = sizeof(CmdInitReply);
    return STATUS_SUCCESS;
}
