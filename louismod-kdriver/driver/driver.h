#pragma once
#include <ntddk.h>
#include <ntstatus.h>
#include <windef.h>
#include <intrin.h>
#include <ntimage.h>   // IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY

// Suppress WDK deprecation warnings (ExAllocatePoolWithTag → ExAllocatePool2)
#pragma warning(disable:4996)

// ------------------------------------------------------------
// IOCTL
// ------------------------------------------------------------
#define IOCTL_LOUISMOD_COMMAND \
    CTL_CODE(0x8000, 0x0824, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ------------------------------------------------------------
// Command IDs (mirrors Rust crate)
// ------------------------------------------------------------
#define CMD_INIT            0x00
#define CMD_PROCESS_LIST    0x01
#define CMD_MODULE_LIST     0x02
#define CMD_READ_MEMORY     0x03
#define CMD_WRITE_MEMORY    0x04
#define CMD_MOUSE_INPUT     0x05
#define CMD_KEYBOARD_INPUT  0x06
#define CMD_PROTECT_PROCESS 0x07
#define CMD_CR3_ENABLE      0x08
#define CMD_CR3_DISABLE     0x09
#define CMD_BATCH_READ      0x0A

// Batch read limits
#define BATCH_MAX_ENTRIES     64
#define BATCH_MAX_ENTRY_SIZE  4096

// ------------------------------------------------------------
// Protocol version
// ------------------------------------------------------------
#define LOUISMOD_PROTOCOL_VERSION 0x01
#define LOUISMOD_DRIVER_MAJOR     0
#define LOUISMOD_DRIVER_MINOR     1

// ------------------------------------------------------------
// Wire format: request / response header
// All multi-byte values are little-endian.
// ------------------------------------------------------------
// Request: [4: command_id][4: xor_key][N: encrypted payload]
// Response:[4: status(NTSTATUS)][4: xor_key][N: encrypted payload]
#define WIRE_HEADER_SIZE 8

// ------------------------------------------------------------
// Payload structs (packed, on-the-wire)
// ------------------------------------------------------------

#pragma pack(push, 1)

// CMD_INIT response
typedef struct {
    UINT32 protocol_version;
    UINT16 driver_major;
    UINT16 driver_minor;
    UINT64 features;
} CmdInitReply;

// CMD_PROCESS_LIST response header + entries
#define PROCESS_NAME_MAX 32
typedef struct {
    UINT32 process_id;
    WCHAR  name[PROCESS_NAME_MAX];
} ProcessEntry;

// CMD_MODULE_LIST request
typedef struct {
    UINT32 process_id;
} CmdModuleListReq;

#define MODULE_NAME_MAX 64
typedef struct {
    UINT64 base_address;
    UINT64 module_size;
    WCHAR  name[MODULE_NAME_MAX];
} ModuleEntry;

// CMD_READ_MEMORY request
typedef struct {
    UINT32 process_id;
    UINT64 address;
    UINT32 size;
} CmdReadMemoryReq;

// CMD_WRITE_MEMORY request header (payload data follows)
typedef struct {
    UINT32 process_id;
    UINT64 address;
    UINT32 size;
} CmdWriteMemoryReq;

// CMD_BATCH_READ request entry (entries[] follow a UINT32 count)
typedef struct {
    UINT32 process_id;
    UINT64 address;
    UINT32 size;
} CmdBatchReadEntry;

// CMD_MOUSE_INPUT
#define MOUSE_BUTTON_MAX 5
typedef struct {
    UINT16 button_states[MOUSE_BUTTON_MAX]; // 0=none, 1=press, 2=release
    INT16  x_delta;
    INT16  y_delta;
    INT16  wheel_delta;
} CmdMouseInput;

// CMD_KEYBOARD_INPUT
#define KEYBOARD_MAX_KEYS 256
typedef struct {
    UINT16 scan_codes[KEYBOARD_MAX_KEYS]; // each: 0=release, 1-255=make+repeat
} CmdKeyboardInput;

// CMD_PROTECT_PROCESS request
typedef struct {
    UINT32 process_id;
    UINT32 enable; // 0=disable, 1=enable
} CmdProtectProcess;

// Feature flags (matches Rust DriverFeature)
#define FEATURE_PROCESS_LIST     0x00000001ULL
#define FEATURE_PROCESS_MODULES  0x00000002ULL
#define FEATURE_MEMORY_READ      0x00000100ULL
#define FEATURE_MEMORY_WRITE     0x00000200ULL
#define FEATURE_INPUT_KEYBOARD   0x00010000ULL
#define FEATURE_INPUT_MOUSE      0x00020000ULL
#define FEATURE_CR3              0x01000000ULL

#pragma pack(pop)

// ------------------------------------------------------------
// Input injection types (for NtUserSendInput)
// ------------------------------------------------------------
typedef struct {
    LONG dx;
    LONG dy;
    LONG mouseData;
    DWORD dwFlags;
    DWORD time;
    ULONG_PTR dwExtraInfo;
} MOUSEINPUT_KM;

typedef struct {
    WORD wVk;
    WORD wScan;
    DWORD dwFlags;
    DWORD time;
    ULONG_PTR dwExtraInfo;
} KEYBDINPUT_KM;

typedef struct {
    DWORD type;
    union {
        MOUSEINPUT_KM mi;
        KEYBDINPUT_KM ki;
    } u;
} INPUT_KM;

#define INPUT_MOUSE    0
#define INPUT_KEYBOARD 1

#define MOUSEEVENTF_MOVE       0x0001
#define MOUSEEVENTF_LEFTDOWN   0x0002
#define MOUSEEVENTF_LEFTUP     0x0004
#define MOUSEEVENTF_RIGHTDOWN  0x0008
#define MOUSEEVENTF_RIGHTUP    0x0010
#define MOUSEEVENTF_MIDDLEDOWN 0x0020
#define MOUSEEVENTF_MIDDLEUP   0x0040
#define MOUSEEVENTF_XBUTTONDOWN 0x0080
#define MOUSEEVENTF_XBUTTONUP  0x0100
#define MOUSEEVENTF_WHEEL      0x0800
#define MOUSEEVENTF_HWHEEL     0x1000
#define MOUSEEVENTF_ABSOLUTE   0x8000

#define KEYEVENTF_EXTENDEDKEY  0x0001
#define KEYEVENTF_KEYUP        0x0002
#define KEYEVENTF_SCANCODE     0x0008

// Resolved at DriverEntry via MmGetSystemRoutineAddress
// Uses INPUT_KM* which matches the Windows INPUT struct layout
typedef UINT (*NtUserSendInput_t)(UINT cInputs, INPUT_KM* pInputs, int cbSize);

// Access rights to strip from protected process
#define PROCESS_PROTECT_MASK (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_TERMINATE)

// Process access rights (not available in kernel mode headers via ntddk.h; winnt.h
// is blocked by NT_INCLUDED being already defined when windef.h is included)
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                  (0x0001)
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION               (0x0008)
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE                   (0x0020)
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE                 (0x0040)
#endif

// EPROCESS DirectoryTableBase offset (x64, stable since Win7)
#define EPROCESS_DTB_OFFSET 0x28

// XOR payload helper
// ------------------------------------------------------------
__forceinline void xor_payload(UINT8* data, UINT32 len, UINT32 key) {
    for (UINT32 i = 0; i < len; i++) {
        data[i] ^= (UINT8)((key + i) & 0xFF);
    }
}

// ------------------------------------------------------------
// Global driver state
// ------------------------------------------------------------
typedef struct _DRIVER_GLOBALS {
    WCHAR  device_name[64];
    WCHAR  symlink_name[64];
    PDEVICE_OBJECT device_object;
    BOOLEAN hiding_active;

    // Process protection spinlock
    KSPIN_LOCK ob_lock;

    // Input injection (resolved at DriverEntry)
    NtUserSendInput_t fn_send_input;

    // Process protection (ObRegisterCallbacks)
    PVOID protection_callback_handle;
    PEPROCESS protected_process;

    // CR3 mitigation
    PEPROCESS cr3_cached_process;
    UINT32    cr3_cached_pid;
    ULONG_PTR cr3_expected_dtb;
    BOOLEAN   cr3_active;

    // Input function resolution state
    BOOLEAN   win32kbase_checked;
} DRIVER_GLOBALS;

extern DRIVER_GLOBALS g_driver;

// ------------------------------------------------------------
// Forward declarations for kernel routines not in ntddk.h
// (ntifs.h provides these but including it conflicts with ntddk.h)
// ------------------------------------------------------------
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process);

NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
    _In_ PEPROCESS FromProcess,
    _In_ const VOID* FromAddress,
    _In_ PEPROCESS ToProcess,
    _Out_ VOID* ToAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T NumberOfBytesCopied);

NTKERNELAPI VOID ObMakeTemporaryObject(_In_ PVOID Object);

NTSTATUS ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTSTATUS ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInformationClass,
    _Out_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

// Registry path where the driver stores its device name for Rust-side discovery
#define LOUISMOD_REGISTRY_PATH L"\\Registry\\Machine\\SOFTWARE\\LouisMod"
#define LOUISMOD_REGISTRY_VALUE L"DeviceName"

// ------------------------------------------------------------
// Command handlers
// ------------------------------------------------------------
NTSTATUS handle_init(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len);
NTSTATUS handle_process_list(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len);
NTSTATUS handle_module_list(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len);
NTSTATUS handle_read_memory(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len);
NTSTATUS handle_write_memory(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len);
NTSTATUS handle_mouse_input(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len);
NTSTATUS handle_keyboard_input(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len);
NTSTATUS handle_protect_process(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len);
NTSTATUS handle_batch_read(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len);
NTSTATUS handle_cr3_enable(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len);
NTSTATUS handle_cr3_disable(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len);

// ------------------------------------------------------------
// Stealth helpers
// ------------------------------------------------------------
NTSTATUS hiding_remove_from_loaded_modules(VOID);
NTSTATUS hiding_clear_driver_name(VOID);
NTSTATUS hiding_hide_device_object(VOID);
NTSTATUS hiding_delete_service_registry(VOID);
NTSTATUS verify_cr3_cache(VOID);
NTSTATUS ensure_input_resolved(VOID);
NTSTATUS hiding_cleanup_unloaded_drivers(VOID);
NTSTATUS hiding_cleanup_piddb_cache(VOID);
