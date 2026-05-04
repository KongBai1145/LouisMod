#include "driver.h"

// ------------------------------------------------------------
// Mouse input injection via NtUserSendInput
// Converts CmdMouseInput → MOUSEINPUT_KM + NtUserSendInput call
// ------------------------------------------------------------
NTSTATUS handle_mouse_input(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len) {
    UNREFERENCED_PARAMETER(output);
    UNREFERENCED_PARAMETER(output_len);

    if (input_len < sizeof(CmdMouseInput)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    NTSTATUS status = ensure_input_resolved();
    if (!NT_SUCCESS(status)) return status;

    CmdMouseInput* req = (CmdMouseInput*)input;
    INPUT_KM inputs[7]; // max: 5 buttons + move + wheel
    UINT32 count = 0;

    // Button state mapping: button_states[i] → {flag_down, flag_up}
    static const struct { DWORD down; DWORD up; } button_map[MOUSE_BUTTON_MAX] = {
        { MOUSEEVENTF_LEFTDOWN,   MOUSEEVENTF_LEFTUP },
        { MOUSEEVENTF_RIGHTDOWN,  MOUSEEVENTF_RIGHTUP },
        { MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP },
        { MOUSEEVENTF_XBUTTONDOWN, MOUSEEVENTF_XBUTTONUP },
        { MOUSEEVENTF_XBUTTONDOWN, MOUSEEVENTF_XBUTTONUP },
    };

    // Process button states: 1=press, 2=release
    for (UINT32 i = 0; i < MOUSE_BUTTON_MAX && count < 5; i++) {
        if (req->button_states[i] == 1) {
            // Press
            RtlZeroMemory(&inputs[count], sizeof(INPUT_KM));
            inputs[count].type = INPUT_MOUSE;
            inputs[count].u.mi.dwFlags = button_map[i].down;
            if (i >= 3) {
                // XBUTTON1 (XBUTTON = 0x0001) or XBUTTON2 (XBUTTON = 0x0002)
                inputs[count].u.mi.mouseData = (i == 3) ? 1 : 2;
            }
            count++;
        } else if (req->button_states[i] == 2) {
            // Release
            RtlZeroMemory(&inputs[count], sizeof(INPUT_KM));
            inputs[count].type = INPUT_MOUSE;
            inputs[count].u.mi.dwFlags = button_map[i].up;
            if (i >= 3) {
                inputs[count].u.mi.mouseData = (i == 3) ? 1 : 2;
            }
            count++;
        }
    }

    // Mouse movement
    if (req->x_delta != 0 || req->y_delta != 0) {
        RtlZeroMemory(&inputs[count], sizeof(INPUT_KM));
        inputs[count].type = INPUT_MOUSE;
        inputs[count].u.mi.dwFlags = MOUSEEVENTF_MOVE;
        inputs[count].u.mi.dx = (LONG)req->x_delta;
        inputs[count].u.mi.dy = (LONG)req->y_delta;
        count++;
    }

    // Mouse wheel
    if (req->wheel_delta != 0) {
        RtlZeroMemory(&inputs[count], sizeof(INPUT_KM));
        inputs[count].type = INPUT_MOUSE;
        inputs[count].u.mi.dwFlags = MOUSEEVENTF_WHEEL;
        inputs[count].u.mi.mouseData = (LONG)req->wheel_delta * 120;
        count++;
    }

    if (count == 0) {
        return STATUS_SUCCESS; // nothing to do
    }

    UINT sent = g_driver.fn_send_input(count, inputs, sizeof(INPUT_KM));
    if (sent == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// Keyboard input injection via NtUserSendInput
// Converts CmdKeyboardInput → KEYBDINPUT_KM + NtUserSendInput call
// scan_codes[i] != 0 → key press (scan code value), 0 → no-op (ignored)
// The Rust side sets non-zero for pressed keys, 0 for others.
// ------------------------------------------------------------
NTSTATUS handle_keyboard_input(PUINT8 input, UINT32 input_len, PUINT8* output, UINT32* output_len) {
    UNREFERENCED_PARAMETER(output);
    UNREFERENCED_PARAMETER(output_len);

    if (input_len < sizeof(CmdKeyboardInput)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    NTSTATUS status = ensure_input_resolved();
    if (!NT_SUCCESS(status)) return status;

    CmdKeyboardInput* req = (CmdKeyboardInput*)input;

    // Count non-zero entries (up to 256)
    UINT32 max_events = 0;
    for (UINT32 i = 0; i < KEYBOARD_MAX_KEYS; i++) {
        if (req->scan_codes[i] != 0) max_events++;
    }

    if (max_events == 0) {
        return STATUS_SUCCESS;
    }

    // Allocate event array on stack (max 256 entries)
    INPUT_KM events[KEYBOARD_MAX_KEYS];
    UINT32 event_count = 0;

    for (UINT32 i = 0; i < KEYBOARD_MAX_KEYS && event_count < KEYBOARD_MAX_KEYS; i++) {
        if (req->scan_codes[i] == 0) continue;

        RtlZeroMemory(&events[event_count], sizeof(INPUT_KM));
        events[event_count].type = INPUT_KEYBOARD;
        events[event_count].u.ki.wScan = req->scan_codes[i];
        events[event_count].u.ki.dwFlags = KEYEVENTF_SCANCODE;
        event_count++;
    }

    if (event_count == 0) {
        return STATUS_SUCCESS;
    }

    // Send all keyboard events in one call
    UINT sent = g_driver.fn_send_input(event_count, events, sizeof(INPUT_KM));
    if (sent == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}
