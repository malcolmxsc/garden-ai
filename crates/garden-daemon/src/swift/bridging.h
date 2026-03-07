#include <stdbool.h>
#include <stdint.h>

// =====================================================================
// SYNTAX BREAKDOWN: The C Bridging Header
// =====================================================================
// This file acts as the translation layer between C and Rust. It clearly
// defines the exact "shape" of the functions that both languages must agree on.

// 1. The Allocation Function
// Returns a raw pointer (void*) to our Swift object.
void* garden_virtualizer_create(void);

// 2. The Method Function
// Takes the raw pointer (`instance`) and a double-pointer for the Error (`error_out`).
// Returns true if supported, false if an error occurred.
bool garden_virtualizer_check_hardware(void* instance, void** error_out);

// 3. The Configure Function
// Passes C-Strings (const char*) and integers (uint32_t) across the FFI bridge
// to configure the Virtual Machine Hardware attributes.
bool garden_virtualizer_configure(
    void* instance, 
    const char* kernel_path, 
    const char* initrd_path, 
    uint32_t cpus, 
    uint64_t memory_mb, 
    void** error_out
);

// 4. The Start Function
// Triggers the actual hypervisor boot sequence.
bool garden_virtualizer_start(void* instance, void** error_out);

// 5. The Deallocation Function
// Takes the raw pointer (`instance`) and tells Swift to free the memory.
void garden_virtualizer_destroy(void* instance);

// 6. The Run Loop
// Apple's Virtualization.framework requires an active macOS RunLoop to process
// I/O streams (like the serial console). This hands control to the OS.
void garden_run_loop();
