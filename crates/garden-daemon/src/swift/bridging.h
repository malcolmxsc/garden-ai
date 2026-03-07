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

// 3. The Deallocation Function
// Takes the raw pointer (`instance`) and tells Swift to free the memory.
void garden_virtualizer_destroy(void* instance);
