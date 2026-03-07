// =====================================================================
// SYNTAX BREAKDOWN: The C Bridging Header
// =====================================================================
// This file acts as the translation layer between Rust and Swift.
// In Swift, we used `@objc` which generated a C-compatible interface.
// In Rust, we use `extern "C"` to call C-compatible functions.
// This header file DECLARES those functions so both sides agree on the "contract".

#include <stdbool.h>
#include <stdint.h>

// 1. The Allocation Function Declaration
// In our Rust file, we called `OBJC_CLASS_$_GardenVirtualizer`.
// Because that is an internal Swift/Obj-C symbol, it's safer to expose a simple C function
// that allocates the class for us.
// 
// TASK: Declare a C function named `garden_virtualizer_create` that returns a `void*` (a raw pointer).
// 

// 2. The Method Declaration
// In our Rust file, we called `GardenVirtualizer_checkHardwareSupport`.
// 
// TASK: Declare a C function named `garden_virtualizer_check_hardware` that takes two arguments:
//   - A `void*` named `instance` (the pointer returned by `garden_virtualizer_create`)
//   - A `void**` named `error` (a double-pointer where Swift will write the error if it fails)
// And returns a `bool` (true if supported, false if not).
//

// 3. The Deallocation Function Declaration
// In our Rust file's `Drop` trait, we need a way to tell Swift to release the memory.
// 
// TASK: Declare a C function named `garden_virtualizer_destroy` that takes one argument:
//   - A `void*` named `instance`
// And returns nothing (`void`).
//
