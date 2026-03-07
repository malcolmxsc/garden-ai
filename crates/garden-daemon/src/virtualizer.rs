use std::ffi::c_void;
use std::os::raw::c_char;

// =====================================================================
// SYNTAX BREAKDOWN: The `extern "C"` Block
// =====================================================================
// Here we declare the exact C functions that we defined in `bridging.h`.
// The Rust compiler will look for these symbols in the `libgarden_swift.a`
// static library when linking the final executable.
#[link(name = "garden_swift", kind = "static")]
extern "C" {
    // 1. the Allocation function
    fn garden_virtualizer_create() -> *mut c_void;
    
    // 2. The Method call
    fn garden_virtualizer_check_hardware(
        instance: *mut c_void, 
        error_out: *mut *mut std::ffi::c_void
    ) -> bool;

    // 3. The Destructor call
    fn garden_virtualizer_destroy(instance: *mut c_void);
}

// =====================================================================
// SYNTAX BREAKDOWN: The Safe Rust Wrapper
// =====================================================================
pub struct Virtualizer {
    instance: *mut c_void,
}

impl Virtualizer {
    pub fn new() -> Result<Self, String> {
        unsafe {
            // We call our explicit C function which triggers the Swift 
            // `Unmanaged.passRetained().toOpaque()` logic!
            let instance = garden_virtualizer_create();
            
            if instance.is_null() {
                return Err("Failed to allocate GardenVirtualizer".to_string());
            }

            Ok(Self { instance })
        }
    }

    pub fn check_hardware(&self) -> Result<(), String> {
        let mut error_ptr: *mut c_void = std::ptr::null_mut();
        
        unsafe {
            // We pass the raw instance pointer to our explicit C method wrapper.
            // If it throws an error in Swift, it will populate `error_ptr`.
            let is_supported = garden_virtualizer_check_hardware(self.instance, &mut error_ptr);
            
            if !is_supported {
               if !error_ptr.is_null() {
                   return Err("Hardware not supported (FFI Error returned)".to_string());
               }
               return Err("Hardware not supported (Unknown reason)".to_string());
            }
        }
        
        Ok(())
    }
}

// =====================================================================
// SYNTAX BREAKDOWN: The Drop Trait
// =====================================================================
impl Drop for Virtualizer {
    fn drop(&mut self) {
        unsafe {
            // When this Rust struct is destroyed, we call back into Swift 
            // to run `.release()` on the Unmanaged pointer, freeing the memory!
            if !self.instance.is_null() {
                garden_virtualizer_destroy(self.instance);
            }
        }
    }
}
