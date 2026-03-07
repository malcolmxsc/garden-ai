use std::ffi::{c_void, CStr};
use std::os::raw::{c_char, c_int};

// 1. The `extern "C"` block
#[link(name = "garden_swift", kind = "static")]
extern "C" {
    // These correspond to the generated Objective-C symbols from our Swift class
    // We will need to look at the generated header to get the exact Objective-C selector names later,
    // but here is the conceptual bridge.
    
    // Allocate the class
    fn OBJC_CLASS_$_GardenVirtualizer() -> *mut c_void;
    
    // Call the method
    fn GardenVirtualizer_checkHardwareSupport(
        instance: *mut c_void, 
        error: *mut *mut std::ffi::c_void
    ) -> bool;
}

// 2. The Safe Rust Wrapper
pub struct Virtualizer {
    // 3. The raw pointer (Unsafe)
    instance: *mut c_void,
}

impl Virtualizer {
    pub fn new() -> Result<Self, String> {
        // 4. `unsafe` block
        unsafe {
            // In a real Objective-C runtime, allocating an object is more complex 
            // (e.g., calling `[[GardenVirtualizer alloc] init]`), 
            // but we will use a C-wrapper function in Swift to make this easier shortly.
            // For now, assume this function exists.
            let instance = OBJC_CLASS_$_GardenVirtualizer();
            
            if instance.is_null() {
                return Err("Failed to allocate GardenVirtualizer".to_string());
            }

            Ok(Self { instance })
        }
    }

    pub fn check_hardware(&self) -> Result<(), String> {
        let mut error_ptr: *mut c_void = std::ptr::null_mut();
        
        unsafe {
            // Call the Objective-C method, passing a pointer to our error pointer
            let is_supported = GardenVirtualizer_checkHardwareSupport(self.instance, &mut error_ptr);
            
            if !is_supported {
               // 5. Handling the FFI Error
               if !error_ptr.is_null() {
                   return Err("Hardware not supported (FFI Error returned)".to_string());
               }
               return Err("Hardware not supported (Unknown reason)".to_string());
            }
        }
        
        Ok(())
    }
}

// 6. The Drop trait (Destructor)
impl Drop for Virtualizer {
    fn drop(&mut self) {
        unsafe {
            // Here we would call the Objective-C `release` method to free the Swift object
            // to prevent memory leaks.
            // release(self.instance);
        }
    }
}
