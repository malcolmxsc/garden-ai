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
        error_out: *mut *mut c_void
    ) -> bool;

    // 3. The Configure Function
    fn garden_virtualizer_configure(
        instance: *mut c_void,
        kernel_path: *const std::os::raw::c_char,
        initrd_path: *const std::os::raw::c_char,
        cpus: u32,
        memory_mb: u64,
        error_out: *mut *mut c_void,
    ) -> bool;

    // 4. The Start Function
    fn garden_virtualizer_start(
        instance: *mut c_void,
        error_out: *mut *mut c_void,
    ) -> bool;

    // 5. The Deallocation Function
    fn garden_virtualizer_destroy(instance: *mut c_void);

    // 6. The vSock Connect Function
    fn garden_virtualizer_connect_vsock(instance: *mut c_void, port: u32) -> i32;

    // 7. The Run Loop
    fn garden_run_loop();
}

// =====================================================================
// SYNTAX BREAKDOWN: The Safe Rust Wrapper
// =====================================================================
pub struct Virtualizer {
    instance: *mut c_void,
}

// SAFETY: The underlying Swift GardenVirtualizer object is safe to access
// from multiple threads. The connect_vsock FFI call uses DispatchSemaphore
// internally and does not mutate the Virtualizer's Rust state.
unsafe impl Send for Virtualizer {}
unsafe impl Sync for Virtualizer {}

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

    // =====================================================================
    // SYNTAX BREAKDOWN: Safely passing Strings from Rust to C
    // =====================================================================
    // Rust strings (`String`, `&str`) are highly advanced. They guarantee valid UTF-8
    // and inherently know their own length.
    // 
    // C-Strings (`*const c_char`) do not know their own length. They exist as memory bytes
    // until a physical `\0` (null-byte) is found.
    //
    // `std::ffi::CString` allocates new memory and safely copies the Rust string into it,
    // explicitly appending the `\0` so C/Swift can read it until the termination point.
    pub fn configure(
        &mut self,
        kernel: &str,
        initrd: &str,
        cpus: u32,
        memory_mb: u64,
    ) -> Result<(), String> {
        // Step 1: Convert Rust Strings into C-compatible Strings.
        // This can fail if the original string accidentally contains a `\0` somewhere inside it!
        let c_kernel = std::ffi::CString::new(kernel).map_err(|_| "Invalid Kernel path")?;
        let c_initrd = std::ffi::CString::new(initrd).map_err(|_| "Invalid Initrd path")?;

        let mut error_ptr: *mut c_void = std::ptr::null_mut();

        // Step 2: Pass down the FFI boundary
        let success = unsafe {
            garden_virtualizer_configure(
                self.instance,
                c_kernel.as_ptr(), // .as_ptr() yields the raw `*const c_char` address
                c_initrd.as_ptr(),
                cpus,
                memory_mb,
                &mut error_ptr,
            )
        };

        if success {
            Ok(())
        } else {
            // Re-use our NSError extraction logic from before
            if error_ptr.is_null() {
                return Err("Failed to configure Virtualizer. (Unknown Error)".into());
            }
            let err_msg = unsafe { extract_nserror_description(error_ptr) };
            Err(format!("Apple Hypervisor rejected configuration: {}", err_msg))
        }
    }

    pub fn start(&self) -> Result<(), String> {
        let mut error_ptr: *mut c_void = std::ptr::null_mut();

        // Step 1: Pass the command down the FFI boundary
        let success = unsafe {
            garden_virtualizer_start(self.instance, &mut error_ptr)
        };

        if success {
            Ok(())
        } else {
            // Re-use our NSError extraction logic from before
            if error_ptr.is_null() {
                return Err("Failed to start Virtual Machine. (Unknown Error)".into());
            }
            let err_msg = unsafe { extract_nserror_description(error_ptr) };
            Err(format!("Apple Hypervisor failed to boot: {}", err_msg))
        }
    }

    // =====================================================================
    // SYNTAX BREAKDOWN: vSock Connection
    // =====================================================================
    // This method asks Swift's VZVirtioSocketDevice to open a channel
    // directly into the Linux Guest. The returned file descriptor is a
    // standard Unix fd that Rust can wrap in a `TcpStream` (or any
    // `FromRawFd`-compatible type) for bidirectional byte I/O.
    //
    // The port number must match what the guest agent listens on (6000).
    // Returns the raw fd, or an error if the connection fails.
    pub fn connect_vsock(&self, port: u32) -> Result<i32, String> {
        let fd = unsafe {
            garden_virtualizer_connect_vsock(self.instance, port)
        };
        
        if fd < 0 {
            Err(format!("vSock connection to port {} failed (fd={})", port, fd))
        } else {
            Ok(fd)
        }
    }

    pub fn run_loop() {
        unsafe {
            garden_run_loop();
        }
    }
}

// Helper to extract the description string from an Objective-C NSError**
unsafe fn extract_nserror_description(error_ptr: *mut c_void) -> String {
    if error_ptr.is_null() {
        return "Unknown Error".to_string();
    }
    
    // We bind to the Objective-C runtime strictly to call `-[NSError localizedDescription]`
    // and grab the UTF-8 C string out of the resulting NSString.
    use objc::runtime::Object;
    use objc::{msg_send, sel, sel_impl};
    
    let ns_error = error_ptr as *mut Object;
    let desc: *mut Object = msg_send![ns_error, localizedDescription];
    let utf8_str: *const c_char = msg_send![desc, UTF8String];
    
    if utf8_str.is_null() {
        return "Failed to extract error description".to_string();
    }
    
    let c_str = std::ffi::CStr::from_ptr(utf8_str);
    c_str.to_string_lossy().into_owned()
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
