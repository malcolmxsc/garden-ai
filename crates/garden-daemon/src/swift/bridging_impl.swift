import Foundation
import Virtualization

// ... (previous Swift class code here) ...

// =====================================================================
// 1. The Allocation Function
// =====================================================================
// TASK: Create the object and give Rust a raw pointer to it.
@_cdecl("garden_virtualizer_create")
public func garden_virtualizer_create() -> UnsafeMutableRawPointer {
    
    // Step A: Create the normal Swift object.
    let virtualizer = GardenVirtualizer()
    
    // =================================================================
    // SYNTAX BREAKDOWN: Managing Memory across the C-Bridge
    // =================================================================
    // `Unmanaged.passRetained(...)`:
    // Swift uses ARC (Automatic Reference Counting) to track when to delete objects.
    // Rust does not use ARC. If we just handed Rust the object, Swift would see
    // "Oh, no Swift code is using this anymore!" and delete it instantly.
    // `passRetained` tells Swift: "Increment the reference count artificially by +1.
    // Do NOT delete this object until I explicitly tell you to later."
    // 
    // `.toOpaque()`:
    // This takes our safe Swift object and turns it into a raw, untyped C-pointer
    // (`void*` in C, `UnsafeMutableRawPointer` in Swift). This is exactly what
    // Rust is expecting to receive.
    return Unmanaged.passRetained(virtualizer).toOpaque()
}

// =====================================================================
// 2. The Method Function
// =====================================================================
// TASK: Take the raw pointer from Rust, turn it back into a Swift object, 
// and call the method on it.
@_cdecl("garden_virtualizer_check_hardware")
public func garden_virtualizer_check_hardware(
    _ instance: UnsafeMutableRawPointer,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<NSError>?>?
) -> Bool {
    
    // =================================================================
    // SYNTAX BREAKDOWN: Restoring the Swift Object
    // =================================================================
    // `Unmanaged<GardenVirtualizer>.fromOpaque(instance)`:
    // This is the reverse of `toOpaque()`. We take the raw C-pointer and 
    // tell Swift, "Trust me, there is a `GardenVirtualizer` object at this address."
    //
    // `.takeUnretainedValue()`:
    // This is crucial. It tells ARC: "Give me the Swift object, but DO NOT 
    // change the reference count." We don't want Swift to accidentally delete
    // the object when this function ends; Rust still "owns" the main reference!
    let virtualizer = Unmanaged<GardenVirtualizer>.fromOpaque(instance).takeUnretainedValue()
    
    // Now we use the do / try / catch pattern we learned!
    do {
        return try virtualizer.checkHardwareSupport()
    } catch {
        // If it fails, cast the Swift Error to an Objective-C NSError
        let nsError = error as NSError
        
        // Write the NSError's address into the double-pointer provided by Rust.
        // We must passRetained() here because Rust will be responsible for releasing this error object later if it exists!
        if let out = errorOut {
            out.pointee = Unmanaged.passRetained(nsError).toOpaque().bindMemory(to: NSError.self, capacity: 1)
        }
        
        return false
    }
}

// =====================================================================
// 3. The Configuration Function
// =====================================================================
// TASK: Take raw C data (char*, ints) from Rust, convert them into Safe 
// Swift objects (String, UInt), and pass them to our class.
@_cdecl("garden_virtualizer_configure")
public func garden_virtualizer_configure(
    _ instance: UnsafeMutableRawPointer,
    _ kernelPathC: UnsafePointer<CChar>,
    _ initrdPathC: UnsafePointer<CChar>,
    _ cpus: UInt32,
    _ memoryMB: UInt64,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<NSError>?>?
) -> Bool {
    
    // =================================================================
    // SYNTAX BREAKDOWN: C-Strings to Swift Strings
    // =================================================================
    // Rust passes strings as `const char*` (null-terminated byte arrays).
    // Swift cannot naturally use these. `String(cString:)` scans the C-pointer
    // until it finds the `\0` null-byte, and safely copies the bytes into 
    // a real, ARC-managed Swift String!
    let kernelPath = String(cString: kernelPathC)
    let initrdPath = String(cString: initrdPathC)
    
    // Retrieve our Swift instance without modifying the ARC count
    let virtualizer = Unmanaged<GardenVirtualizer>.fromOpaque(instance).takeUnretainedValue()
    
    do {
        // Attempt to configure the machine! This will trigger `config.validate()`
        try virtualizer.configure(
            kernelPath: kernelPath,
            initrdPath: initrdPath,
            cpus: UInt(cpus),
            memoryMB: memoryMB
        )
        return true
        
    } catch {
        // If Apple's Hypervisor rejects our config (e.g. Memory > Host RAM),
        // we bounce the error exactly back to Rust through the double-pointer.
        let nsError = error as NSError
        if let out = errorOut {
            out.pointee = Unmanaged.passRetained(nsError).toOpaque().bindMemory(to: NSError.self, capacity: 1)
        }
        return false
    }
}

// =====================================================================
// 4. The Start Function
// =====================================================================
// TASK: Tell the virtualizer to boot the machine.
@_cdecl("garden_virtualizer_start")
public func garden_virtualizer_start(
    _ instance: UnsafeMutableRawPointer,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<NSError>?>?
) -> Bool {
    let virtualizer = Unmanaged<GardenVirtualizer>.fromOpaque(instance).takeUnretainedValue()
    
    do {
        try virtualizer.start()
        return true
    } catch {
        let nsError = error as NSError
        if let out = errorOut {
            out.pointee = Unmanaged.passRetained(nsError).toOpaque().bindMemory(to: NSError.self, capacity: 1)
        }
        return false
    }
}

// =====================================================================
// 5. The Deallocation Function
// =====================================================================
// TASK: Rust's `Drop` trait calls this function when it is done with the object.
@_cdecl("garden_virtualizer_destroy")
public func garden_virtualizer_destroy(_ instance: UnsafeMutableRawPointer) {
    // Decrease the ARC retain count by 1, physically deleting the Virtualizer
    // object and destroying the running Virtual Machine!
    Unmanaged<GardenVirtualizer>.fromOpaque(instance).release()
}

// =====================================================================
// 6. The Run Loop
// =====================================================================
@_cdecl("garden_run_loop")
public func garden_run_loop() {
    // This locks the thread and hands control to Apple so it can process 
    // background hardware events like Serial terminal I/O.
    CFRunLoopRun()
}
