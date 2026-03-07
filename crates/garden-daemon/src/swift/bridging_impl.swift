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
// 3. The Deallocation Function
// =====================================================================
// TASK: Rust's `Drop` trait calls this function when it is done with the object.
@_cdecl("garden_virtualizer_destroy")
public func garden_virtualizer_destroy(_ instance: UnsafeMutableRawPointer) {
    
    // =================================================================
    // SYNTAX BREAKDOWN: Releasing the Memory
    // =================================================================
    // `.release()`:
    // Remember in the Allocation function when we used `passRetained` to 
    // artificially add +1 to the ARC reference count? 
    // Calling `.release()` subtracts exactly 1 from the reference count.
    // Because the count hits 0, Swift will now permanently delete the 
    // object from the computer's memory. No memory leaks!
    Unmanaged<GardenVirtualizer>.fromOpaque(instance).release()
}

