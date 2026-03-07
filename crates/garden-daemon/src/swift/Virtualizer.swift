import Foundation
import Virtualization

// 1. The @objc attribute
@objc
public class GardenVirtualizer: NSObject {
    
    // 2. The override init
    @objc
    public override init() {
        super.init()
    }
    
    // 3. Error Handling (throws)
    public func checkHardwareSupport() throws -> Bool {
        // Virtualization.framework check
        guard VZVirtualMachine.isSupported else {
            let error = NSError(
                domain: "GardenVirtualizer",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Apple Silicon Virtualization is not supported on this Mac."]
            )
            throw error 
        }
        return true
    }
}
