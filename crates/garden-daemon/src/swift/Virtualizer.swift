import Foundation
import Virtualization

// 1. The @objc attribute
@objc
public class GardenVirtualizer: NSObject {
    
    // =====================================================================
    // SYNTAX BREAKDOWN: Properties
    // =====================================================================
    // We store the configuration and bootloader as properties on our class 
    // so they stay alive as long as the Virtualizer object exists.
    private var config: VZVirtualMachineConfiguration?
    private var bootloader: VZLinuxBootLoader?
    
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
    
    // =====================================================================
    // SYNTAX BREAKDOWN: Configuring the VM
    // =====================================================================
    // This function takes our hard drive paths and computes the VM profile.
    public func configure(kernelPath: String, initrdPath: String, cpus: UInt, memoryMB: UInt64) throws {
        
        // 1. Set up the Linux Bootloader
        // VZLinuxBootLoader tells Apple's hypervisor exactly where the Linux kernel
        // binaries are physically located on the Mac's hard drive.
        let bootloader = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: kernelPath))
        bootloader.initialRamdiskURL = URL(fileURLWithPath: initrdPath)
        
        // Command line arguments passed directly into the Linux kernel on boot.
        // "console=hvc0" forces Linux to print its boot logs to the virtual serial port!
        bootloader.commandLine = "console=hvc0"
        self.bootloader = bootloader
        
        // 2. Set up the Hardware Configuration
        let config = VZVirtualMachineConfiguration()
        config.bootLoader = bootloader
        config.cpuCount = Int(cpus)
        // Virtualization.framework expects memory in pure Bytes, so we multiply MB * 1024 * 1024
        config.memorySize = memoryMB * 1024 * 1024 
        
        // 3. Attach a Serial Port (so we can see it boot!)
        // Without this, the VM would boot silently in the background and we'd be blind.
        let serialPort = VZVirtioConsoleDeviceSerialPortConfiguration()
        
        // We attach the virtual serial port directly to the Mac's standard input/output (our terminal!)
        let attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: FileHandle.standardInput,
            fileHandleForWriting: FileHandle.standardOutput
        )
        serialPort.attachment = attachment
        config.serialPorts = [serialPort]
        
        // 4. Validate the Configuration
        // This asks the Apple Hypervisor: "Is this a legal machine constraint?"
        // (e.g. Did we ask for 500 CPU cores when the Mac only has 8?)
        // If it's invalid, `.validate()` automatically `throws` an Error which Rust will catch!
        try config.validate()
        
        // Save the valid configuration to our class
        self.config = config
    }
}
