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
    private var machine: VZVirtualMachine?
    
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
        
        // 4. Set up External Networking (NAT)
        // VZNATNetworkDeviceAttachment creates an invisible virtual router.
        // It gives the VM an internal IP address and allows it to reach the 
        // internet using the macOS Host's Wi-Fi connection.
        let networkDevice = VZVirtioNetworkDeviceConfiguration()
        networkDevice.attachment = VZNATNetworkDeviceAttachment()
        config.networkDevices = [networkDevice]
        
        // 5. Set up Internal IPC (vSock)
        // VZVirtioSocketDeviceConfiguration establishes a direct, high-speed 
        // communication channel between the Host macOS and the Guest Alpine kernel,
        // side-stepping standard TCP/IP firewalls entirely!
        let socketDevice = VZVirtioSocketDeviceConfiguration()
        config.socketDevices = [socketDevice]
        
        // 6. Validate the Configuration
        // This asks the Apple Hypervisor: "Is this a legal machine constraint?"
        // (e.g. Did we ask for 500 CPU cores when the Mac only has 8?)
        // If it's invalid, `.validate()` automatically `throws` an Error which Rust will catch!
        try config.validate()
        
        // Save the valid configuration to our class
        self.config = config
    }
    
    // =====================================================================
    // SYNTAX BREAKDOWN: Booting the VM
    // =====================================================================
    public func start() throws {
        guard let config = self.config else {
            throw NSError(domain: "GardenVirtualizer", code: 2, userInfo: [NSLocalizedDescriptionKey: "Machine not configured."])
        }
        
        // 1. Create the Physical Virtual Machine object using our validated config
        let machine = VZVirtualMachine(configuration: config)
        self.machine = machine
        
        // 2. We use dispatch groups to handle the async boot process safely
        let group = DispatchGroup()
        group.enter()
        
        var bootError: Error?
        
        // Ask Apple to boot the hypervisor
        machine.start { result in
            switch result {
            case .success:
                print("✅ [Swift] VZVirtualMachine hardware launched successfully!")
            case .failure(let error):
                bootError = error
            }
            group.leave()
        }
        
        // Wait for the boot callback to finish before returning
        group.wait()
        
        // If Apple failed to boot it, bounce the error to Rust
        if let error = bootError {
            throw error
        }
    }
}
