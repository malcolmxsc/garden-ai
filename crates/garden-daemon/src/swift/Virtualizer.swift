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
        bootloader.commandLine = "console=hvc0 console=ttyAMA0,115200 earlycon"
        self.bootloader = bootloader
        
        // 2. Set up the Hardware Configuration
        let config = VZVirtualMachineConfiguration()
        config.bootLoader = bootloader
        config.cpuCount = Int(cpus)
        // Virtualization.framework expects memory in pure Bytes, so we multiply MB * 1024 * 1024
        config.memorySize = memoryMB * 1024 * 1024 
        
        // Define the hardware platform explicitely as a Generic Linux Platform
        config.platform = VZGenericPlatformConfiguration()
        
        // 3. Attach a Serial Port (so we can see it boot!)
        let serialPort = VZVirtioConsoleDeviceSerialPortConfiguration()
        let attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: FileHandle.standardInput,
            fileHandleForWriting: FileHandle.standardOutput
        )
        serialPort.attachment = attachment
        config.serialPorts = [serialPort]
        
        // 4. Set up External Networking (NAT)
        let network = VZVirtioNetworkDeviceConfiguration()
        network.attachment = VZNATNetworkDeviceAttachment()
        config.networkDevices = [network]
        
        // 5. Provide an Entropy Device (required by Linux)
        let entropy = VZVirtioEntropyDeviceConfiguration()
        config.entropyDevices = [entropy]
        
        // 6. Set up Inter-Process Communication (vSock)
        let vsock = VZVirtioSocketDeviceConfiguration()
        config.socketDevices = [vsock]
        
        // 7. Validate the Configuration
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
        machine.delegate = self
        self.machine = machine
        
        // 2. Ask Apple to boot the hypervisor asynchronously.
        machine.start { result in
            switch result {
            case .success:
                print("✅ [Swift] VZVirtualMachine hardware launched successfully!")
                fflush(stdout)
            case .failure(let error):
                print("❌ [Swift] VZVirtualMachine failed to boot: \(error)")
                fflush(stdout)
            }
        }
    }
}

// =====================================================================
// SYNTAX BREAKDOWN: Handling VM Crash Events
// =====================================================================
// This allows us to intercept Apple's background hypervisor errors if the Linux
// kernel crashes or panics seconds after booting.
extension GardenVirtualizer: VZVirtualMachineDelegate {
    public func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        print("🛑 [Swift] VZVirtualMachine guest did stop!")
        fflush(stdout)
    }
    
    public func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        print("❌ [Swift] VZVirtualMachine stopped with error: \(error)")
        fflush(stdout)
    }
}
