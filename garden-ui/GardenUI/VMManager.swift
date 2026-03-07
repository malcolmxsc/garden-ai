import Foundation
import Virtualization

/// Manages the lifecycle of Linux micro-VMs using Apple's Virtualization.framework.
///
/// This class is the **owner** of all VM operations — boot, stop, configure
/// VirtioFS shares, and monitor VM state. The Rust engine communicates with
/// this class indirectly through the FFI bridge (`RustBridge`).
@MainActor
class VMManager: ObservableObject {
    @Published var state: VMState = .stopped
    @Published var statusMessage: String = "Ready"

    private var virtualMachine: VZVirtualMachine?

    enum VMState: String {
        case stopped = "Stopped"
        case booting = "Booting"
        case running = "Running"
        case stopping = "Stopping"
        case error = "Error"
    }

    // MARK: - VM Lifecycle

    /// Boot a new Linux micro-VM with the given configuration.
    func boot(kernelPath: String, rootfsPath: String, memoryMB: UInt64 = 512, cpuCount: Int = 2) async throws {
        state = .booting
        statusMessage = "Configuring VM..."

        // --- Boot Loader ---
        let kernelURL = URL(fileURLWithPath: kernelPath)
        let bootLoader = VZLinuxBootLoader(kernelURL: kernelURL)
        bootLoader.commandLine = "console=hvc0 root=/dev/vda rw"

        // --- VM Configuration ---
        let config = VZVirtualMachineConfiguration()
        config.bootLoader = bootLoader
        config.cpuCount = cpuCount
        config.memorySize = memoryMB * 1024 * 1024

        // --- Serial Console ---
        let serialPort = VZVirtioConsoleDeviceSerialPortConfiguration()
        serialPort.attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: FileHandle.standardInput,
            fileHandleForWriting: FileHandle.standardOutput
        )
        config.serialPorts = [serialPort]

        // --- Storage (Root FS) ---
        let rootfsURL = URL(fileURLWithPath: rootfsPath)
        if let diskAttachment = try? VZDiskImageStorageDeviceAttachment(url: rootfsURL, readOnly: false) {
            config.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: diskAttachment)]
        }

        // --- Entropy ---
        config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]

        // --- Network ---
        let networkDevice = VZVirtioNetworkDeviceConfiguration()
        networkDevice.attachment = VZNATNetworkDeviceAttachment()
        config.networkDevices = [networkDevice]

        // --- Memory Balloon ---
        config.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]

        // --- Validate & Boot ---
        try config.validate()

        let vm = VZVirtualMachine(configuration: config)
        self.virtualMachine = vm

        statusMessage = "Starting VM..."
        try await vm.start()

        state = .running
        statusMessage = "VM running"
    }

    /// Add a VirtioFS shared directory to the VM configuration.
    func addSharedDirectory(hostPath: String, mountTag: String, readOnly: Bool = false) -> VZVirtioFileSystemDeviceConfiguration {
        let sharedDir = VZSharedDirectory(url: URL(fileURLWithPath: hostPath), readOnly: readOnly)
        let share = VZSingleDirectoryShare(directory: sharedDir)
        let fsConfig = VZVirtioFileSystemDeviceConfiguration(tag: mountTag)
        fsConfig.share = share
        return fsConfig
    }

    /// Stop the running VM.
    func stop() async throws {
        guard let vm = virtualMachine else { return }
        state = .stopping
        statusMessage = "Stopping VM..."

        try await vm.stop()

        self.virtualMachine = nil
        state = .stopped
        statusMessage = "Stopped"
    }
}
