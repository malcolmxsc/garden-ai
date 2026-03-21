//! Diagnostic test for BPF ELF loading
#[cfg(target_os = "linux")]
mod linux_tests {
    #[test]
    #[ignore]
    fn test_bpf_elf_bytes() {
        let bpf_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../garden-ebpf-probes/target/bpfel-unknown-none/release/garden-ebpf-probes"
        ));

        eprintln!("BPF ELF size: {} bytes", bpf_bytes.len());
        eprintln!("First 16 bytes: {:02x?}", &bpf_bytes[..16.min(bpf_bytes.len())]);

        // Check ELF magic
        assert_eq!(&bpf_bytes[0..4], b"\x7fELF", "Not a valid ELF file");
        eprintln!("ELF magic OK");

        // Copy to Vec for 8-byte alignment (include_bytes! only guarantees 1-byte)
        let aligned = bpf_bytes.to_vec();

        // Try loading with aya
        match aya::Ebpf::load(&aligned) {
            Ok(ebpf) => {
                eprintln!("Ebpf::load() succeeded!");
                for (name, _) in ebpf.programs() {
                    eprintln!("  Program: {}", name);
                }
            }
            Err(e) => {
                eprintln!("Ebpf::load() FAILED: {}", e);
                eprintln!("Error debug: {:?}", e);
                panic!("Ebpf::load failed: {:?}", e);
            }
        }
    }
}
