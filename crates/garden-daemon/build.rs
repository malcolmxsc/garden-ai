use std::process::Command;
use std::env;

fn main() {
    // Only compile the Swift code if we are building for macOS
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() != "macos" {
        return;
    }

    // 1. Tell Cargo to re-run this build script if our Swift files change
    println!("cargo:rerun-if-changed=src/swift/Virtualizer.swift");
    println!("cargo:rerun-if-changed=src/swift/bridging_impl.swift");
    println!("cargo:rerun-if-changed=src/swift/bridging.h");

    let out_dir = env::var("OUT_DIR").unwrap();
    let swift_header_path = format!("{}/Virtualizer-Swift.h", out_dir);
    let static_lib_path = format!("{}/libgarden_swift.a", out_dir);

    // 2. We use `std::process::Command` to invoke the Swift compiler directly.
    // The `cc` crate assumes we are using a C compiler and passes flags like `-O0` 
    // which swiftc doesn't understand. By invoking it manually, we control the exact flags.
    let status = Command::new("swiftc")
        .args([
            "-emit-library", // We want to output a library
            "-static",       // Specifically a static library
            "-emit-objc-header",
            "-emit-objc-header-path", &swift_header_path,
            "-o", &static_lib_path,
            "-framework", "Virtualization",
            "-framework", "Foundation",
            "src/swift/Virtualizer.swift",
            "src/swift/bridging_impl.swift",
        ])
        .status()
        .expect("Failed to execute swiftc compile command. Is swiftc installed?");

    if !status.success() {
        panic!("Swift compiler failed with exit status: {}", status);
    }

    // 3. Tell Cargo where to find our newly compiled static library
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=garden_swift");
    
    // 4. Swift standard libraries must also be explicitly linked by Rust
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    println!("cargo:rustc-link-lib=swiftCore");
    println!("cargo:rustc-link-lib=swiftFoundation");
    println!("cargo:rustc-link-lib=swift_Concurrency");

    // 5. Set rpath so the dynamic linker can find Swift runtime dylibs at runtime.
    // Swift's runtime libraries live in /usr/lib/swift on macOS, but the binary
    // needs an LC_RPATH entry to locate them (macOS SIP strips DYLD_LIBRARY_PATH).
    let swift_runtime_paths = Command::new("swift")
        .args(["-print-target-info"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            // Parse the JSON to extract runtimeLibraryPaths
            serde_json::from_str::<serde_json::Value>(&s).ok()
        })
        .and_then(|v| {
            v["paths"]["runtimeLibraryPaths"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|p| p.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
        })
        .unwrap_or_else(|| vec![
            "/usr/lib/swift".to_string(),
            "/Library/Developer/CommandLineTools/usr/lib/swift/macosx".to_string(),
        ]);

    for path in &swift_runtime_paths {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", path);
        println!("cargo:rustc-link-search=native={}", path);
    }
}
