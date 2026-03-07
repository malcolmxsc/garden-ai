fn main() {
    // Only compile the Swift code if we are building for macOS
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() != "macos" {
        return;
    }

    // 1. Tell Cargo to re-run this build script if our Swift file changes
    println!("cargo:rerun-if-changed=src/swift/Virtualizer.swift");

    // 2. We use the `cc` crate to invoke the Swift compiler (swiftc)
    // This will compile our Swift file into a static library called `libgarden_swift.a`
    cc::Build::new()
        .compiler("swiftc")
        .file("src/swift/Virtualizer.swift")
        // We need to emit an Objective-C module so C/Rust can call it
        .flag("-emit-objc-header")
        .flag("-emit-objc-header-path")
        .flag(&format!("{}/Virtualizer-Swift.h", std::env::var("OUT_DIR").unwrap()))
        // Automatically link the Virtualization framework
        .flag("-framework")
        .flag("Virtualization")
        .flag("-framework")
        .flag("Foundation")
        .compile("garden_swift");

    // 3. Tell Cargo to link against our newly compiled static library
    println!("cargo:rustc-link-lib=static=garden_swift");
    
    // 4. Swift standard libraries must also be explicitly linked
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    println!("cargo:rustc-link-lib=swiftCore");
    println!("cargo:rustc-link-lib=swiftFoundation");
}
