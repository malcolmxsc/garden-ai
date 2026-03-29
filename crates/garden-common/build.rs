fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/agent.proto");
    println!("cargo:rerun-if-changed=proto/daemon.proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&["proto/agent.proto", "proto/daemon.proto"], &["proto"])?;
        
    Ok(())
}
