//! Build script for valayam-proto — single source of truth for all .proto compilation.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/valayam.proto");
    println!("cargo:rerun-if-changed=proto/plugin.proto");
    println!("cargo:rerun-if-changed=proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&["proto/valayam.proto", "proto/plugin.proto"], &["proto"])?;

    Ok(())
}