use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_path = Path::new("../valayam-engine/proto/plugin.proto");
    println!("cargo:rerun-if-changed={}", proto_path.display());

    tonic_build::configure()
        .build_server(true)
        .build_client(true) // might as well
        .compile(&[proto_path], &["../valayam-engine/proto"])?;

    Ok(())
}
