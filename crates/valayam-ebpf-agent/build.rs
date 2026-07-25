fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../valayam-engine/proto/valayam.proto")?;
    Ok(())
}
