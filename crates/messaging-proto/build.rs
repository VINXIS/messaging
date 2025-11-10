fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()?;
        unsafe {
            std::env::set_var("PROTOC", protoc);
        }
    }

    let proto_root = std::path::Path::new("proto");
    let mut config = prost_build::Config::new();
    config.out_dir(std::env::var("OUT_DIR")?);
    let files = [proto_root.join("messaging.proto")];
    config.compile_protos(&files, &[proto_root])?;
    Ok(())
}
