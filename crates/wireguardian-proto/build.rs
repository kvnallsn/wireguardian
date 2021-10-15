//! Wireguard Build Script
//!
//! Used to compile grpc protos

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile(&["../../proto/wireguardian.proto"], &["../../proto"])?;

    println!("cargo:rerun-if-changed=../../proto");
    Ok(())
}
