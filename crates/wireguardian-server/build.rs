//! Wireguard Build Script
//!
//! Used to compile grpc protos

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=migrations");
    Ok(())
}
