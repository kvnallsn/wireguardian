//! Wireguardian Protobuf Protocols

mod wireguardian {
    tonic::include_proto!("wireguardian");
}
pub use wireguardian::*;
