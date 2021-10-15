//! Wireguardian Config Format

use color_eyre::eyre;
use ipnetwork::Ipv4Network;
use serde::Deserialize;
use std::{convert::TryInto, fs, net::Ipv4Addr, net::SocketAddr, path::Path};
use x25519_dalek::StaticSecret;

#[derive(Debug, Deserialize)]
pub struct WireguardianConfig {
    /// Configuration settings for the gRPC server
    pub rpc: RpcConfig,

    /// Configuration of Wireguardian wireguard device
    pub device: DeviceConfig,

    /// Configuration of mock DHCP service
    pub dhcp: DhcpConfig,
}

#[derive(Debug, Deserialize)]
pub struct RpcConfig {
    /// IP Address and TCP port to bind/listen on for gRPC server
    pub listen: SocketAddr,
}

#[derive(Debug, Deserialize)]
pub struct DeviceConfig {
    /// Name to assign the host interface/adapter
    pub adapter_name: String,

    /// IPv4 address to assign this interface
    pub address: Ipv4Network,

    /// Server's private key
    pub private_key: String,

    /// UDP port to listen on
    pub listen_port: u16,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub struct DhcpConfig {
    /// Addresss to start handing out for dynamic addresses
    pub start: Ipv4Addr,

    /// Address to stop handing out for dynamic addresses
    pub end: Ipv4Addr,
}

impl WireguardianConfig {
    /// Attempts to load and parse a configuration file
    ///
    /// # Arguments
    /// * `path` - Path to the Wireguardian configuration file
    pub fn load(path: impl AsRef<Path>) -> eyre::Result<WireguardianConfig> {
        let contents = fs::read_to_string(path)?;
        let cfg: WireguardianConfig = toml::from_str(&contents)?;
        Ok(cfg)
    }
}

impl DeviceConfig {
    /// Parses the base64-encoded private key into a X25519 static secret
    pub fn secret_key(&self) -> eyre::Result<StaticSecret> {
        let key = base64::decode(&self.private_key)?;
        if key.len() != 32 {
            eyre::bail!("wireguard key must be 32-bytes, no more, no less");
        }

        // this should never fail because we check the length above
        let data: [u8; 32] = key.try_into().map_err(|error| {
            tracing::error!(?error, "failed to convert into 32-byte array");
            eyre::eyre!("failed to convert into 32-byte array")
        })?;

        let key: StaticSecret = data.into();
        Ok(key)
    }
}
