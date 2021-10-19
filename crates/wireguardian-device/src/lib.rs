//! Wireguardian Device Library
//!
//! Creates and configures new WireGuard devices for all supported platforms.  If a kernel-based
//! device is available, then attempt to use that before the userspace implementation

mod cmd;
mod userspace;

use ipnetwork::Ipv4Network;
use std::net::SocketAddr;
use wireguard_rs::configuration::{ConfigError, Configuration};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to configure WireGuard device: {0}")]
    Config(#[from] ConfigError),

    #[error("input/ouput error: {0}")]
    IO(#[from] std::io::Error),

    #[error("WireGuard tunnel error: {0}")]
    Tunnel(String),

    #[error("failed to run command: {0}")]
    Shell(#[from] cmd::ShellCommandError),

    #[error("private key not set")]
    MissingPrivateKey,

    #[error("interface address not set")]
    MissingInterfaceAddress,

    #[error("device endpoint missing")]
    MissingDeviceEndpoint,
}

/// A WireGuard device that can send/receive packets over the network
///
/// A device comes in two flavors:
/// * `Userspace`
/// * `Kernel`
///
/// `Userspace` devices are supported on
/// * `Mac OS`
/// * `Linux`
///
/// `Kernel` devices are supported on
/// * `Linux Kernel >= 5.6`
/// * `Linux Kernel < 5.6 w/ wireguard.ko loaded`
pub struct Device {
    /// Type of device (userspace vs kernel)
    ty: DeviceType,

    /// Public key associated with this device
    pub_key: PublicKey,

    /// Address of this device
    address: Ipv4Network,

    /// Public / Reachable IP:Port combo for this device
    endpoint: SocketAddr,

    /// IPs that are allowed to route over this device
    allowed_ips: Vec<Ipv4Network>,
}

/// The specific kind of device in use by a WireGuard interface
pub enum DeviceType {
    /// A userspace devices operates in user land but is supported on more platforms
    Userspace(userspace::UserspaceDevice),

    #[cfg(target_os = "linux")]
    LinuxKernel,
}

#[derive(Default)]
pub struct DeviceBuilder {
    /// Name to assign to the device/interface
    name: Option<String>,

    /// Private key to associate with this device
    key: Option<StaticSecret>,

    /// IPv4 address and netmask to associate with this device
    address: Option<Ipv4Network>,

    /// Public / Reachable IP:Port combo for this device
    endpoint: Option<SocketAddr>,

    /// Port to listen on for incoming wireguard connections
    listen_port: Option<u16>,

    /// IPs that are allowed to route over this device
    allowed_ips: Vec<Ipv4Network>,

    /// Maximum Transfer Unit for all packets
    mtu: Option<u16>,
}

pub struct Peer {
    /// Public Key assigned to peer
    pub_key: PublicKey,

    /// Remote endpoint of WireGuard peer (only set on clients)
    endpoint: Option<SocketAddr>,

    /// Allowed IPv4 addresses and netmasks to route over this device
    allowed_ips: Vec<Ipv4Network>,

    /// Time (in seconds) to send keepalive packets
    ///
    /// Useful if both ends are behind NAT-ing routings / hole-punching
    keepalive: Option<u16>,
}

impl Device {
    /// Builds a new WireGuard device
    ///
    /// Attempts to auto-detect if a kernel device can be used, otherise falls back to a userspace
    /// device
    pub fn builder() -> DeviceBuilder {
        DeviceBuilder::default()
    }

    /// Returns the public key associated with this device
    pub fn public_key(&self) -> PublicKey {
        self.pub_key
    }

    /// Returns the IPv4 address and netmask associated with this device
    pub fn address(&self) -> Ipv4Network {
        self.address
    }

    /// Returns the external endpoint this device is reachable on
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Returns all IPs/networks allowed to route over this device
    pub fn allowed_ips(&self) -> &[Ipv4Network] {
        &self.allowed_ips
    }
}

impl DeviceBuilder {
    /// Sets the interface name associated with this WireGuard device
    ///
    /// # Arguments
    /// * `name` - Name of the interface (e.g., `tun0`, `utun10`)
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the private key associated with this WireGuard device
    ///
    /// # Arguments
    /// * `key` - X25519 key to associate with this device
    pub fn private_key(mut self, key: StaticSecret) -> Self {
        self.key = Some(key);
        self
    }

    /// Sets the address associated with this WireGuard device
    ///
    /// # Arguments
    /// * `ip` - IPv4 address and netmask to associate with this device
    pub fn address(mut self, ip: Ipv4Network) -> Self {
        self.address = Some(ip);
        self
    }

    /// Sets the port to listen on for inbound WireGuard connections
    ///
    /// # Arguments
    /// * `port` - Port to listen on
    pub fn endpoint(mut self, endpoint: impl Into<SocketAddr>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Sets the port to listen on for inbound WireGuard connections
    ///
    /// # Arguments
    /// * `port` - Port to listen on
    pub fn listen(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    /// Maximum Transfer Unit for all packets
    ///
    /// # Arguments
    /// * `mtu` - Value to set for MTU
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Adds all routes to the allowed ips list
    ///
    /// # Arguments
    /// *  `alloawed_ips` - IPs/networks to route over this device
    pub fn allowed_ips(mut self, allowed_ips: Vec<Ipv4Network>) -> Self {
        let mut allowed_ips = allowed_ips;
        self.allowed_ips.append(&mut allowed_ips);
        self
    }

    /// Builds this device, returning a handle that can be used for further configuration
    pub fn build(self) -> Result<Device, Error> {
        let name = self.name.unwrap_or("wireguardian0".into());
        let key = self.key.ok_or(Error::MissingPrivateKey)?;
        let pub_key = PublicKey::from(&key);
        let address = self.address.ok_or(Error::MissingInterfaceAddress)?;
        let endpoint = self.endpoint.ok_or(Error::MissingDeviceEndpoint)?;

        let device = userspace::create(&name, address, key, self.listen_port)?;
        Ok(Device {
            ty: DeviceType::Userspace(device),
            pub_key,
            address,
            endpoint,
            allowed_ips: self.allowed_ips,
        })
    }
}

impl Peer {
    /// Creates a new `Peer` for the peer with the provided public key
    ///
    /// # Arguments
    /// * `pub_key` - Public Key of peer
    pub fn new(pub_key: PublicKey) -> Self {
        Self {
            pub_key,
            endpoint: None,
            allowed_ips: Vec::new(),
            keepalive: None,
        }
    }

    /// Sets the peer's endpoint
    ///
    /// Note: This is (usually) only set on the "client" side of the tunnel. The "server" side
    /// generally does not contain an endpoint
    ///
    /// # Arguments
    /// * `endpoint` - IP/Port of peer to connect to
    pub fn endpoint(mut self, endpoint: impl Into<SocketAddr>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Allows an IPv4 network (ip + subnet mask) to route over the tunnel
    ///
    /// # Arguments
    /// * `network` - Network to route over the tunnel
    pub fn allow_ip(mut self, network: impl Into<Ipv4Network>) -> Self {
        self.allowed_ips.push(network.into());
        self
    }

    /// Sets the keepalive interval (in seconds) to ensure the connection stays open
    ///
    /// Used to assist in UDP hole-punching (and ensuring NAT devices don't close the connection)
    ///
    /// # Arguments
    /// * `keepalive` - Interval (in seconds)
    pub fn keepalive(mut self, keepalive: u16) -> Self {
        self.keepalive = Some(keepalive);
        self
    }

    /// Adds the peer to the device
    ///
    /// # Arguments
    /// * `device` - Device to add peer to
    pub fn add(self, device: &Device) -> Result<bool, Error> {
        match &device.ty {
            DeviceType::Userspace(dev) => {
                dev.add_peer(&self.pub_key);
                for net in self.allowed_ips {
                    dev.add_allowed_ip(&self.pub_key, net.ip().into(), net.prefix() as u32);
                }
            }
            DeviceType::LinuxKernel => {
                unimplemented!("linux kernel device not supported (yet)");
            }
        }

        Ok(false)
    }

    /// Removes this peer from the associated device
    ///
    /// # Arguments
    /// * `device` - Device to remove peer from
    pub fn remove(self, device: &Device) {
        match &device.ty {
            DeviceType::Userspace(dev) => {
                dev.remove_peer(&self.pub_key);
            }
            DeviceType::LinuxKernel => {
                unimplemented!("linux kernel device not supported (yet)");
            }
        }
    }
}
