//! Linux Specific OS interface

use crate::{cmd, Error};
use ipnetwork::Ipv4Network;

/// Assigns an IP address to a network interface
///
/// # Arguments
/// * `device_name` - Name of network device (e.g. `wg0`, `utunX`, etc.)
/// * `ip` - IPv4 address and netmask (e.g. `192.168.127.1/24`)
pub fn assign_ip(device_name: &str, ip: Ipv4Network) -> Result<(), Error> {
    cmd!("ip", "address", "add", ip.to_string(), "dev", device_name)?;
    cmd!("ip", "link", "set", device_name, "up")?;
    Ok(())
}
