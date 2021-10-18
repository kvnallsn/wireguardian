//! Linux Specific OS interface

use crate::cmd;
use color_eyre::eyre;
use ipnetwork::Ipv4Network;

/// Assigns an IP address to a network interface
///
/// # Arguments
/// * `device_name` - Name of network device (e.g. `wg0`, `utunX`, etc.)
/// * `ip` - IPv4 address and netmask (e.g. `192.168.127.1/24`)
pub fn assign_ip(device_name: &str, ip: Ipv4Network) -> eyre::Result<()> {
    cmd!(
        "ipconfig",
        "set",
        device_name,
        "MANUAL",
        ip.ip().to_string(),
        ip.mask().to_string()
    )?;
    Ok(())
}
