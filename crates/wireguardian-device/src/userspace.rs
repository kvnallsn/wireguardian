//! Runs the wireguard device

#[cfg_attr(target_os = "linux", path = "os/linux.rs")]
#[cfg_attr(target_os = "windows", path = "os/windows.rs")]
#[cfg_attr(target_os = "macos", path = "os/osx.rs")]
mod os;

use crate::Error;
use ipnetwork::Ipv4Network;
use std::thread;
use wireguard_rs::{
    configuration::{self, Configuration, WireGuardConfig},
    plt,
    tun::{PlatformTun, Status, TunEvent},
    uapi::{BindUAPI, PlatformUAPI},
    wireguard::WireGuard,
};
use x25519_dalek::StaticSecret;

/// A platform-specific userspace WireGuard tunnel device
pub type UserspaceDevice = WireGuardConfig<plt::Tun, plt::UDP>;

#[macro_export]
macro_rules! cmd {
    ($cmd:expr) => {
        $crate::cmd::ShellCommand::new($cmd).execute()
    };

    ($cmd:expr, $($arg:expr),+) => {{
        let mut cmd = $crate::cmd::ShellCommand::new($cmd);
        $(cmd.arg($arg);)+
        cmd.execute()
    }};

    ($cmd:expr; $($arg:expr),+; $f:expr) => {{
        let mut cmd = $crate::cmd::ShellCommand::new($cmd);
        $(cmd.arg($arg);)+
        cmd.spawn($f)
    }}
}

/// Creates a new WireGuard interface on the host
///
/// On MacOS and Windows, this creates a userspace tunnel
/// On Linux 5.4+, this creates a kernel device, on <5.4 this creates a userspace tunnel
///
/// # Arguments
/// * `name` - Name to assign to the tunnel device (e.g. `tun0`, `utun10`)
/// * `address` - IPv4 address and netmask to assign to the tunnel device (e.g. `192.168.127.1/24`)
/// * `key` - ED25519 private key used to identify this device
/// * `listen` - Optional port to listen on for new WireGuard connections
pub fn create(
    name: &str,
    address: Ipv4Network,
    key: StaticSecret,
    listen: Option<u16>,
) -> Result<UserspaceDevice, Error> {
    // create userspace api
    let uapi = plt::UAPI::bind(name)?;

    // create tunnel device
    let (mut readers, writer, status) =
        plt::Tun::create(name).map_err(|err| Error::Tunnel(format!("{:?}", err)))?;

    // create wireguard device
    let wg: WireGuard<plt::Tun, plt::UDP> = WireGuard::new(writer);
    while let Some(reader) = readers.pop() {
        wg.add_tun_reader(reader);
    }

    // wrap in a configuration instance
    let cfg = WireGuardConfig::new(wg.clone());

    // start tunnel event thread
    {
        let cfg = cfg.clone();
        let mut status = status;
        thread::spawn(move || loop {
            match status.event() {
                Err(error) => {
                    tracing::error!(?error, "tun device error");
                    //exit(0);
                }
                Ok(TunEvent::Up(mtu)) => {
                    tracing::info!("tun up (mtu = {})", mtu);
                    let _ = cfg.up(mtu); // TODO: handle
                }
                Ok(TunEvent::Down) => {
                    tracing::info!("tun down");
                    cfg.down();
                }
            }
        });
    }

    // start userspace api (UAPI) server
    {
        let cfg = cfg.clone();
        thread::spawn(move || loop {
            // accept and handle UAPI config connections
            match uapi.connect() {
                Ok(mut stream) => {
                    let cfg = cfg.clone();
                    thread::spawn(move || configuration::uapi::handle(&mut stream, &cfg));
                }
                Err(error) => {
                    tracing::error!(?error, "UAPI connection error");
                }
            }
        });
    }

    // 3. configure device with specificed parameters
    tracing::info!("configuring wireguard interface");

    if let Some(port) = listen {
        cfg.down();
        cfg.set_listen_port(port)?;
        cfg.up(1380)?;
    }

    cfg.set_private_key(Some(key));

    os::assign_ip(name, address)?;

    Ok(cfg)
}
