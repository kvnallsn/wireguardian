//! Runs the wireguard device

#[cfg_attr(target_os = "linux", path = "os/linux.rs")]
#[cfg_attr(target_os = "windows", path = "os/windows.rs")]
#[cfg_attr(target_os = "macos", path = "os/osx.rs")]
mod os;

use crate::config::DeviceConfig;
use color_eyre::eyre;
use std::thread;
use wireguard_rs::{
    configuration::{self, Configuration, WireGuardConfig},
    plt,
    tun::{PlatformTun, Status, TunEvent},
    uapi::{BindUAPI, PlatformUAPI},
    wireguard::WireGuard,
};

#[macro_export]
macro_rules! cmd {
    ($cmd:expr) => {
        $crate::shell::ShellCommand::new($cmd).execute()
    };

    ($cmd:expr, $($arg:expr),+) => {{
        let mut cmd = $crate::shell::ShellCommand::new($cmd);
        $(cmd.arg($arg);)+
        cmd.execute()
    }};

    ($cmd:expr; $($arg:expr),+; $f:expr) => {{
        let mut cmd = $crate::shell::ShellCommand::new($cmd);
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
/// * `device` - Wireguardian Device Configuration
pub fn create(device: DeviceConfig) -> eyre::Result<WireGuardConfig<plt::Tun, plt::UDP>> {
    let tun_name = device.adapter_name.as_str();

    // create userspace api
    let uapi = match plt::UAPI::bind(tun_name) {
        Ok(uapi) => uapi,
        Err(error) => {
            tracing::error!(?error);
            eyre::bail!("failed to init wireguard userspace api");
        }
    };

    // create tunnel device
    let (mut readers, writer, status) = match plt::Tun::create(tun_name) {
        Ok(tun) => tun,
        Err(error) => {
            tracing::error!(?error);
            eyre::bail!("failed to init wireguard tunnels");
        }
    };

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

    cfg.down();
    cfg.set_listen_port(device.listen_port)?;
    cfg.up(1380)?;

    cfg.set_private_key(Some(device.secret_key()?));

    os::assign_ip(tun_name, device.address)?;

    Ok(cfg)
}
