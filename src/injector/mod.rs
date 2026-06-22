use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::config::AppConfig;
use crate::ConnectionMap;

mod logic;
mod packet;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
mod linux;

pub struct PacketInjector;

impl PacketInjector {
    pub fn run(
        config: &AppConfig,
        interface_ip: &str,
        connections: ConnectionMap,
        cancel: CancellationToken,
    ) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            windows::run_windivert(config, interface_ip, connections, cancel)
        }

        #[cfg(target_os = "linux")]
        {
            linux::run_nfqueue(config, interface_ip, connections, cancel)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            let _ = (config, interface_ip, connections, cancel);
            anyhow::bail!("Packet injection is not supported on this platform")
        }
    }
}

// Shared across logic.rs, windows.rs, and linux.rs via `super::`.
pub(super) struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub rst: bool,
    pub fin: bool,
    pub psh: bool,
}

pub(super) struct FakePacketAction {
    pub seq_num: u32,
    pub ack_num: u32,
    pub payload: Vec<u8>,
}