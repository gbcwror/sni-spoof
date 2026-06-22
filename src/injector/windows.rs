use super::{FakePacketAction, TcpFlags};
use super::logic::InjectorLogic;
use super::packet::{build_raw_tcp_packet, parse_ipv4_addrs, parse_tcp_header};
use crate::config::AppConfig;
use crate::connection::ConnectionId;
use crate::ConnectionMap;
use anyhow::Context;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};
use windivert::prelude::*;

/// Maximum consecutive recv errors before we consider the handle broken.
const MAX_CONSECUTIVE_ERRORS: u32 = 50;

/// Backoff durations for consecutive recv errors.
const BACKOFF_MS: &[u64] = &[1, 2, 5, 10, 25, 50, 100, 250, 500];

pub fn run_windivert(
    config: &AppConfig,
    interface_ip: &str,
    connections: ConnectionMap,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let filter = format!(
        "tcp and ((ip.SrcAddr == {} and ip.DstAddr == {}) or \
                  (ip.SrcAddr == {} and ip.DstAddr == {}))",
        interface_ip, config.connect_ip,
        config.connect_ip, interface_ip
    );

    let wd = WinDivert::network(&filter, 0, WinDivertFlags::new())
        .context("Failed to open WinDivert. Are you running as Administrator?")?;

    let mut buf = vec![0u8; 65535];
    let mut consecutive_errors: u32 = 0;

    loop {
        if cancel.is_cancelled() {
            break;
        }

        let packet = match wd.recv(Some(&mut buf)) {
            Ok(p) => {
                consecutive_errors = 0;
                p
            }
            Err(e) => {
                consecutive_errors += 1;

                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    error!(
                        "WinDivert recv failed {} times consecutively, last error: {}. Giving up.",
                        consecutive_errors, e
                    );
                    anyhow::bail!(
                        "WinDivert recv failed {} consecutive times: {}",
                        consecutive_errors, e
                    );
                }

                let backoff_idx = (consecutive_errors as usize).min(BACKOFF_MS.len() - 1);
                let sleep_ms = BACKOFF_MS[backoff_idx];

                warn!(
                    "WinDivert recv error ({}/{}): {}. Retrying in {} ms.",
                    consecutive_errors, MAX_CONSECUTIVE_ERRORS, e, sleep_ms
                );

                std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                continue;
            }
        };

        let raw = &packet.data;

        let (src_ip, dst_ip, ip_hdr_len) = match parse_ipv4_addrs(raw) {
            Some(v) => v,
            None => {
                if let Err(e) = wd.send(&packet) {
                    warn!("WinDivert send failed: {}", e);
                }
                continue;
            }
        };

        if raw.len() < ip_hdr_len + 20 || raw[9] != 6 {
            if let Err(e) = wd.send(&packet) {
                warn!("WinDivert send failed: {}", e);
            }
            continue;
        }

        let tcp_data = &raw[ip_hdr_len..];
        let (src_port, dst_port, seq, ack, flags, tcp_hdr_len) =
            match parse_tcp_header(tcp_data) {
                Some(v) => v,
                None => {
                    if let Err(e) = wd.send(&packet) {
                        warn!("WinDivert send failed: {}", e);
                    }
                    continue;
                }
            };

        let payload_len = tcp_data.len().saturating_sub(tcp_hdr_len);
        let is_outbound = packet.address.outbound();

        if is_outbound {
            let conn_id = ConnectionId { src_ip, src_port, dst_ip, dst_port };

            let (forward, fake_action) = InjectorLogic::process_outbound(
                &connections, &conn_id, flags, seq, ack, payload_len,
                &config.bypass_method,
            );

            let saved_addr = packet.address.clone();
            if forward {
                if let Err(e) = wd.send(&packet) {
                    warn!("WinDivert send failed: {}", e);
                }
            }

            if let Some(action) = fake_action {
                let raw_fake = build_raw_tcp_packet(
                    &src_ip, &dst_ip, src_port, dst_port,
                    action.seq_num, action.ack_num, &action.payload,
                );
                let fake_pkt = WinDivertPacket::<NetworkLayer> {
                    address: saved_addr,
                    data: raw_fake.into(),
                };
                match wd.send(&fake_pkt) {
                    Ok(_)  => debug!("Fake packet injected for {}", conn_id),
                    Err(e) => warn!("Failed to inject fake packet: {}", e),
                }
            }
        } else {
            let conn_id = ConnectionId {
                src_ip: dst_ip, src_port: dst_port,
                dst_ip: src_ip, dst_port: src_port,
            };
            let forward = InjectorLogic::process_inbound(
                &connections, &conn_id, flags, seq, ack, payload_len,
            );
            if forward {
                if let Err(e) = wd.send(&packet) {
                    warn!("WinDivert send failed: {}", e);
                }
            }
        }
    }

    Ok(())
}