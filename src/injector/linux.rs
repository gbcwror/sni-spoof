use super::{FakePacketAction, TcpFlags};
use super::logic::InjectorLogic;
use crate::config::AppConfig;
use crate::connection::ConnectionId;
use crate::ConnectionMap;
use anyhow::Context;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags as PnetTcpFlags, TcpPacket};
use pnet::packet::Packet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// RAII guard that ensures iptables rules are cleaned up on drop.
/// Handles panics, early returns, and normal exit paths.
struct IptablesGuard {
    interface_ip: String,
    connect_ip:   String,
    connect_port: u16,
    queue_num:    u16,
}

impl IptablesGuard {
    fn new(
        interface_ip: &str,
        connect_ip: &str,
        connect_port: u16,
        queue_num: u16,
    ) -> anyhow::Result<Self> {
        let guard = Self {
            interface_ip: interface_ip.to_string(),
            connect_ip:   connect_ip.to_string(),
            connect_port,
            queue_num,
        };
        // Clean up any stale rules from a previous crash, then install fresh ones.
        cleanup_iptables_inner(&guard.interface_ip, &guard.connect_ip, guard.connect_port, guard.queue_num);
        setup_iptables_inner(&guard.interface_ip, &guard.connect_ip, guard.connect_port, guard.queue_num)?;
        Ok(guard)
    }
}

impl Drop for IptablesGuard {
    fn drop(&mut self) {
        info!("Cleaning up iptables rules");
        cleanup_iptables_inner(&self.interface_ip, &self.connect_ip, self.connect_port, self.queue_num);
    }
}

pub fn run_nfqueue(
    config: &AppConfig,
    interface_ip: &str,
    connections: ConnectionMap,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let queue_num = 0u16;

    // Guard installs iptables rules now and removes them when dropped —
    // whether we return normally, hit an error, or unwind from a panic.
    let _guard = IptablesGuard::new(
        interface_ip,
        &config.connect_ip,
        config.connect_port,
        queue_num,
    )?;

    run_loop(config, interface_ip, connections, cancel, queue_num)
}

fn run_loop(
    config: &AppConfig,
    interface_ip: &str,
    connections: ConnectionMap,
    cancel: CancellationToken,
    queue_num: u16,
) -> anyhow::Result<()> {
    let mut queue = nfq::Queue::open()
        .context("Failed to open nfqueue. Are you running as root?")?;
    queue.bind(queue_num)
        .context("Failed to bind to nfqueue")?;

    let interface_bytes = crate::net::parse_ipv4(interface_ip)?;
    let connect_bytes   = crate::net::parse_ipv4(&config.connect_ip)?;

    let raw_sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::from(6)),
    ).context("Failed to create raw socket. Are you running as root?")?;
    raw_sock.set_header_included_v4(true)?;

    loop {
        if cancel.is_cancelled() {
            break;
        }

        let msg = match queue.recv() {
            Ok(m)  => m,
            Err(e) => { warn!("nfqueue recv error: {}", e); continue; }
        };

        process_nfqueue_msg(
            msg, &mut queue, &interface_bytes, &connect_bytes,
            &connections, &raw_sock, &config.bypass_method,
        );
    }

    Ok(())
}

fn process_nfqueue_msg(
    mut msg: nfq::Message,
    queue: &mut nfq::Queue,
    interface_bytes: &[u8; 4],
    connect_bytes: &[u8; 4],
    connections: &ConnectionMap,
    raw_sock: &socket2::Socket,
    bypass_method: &crate::config::BypassMethod,
) {
    let payload = msg.get_payload();

    let ipv4_pkt = match Ipv4Packet::new(payload) {
        Some(p) => p,
        None    => {
            msg.set_verdict(nfq::Verdict::Accept);
            if let Err(e) = queue.verdict(msg) {
                warn!("nfqueue verdict failed: {}", e);
            }
            return;
        }
    };

    if ipv4_pkt.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        msg.set_verdict(nfq::Verdict::Accept);
        if let Err(e) = queue.verdict(msg) {
            warn!("nfqueue verdict failed: {}", e);
        }
        return;
    }

    let tcp_pkt = match TcpPacket::new(ipv4_pkt.payload()) {
        Some(p) => p,
        None    => {
            msg.set_verdict(nfq::Verdict::Accept);
            if let Err(e) = queue.verdict(msg) {
                warn!("nfqueue verdict failed: {}", e);
            }
            return;
        }
    };

    let src_ip   = ipv4_pkt.get_source().octets();
    let dst_ip   = ipv4_pkt.get_destination().octets();
    let src_port = tcp_pkt.get_source();
    let dst_port = tcp_pkt.get_destination();
    let seq      = tcp_pkt.get_sequence();
    let ack      = tcp_pkt.get_acknowledgement();
    let tcp_hdr_len  = (tcp_pkt.get_data_offset() * 4) as usize;
    let payload_len  = ipv4_pkt.payload().len().saturating_sub(tcp_hdr_len);

    let rf = tcp_pkt.get_flags();
    let flags = TcpFlags {
        syn: (rf & PnetTcpFlags::SYN) != 0,
        ack: (rf & PnetTcpFlags::ACK) != 0,
        rst: (rf & PnetTcpFlags::RST) != 0,
        fin: (rf & PnetTcpFlags::FIN) != 0,
        psh: (rf & PnetTcpFlags::PSH) != 0,
    };

    let is_outbound = src_ip == *interface_bytes && dst_ip == *connect_bytes;

    if is_outbound {
        let conn_id = ConnectionId { src_ip, src_port, dst_ip, dst_port };

        let (forward, fake_action) = InjectorLogic::process_outbound(
            connections, &conn_id, flags, seq, ack, payload_len,
            bypass_method,
        );

        msg.set_verdict(if forward {
            nfq::Verdict::Accept
        } else {
            nfq::Verdict::Drop
        });
        if let Err(e) = queue.verdict(msg) {
            warn!("nfqueue verdict failed: {}", e);
        }

        if let Some(action) = fake_action {
            let fake = build_fake_packet_linux(
                &src_ip, &dst_ip, src_port, dst_port,
                action.seq_num, action.ack_num, &action.payload,
            );
            let dst_addr = SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(dst_ip), dst_port,
            ));
            match raw_sock.send_to(&fake, &socket2::SockAddr::from(dst_addr)) {
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
            connections, &conn_id, flags, seq, ack, payload_len,
        );
        msg.set_verdict(if forward {
            nfq::Verdict::Accept
        } else {
            nfq::Verdict::Drop
        });
        if let Err(e) = queue.verdict(msg) {
            warn!("nfqueue verdict failed: {}", e);
        }
    }
}

fn build_fake_packet_linux(
    src_ip:   &[u8; 4],
    dst_ip:   &[u8; 4],
    src_port: u16,
    dst_port: u16,
    seq:      u32,
    ack:      u32,
    payload:  &[u8],
) -> Vec<u8> {
    let tcp_len      = 20 + payload.len();
    let ip_total_len = 20 + tcp_len;
    let mut pkt      = vec![0u8; ip_total_len];

    {
        let mut ip = MutableIpv4Packet::new(&mut pkt[..]).expect("buffer large enough for IPv4 header");
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(ip_total_len as u16);
        ip.set_identification(rand::random());
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_ttl(128);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(Ipv4Addr::from(*src_ip));
        ip.set_destination(Ipv4Addr::from(*dst_ip));
        ip.set_checksum(ipv4::checksum(&ip.to_immutable()));
    }

    {
        let mut tcp = MutableTcpPacket::new(&mut pkt[20..20 + tcp_len]).expect("buffer large enough for TCP header");
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(PnetTcpFlags::PSH | PnetTcpFlags::ACK);
        tcp.set_window(65535);
        tcp.set_payload(payload);
        let cs = tcp::ipv4_checksum(
            &tcp.to_immutable(),
            &Ipv4Addr::from(*src_ip),
            &Ipv4Addr::from(*dst_ip),
        );
        tcp.set_checksum(cs);
    }

    pkt
}

fn run_iptables(args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new("iptables")
        .args(args)
        .status()
        .with_context(|| format!("Failed to execute: iptables {}", args.join(" ")))?;
    if !status.success() {
        anyhow::bail!("iptables failed: iptables {}", args.join(" "));
    }
    Ok(())
}

fn setup_iptables_inner(interface_ip: &str, connect_ip: &str, connect_port: u16, queue_num: u16) -> anyhow::Result<()> {
    let port_str = connect_port.to_string();
    run_iptables(&[
        "-I", "OUTPUT", "-p", "tcp", "-s", interface_ip, "-d", connect_ip,
        "--dport", &port_str,
        "--tcp-flags", "SYN,ACK,FIN,RST", "SYN",
        "-j", "NFQUEUE", "--queue-num", &queue_num.to_string(),
        "-m", "comment", "--comment", "SNI_SPOOF",
    ])?;
    run_iptables(&[
        "-I", "OUTPUT", "-p", "tcp", "-s", interface_ip, "-d", connect_ip,
        "--dport", &port_str,
        "--tcp-flags", "SYN,ACK,FIN,RST", "ACK",
        "-j", "NFQUEUE", "--queue-num", &queue_num.to_string(),
        "-m", "comment", "--comment", "SNI_SPOOF",
    ])?;
    run_iptables(&[
        "-I", "INPUT", "-p", "tcp", "-s", connect_ip, "-d", interface_ip,
        "--sport", &port_str,
        "-j", "NFQUEUE", "--queue-num", &queue_num.to_string(),
        "-m", "comment", "--comment", "SNI_SPOOF",
    ])?;

    Ok(())
}

fn cleanup_iptables_inner(interface_ip: &str, connect_ip: &str, connect_port: u16, queue_num: u16) {
    let queue_str = queue_num.to_string();
    let port_str = connect_port.to_string();
    let rules: Vec<Vec<&str>> = vec![
        vec!["-D", "OUTPUT", "-p", "tcp", "-s", interface_ip, "-d", connect_ip,
             "--dport", &port_str,
             "--tcp-flags", "SYN,ACK,FIN,RST", "SYN",
             "-j", "NFQUEUE", "--queue-num", &queue_str,
             "-m", "comment", "--comment", "SNI_SPOOF"],
        vec!["-D", "OUTPUT", "-p", "tcp", "-s", interface_ip, "-d", connect_ip,
             "--dport", &port_str,
             "--tcp-flags", "SYN,ACK,FIN,RST", "ACK",
             "-j", "NFQUEUE", "--queue-num", &queue_str,
             "-m", "comment", "--comment", "SNI_SPOOF"],
        vec!["-D", "INPUT", "-p", "tcp", "-s", connect_ip, "-d", interface_ip,
             "--sport", &port_str,
             "-j", "NFQUEUE", "--queue-num", &queue_str,
             "-m", "comment", "--comment", "SNI_SPOOF"],
    ];
    for args in &rules {
        let _ = std::process::Command::new("iptables").args(args).status();
    }
}