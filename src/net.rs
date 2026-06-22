use anyhow::{bail, Result};
use std::net::{Ipv4Addr, UdpSocket};
use tracing::warn;

pub fn get_default_interface_ipv4(target: &str) -> Result<String> {
    let target_addr: Ipv4Addr = target.parse().unwrap_or(Ipv4Addr::new(8, 8, 8, 8));
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    if let Err(e) = sock.connect((target_addr, 53)) {
        warn!("Routing probe to {} failed: {}. Using fallback detection.", target_addr, e);
    }
    let local_addr = sock.local_addr()?;
    let ip = local_addr.ip();
    if ip.is_unspecified() {
        bail!("Could not determine local interface IP");
    }
    Ok(ip.to_string())
}

pub fn parse_ipv4(s: &str) -> Result<[u8; 4]> {
    let addr: Ipv4Addr = s.parse()?;
    Ok(addr.octets())
}