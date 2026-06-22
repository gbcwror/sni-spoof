use super::TcpFlags;

pub fn parse_ipv4_addrs(data: &[u8]) -> Option<([u8; 4], [u8; 4], usize)> {
    if data.len() < 20 {
        return None;
    }
    if (data[0] >> 4) != 4 {
        return None;
    }
    let ihl = (data[0] & 0x0f) as usize * 4;
    if data.len() < ihl {
        return None;
    }
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&data[12..16]);
    dst.copy_from_slice(&data[16..20]);
    Some((src, dst, ihl))
}

pub fn parse_tcp_header(data: &[u8]) -> Option<(u16, u16, u32, u32, TcpFlags, usize)> {
    if data.len() < 20 {
        return None;
    }
    let src_port  = u16::from_be_bytes([data[0], data[1]]);
    let dst_port  = u16::from_be_bytes([data[2], data[3]]);
    let seq       = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack       = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_off  = ((data[12] >> 4) & 0x0f) as usize * 4;
    let f         = data[13];
    let flags = TcpFlags {
        fin: (f & 0x01) != 0,
        syn: (f & 0x02) != 0,
        rst: (f & 0x04) != 0,
        psh: (f & 0x08) != 0,
        ack: (f & 0x10) != 0,
    };
    Some((src_port, dst_port, seq, ack, flags, data_off))
}

pub fn build_raw_tcp_packet(
    src_ip:   &[u8; 4],
    dst_ip:   &[u8; 4],
    src_port: u16,
    dst_port: u16,
    seq:      u32,
    ack:      u32,
    payload:  &[u8],
) -> Vec<u8> {
    let ip_hdr_len  = 20usize;
    let tcp_hdr_len = 20usize;
    let total       = ip_hdr_len + tcp_hdr_len + payload.len();
    let mut pkt     = vec![0u8; total];

    // IPv4 header
    pkt[0]    = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    let id: u16 = rand::random();
    pkt[4..6].copy_from_slice(&id.to_be_bytes());
    pkt[6]    = 0x40; // DF
    pkt[8]    = 128;  // TTL
    pkt[9]    = 6;    // TCP
    pkt[12..16].copy_from_slice(src_ip);
    pkt[16..20].copy_from_slice(dst_ip);

    // TCP header
    let tcp = &mut pkt[ip_hdr_len..];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x18; // PSH + ACK
    tcp[14..16].copy_from_slice(&[0xff, 0xff]);

    if !payload.is_empty() {
        pkt[ip_hdr_len + tcp_hdr_len..].copy_from_slice(payload);
    }

    // Compute IPv4 header checksum
    let ip_cksum = ipv4_checksum(&pkt[..ip_hdr_len]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // Compute TCP checksum
    let tcp_cksum = tcp_ipv4_checksum(
        src_ip, dst_ip,
        &pkt[ip_hdr_len..],
    );
    pkt[ip_hdr_len + 16..ip_hdr_len + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

    pkt
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn tcp_ipv4_checksum(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    tcp_segment: &[u8],
) -> u16 {
    let tcp_len = tcp_segment.len() as u32;
    let mut sum: u32 = 0;

    // Pseudo-header
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6u32; // protocol: TCP
    sum += tcp_len;

    // TCP segment (checksum field at bytes 16-17 zeroed for computation)
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        let word = if i == 16 {
            0u32
        } else {
            u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32
        };
        sum += word;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}
