//! Just enough Ethernet / ARP / IPv4 / UDP / TCP to read the packets the capture
//! source asks for. Malformed or truncated input returns None, never panics.

use std::net::Ipv4Addr;

use na_model::{MacAddr, TcpSignature};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_VLAN: u16 = 0x8100;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn mac_at(b: &[u8], i: usize) -> Option<MacAddr> {
    Some(MacAddr(b.get(i..i + 6)?.try_into().ok()?))
}

fn ip_at(b: &[u8], i: usize) -> Option<Ipv4Addr> {
    let o: [u8; 4] = b.get(i..i + 4)?.try_into().ok()?;
    Some(Ipv4Addr::from(o))
}

pub struct Ethernet<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

/// Ethernet II, with at most one 802.1Q tag.
pub fn ethernet(frame: &[u8]) -> Option<Ethernet<'_>> {
    let mut ethertype = u16_at(frame, 12)?;
    let mut start = 14;
    if ethertype == ETHERTYPE_VLAN {
        ethertype = u16_at(frame, 16)?;
        start = 18;
    }
    Some(Ethernet { dst: mac_at(frame, 0)?, src: mac_at(frame, 6)?, ethertype, payload: frame.get(start..)? })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arp {
    /// 1 = request, 2 = reply.
    pub op: u16,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl Arp {
    /// Announces the sender's own address (sender IP == target IP).
    pub fn is_gratuitous(&self) -> bool {
        self.sender_ip == self.target_ip
    }

    /// An RFC 5227 probe: "is anyone using this address?" (sender IP 0.0.0.0). Claims nothing.
    pub fn is_probe(&self) -> bool {
        self.sender_ip.is_unspecified()
    }
}

/// Ethernet/IPv4 ARP only.
pub fn arp(p: &[u8]) -> Option<Arp> {
    if u16_at(p, 0)? != 1 || u16_at(p, 2)? != ETHERTYPE_IPV4 || p.get(4..6)? != [6, 4] {
        return None;
    }
    Some(Arp {
        op: u16_at(p, 6)?,
        sender_mac: mac_at(p, 8)?,
        sender_ip: ip_at(p, 14)?,
        target_mac: mac_at(p, 18)?,
        target_ip: ip_at(p, 24)?,
    })
}

pub struct Ipv4<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ttl: u8,
    pub proto: u8,
    pub payload: &'a [u8],
}

/// IPv4 header. Fragments other than the first are skipped (no transport header).
pub fn ipv4(p: &[u8]) -> Option<Ipv4<'_>> {
    let vihl = *p.first()?;
    let ihl = usize::from(vihl & 0x0F) * 4;
    if vihl >> 4 != 4 || ihl < 20 {
        return None;
    }
    let total = usize::from(u16_at(p, 2)?).clamp(ihl, p.len());
    let frag_offset = u16_at(p, 6)? & 0x1FFF;
    if frag_offset != 0 {
        return None;
    }
    Some(Ipv4 { src: ip_at(p, 12)?, dst: ip_at(p, 16)?, ttl: p[8], proto: p[9], payload: p.get(ihl..total)? })
}

pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn udp(p: &[u8]) -> Option<Udp<'_>> {
    let len = usize::from(u16_at(p, 4)?).clamp(8, p.len());
    Some(Udp { src_port: u16_at(p, 0)?, dst_port: u16_at(p, 2)?, payload: p.get(8..len)? })
}

/// A TCP segment that opens a connection (SYN without ACK), reduced to its signature.
pub fn tcp_syn(ip: &Ipv4<'_>) -> Option<TcpSignature> {
    let p = ip.payload;
    let off = usize::from(*p.get(12)? >> 4) * 4;
    let flags = *p.get(13)?;
    if flags & 0x12 != 0x02 || off < 20 {
        return None;
    }
    let mut sig = TcpSignature {
        ttl: ip.ttl,
        initial_ttl: [32u8, 64, 128, 255].into_iter().find(|&t| ip.ttl <= t).unwrap_or(255),
        window: u16_at(p, 14)?,
        ..Default::default()
    };
    let mut opts = p.get(20..off)?;
    let mut layout = Vec::new();
    while let Some(&kind) = opts.first() {
        match kind {
            0 => {
                layout.push("E".to_owned());
                break;
            }
            1 => {
                layout.push("N".to_owned());
                opts = &opts[1..];
            }
            _ => {
                let len = usize::from(*opts.get(1)?);
                if len < 2 || len > opts.len() {
                    break;
                }
                let body = &opts[2..len];
                match kind {
                    2 if body.len() == 2 => {
                        sig.mss = Some(u16::from_be_bytes([body[0], body[1]]));
                        layout.push("M".into());
                    }
                    3 if body.len() == 1 => {
                        sig.wscale = Some(body[0]);
                        layout.push("W".into());
                    }
                    4 => layout.push("S".into()),
                    8 => layout.push("T".into()),
                    k => layout.push(format!("?{k}")),
                }
                opts = &opts[len..];
            }
        }
    }
    sig.layout = layout.join(",");
    Some(sig)
}

/// Internet checksum (RFC 1071).
pub fn checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for c in chunks {
        for pair in c.chunks(2) {
            let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
            sum += u32::from(word);
        }
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Ethernet + IPv4 + UDP around `payload` (both checksums filled in).
pub fn udp_frame(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, PROTO_UDP, 0, 0];
    ip[2..4].copy_from_slice(&((20 + udp_len) as u16).to_be_bytes());
    ip.extend_from_slice(&src.0.octets());
    ip.extend_from_slice(&dst.0.octets());
    let ip_sum = checksum(&[&ip]);
    ip[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src.1.to_be_bytes());
    udp.extend_from_slice(&dst.1.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&src.0.octets());
    pseudo.extend_from_slice(&dst.0.octets());
    pseudo.extend_from_slice(&[0, PROTO_UDP]);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    let udp_sum = match checksum(&[&pseudo, &udp]) {
        0 => 0xFFFF,
        s => s,
    };
    udp[6..8].copy_from_slice(&udp_sum.to_be_bytes());

    let mut frame = Vec::with_capacity(14 + 20 + udp_len);
    frame.extend_from_slice(&dst_mac.0);
    frame.extend_from_slice(&src_mac.0);
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn arp_reply_and_gratuitous() {
        let mut f = vec![0xFF; 6];
        f.extend_from_slice(&mac("3C:37:86:00:00:01").0);
        f.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 2]);
        f.extend_from_slice(&mac("3C:37:86:00:00:01").0);
        f.extend_from_slice(&[192, 168, 1, 1]);
        f.extend_from_slice(&[0; 6]);
        f.extend_from_slice(&[192, 168, 1, 1]);
        let e = ethernet(&f).unwrap();
        assert_eq!(e.ethertype, ETHERTYPE_ARP);
        let a = arp(e.payload).unwrap();
        assert_eq!((a.op, a.sender_ip), (2, Ipv4Addr::new(192, 168, 1, 1)));
        assert!(a.is_gratuitous() && !a.is_probe());
        assert!(arp(&e.payload[..20]).is_none(), "truncated");
    }

    #[test]
    fn built_udp_frame_parses_and_checksums() {
        let f = udp_frame(
            mac("3C:37:86:00:00:01"),
            MacAddr([0xFF; 6]),
            (Ipv4Addr::UNSPECIFIED, 68),
            (Ipv4Addr::BROADCAST, 67),
            b"hello",
        );
        let e = ethernet(&f).unwrap();
        let ip = ipv4(e.payload).unwrap();
        assert_eq!((ip.proto, ip.dst), (PROTO_UDP, Ipv4Addr::BROADCAST));
        assert_eq!(checksum(&[&e.payload[..20]]), 0, "IPv4 header checksum verifies");
        let u = udp(ip.payload).unwrap();
        assert_eq!((u.src_port, u.dst_port, u.payload), (68, 67, &b"hello"[..]));
    }

    #[test]
    fn windows_style_syn_signature() {
        // TTL 128, window 64240, MSS 1460, NOP, WS 8, NOP, NOP, SACK-permitted.
        let mut ip = vec![0x45, 0, 0, 52, 0, 0, 0x40, 0, 128, PROTO_TCP, 0, 0, 192, 168, 1, 23, 192, 168, 1, 1];
        let mut tcp = vec![0xC0, 0x01, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x80, 0x02, 0xFA, 0xF0, 0, 0, 0, 0];
        tcp.extend_from_slice(&[2, 4, 0x05, 0xB4, 1, 3, 3, 8, 1, 1, 4, 2]);
        ip.extend_from_slice(&tcp);
        let sig = tcp_syn(&ipv4(&ip).unwrap()).unwrap();
        assert_eq!((sig.initial_ttl, sig.window, sig.mss, sig.wscale), (128, 64240, Some(1460), Some(8)));
        assert_eq!(sig.layout, "M,N,W,N,N,S");
        ip[20 + 13] = 0x12; // SYN-ACK: a reply, not a connection attempt
        assert!(tcp_syn(&ipv4(&ip).unwrap()).is_none());
    }
}
