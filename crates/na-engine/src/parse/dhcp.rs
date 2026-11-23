//! DHCP (RFC 2131/2132): parse client and server messages, and build the
//! Discover used by the rogue-DHCP check.

use std::net::Ipv4Addr;

use na_model::{DhcpFingerprint, MacAddr};

const MAGIC: [u8; 4] = [99, 130, 83, 99];

pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const ACK: u8 = 5;
pub const INFORM: u8 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dhcp {
    /// 1 = from a client, 2 = from a server.
    pub op: u8,
    pub xid: u32,
    pub yiaddr: Ipv4Addr,
    pub chaddr: MacAddr,
    pub options: Vec<(u8, Vec<u8>)>,
}

impl Dhcp {
    pub fn opt(&self, code: u8) -> Option<&[u8]> {
        self.options.iter().find(|(c, _)| *c == code).map(|(_, v)| v.as_slice())
    }

    /// Option 53.
    pub fn msg_type(&self) -> Option<u8> {
        self.opt(53).and_then(|v| v.first().copied())
    }

    fn ips(&self, code: u8) -> Vec<Ipv4Addr> {
        self.opt(code)
            .map(|v| v.as_chunks::<4>().0.iter().map(|c| Ipv4Addr::from(*c)).collect())
            .unwrap_or_default()
    }

    /// Option 54.
    pub fn server_id(&self) -> Option<Ipv4Addr> {
        self.ips(54).into_iter().next()
    }

    /// Option 3.
    pub fn routers(&self) -> Vec<Ipv4Addr> {
        self.ips(3)
    }

    /// Option 6.
    pub fn dns(&self) -> Vec<Ipv4Addr> {
        self.ips(6)
    }

    fn text(&self, code: u8) -> Option<String> {
        let v = self.opt(code)?;
        let s: String = String::from_utf8_lossy(v).trim_end_matches('\0').chars().filter(|c| !c.is_control()).collect();
        (!s.trim().is_empty()).then(|| s.trim().to_owned())
    }

    /// The client's fingerprint, for client messages that carry a request list.
    pub fn fingerprint(&self) -> Option<DhcpFingerprint> {
        if self.op != 1 {
            return None;
        }
        let prl = self.opt(55)?.to_vec();
        Some(DhcpFingerprint { vendor_class: self.text(60), prl, hostname: self.text(12) })
    }
}

/// A BOOTP/DHCP message (the UDP payload).
pub fn parse(p: &[u8]) -> Option<Dhcp> {
    if p.len() < 240 || p[236..240] != MAGIC || p[1] != 1 || p[2] != 6 {
        return None;
    }
    let mut options = Vec::new();
    let mut i = 240;
    while i < p.len() {
        match p[i] {
            0 => i += 1,
            255 => break,
            code => {
                let len = usize::from(*p.get(i + 1)?);
                let body = p.get(i + 2..i + 2 + len)?;
                // Long options may be split into several (RFC 3396): concatenate.
                match options.iter_mut().find(|(c, _): &&mut (u8, Vec<u8>)| *c == code) {
                    Some((_, v)) => v.extend_from_slice(body),
                    None => options.push((code, body.to_vec())),
                }
                i += 2 + len;
            }
        }
    }
    Some(Dhcp {
        op: p[0],
        xid: u32::from_be_bytes(p[4..8].try_into().ok()?),
        yiaddr: Ipv4Addr::new(p[16], p[17], p[18], p[19]),
        chaddr: MacAddr(p[28..34].try_into().ok()?),
        options,
    })
}

/// A Discover from `mac` asking servers to broadcast their offers. The check
/// never follows up with a Request, so no address is taken.
pub fn discover(mac: MacAddr, xid: u32) -> Vec<u8> {
    let mut p = vec![0u8; 240];
    p[0] = 1; // BOOTREQUEST
    p[1] = 1; // Ethernet
    p[2] = 6;
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    p[10] = 0x80; // broadcast flag: offers come back as broadcasts we can capture
    p[28..34].copy_from_slice(&mac.0);
    p[236..240].copy_from_slice(&MAGIC);
    p.extend_from_slice(&[53, 1, DISCOVER]);
    p.extend_from_slice(&[55, 4, 1, 3, 6, 54]); // subnet mask, router, DNS, server id
    p.push(255);
    while p.len() < 300 {
        p.push(0); // minimum BOOTP size some servers expect
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn discover_round_trip() {
        let d = parse(&discover(mac("3C:37:86:00:00:01"), 0xDEAD_BEEF)).unwrap();
        assert_eq!((d.op, d.xid, d.msg_type()), (1, 0xDEAD_BEEF, Some(DISCOVER)));
        assert_eq!(d.chaddr, mac("3C:37:86:00:00:01"));
        assert_eq!(d.fingerprint().unwrap().prl, vec![1, 3, 6, 54]);
    }

    #[test]
    fn offer_fields_and_windows_fingerprint() {
        let mut offer = discover(mac("3C:37:86:00:00:01"), 7);
        offer[0] = 2;
        offer[16..20].copy_from_slice(&[192, 168, 1, 50]);
        offer.truncate(240);
        offer.extend_from_slice(&[53, 1, OFFER, 54, 4, 192, 168, 1, 1, 3, 4, 192, 168, 1, 1]);
        offer.extend_from_slice(&[6, 8, 192, 168, 1, 1, 8, 8, 8, 8, 255]);
        let o = parse(&offer).unwrap();
        assert_eq!(o.msg_type(), Some(OFFER));
        assert_eq!(o.server_id(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(o.dns(), vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]);
        assert_eq!(o.yiaddr, Ipv4Addr::new(192, 168, 1, 50));
        assert!(o.fingerprint().is_none(), "servers have no client fingerprint");

        let mut req = discover(mac("3C:37:86:00:00:02"), 8);
        req.truncate(240);
        req.extend_from_slice(&[53, 1, REQUEST, 60, 8]);
        req.extend_from_slice(b"MSFT 5.0");
        req.extend_from_slice(&[12, 7]);
        req.extend_from_slice(b"DESKTOP");
        req.extend_from_slice(&[55, 14, 1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252, 255]);
        let fp = parse(&req).unwrap().fingerprint().unwrap();
        assert_eq!(fp.vendor_class.as_deref(), Some("MSFT 5.0"));
        assert_eq!(fp.hostname.as_deref(), Some("DESKTOP"));
        assert_eq!(fp.prl_text(), "1,3,6,15,31,33,43,44,46,47,119,121,249,252");
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(parse(&[0; 100]).is_none());
        let mut bad = discover(mac("3C:37:86:00:00:01"), 1);
        bad.truncate(242);
        bad[240] = 12;
        bad[241] = 50; // option runs past the end
        assert!(parse(&bad).is_none());
    }
}
