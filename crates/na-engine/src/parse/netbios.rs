//! NetBIOS node status (NBSTAT, RFC 1002 §4.2.18): asks a host for its NetBIOS
//! name table. Windows (with NetBIOS over TCP/IP), Samba and many NAS boxes answer.

use na_model::{MacAddr, NetbiosInfo};

/// Wildcard `*` name, first-level encoded (`'*'` = 0x2A → "CK", NUL → "AA").
const WILDCARD: &[u8; 32] = b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

pub fn nbstat_query(id: u16) -> Vec<u8> {
    let mut m = Vec::with_capacity(50);
    m.extend(id.to_be_bytes());
    m.extend([0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    m.push(0x20);
    m.extend(WILDCARD);
    m.push(0);
    m.extend([0x00, 0x21, 0x00, 0x01]); // NBSTAT, IN
    m
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NbName {
    pub name: String,
    pub suffix: u8,
    pub group: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NbstatReply {
    pub names: Vec<NbName>,
    /// Unit ID from the statistics block. Samba reports all zeros.
    pub mac: Option<MacAddr>,
}

pub fn parse_nbstat(msg: &[u8]) -> Option<NbstatReply> {
    if msg.len() < 12 || msg[2] & 0x80 == 0 {
        return None;
    }
    // Answer name: either the full 34-byte encoded name or a compression pointer.
    let mut pos = 12;
    pos += match *msg.get(pos)? {
        0x20 => 34,
        b if b & 0xC0 == 0xC0 => 2,
        _ => return None,
    };
    let rtype = u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]);
    if rtype != 0x21 {
        return None;
    }
    pos += 10; // type, class, ttl, rdlength
    let count = usize::from(*msg.get(pos)?);
    pos += 1;
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        let e = msg.get(pos..pos + 18)?;
        let name = String::from_utf8_lossy(&e[..15]).trim_end_matches([' ', '\0']).to_owned();
        names.push(NbName { name, suffix: e[15], group: e[16] & 0x80 != 0 });
        pos += 18;
    }
    let mac = msg
        .get(pos..pos + 6)
        .map(|b| MacAddr([b[0], b[1], b[2], b[3], b[4], b[5]]))
        .filter(|m| m.0 != [0; 6]);
    Some(NbstatReply { names, mac })
}

impl NbstatReply {
    pub fn summary(&self) -> NetbiosInfo {
        let find = |suffix: u8, group: bool| {
            self.names
                .iter()
                .find(|n| n.suffix == suffix && n.group == group && !n.name.starts_with("__"))
                .map(|n| n.name.clone())
        };
        NetbiosInfo {
            name: find(0x00, false),
            group: find(0x00, true),
            file_server: self.names.iter().any(|n| n.suffix == 0x20 && !n.group),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, suffix: u8, group: bool) -> Vec<u8> {
        let mut e = format!("{name:<15}").into_bytes();
        e.truncate(15);
        e.push(suffix);
        e.extend([if group { 0x84 } else { 0x04 }, 0x00]);
        e
    }

    #[test]
    fn parses_windows_name_table() {
        let mut m = vec![0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0, 0x20];
        m.extend(WILDCARD);
        m.extend([0, 0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0, 0, 0x41, 3]);
        m.extend(entry("DESKTOP-NA01", 0x00, false));
        m.extend(entry("WORKGROUP", 0x00, true));
        m.extend(entry("DESKTOP-NA01", 0x20, false));
        m.extend([0x3C, 0x37, 0x86, 0x00, 0x00, 0x23]);
        m.extend([0u8; 40]);
        let r = parse_nbstat(&m).expect("valid");
        assert_eq!(r.names.len(), 3);
        assert_eq!(r.mac, Some("3C:37:86:00:00:23".parse().unwrap()));
        let s = r.summary();
        assert_eq!(s.name.as_deref(), Some("DESKTOP-NA01"));
        assert_eq!(s.group.as_deref(), Some("WORKGROUP"));
        assert!(s.file_server);
    }

    #[test]
    fn query_shape_and_garbage() {
        let q = nbstat_query(7);
        assert_eq!(q.len(), 50);
        assert_eq!(&q[..2], &[0, 7]);
        assert_eq!(parse_nbstat(&q), None, "a query is not a reply");
        assert_eq!(parse_nbstat(&[0, 0, 0x84]), None);
    }
}
