//! DNS wire format, just enough for mDNS / DNS-SD discovery (RFC 1035, 6762, 6763).
//!
//! Names are kept as label lists, because DNS-SD instance names may themselves contain dots.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_ANY: u16 = 255;

/// A domain name as its labels, e.g. `["Living Room TV", "_googlecast", "_tcp", "local"]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name(pub Vec<String>);

impl Name {
    pub fn parse(dotted: &str) -> Self {
        Self(dotted.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).map(str::to_owned).collect())
    }

    /// `(instance, "_type._proto")` for a DNS-SD instance name `<instance>._type._proto.local`.
    pub fn service_instance(&self) -> Option<(String, String)> {
        let l = &self.0;
        let n = l.len();
        (n >= 4 && is_service_type(&l[n - 3..])).then(|| (l[..n - 3].join("."), format!("{}.{}", l[n - 3], l[n - 2])))
    }

    /// `"_type._proto"` if this name is a bare service type `_type._proto.local`.
    pub fn service_type(&self) -> Option<String> {
        let l = &self.0;
        (l.len() == 3 && is_service_type(l)).then(|| format!("{}.{}", l[0], l[1]))
    }

    /// Host label without `.local`, e.g. `Chromecast-1a2b`.
    pub fn host(&self) -> Option<&str> {
        match self.0.as_slice() {
            [host, local] if local.eq_ignore_ascii_case("local") => Some(host),
            _ => None,
        }
    }

    pub fn eq_ignore_case(&self, dotted: &str) -> bool {
        let other = Name::parse(dotted);
        self.0.len() == other.0.len() && self.0.iter().zip(&other.0).all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.join("."))
    }
}

/// `["_googlecast", "_tcp", "local"]`
fn is_service_type(l: &[String]) -> bool {
    l.len() == 3
        && l[0].starts_with('_')
        && (l[1].eq_ignore_ascii_case("_tcp") || l[1].eq_ignore_ascii_case("_udp"))
        && l[2].eq_ignore_ascii_case("local")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(Name),
    Srv { port: u16, target: Name },
    Txt(Vec<String>),
    Other(u16),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub data: RData,
}

/// Build a query. `unicast_response` sets the mDNS QU bit.
pub fn query(questions: &[(&str, u16)], unicast_response: bool) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0];
    out.extend((questions.len() as u16).to_be_bytes());
    out.extend([0, 0, 0, 0, 0, 0]);
    for (name, qtype) in questions {
        for label in Name::parse(name).0 {
            let b = label.as_bytes();
            out.push(b.len().min(63) as u8);
            out.extend(&b[..b.len().min(63)]);
        }
        out.push(0);
        out.extend(qtype.to_be_bytes());
        let class: u16 = if unicast_response { 0x8001 } else { 0x0001 };
        out.extend(class.to_be_bytes());
    }
    out
}

/// All resource records (answer, authority and additional sections) in a response.
/// Returns None for queries and malformed packets.
pub fn parse(msg: &[u8]) -> Option<Vec<Record>> {
    let u16_at = |i: usize| msg.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let flags = u16_at(2)?;
    if flags & 0x8000 == 0 {
        return None; // a query, not a response
    }
    let qd = u16_at(4)?;
    let rr = usize::from(u16_at(6)?) + usize::from(u16_at(8)?) + usize::from(u16_at(10)?);
    let mut pos = 12;
    for _ in 0..qd {
        let (_, next) = read_name(msg, pos)?;
        pos = next + 4;
    }
    let mut out = Vec::with_capacity(rr);
    for _ in 0..rr {
        let (name, next) = read_name(msg, pos)?;
        let rtype = u16_at(next)?;
        let len = usize::from(u16_at(next + 8)?);
        let start = next + 10;
        let rdata = msg.get(start..start + len)?;
        let data = match rtype {
            TYPE_A if len == 4 => RData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            TYPE_AAAA if len == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(rdata);
                RData::Aaaa(Ipv6Addr::from(a))
            }
            TYPE_PTR => RData::Ptr(read_name(msg, start)?.0),
            TYPE_SRV if len >= 7 => RData::Srv {
                port: u16::from_be_bytes([rdata[4], rdata[5]]),
                target: read_name(msg, start + 6)?.0,
            },
            TYPE_TXT => RData::Txt(read_txt(rdata)),
            other => RData::Other(other),
        };
        out.push(Record { name, data });
        pos = start + len;
    }
    Some(out)
}

/// Read a (possibly compressed) name at `pos`. Returns the name and the offset just past it.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(Name, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    for _ in 0..128 {
        let len = *msg.get(pos)?;
        match len {
            0 => return Some((Name(labels), end.unwrap_or(pos + 1))),
            l if l & 0xC0 == 0xC0 => {
                let ptr = usize::from(u16::from_be_bytes([l & 0x3F, *msg.get(pos + 1)?]));
                end.get_or_insert(pos + 2);
                if ptr >= pos {
                    return None; // pointers must go backwards
                }
                pos = ptr;
            }
            l if l < 64 => {
                let label = msg.get(pos + 1..pos + 1 + usize::from(l))?;
                labels.push(String::from_utf8_lossy(label).into_owned());
                pos += 1 + usize::from(l);
            }
            _ => return None,
        }
    }
    None // pointer loop
}

fn read_txt(mut rdata: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    while let Some((&len, rest)) = rdata.split_first() {
        let len = usize::from(len).min(rest.len());
        let (s, next) = rest.split_at(len);
        if !s.is_empty() {
            out.push(String::from_utf8_lossy(s).into_owned());
        }
        rdata = next;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a response by hand: header, then records using a compression pointer.
    fn chromecast_reply() -> Vec<u8> {
        let mut m = vec![0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 3];
        // Answer: _googlecast._tcp.local PTR "Living Room TV._googlecast._tcp.local"
        let type_name_at = m.len();
        for l in ["_googlecast", "_tcp", "local"] {
            m.push(l.len() as u8);
            m.extend(l.as_bytes());
        }
        m.push(0);
        m.extend([0, 12, 0, 1, 0, 0, 0, 120]);
        let inst = b"Living Room TV";
        m.extend(((inst.len() + 1 + 2) as u16).to_be_bytes());
        let inst_at = m.len();
        m.push(inst.len() as u8);
        m.extend(inst);
        m.extend([0xC0, type_name_at as u8]);
        // Additional: SRV <instance> port 8009 target Chromecast-1a2b.local
        m.extend([0xC0, inst_at as u8, 0, 33, 0x80, 1, 0, 0, 0, 120]);
        let host = b"Chromecast-1a2b";
        m.extend(((6 + 1 + host.len() + 1 + 5 + 1) as u16).to_be_bytes());
        m.extend([0, 0, 0, 0, 0x1F, 0x49]);
        let host_at = m.len();
        m.push(host.len() as u8);
        m.extend(host);
        m.push(5);
        m.extend(b"local");
        m.push(0);
        // Additional: TXT md=Chromecast fn=Living Room TV
        m.extend([0xC0, inst_at as u8, 0, 16, 0x80, 1, 0, 0, 0, 120]);
        let txt: Vec<&[u8]> = vec![b"md=Chromecast", b"fn=Living Room TV"];
        let txt_len: usize = txt.iter().map(|t| t.len() + 1).sum();
        m.extend((txt_len as u16).to_be_bytes());
        for t in txt {
            m.push(t.len() as u8);
            m.extend(t);
        }
        // Additional: A for the host
        m.extend([0xC0, host_at as u8, 0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 31]);
        m
    }

    #[test]
    fn parses_compressed_dns_sd_reply() {
        let recs = parse(&chromecast_reply()).expect("valid");
        assert_eq!(recs.len(), 4);
        let RData::Ptr(inst) = &recs[0].data else { panic!() };
        assert_eq!(inst.service_instance(), Some(("Living Room TV".into(), "_googlecast._tcp".into())));
        assert_eq!(recs[0].name.service_type().as_deref(), Some("_googlecast._tcp"));
        let RData::Srv { port, target } = &recs[1].data else { panic!() };
        assert_eq!(*port, 8009);
        assert_eq!(target.host(), Some("Chromecast-1a2b"));
        assert_eq!(recs[2].data, RData::Txt(vec!["md=Chromecast".into(), "fn=Living Room TV".into()]));
        assert_eq!(recs[3].data, RData::A(Ipv4Addr::new(192, 168, 1, 31)));
    }

    #[test]
    fn rejects_queries_loops_and_truncation() {
        let q = query(&[("_services._dns-sd._udp.local", TYPE_PTR)], true);
        assert_eq!(parse(&q), None, "queries are not responses");
        assert_eq!(&q[q.len() - 4..], &[0, 12, 0x80, 0x01], "PTR with the QU bit");
        let mut looped = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        looped.extend([0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        assert_eq!(parse(&looped), None, "self-referencing pointer");
        let reply = chromecast_reply();
        assert_eq!(parse(&reply[..reply.len() - 3]), None);
    }

    #[test]
    fn names() {
        let n = Name::parse("Office Printer._ipp._tcp.local.");
        assert_eq!(n.service_instance(), Some(("Office Printer".into(), "_ipp._tcp".into())));
        assert_eq!(n.service_type(), None);
        assert!(Name::parse("_IPP._TCP.local").eq_ignore_case("_ipp._tcp.local"));
        assert_eq!(Name::parse("nas.local").host(), Some("nas"));
    }
}
