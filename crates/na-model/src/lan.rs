use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::MacAddr;

/// A host on the local network, merged from ARP, mDNS, SSDP, NetBIOS and probes.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LanInfo {
    pub mac: Option<MacAddr>,
    pub ips: Vec<IpAddr>,
    pub hostname: Option<String>,
    pub open_ports: Vec<u16>,
    /// DNS-SD service types, e.g. `_googlecast._tcp`.
    pub services: Vec<String>,
    pub is_gateway: bool,
    /// This machine.
    pub is_self: bool,
}

impl LanInfo {
    /// Union `other` into `self`. Later sources fill gaps but never erase data.
    pub fn merge(&mut self, other: &LanInfo) {
        if other.mac.is_some() {
            self.mac = other.mac;
        }
        if other.hostname.is_some() {
            self.hostname.clone_from(&other.hostname);
        }
        for ip in &other.ips {
            if !self.ips.contains(ip) {
                self.ips.push(*ip);
            }
        }
        for p in &other.open_ports {
            if !self.open_ports.contains(p) {
                self.open_ports.push(*p);
            }
        }
        self.open_ports.sort_unstable();
        for s in &other.services {
            if !self.services.contains(s) {
                self.services.push(s.clone());
            }
        }
        self.is_gateway |= other.is_gateway;
        self.is_self |= other.is_self;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_unions_without_erasing() {
        let mut a = LanInfo {
            ips: vec!["192.168.1.10".parse().unwrap()],
            open_ports: vec![445, 22],
            hostname: Some("nas".into()),
            ..Default::default()
        };
        let b = LanInfo {
            ips: vec!["192.168.1.10".parse().unwrap()],
            open_ports: vec![80, 22],
            services: vec!["_smb._tcp".into()],
            ..Default::default()
        };
        a.merge(&b);
        assert_eq!(a.ips.len(), 1);
        assert_eq!(a.open_ports, vec![22, 80, 445]);
        assert_eq!(a.hostname.as_deref(), Some("nas"));
        assert_eq!(a.services, vec!["_smb._tcp".to_string()]);
    }
}
