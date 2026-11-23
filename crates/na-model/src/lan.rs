use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::MacAddr;

/// One DNS-SD service instance a host advertises over mDNS.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdnsService {
    /// Instance name, e.g. "Living Room TV".
    pub instance: String,
    /// Service type, e.g. `_googlecast._tcp`.
    pub service: String,
    pub port: Option<u16>,
    /// TXT record entries (`key=value`).
    pub txt: Vec<String>,
}

impl MdnsService {
    pub fn txt_value(&self, key: &str) -> Option<&str> {
        self.txt.iter().find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            k.eq_ignore_ascii_case(key).then_some(v)
        })
    }
}

/// UPnP root-device description (from SSDP + the description XML).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpnpInfo {
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub model_description: Option<String>,
    /// e.g. `urn:schemas-upnp-org:device:InternetGatewayDevice:1`.
    pub device_type: Option<String>,
    /// SSDP `SERVER` header, e.g. `Linux/5.4 UPnP/1.0 Sonos/80.1`.
    pub server: Option<String>,
    /// Device and service types advertised in SSDP replies (`ST`).
    pub advertised: Vec<String>,
}

/// NetBIOS node status (NBSTAT) reply.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetbiosInfo {
    pub name: Option<String>,
    /// Workgroup or domain.
    pub group: Option<String>,
    /// Runs the file-server service (`<20>`).
    pub file_server: bool,
}

/// First line of a TCP service's greeting, or an HTTP `Server` header / page title.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Banner {
    pub port: u16,
    pub text: String,
}

/// A host on the local network, merged from ARP, mDNS, SSDP, NetBIOS and probes.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LanInfo {
    pub mac: Option<MacAddr>,
    pub ips: Vec<IpAddr>,
    pub hostname: Option<String>,
    pub open_ports: Vec<u16>,
    /// DNS-SD service types, e.g. `_googlecast._tcp`.
    pub services: Vec<String>,
    pub mdns: Vec<MdnsService>,
    pub upnp: Option<UpnpInfo>,
    pub netbios: Option<NetbiosInfo>,
    pub banners: Vec<Banner>,
    /// Local interface the host was seen on, e.g. "Wi-Fi".
    pub interface: Option<String>,
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
        if other.interface.is_some() {
            self.interface.clone_from(&other.interface);
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
        for m in &other.mdns {
            match self.mdns.iter_mut().find(|x| x.instance == m.instance && x.service == m.service) {
                Some(x) => *x = m.clone(),
                None => self.mdns.push(m.clone()),
            }
        }
        for b in &other.banners {
            match self.banners.iter_mut().find(|x| x.port == b.port) {
                Some(x) => *x = b.clone(),
                None => self.banners.push(b.clone()),
            }
        }
        if other.upnp.is_some() {
            self.upnp.clone_from(&other.upnp);
        }
        if other.netbios.is_some() {
            self.netbios.clone_from(&other.netbios);
        }
        self.is_gateway |= other.is_gateway;
        self.is_self |= other.is_self;
    }

    /// First TXT value for `key` across all mDNS services.
    pub fn txt(&self, key: &str) -> Option<&str> {
        self.mdns.iter().find_map(|m| m.txt_value(key))
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
            netbios: Some(NetbiosInfo { name: Some("NAS".into()), ..Default::default() }),
            ..Default::default()
        };
        let b = LanInfo {
            ips: vec!["192.168.1.10".parse().unwrap()],
            open_ports: vec![80, 22],
            services: vec!["_smb._tcp".into()],
            mdns: vec![MdnsService {
                instance: "nas".into(),
                service: "_smb._tcp".into(),
                port: Some(445),
                txt: vec!["model=DS920+".into()],
            }],
            banners: vec![Banner { port: 22, text: "SSH-2.0-OpenSSH_8.2".into() }],
            ..Default::default()
        };
        a.merge(&b);
        assert_eq!(a.ips.len(), 1);
        assert_eq!(a.open_ports, vec![22, 80, 445]);
        assert_eq!(a.hostname.as_deref(), Some("nas"));
        assert_eq!(a.services, vec!["_smb._tcp".to_string()]);
        assert!(a.netbios.is_some(), "a later update without NetBIOS doesn't erase it");
        assert_eq!(a.txt("MODEL"), Some("DS920+"));
        a.merge(&b);
        assert_eq!(a.mdns.len(), 1);
        assert_eq!(a.banners.len(), 1);
    }
}
