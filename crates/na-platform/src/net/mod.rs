//! Local network: interfaces, default gateway, and the OS neighbor (ARP) table.
//!
//! | OS      | Interfaces / gateway / DNS | Neighbor table      |
//! |---------|----------------------------|---------------------|
//! | Windows | `netdev` (GetAdaptersAddresses) | `GetIpNetTable2` |
//! | Linux   | `netdev` (netlink)         | `/proc/net/arp`     |

use std::net::{IpAddr, Ipv4Addr};

use na_model::MacAddr;

#[cfg(windows)]
mod windows;

// Also compiled for tests everywhere, so the /proc parser is checked on Windows too.
#[cfg(any(target_os = "linux", test))]
mod linux;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceKind {
    Wifi,
    Ethernet,
    Other,
}

/// An IPv4 address with its prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Cidr {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Ipv4Cidr {
    pub fn netmask(self) -> u32 {
        if self.prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(self.prefix.min(32))) }
    }

    pub fn contains(self, ip: Ipv4Addr) -> bool {
        let m = self.netmask();
        u32::from(ip) & m == u32::from(self.addr) & m
    }

    pub fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & self.netmask())
    }

    pub fn broadcast(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) | !self.netmask())
    }

    /// Usable host addresses (network and broadcast excluded), in order.
    pub fn hosts(self) -> impl Iterator<Item = Ipv4Addr> {
        let (net, bcast) = (u32::from(self.network()), u32::from(self.broadcast()));
        let range = if self.prefix >= 31 { net..=bcast } else { net + 1..=bcast - 1 };
        range.map(Ipv4Addr::from)
    }
}

/// One local interface that is up and has an IPv4 address.
#[derive(Clone, Debug)]
pub struct LocalInterface {
    pub index: u32,
    /// Human-readable name ("Wi-Fi", "eth0").
    pub name: String,
    pub description: Option<String>,
    pub kind: InterfaceKind,
    pub mac: Option<MacAddr>,
    pub ipv4: Vec<Ipv4Cidr>,
    pub gateway: Option<Ipv4Addr>,
    /// Resolved gateway MAC, when the OS knows it.
    pub gateway_mac: Option<MacAddr>,
    pub dns_servers: Vec<IpAddr>,
    /// Carries the default route.
    pub is_default: bool,
}

/// Interfaces that are up, non-loopback and have IPv4. The default-route interface comes first.
pub fn interfaces() -> Vec<LocalInterface> {
    let mut out: Vec<LocalInterface> = netdev::get_interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback() && !i.ipv4.is_empty())
        .map(|i| {
            let mac = i.mac_addr.map(|m| MacAddr(m.octets())).filter(|m| m.0 != [0; 6]);
            let gw = i.gateway.as_ref();
            LocalInterface {
                index: i.index,
                name: i.friendly_name.clone().unwrap_or_else(|| i.name.clone()),
                description: i.description.clone(),
                kind: match i.if_type {
                    netdev::interface::types::InterfaceType::Wireless80211 => InterfaceKind::Wifi,
                    netdev::interface::types::InterfaceType::Ethernet => InterfaceKind::Ethernet,
                    _ => InterfaceKind::Other,
                },
                mac,
                ipv4: i.ipv4.iter().map(|n| Ipv4Cidr { addr: n.addr(), prefix: n.prefix_len() }).collect(),
                gateway: gw.and_then(|g| g.ipv4.first().copied()),
                gateway_mac: gw.map(|g| MacAddr(g.mac_addr.octets())).filter(|m| m.0 != [0; 6]),
                dns_servers: i.dns_servers.clone(),
                is_default: i.default,
            }
        })
        .collect();
    out.sort_by_key(|i| !i.is_default);
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeighborState {
    /// Confirmed recently (traffic or an ARP reply).
    Reachable,
    /// Resolved earlier but not confirmed lately. The host may have left.
    Stale,
    /// Configured statically.
    Permanent,
}

/// One resolved entry in the OS neighbor (ARP) cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub interface_index: u32,
    pub state: NeighborState,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum NetError {
    #[error("{context} failed (OS error {code})")]
    Os { code: u32, context: &'static str },
    #[error("not supported on this platform")]
    Unsupported,
    #[error("{0}")]
    Io(String),
}

/// Resolved IPv4 neighbors. Multicast, broadcast and incomplete entries are dropped.
pub fn neighbors() -> Result<Vec<Neighbor>, NetError> {
    #[cfg(windows)]
    let raw = windows::neighbors()?;
    #[cfg(target_os = "linux")]
    let raw = linux::neighbors()?;
    #[cfg(not(any(windows, target_os = "linux")))]
    let raw: Vec<Neighbor> = return Err(NetError::Unsupported);
    Ok(raw.into_iter().filter(|n| is_real_neighbor(n.ip, n.mac)).collect())
}

fn is_real_neighbor(ip: Ipv4Addr, mac: MacAddr) -> bool {
    !(ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_loopback()
        || mac.0 == [0; 6]
        || mac.0 == [0xFF; 6]
        || mac.is_multicast())
}

/// This machine's maker and model from firmware (SMBIOS), e.g. ("LENOVO", "IdeaPad Pro 5 16AKP10 (83JN)").
/// Placeholder strings that OEMs leave unfilled are dropped.
pub fn system_model() -> (Option<String>, Option<String>) {
    #[cfg(windows)]
    let [vendor, product, family, version] = {
        const BIOS: &str = r"HARDWARE\DESCRIPTION\System\BIOS";
        ["SystemManufacturer", "SystemProductName", "SystemFamily", "SystemVersion"].map(|v| windows::reg_sz(BIOS, v))
    };
    #[cfg(not(windows))]
    let [vendor, product, family, version] = ["sys_vendor", "product_name", "product_family", "product_version"]
        .map(|f| std::fs::read_to_string(format!("/sys/class/dmi/id/{f}")).ok());
    let [vendor, product, family, version] = [vendor, product, family, version].map(clean_smbios);
    (vendor, pick_model(product, family.or(version)))
}

fn clean_smbios(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_owned()).filter(|v| {
        let l = v.to_ascii_lowercase();
        !(v.is_empty()
            || l.contains("to be filled")
            || l.contains("default string")
            || l.contains("not applicable")
            || l.starts_with("system ")
            || matches!(l.as_str(), "o.e.m." | "none" | "1.0" | "0.1" | "123456789"))
    })
}

/// Some makers (Lenovo) put a type code in the product name and the readable name in family/version.
fn pick_model(product: Option<String>, readable: Option<String>) -> Option<String> {
    let looks_like_code = |p: &str| p.len() <= 6 && !p.contains(' ');
    match (product, readable) {
        (Some(p), Some(r)) if looks_like_code(&p) && r.contains(' ') => Some(format!("{r} ({p})")),
        (Some(p), _) => Some(p),
        (None, r) => r,
    }
}

/// This machine's host name.
pub fn hostname() -> Option<String> {
    #[cfg(windows)]
    let name = std::env::var("COMPUTERNAME").ok();
    #[cfg(not(windows))]
    let name = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok());
    name.map(|n| n.trim().to_owned()).filter(|n| !n.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_math() {
        let c = Ipv4Cidr { addr: "192.168.1.23".parse().unwrap(), prefix: 24 };
        assert_eq!(c.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(c.broadcast(), Ipv4Addr::new(192, 168, 1, 255));
        assert!(c.contains("192.168.1.200".parse().unwrap()));
        assert!(!c.contains("192.168.2.1".parse().unwrap()));
        assert_eq!(c.hosts().count(), 254);
        assert_eq!(c.hosts().next(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        let hotspot = Ipv4Cidr { addr: "10.94.12.7".parse().unwrap(), prefix: 28 };
        assert_eq!(hotspot.hosts().count(), 14);
        assert_eq!(Ipv4Cidr { addr: Ipv4Addr::LOCALHOST, prefix: 0 }.netmask(), 0);
    }

    #[test]
    fn smbios_model_choice() {
        let s = |v: &str| Some(v.to_owned());
        assert_eq!(pick_model(s("83JN"), s("IdeaPad Pro 5 16AKP10")).as_deref(), Some("IdeaPad Pro 5 16AKP10 (83JN)"));
        assert_eq!(pick_model(s("XPS 13 9310"), s("XPS")).as_deref(), Some("XPS 13 9310"));
        assert_eq!(clean_smbios(s("To Be Filled By O.E.M.")), None);
        assert_eq!(clean_smbios(s("System Product Name")), None);
        assert_eq!(clean_smbios(s(" LENOVO ")).as_deref(), Some("LENOVO"));
    }

    #[test]
    fn neighbor_filter() {
        let mac: MacAddr = "3C:37:86:00:00:01".parse().unwrap();
        assert!(is_real_neighbor("192.168.1.1".parse().unwrap(), mac));
        assert!(!is_real_neighbor("224.0.0.251".parse().unwrap(), "01:00:5E:00:00:FB".parse().unwrap()));
        assert!(!is_real_neighbor("192.168.1.9".parse().unwrap(), MacAddr([0; 6])));
        assert!(!is_real_neighbor("255.255.255.255".parse().unwrap(), MacAddr([0xFF; 6])));
    }
}
