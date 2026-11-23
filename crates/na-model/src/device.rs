use std::collections::VecDeque;
use std::fmt;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{ApInfo, BleInfo, BtClassicInfo, Evidence, Identity, LanInfo, MacAddr, stable_hash};

/// Milliseconds since the Unix epoch.
pub type Millis = u64;

pub fn now_millis() -> Millis {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as Millis)
        .unwrap_or(0)
}

pub const RSSI_HISTORY_LEN: usize = 120;

/// Stable identifier derived from the device's primary key, so the same
/// device keeps its ID (and its 3D position) across restarts.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId(pub u64);

impl DeviceId {
    pub fn for_key(key: &DeviceKey) -> Self {
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(key.tag().as_bytes());
        match key {
            DeviceKey::Bssid(m)
            | DeviceKey::WifiClient(m)
            | DeviceKey::Ble(m)
            | DeviceKey::BtClassic(m)
            | DeviceKey::LanMac(m) => bytes.extend_from_slice(&m.0),
            DeviceKey::LanIp(ip) => bytes.extend_from_slice(ip.to_string().as_bytes()),
        }
        Self(stable_hash(&bytes))
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({self})")
    }
}

/// The identifier a source uses to say which device it saw.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeviceKey {
    Bssid(MacAddr),
    WifiClient(MacAddr),
    Ble(MacAddr),
    BtClassic(MacAddr),
    LanMac(MacAddr),
    /// LAN host seen without a MAC (e.g. off-subnet or before ARP resolves).
    LanIp(IpAddr),
}

impl DeviceKey {
    fn tag(&self) -> &'static str {
        match self {
            Self::Bssid(_) => "ap",
            Self::WifiClient(_) => "sta",
            Self::Ble(_) => "ble",
            Self::BtClassic(_) => "bt",
            Self::LanMac(_) => "lan",
            Self::LanIp(_) => "lanip",
        }
    }

    pub fn kind(&self) -> DeviceKind {
        match self {
            Self::Bssid(_) => DeviceKind::AccessPoint,
            Self::WifiClient(_) => DeviceKind::WifiClient,
            Self::Ble(_) => DeviceKind::Ble,
            Self::BtClassic(_) => DeviceKind::BtClassic,
            Self::LanMac(_) | Self::LanIp(_) => DeviceKind::LanHost,
        }
    }
}

impl fmt::Display for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bssid(m)
            | Self::WifiClient(m)
            | Self::Ble(m)
            | Self::BtClassic(m)
            | Self::LanMac(m) => write!(f, "{m}"),
            Self::LanIp(ip) => write!(f, "{ip}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DeviceKind {
    AccessPoint,
    WifiClient,
    Ble,
    BtClassic,
    LanHost,
}

impl DeviceKind {
    pub const ALL: [DeviceKind; 5] = [
        DeviceKind::AccessPoint,
        DeviceKind::WifiClient,
        DeviceKind::Ble,
        DeviceKind::BtClassic,
        DeviceKind::LanHost,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::AccessPoint => "Wi-Fi AP",
            Self::WifiClient => "Wi-Fi client",
            Self::Ble => "Bluetooth LE",
            Self::BtClassic => "Bluetooth",
            Self::LanHost => "LAN host",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum DeviceDetails {
    #[default]
    None,
    Ap(ApInfo),
    Ble(BleInfo),
    BtClassic(BtClassicInfo),
    Lan(LanInfo),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RssiSample {
    pub at: Millis,
    pub dbm: i16,
}

/// The engine's merged view of one physical (or logical) device.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub key: DeviceKey,
    pub kind: DeviceKind,
    pub first_seen: Millis,
    pub last_seen: Millis,
    /// Smoothed signal strength in dBm (None for wired/LAN-only devices).
    pub rssi: Option<i16>,
    pub rssi_history: VecDeque<RssiSample>,
    pub details: DeviceDetails,
    pub identity: Identity,
    pub evidence: Vec<Evidence>,
    /// 0.0 (benign) to 1.0 (almost certainly hostile), set by the guard detectors.
    pub risk: f32,
    /// The guard's current findings behind `risk`, one sentence each.
    #[serde(default)]
    pub risk_reasons: Vec<String>,
    pub links: Vec<DeviceId>,
}

impl Device {
    pub fn new(key: DeviceKey, at: Millis) -> Self {
        Self {
            id: DeviceId::for_key(&key),
            kind: key.kind(),
            key,
            first_seen: at,
            last_seen: at,
            rssi: None,
            rssi_history: VecDeque::new(),
            details: DeviceDetails::None,
            identity: Identity::default(),
            evidence: Vec::new(),
            risk: 0.0,
            risk_reasons: Vec::new(),
            links: Vec::new(),
        }
    }

    pub fn ap(&self) -> Option<&ApInfo> {
        match &self.details {
            DeviceDetails::Ap(a) => Some(a),
            _ => None,
        }
    }

    pub fn ble(&self) -> Option<&BleInfo> {
        match &self.details {
            DeviceDetails::Ble(b) => Some(b),
            _ => None,
        }
    }

    pub fn bt_classic(&self) -> Option<&BtClassicInfo> {
        match &self.details {
            DeviceDetails::BtClassic(b) => Some(b),
            _ => None,
        }
    }

    pub fn lan(&self) -> Option<&LanInfo> {
        match &self.details {
            DeviceDetails::Lan(l) => Some(l),
            _ => None,
        }
    }

    /// Best human-readable name: identity name, then SSID / BLE name / hostname, then the key.
    pub fn display_name(&self) -> String {
        if let Some(n) = &self.identity.name {
            return n.value.clone();
        }
        let fallback = match &self.details {
            DeviceDetails::Ap(a) => Some(a.display_ssid().to_owned()),
            DeviceDetails::Ble(b) => b.local_name.clone(),
            DeviceDetails::BtClassic(b) => b.name.clone(),
            DeviceDetails::Lan(l) => l
                .hostname
                .clone()
                .or_else(|| l.ips.first().map(|ip| ip.to_string())),
            DeviceDetails::None => None,
        };
        fallback.unwrap_or_else(|| self.key.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_stable_and_kind_scoped() {
        let m: MacAddr = "3C:37:86:12:34:56".parse().unwrap();
        let a = DeviceId::for_key(&DeviceKey::Bssid(m));
        assert_eq!(a, DeviceId::for_key(&DeviceKey::Bssid(m)));
        // Same MAC seen as a BSSID and as a LAN host must stay separate devices.
        assert_ne!(a, DeviceId::for_key(&DeviceKey::LanMac(m)));
    }
}
