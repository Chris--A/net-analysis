use serde::{Deserialize, Serialize};

use crate::MacAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Band {
    G2_4,
    G5,
    G6,
}

impl Band {
    pub fn label(self) -> &'static str {
        match self {
            Band::G2_4 => "2.4 GHz",
            Band::G5 => "5 GHz",
            Band::G6 => "6 GHz",
        }
    }
}

/// Authentication and key management suites from the RSN IE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Akm {
    /// No RSN IE: an open network.
    Open,
    /// Privacy bit set but no RSN/WPA IE: legacy WEP.
    Wep,
    /// Pre-RSN WPA (vendor IE, usually TKIP).
    Wpa1,
    /// Opportunistic Wireless Encryption ("Enhanced Open").
    Owe,
    Psk,
    Sae,
    Eap,
    EapSuiteB,
    Other(u32),
}

impl Akm {
    pub fn label(self) -> &'static str {
        match self {
            Akm::Open => "Open",
            Akm::Wep => "WEP",
            Akm::Wpa1 => "WPA (legacy)",
            Akm::Owe => "OWE",
            Akm::Psk => "WPA2-PSK",
            Akm::Sae => "WPA3-SAE",
            Akm::Eap => "WPA2/3-Enterprise",
            Akm::EapSuiteB => "WPA3-Enterprise 192",
            Akm::Other(_) => "Other",
        }
    }

    /// Rough ordering used for downgrade detection.
    fn strength(self) -> u8 {
        match self {
            Akm::Open | Akm::Wep | Akm::Other(_) => 0,
            Akm::Wpa1 | Akm::Owe => 1,
            Akm::Psk => 2,
            Akm::Sae => 3,
            Akm::Eap => 4,
            Akm::EapSuiteB => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Cipher {
    Wep,
    Tkip,
    Ccmp128,
    Ccmp256,
    Gcmp128,
    Gcmp256,
    Other(u32),
}

/// Protected Management Frames (802.11w) — blocks trivial deauth attacks. Ordered weakest first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Pmf {
    #[default]
    Disabled,
    Capable,
    Required,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Security {
    pub akms: Vec<Akm>,
    pub pairwise: Vec<Cipher>,
    pub group: Option<Cipher>,
    pub pmf: Pmf,
}

impl Security {
    pub fn open() -> Self {
        Self::default()
    }

    pub fn is_open(&self) -> bool {
        self.akms.iter().all(|a| matches!(a, Akm::Open))
    }

    /// The *weakest* AKM a client could be steered onto. A WPA3/WPA2
    /// transition network therefore ranks as WPA2.
    pub fn floor_strength(&self) -> u8 {
        self.akms.iter().map(|a| a.strength()).min().unwrap_or(0)
    }

    pub fn label(&self) -> String {
        if self.is_open() {
            return "Open".into();
        }
        let mut names: Vec<&str> = self.akms.iter().map(|a| a.label()).collect();
        names.dedup();
        names.join(" / ")
    }
}

/// Fields from the WPS information element. Routers often broadcast their exact model here.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WpsInfo {
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub device_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApInfo {
    /// Empty for hidden networks.
    pub ssid: String,
    pub bssid: MacAddr,
    pub channel: u16,
    pub band: Band,
    pub width_mhz: u16,
    pub security: Security,
    /// 4 = HT (n), 5 = VHT (ac), 6 = HE (ax), 7 = EHT (be).
    pub wifi_gen: Option<u8>,
    pub beacon_interval_tu: u16,
    /// Derived from the beacon TSF timer: how long the AP radio has been up.
    pub tsf_uptime_secs: Option<u64>,
    pub wps: Option<WpsInfo>,
    /// Hash over the stable parts of the IE set, used to compare APs claiming the same SSID.
    pub ie_fingerprint: u64,
    /// This host is currently associated with this BSSID.
    pub connected: bool,
    /// Associated clients, from the BSS Load element.
    pub station_count: Option<u16>,
    /// Channel busy fraction, 0 to 255, from the BSS Load element.
    pub channel_utilization: Option<u8>,
    /// Country element (two-letter code).
    pub country: Option<String>,
    /// Vendor-specific IEs present, as OUI + vendor type.
    pub vendor_ies: Vec<[u8; 4]>,
    /// The information elements as last received, for the inspector.
    pub raw_ies: Vec<u8>,
}

impl ApInfo {
    pub fn display_ssid(&self) -> &str {
        if self.ssid.is_empty() { "<hidden>" } else { &self.ssid }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_network_floor_is_wpa2() {
        let s = Security {
            akms: vec![Akm::Sae, Akm::Psk],
            pmf: Pmf::Capable,
            ..Default::default()
        };
        assert_eq!(s.floor_strength(), Akm::Psk.strength());
        assert_eq!(s.label(), "WPA3-SAE / WPA2-PSK");
        assert!(!s.is_open());
    }

    #[test]
    fn open_network() {
        let s = Security::open();
        assert!(s.is_open());
        assert_eq!(s.floor_strength(), 0);
        assert_eq!(s.label(), "Open");
    }
}
