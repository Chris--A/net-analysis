use serde::{Deserialize, Serialize};

use crate::{DeviceId, Millis};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertKind {
    EvilTwin,
    SecurityDowngrade,
    RandomizedBssid,
    TsfAnomaly,
    KarmaAp,
    MultiSsid,
    PmfMissing,
    GatewayChange,
    RogueDhcp,
    ArpSpoof,
    DeauthFlood,
    Other,
}

impl AlertKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::EvilTwin => "Evil twin",
            Self::SecurityDowngrade => "Security downgrade",
            Self::RandomizedBssid => "Randomized BSSID",
            Self::TsfAnomaly => "Uptime anomaly",
            Self::KarmaAp => "Karma/MANA AP",
            Self::MultiSsid => "Many networks, one radio",
            Self::PmfMissing => "No management-frame protection",
            Self::GatewayChange => "Gateway change",
            Self::RogueDhcp => "Rogue DHCP",
            Self::ArpSpoof => "ARP spoofing",
            Self::DeauthFlood => "Deauth flood",
            Self::Other => "Other",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub id: u64,
    pub at: Millis,
    pub severity: Severity,
    pub kind: AlertKind,
    pub devices: Vec<DeviceId>,
    pub title: String,
    /// Plain-language reasoning: why the app raised this alert.
    pub explanation: String,
    /// The individual observations behind it, one sentence each.
    #[serde(default)]
    pub findings: Vec<String>,
}
