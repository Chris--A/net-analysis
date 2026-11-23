use serde::{Deserialize, Serialize};

/// Where a piece of identification evidence came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceSource {
    /// MAC vendor prefix lookup.
    Oui,
    /// WPS information element in a beacon.
    Wps,
    /// Other 802.11 information elements (vendor IEs, capabilities).
    Ie,
    Mdns,
    Ssdp,
    NetBios,
    /// Port or service banner probe.
    Banner,
    BleAdv,
    /// Bluetooth Classic Class of Device.
    BtClass,
    /// What the OS learned about a paired/connected Bluetooth device (GATT name, appearance).
    BtPaired,
    Dhcp,
    TcpFingerprint,
    /// Cross-source inference, e.g. BSSID ± 1 matching a LAN MAC.
    Heuristic,
}

impl EvidenceSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Oui => "OUI",
            Self::Wps => "WPS IE",
            Self::Ie => "802.11 IE",
            Self::Mdns => "mDNS",
            Self::Ssdp => "SSDP/UPnP",
            Self::NetBios => "NetBIOS",
            Self::Banner => "Banner",
            Self::BleAdv => "BLE adv",
            Self::BtClass => "BT class",
            Self::BtPaired => "BT paired",
            Self::Dhcp => "DHCP",
            Self::TcpFingerprint => "TCP fp",
            Self::Heuristic => "Heuristic",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ClaimKind {
    Name,
    Vendor,
    DeviceType,
    Model,
    Os,
}

impl ClaimKind {
    pub const ALL: [ClaimKind; 5] = [
        ClaimKind::Name,
        ClaimKind::Vendor,
        ClaimKind::DeviceType,
        ClaimKind::Model,
        ClaimKind::Os,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Vendor => "Vendor",
            Self::DeviceType => "Type",
            Self::Model => "Model",
            Self::Os => "OS",
        }
    }
}

/// One observation-backed claim, e.g. "WPS IE says Model = RAX50 (0.9)".
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub source: EvidenceSource,
    pub kind: ClaimKind,
    pub value: String,
    /// 0.0 to 1.0: how much this one observation supports the claim.
    pub confidence: f32,
    /// Human-readable provenance shown in the inspector.
    pub detail: String,
}

impl Evidence {
    pub fn new(
        source: EvidenceSource,
        kind: ClaimKind,
        value: impl Into<String>,
        confidence: f32,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            source,
            kind,
            value: value.into(),
            confidence: confidence.clamp(0.0, 1.0),
            detail: detail.into(),
        }
    }
}

/// The winning value for one claim kind after combining all evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub value: String,
    pub confidence: f32,
    pub sources: Vec<EvidenceSource>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    pub name: Option<Claim>,
    pub vendor: Option<Claim>,
    pub device_type: Option<Claim>,
    pub model: Option<Claim>,
    pub os: Option<Claim>,
}

impl Identity {
    pub fn get(&self, kind: ClaimKind) -> Option<&Claim> {
        match kind {
            ClaimKind::Name => self.name.as_ref(),
            ClaimKind::Vendor => self.vendor.as_ref(),
            ClaimKind::DeviceType => self.device_type.as_ref(),
            ClaimKind::Model => self.model.as_ref(),
            ClaimKind::Os => self.os.as_ref(),
        }
    }

    pub fn set(&mut self, kind: ClaimKind, claim: Option<Claim>) {
        match kind {
            ClaimKind::Name => self.name = claim,
            ClaimKind::Vendor => self.vendor = claim,
            ClaimKind::DeviceType => self.device_type = claim,
            ClaimKind::Model => self.model = claim,
            ClaimKind::Os => self.os = claim,
        }
    }

    /// Short "Vendor Model (Type)" string for lists.
    pub fn summary(&self) -> Option<String> {
        let parts: Vec<&str> = [&self.vendor, &self.model]
            .into_iter()
            .flatten()
            .map(|c| c.value.as_str())
            .collect();
        let mut s = parts.join(" ");
        if let Some(t) = &self.device_type {
            if s.is_empty() {
                s = t.value.clone();
            } else {
                s = format!("{s} ({})", t.value);
            }
        }
        (!s.is_empty()).then_some(s)
    }
}
