//! Guard state shared with the frontend: trusted-network baselines and the
//! Karma test status.

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::{Akm, Band, MacAddr, Millis, Security};

/// Why a network (or one of its access points) is trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustSource {
    /// Imported from the operating system's saved Wi-Fi profiles.
    SavedProfile,
    /// This machine connected with a key (WPA2/WPA3/Enterprise). Only an AP that
    /// knows the key can complete that handshake.
    Connected,
    /// The user chose "Trust".
    User,
}

impl TrustSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::SavedProfile => "saved profile",
            Self::Connected => "connected",
            Self::User => "trusted by you",
        }
    }
}

/// Coarse security class, comparable between saved profiles and beacons.
/// Ordered weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityClass {
    /// No encryption, or WEP.
    Open,
    /// Encrypted but unauthenticated: OWE ("Enhanced Open").
    Owe,
    /// Shared key: WPA/WPA2-PSK, WPA3-SAE.
    Personal,
    /// 802.1X / EAP.
    Enterprise,
}

impl SecurityClass {
    /// The weakest class a client could be steered onto.
    pub fn of(sec: &Security) -> Self {
        sec.akms
            .iter()
            .map(|a| match a {
                Akm::Open | Akm::Wep | Akm::Other(_) => Self::Open,
                Akm::Owe => Self::Owe,
                Akm::Wpa1 | Akm::Psk | Akm::Sae => Self::Personal,
                Akm::Eap | Akm::EapSuiteB => Self::Enterprise,
            })
            .min()
            .unwrap_or(Self::Open)
    }

    /// Connecting proves the AP holds a secret only for these classes.
    pub fn authenticated(self) -> bool {
        matches!(self, Self::Personal | Self::Enterprise)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Owe => "Enhanced Open (OWE)",
            Self::Personal => "password-protected (WPA/WPA2/WPA3 Personal)",
            Self::Enterprise => "Enterprise (802.1X)",
        }
    }
}

/// Security a saved OS profile expects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedSecurity {
    pub class: SecurityClass,
    /// The profile's own name for it, e.g. `WPA2PSK`.
    pub auth: String,
}

/// One access point remembered as a legitimate member of a network.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KnownBss {
    pub bssid: MacAddr,
    pub security: Security,
    /// IE fingerprints seen from it. Beacons and probe responses can differ slightly.
    pub fingerprints: Vec<u64>,
    pub band: Band,
    pub channel: u16,
    pub source: TrustSource,
    pub first_seen: Millis,
    pub last_seen: Millis,
}

/// The LAN side of a trusted network, learned while connected to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayBaseline {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub dns: Vec<IpAddr>,
    /// DHCP server identifiers seen answering on this network.
    pub dhcp_servers: Vec<Ipv4Addr>,
    pub learned: Millis,
}

/// What "normal" looks like for one network name.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkBaseline {
    pub ssid: String,
    pub sources: Vec<TrustSource>,
    /// From a saved profile, when there is one.
    pub expected: Option<ExpectedSecurity>,
    pub known: Vec<KnownBss>,
    #[serde(default)]
    pub gateway: Option<GatewayBaseline>,
    pub created: Millis,
}

impl NetworkBaseline {
    pub fn new(ssid: impl Into<String>, at: Millis) -> Self {
        Self { ssid: ssid.into(), sources: Vec::new(), expected: None, known: Vec::new(), gateway: None, created: at }
    }

    pub fn find(&self, bssid: MacAddr) -> Option<&KnownBss> {
        self.known.iter().find(|k| k.bssid == bssid)
    }

    /// The weakest security a legitimate AP of this network uses. Known access
    /// points win over the profile, because the user vouched for them.
    pub fn expected_class(&self) -> Option<SecurityClass> {
        let known = self.known.iter().map(|k| SecurityClass::of(&k.security)).min();
        known.or(self.expected.as_ref().map(|e| e.class))
    }

    pub fn add_source(&mut self, s: TrustSource) {
        if !self.sources.contains(&s) {
            self.sources.push(s);
            self.sources.sort();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KarmaOutcome {
    /// The probe went out and nothing answered: no Karma AP in range.
    NoResponse,
    /// These BSSIDs answered for a network that doesn't exist.
    Responders(Vec<MacAddr>),
    /// The probe couldn't be sent, so the result proves nothing.
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KarmaResult {
    pub at: Millis,
    /// The random network name that was probed for.
    pub decoy: String,
    pub outcome: KarmaOutcome,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KarmaStatus {
    /// A test is in progress.
    pub running: bool,
    pub last: Option<KarmaResult>,
    /// When the next automatic test is due (None = only on request).
    pub next_at: Option<Millis>,
}

/// One DHCP server that answered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpServerSeen {
    /// Server identifier (option 54), or the source address.
    pub server: Ipv4Addr,
    pub mac: MacAddr,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpCheckResult {
    pub at: Millis,
    pub servers: Vec<DhcpServerSeen>,
    /// The Discover couldn't be sent, so an empty list proves nothing.
    pub error: Option<String>,
}

/// The rogue-DHCP check: one DHCP Discover (never followed by a Request), then
/// count who offers an address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpCheckStatus {
    pub running: bool,
    pub last: Option<DhcpCheckResult>,
    pub next_at: Option<Millis>,
}

/// Snapshot of the guard, sent to the frontend whenever it changes.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GuardStatus {
    /// Sorted by SSID.
    pub networks: Vec<NetworkBaseline>,
    pub karma: KarmaStatus,
    #[serde(default)]
    pub dhcp: DhcpCheckStatus,
    /// The gateway this machine uses right now, as (IP, MAC).
    #[serde(default)]
    pub gateway: Option<(Ipv4Addr, MacAddr)>,
    /// Outcome of importing the OS's saved Wi-Fi profiles, for display.
    pub profile_import: Option<String>,
}

impl GuardStatus {
    pub fn network(&self, ssid: &str) -> Option<&NetworkBaseline> {
        self.networks.iter().find(|n| n.ssid == ssid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Pmf;

    #[test]
    fn class_is_the_weakest_akm() {
        let sec = |akms: &[Akm]| Security { akms: akms.to_vec(), pmf: Pmf::Capable, ..Default::default() };
        assert_eq!(SecurityClass::of(&Security::open()), SecurityClass::Open);
        assert_eq!(SecurityClass::of(&sec(&[Akm::Sae, Akm::Psk])), SecurityClass::Personal);
        assert_eq!(SecurityClass::of(&sec(&[Akm::Eap])), SecurityClass::Enterprise);
        assert_eq!(SecurityClass::of(&sec(&[Akm::Owe])), SecurityClass::Owe);
        assert!(SecurityClass::Open < SecurityClass::Personal);
        assert!(!SecurityClass::Owe.authenticated());
    }

    #[test]
    fn known_aps_override_the_profile() {
        let mut b = NetworkBaseline::new("Home", 0);
        b.expected = Some(ExpectedSecurity { class: SecurityClass::Personal, auth: "WPA2PSK".into() });
        assert_eq!(b.expected_class(), Some(SecurityClass::Personal));
        b.known.push(KnownBss {
            bssid: MacAddr([2, 0, 0, 0, 0, 1]),
            security: Security::open(),
            fingerprints: vec![],
            band: Band::G2_4,
            channel: 6,
            source: TrustSource::User,
            first_seen: 0,
            last_seen: 0,
        });
        assert_eq!(b.expected_class(), Some(SecurityClass::Open));
    }
}
