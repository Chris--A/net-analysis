use serde::{Deserialize, Serialize};

use crate::{Alert, Device, DeviceDetails, DeviceId, DeviceKey, Evidence, Millis};

/// One sighting of a device by one source. The store merges these into `Device`s.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub key: DeviceKey,
    pub at: Millis,
    pub rssi: Option<i16>,
    /// `DeviceDetails::None` means "seen, but no new details".
    pub details: DeviceDetails,
    pub evidence: Vec<Evidence>,
    /// Other devices this one is known to be related to (e.g. gateway ↔ its APs).
    pub links: Vec<DeviceKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SourceKind {
    Wifi,
    Ble,
    Lan,
    Capture,
    Sim,
}

impl SourceKind {
    pub const ALL: [SourceKind; 5] = [
        SourceKind::Wifi,
        SourceKind::Ble,
        SourceKind::Lan,
        SourceKind::Capture,
        SourceKind::Sim,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Wifi => "Wi-Fi",
            Self::Ble => "Bluetooth",
            Self::Lan => "LAN",
            Self::Capture => "Capture",
            Self::Sim => "Sim",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceState {
    Stopped,
    Running,
    /// Not usable on this machine or build (missing driver, permission, not implemented yet).
    Unavailable(String),
    Failed(String),
}

/// Engine → frontend.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum EngineEvent {
    DeviceUpserted(Box<Device>),
    DeviceRemoved(DeviceId),
    Alert(Alert),
    SourceStatus { source: SourceKind, state: SourceState },
}

/// Frontend → engine.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum EngineCommand {
    SetSourceEnabled { source: SourceKind, enabled: bool },
    /// LAN active probing: subnet sweep and port/banner checks. Off by default;
    /// only for networks you own or are authorized to test.
    SetActiveProbes { enabled: bool },
    Shutdown,
}
