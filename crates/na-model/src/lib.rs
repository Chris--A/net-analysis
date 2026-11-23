//! Shared, platform-independent data model.
//!
//! Everything that crosses the engine ↔ frontend boundary lives here so the
//! GUI, the CLI and the tests all agree on one vocabulary.

mod alert;
mod ble;
mod device;
mod events;
mod hash;
mod identity;
mod lan;
mod mac;
mod wifi;

pub use alert::{Alert, AlertKind, Severity};
pub use ble::{BleAddressType, BleInfo, BleUuid, BtClassicInfo, ManufacturerData, ParseUuidError, ServiceData};
pub use device::{
    Device, DeviceDetails, DeviceId, DeviceKey, DeviceKind, Millis, RSSI_HISTORY_LEN, RssiSample,
    now_millis,
};
pub use events::{EngineCommand, EngineEvent, Observation, SourceKind, SourceState};
pub use hash::stable_hash;
pub use identity::{Claim, ClaimKind, Evidence, EvidenceSource, Identity};
pub use lan::LanInfo;
pub use mac::{MacAddr, ParseMacError};
pub use wifi::{Akm, ApInfo, Band, Cipher, Pmf, Security, WpsInfo};
