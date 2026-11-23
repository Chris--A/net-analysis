use serde::{Deserialize, Serialize};

use crate::MacAddr;

/// Decoded fields from BLE advertisements and scan responses.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct BleInfo {
    pub address: MacAddr,
    /// Random (resolvable/non-resolvable) addresses rotate every ~15 minutes,
    /// so these devices are treated as ephemeral and never merged on weak evidence.
    pub random_address: bool,
    pub local_name: Option<String>,
    /// Bluetooth SIG company identifier from the manufacturer-specific AD.
    pub company_id: Option<u16>,
    pub manufacturer_data: Vec<u8>,
    /// Service UUIDs as strings (16-bit ones in `0xFE2C` form).
    pub service_uuids: Vec<String>,
    pub tx_power: Option<i8>,
    pub appearance: Option<u16>,
    pub connectable: bool,
}
