//! Bluetooth scanning.
//!
//! | OS      | LE advertisements                         | Classic inquiry / connected devices                     |
//! |---------|-------------------------------------------|---------------------------------------------------------|
//! | Windows | WinRT `BluetoothLEAdvertisementWatcher`   | Win32 `BluetoothFindFirstDevice`, WinRT device enumeration |
//! | Linux   | BlueZ, milestone M6 (reports unsupported) | BlueZ, milestone M6                                     |
//!
//! Advertisements arrive as raw AD structures. Decoding happens in `na-engine`.

use std::sync::Arc;
use std::time::Duration;

use na_model::MacAddr;

#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
mod unsupported;

/// Address type as the radio reports it. Random subtypes are derived from the address bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    Public,
    Random,
    Unknown,
}

/// One AD structure: `[type][data]` (the length byte is implied by `data`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdSection {
    pub ad_type: u8,
    pub data: Vec<u8>,
}

/// One received advertising or scan-response PDU.
#[derive(Clone, Debug)]
pub struct RawAdvert {
    pub address: MacAddr,
    pub address_kind: AddressKind,
    pub rssi_dbm: i16,
    /// From the TX Power AD or the extended-advertising header.
    pub tx_power_dbm: Option<i16>,
    pub connectable: bool,
    pub scan_response: bool,
    pub sections: Vec<AdSection>,
    /// Unix ms.
    pub received_at_ms: u64,
}

pub enum LeEvent {
    Advert(RawAdvert),
    /// The OS stopped the scan, e.g. because the radio was turned off.
    Stopped(BtError),
}

pub type LeCallback = Arc<dyn Fn(LeEvent) + Send + Sync + 'static>;

/// A paired LE device that is connected to this host. Connected peripherals usually stop advertising.
#[derive(Clone, Debug)]
pub struct ConnectedLe {
    pub address: MacAddr,
    pub address_kind: AddressKind,
    pub name: Option<String>,
    pub appearance: Option<u16>,
}

/// A Bluetooth Classic device known to, connected to, or discovered by this host.
#[derive(Clone, Debug)]
pub struct ClassicDevice {
    pub address: MacAddr,
    pub name: Option<String>,
    pub class_of_device: u32,
    pub connected: bool,
    /// Paired / remembered by the OS.
    pub remembered: bool,
    pub authenticated: bool,
    /// When the OS last heard from it (Unix ms).
    pub last_seen_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub struct AdapterInfo {
    pub low_energy: bool,
    pub classic: bool,
    pub radio_on: bool,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum BtError {
    #[error("no Bluetooth adapter found")]
    NoAdapter,
    #[error("Bluetooth is turned off")]
    RadioOff,
    /// Present but unusable right now (in use, blocked by policy, needs consent…).
    #[error("{0}")]
    Unavailable(String),
    #[error("Bluetooth scanning is not supported here: {0}")]
    Unsupported(String),
    #[error("{context} failed (OS error {code:#010x})")]
    Os { code: i32, context: &'static str },
}

/// Receives LE advertisements in the background until stopped or dropped.
pub trait LeScanner {
    /// Start scanning. `on_event` runs on an OS thread for every advert.
    fn start(&mut self, on_event: LeCallback) -> Result<(), BtError>;
    fn stop(&mut self);
}

/// Default adapter's capabilities and radio state.
pub fn adapter_info() -> Result<AdapterInfo, BtError> {
    #[cfg(windows)]
    {
        windows::adapter_info()
    }
    #[cfg(not(windows))]
    {
        unsupported::err()
    }
}

/// How aggressively to scan. Most laptops share one antenna between Wi-Fi and
/// Bluetooth, so a full-duty scan costs Wi-Fi airtime.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ScanDuty {
    /// The OS default: a low duty cycle that coexists with Wi-Fi.
    #[default]
    Balanced,
    /// Scan (nearly) continuously: many more adverts per device, at Wi-Fi's expense.
    LowLatency,
}

pub fn open_le_scanner(duty: ScanDuty) -> Result<Box<dyn LeScanner>, BtError> {
    #[cfg(windows)]
    {
        Ok(Box::new(windows::WinLeScanner::open(duty)?))
    }
    #[cfg(not(windows))]
    {
        let _ = duty;
        unsupported::err()
    }
}

/// Paired LE devices currently connected to this host.
pub fn connected_le_devices() -> Result<Vec<ConnectedLe>, BtError> {
    #[cfg(windows)]
    {
        windows::connected_le_devices()
    }
    #[cfg(not(windows))]
    {
        unsupported::err()
    }
}

/// Classic devices the OS knows about. With `inquiry`, first runs a discovery
/// inquiry for about that long (blocking), which finds discoverable devices nearby.
pub fn classic_devices(inquiry: Option<Duration>) -> Result<Vec<ClassicDevice>, BtError> {
    #[cfg(windows)]
    {
        windows::classic_devices(inquiry)
    }
    #[cfg(not(windows))]
    {
        let _ = inquiry;
        unsupported::err()
    }
}
