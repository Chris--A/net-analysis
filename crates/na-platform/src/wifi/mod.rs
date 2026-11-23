//! Wi-Fi scanning.
//!
//! | OS      | Backend                                             |
//! |---------|-----------------------------------------------------|
//! | Windows | Native Wi-Fi API (`wlanapi.dll`)                    |
//! | Linux   | nl80211, milestone M6 (currently reports unsupported) |

use na_model::MacAddr;

#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
mod unsupported;

/// One wireless interface (radio) on this machine.
#[derive(Clone, Debug)]
pub struct WifiInterface {
    /// OS identifier (GUID on Windows, ifname on Linux).
    pub id: String,
    pub description: String,
    pub connected_bssid: Option<MacAddr>,
}

/// One BSS (access point radio) exactly as the OS reports it.
#[derive(Clone, Debug)]
pub struct RawBss {
    pub interface: String,
    /// Raw SSID bytes. They may not be UTF-8, and are empty for hidden networks.
    pub ssid: Vec<u8>,
    pub bssid: MacAddr,
    pub rssi_dbm: i32,
    /// Centre frequency of the primary channel, in kHz.
    pub frequency_khz: u32,
    pub beacon_interval_tu: u16,
    /// 802.11 capability information field.
    pub capability: u16,
    /// TSF timer from the last beacon or probe response, in microseconds since the AP radio started.
    pub tsf_us: u64,
    /// When this host last received a frame from the BSS (Unix ms). The OS cache
    /// keeps entries for a while after an AP goes away, so use this, not "now".
    pub received_at_ms: Option<u64>,
    /// Information elements from the last beacon or probe response.
    pub ies: Vec<u8>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum WifiError {
    /// The OS refused access. On Windows 11 24H2+ this means Location permission is off.
    #[error("{0}")]
    PermissionDenied(String),
    #[error("no wireless interface found")]
    NoInterface,
    #[error("Wi-Fi scanning is not supported here: {0}")]
    Unsupported(String),
    #[error("{context} failed (OS error {code})")]
    Os { code: u32, context: &'static str },
}

/// Blocking Wi-Fi scanner. Not `Send`: create and use it on one thread.
pub trait WifiScanner {
    fn interfaces(&mut self) -> Result<Vec<WifiInterface>, WifiError>;

    /// Ask every interface for a fresh scan. Results show up in [`bss_list`](Self::bss_list)
    /// a few seconds later. With `ssid`, a directed probe request is sent for that
    /// network (used for Karma/MANA detection).
    fn trigger_scan(&mut self, ssid: Option<&[u8]>) -> Result<(), WifiError>;

    /// The OS's current BSS cache across all interfaces.
    fn bss_list(&mut self) -> Result<Vec<RawBss>, WifiError>;
}

/// Open the platform's Wi-Fi scanner.
pub fn open_scanner() -> Result<Box<dyn WifiScanner>, WifiError> {
    #[cfg(windows)]
    {
        Ok(Box::new(windows::WlanScanner::open()?))
    }
    #[cfg(not(windows))]
    {
        unsupported::open()
    }
}

/// Convert a centre frequency to (band, channel number).
pub fn frequency_to_channel(khz: u32) -> Option<(na_model::Band, u16)> {
    use na_model::Band;
    let mhz = khz / 1000;
    match mhz {
        2484 => Some((Band::G2_4, 14)),
        2412..=2472 => Some((Band::G2_4, ((mhz - 2407) / 5) as u16)),
        // 6 GHz channel 2 is a special case at 5935 MHz.
        5935 => Some((Band::G6, 2)),
        5955..=7115 => Some((Band::G6, ((mhz - 5950) / 5) as u16)),
        5160..=5885 => Some((Band::G5, ((mhz - 5000) / 5) as u16)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use na_model::Band;

    use super::*;

    #[test]
    fn channels_from_frequency() {
        assert_eq!(frequency_to_channel(2_412_000), Some((Band::G2_4, 1)));
        assert_eq!(frequency_to_channel(2_437_000), Some((Band::G2_4, 6)));
        assert_eq!(frequency_to_channel(2_484_000), Some((Band::G2_4, 14)));
        assert_eq!(frequency_to_channel(5_180_000), Some((Band::G5, 36)));
        assert_eq!(frequency_to_channel(5_825_000), Some((Band::G5, 165)));
        assert_eq!(frequency_to_channel(5_955_000), Some((Band::G6, 1)));
        assert_eq!(frequency_to_channel(6_135_000), Some((Band::G6, 37)));
        assert_eq!(frequency_to_channel(900_000), None);
    }
}
