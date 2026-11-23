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

    /// Networks saved in the OS, deduplicated by SSID. Only names and security
    /// settings are read; keys are never requested.
    fn saved_networks(&mut self) -> Result<Vec<SavedNetwork>, WifiError>;
}

/// A Wi-Fi network the OS remembers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedNetwork {
    pub profile: String,
    pub ssid: String,
    /// The OS's authentication name: `open`, `WPA2PSK`, `WPA3SAE`, `WPA2`, `OWE`…
    pub auth: String,
    /// `none`, `WEP`, `TKIP`, `AES`, `GCMP256`…
    pub encryption: String,
    /// A WPA3 profile that also accepts WPA2 (transition mode).
    pub transition: bool,
    pub auto_connect: bool,
    /// The network doesn't broadcast its name.
    pub hidden: bool,
}

/// Parse a Windows WLAN profile (`WLANProfile` XML). Returns None for ad-hoc
/// (IBSS) profiles and anything without an SSID. Key material is ignored.
pub fn parse_wlan_profile(xml: &str) -> Option<SavedNetwork> {
    if tag(xml, "connectionType").is_some_and(|t| t.eq_ignore_ascii_case("IBSS")) {
        return None;
    }
    let ssid_block = tag(xml, "SSID")?;
    let ssid = tag(ssid_block, "hex")
        .and_then(hex_bytes)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .or_else(|| tag(ssid_block, "name").map(unescape))?;
    let auth_block = tag(xml, "authEncryption").unwrap_or_default();
    Some(SavedNetwork {
        profile: tag(xml, "name").map(unescape).unwrap_or_else(|| ssid.clone()),
        ssid,
        auth: tag(auth_block, "authentication").unwrap_or("open").to_owned(),
        encryption: tag(auth_block, "encryption").unwrap_or("none").to_owned(),
        transition: tag(auth_block, "transitionMode").is_some_and(|v| v.eq_ignore_ascii_case("true")),
        auto_connect: tag(xml, "connectionMode").is_none_or(|v| v.eq_ignore_ascii_case("auto")),
        hidden: tag(xml, "nonBroadcast").is_some_and(|v| v.eq_ignore_ascii_case("true")),
    })
}

/// Contents of the first `<name ...>…</name>` (namespaced attributes allowed).
fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}");
    let mut from = 0;
    while let Some(i) = xml[from..].find(&open) {
        let start = from + i + open.len();
        match xml[start..].chars().next() {
            Some('>' | ' ' | '\t' | '\r' | '\n') => {
                let gt = start + xml[start..].find('>')? + 1;
                let end = gt + xml[gt..].find(&format!("</{name}>"))?;
                return Some(xml[gt..end].trim());
            }
            _ => from = start,
        }
    }
    None
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.is_empty() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
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
    fn wlan_profile_fields() {
        let xml = r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>Home &amp; Garden</name>
	<SSIDConfig>
		<SSID>
			<hex>486F6D6520262047617264656E</hex>
			<name>Home &amp; Garden</name>
		</SSID>
	</SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>auto</connectionMode>
	<MSM>
		<security>
			<authEncryption>
				<authentication>WPA3SAE</authentication>
				<encryption>AES</encryption>
				<useOneX>false</useOneX>
				<transitionMode xmlns="http://www.microsoft.com/networking/WLAN/profile/v4">true</transitionMode>
			</authEncryption>
			<sharedKey>
				<keyType>passPhrase</keyType>
				<protected>true</protected>
				<keyMaterial>01000000D08C9DDF0115</keyMaterial>
			</sharedKey>
		</security>
	</MSM>
</WLANProfile>"#;
        let n = parse_wlan_profile(xml).unwrap();
        assert_eq!(n.ssid, "Home & Garden");
        assert_eq!(n.profile, "Home & Garden");
        assert_eq!((n.auth.as_str(), n.encryption.as_str()), ("WPA3SAE", "AES"));
        assert!(n.transition && n.auto_connect && !n.hidden);

        let open = "<WLANProfile><name>Cafe</name><SSIDConfig><SSID><name>Cafe</name></SSID>\
            <nonBroadcast>true</nonBroadcast></SSIDConfig><connectionMode>manual</connectionMode>\
            <MSM><security><authEncryption><authentication>open</authentication><encryption>none</encryption>\
            </authEncryption></security></MSM></WLANProfile>";
        let n = parse_wlan_profile(open).unwrap();
        assert_eq!((n.ssid.as_str(), n.auth.as_str()), ("Cafe", "open"));
        assert!(n.hidden && !n.auto_connect && !n.transition);
        assert_eq!(parse_wlan_profile("<WLANProfile><connectionType>IBSS</connectionType></WLANProfile>"), None);
    }

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
