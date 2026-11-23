use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::MacAddr;

/// How a Bluetooth LE address was assigned. For random addresses, the top two
/// bits give the subtype.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BleAddressType {
    /// IEEE-assigned and stable. Its OUI names the vendor.
    Public,
    /// Fixed until power-cycle or factory reset. Common on accessories (mice, tags).
    RandomStatic,
    /// Resolvable private address: rotates (~15 min). Only bonded peers can resolve it.
    RandomResolvable,
    /// Non-resolvable private address: rotates and can't be traced (beacons, Find My).
    RandomNonResolvable,
    #[default]
    Unknown,
}

impl BleAddressType {
    /// Classify an address the radio reported as "random".
    pub fn from_random(addr: MacAddr) -> Self {
        match addr.0[0] >> 6 {
            0b11 => Self::RandomStatic,
            0b01 => Self::RandomResolvable,
            0b00 => Self::RandomNonResolvable,
            _ => Self::Unknown, // 0b10 is reserved
        }
    }

    pub fn is_random(self) -> bool {
        !matches!(self, Self::Public | Self::Unknown)
    }

    /// The same physical device will reappear under a new address, so never
    /// merge these on weak evidence or treat a new one as a new device.
    pub fn is_rotating(self) -> bool {
        matches!(self, Self::RandomResolvable | Self::RandomNonResolvable)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::RandomStatic => "random static",
            Self::RandomResolvable => "resolvable private (rotates)",
            Self::RandomNonResolvable => "non-resolvable private (rotates)",
            Self::Unknown => "unknown",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::RandomStatic => "static",
            Self::RandomResolvable => "rpa",
            Self::RandomNonResolvable => "nrpa",
            Self::Unknown => "?",
        }
    }
}

/// A Bluetooth UUID. 128-bit UUIDs built on the Bluetooth base UUID are
/// normalised to their 16/32-bit short form, so `0xFE2C` compares equal however it was advertised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum BleUuid {
    U16(u16),
    U32(u32),
    U128(u128),
}

/// 00000000-0000-1000-8000-00805F9B34FB
const BASE_UUID: u128 = 0x0000_0000_0000_1000_8000_0080_5F9B_34FB;
const LOW_96: u128 = (1 << 96) - 1;

impl BleUuid {
    pub fn from_u128(v: u128) -> Self {
        if v & LOW_96 == BASE_UUID {
            let short = (v >> 96) as u32;
            match u16::try_from(short) {
                Ok(s) => Self::U16(s),
                Err(_) => Self::U32(short),
            }
        } else {
            Self::U128(v)
        }
    }

    /// Decode the little-endian encoding used in advertising data (2, 4 or 16 bytes).
    pub fn from_le_bytes(b: &[u8]) -> Option<Self> {
        match b.len() {
            2 => Some(Self::U16(u16::from_le_bytes([b[0], b[1]]))),
            4 => Some(Self::from_u128((u128::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])) << 96) | BASE_UUID)),
            16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                Some(Self::from_u128(u128::from_le_bytes(a)))
            }
            _ => None,
        }
    }

    pub fn as_u16(self) -> Option<u16> {
        match self {
            Self::U16(v) => Some(v),
            _ => None,
        }
    }
}

impl fmt::Display for BleUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::U16(v) => write!(f, "0x{v:04X}"),
            Self::U32(v) => write!(f, "0x{v:08X}"),
            Self::U128(v) => {
                let h = format!("{v:032x}");
                write!(f, "{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid Bluetooth UUID: {0:?}")]
pub struct ParseUuidError(String);

impl FromStr for BleUuid {
    type Err = ParseUuidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseUuidError(s.to_owned());
        let t = s.trim();
        let hex = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
        match hex.len() {
            4 => u16::from_str_radix(hex, 16).map(Self::U16).map_err(|_| err()),
            8 => u32::from_str_radix(hex, 16).map(|v| Self::from_u128((u128::from(v) << 96) | BASE_UUID)).map_err(|_| err()),
            36 => {
                let digits: String = hex.chars().filter(|c| *c != '-').collect();
                if digits.len() != 32 {
                    return Err(err());
                }
                u128::from_str_radix(&digits, 16).map(Self::from_u128).map_err(|_| err())
            }
            _ => Err(err()),
        }
    }
}

impl From<BleUuid> for String {
    fn from(u: BleUuid) -> Self {
        u.to_string()
    }
}

impl TryFrom<String> for BleUuid {
    type Error = ParseUuidError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// One manufacturer-specific data AD structure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManufacturerData {
    /// Bluetooth SIG company identifier (e.g. 0x004C Apple).
    pub company_id: u16,
    pub data: Vec<u8>,
}

/// One service-data AD structure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceData {
    pub uuid: BleUuid,
    pub data: Vec<u8>,
}

/// Decoded fields from BLE advertisements and scan responses, merged per device.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct BleInfo {
    pub address: MacAddr,
    pub address_type: BleAddressType,
    pub local_name: Option<String>,
    pub manufacturer_data: Vec<ManufacturerData>,
    pub service_uuids: Vec<BleUuid>,
    pub service_data: Vec<ServiceData>,
    pub tx_power: Option<i8>,
    pub appearance: Option<u16>,
    /// AD Flags: discoverable mode and BR/EDR (classic) support.
    pub flags: Option<u8>,
    pub connectable: bool,
    /// Paired with this host.
    pub paired: bool,
    /// Connected to this host right now. Connected peripherals usually stop advertising.
    pub connected: bool,
    /// Every AD structure heard (`[len][type][data]…`), shown in the inspector.
    pub raw_ad: Vec<u8>,
}

impl BleInfo {
    pub fn company_id(&self) -> Option<u16> {
        self.manufacturer_data.first().map(|m| m.company_id)
    }

    pub fn service_data_for(&self, uuid: u16) -> Option<&[u8]> {
        self.service_data
            .iter()
            .find(|s| s.uuid == BleUuid::U16(uuid))
            .map(|s| s.data.as_slice())
    }

    pub fn manufacturer_data_for(&self, company: u16) -> impl Iterator<Item = &[u8]> {
        self.manufacturer_data
            .iter()
            .filter(move |m| m.company_id == company)
            .map(|m| m.data.as_slice())
    }
}

/// A Bluetooth Classic (BR/EDR) device.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct BtClassicInfo {
    pub address: MacAddr,
    pub name: Option<String>,
    /// 24-bit Class of Device: service classes, major and minor device class.
    pub class_of_device: u32,
    pub paired: bool,
    pub connected: bool,
    /// Answered the most recent inquiry, so it is discoverable right now.
    pub discoverable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_subtypes() {
        let t = |s: &str| BleAddressType::from_random(s.parse().unwrap());
        assert_eq!(t("C2:00:00:12:34:56"), BleAddressType::RandomStatic);
        assert_eq!(t("5A:11:22:33:44:55"), BleAddressType::RandomResolvable);
        assert_eq!(t("1A:11:22:33:44:55"), BleAddressType::RandomNonResolvable);
        assert!(BleAddressType::RandomResolvable.is_rotating());
        assert!(!BleAddressType::RandomStatic.is_rotating());
    }

    #[test]
    fn uuids_normalise_and_round_trip() {
        // 0xFE2C advertised as a full 128-bit UUID.
        let full: BleUuid = "0000fe2c-0000-1000-8000-00805f9b34fb".parse().unwrap();
        assert_eq!(full, BleUuid::U16(0xFE2C));
        assert_eq!(BleUuid::from_le_bytes(&[0x2C, 0xFE]), Some(BleUuid::U16(0xFE2C)));
        let custom: BleUuid = "6e400001-b5a3-f393-e0a9-e50e24dcca9e".parse().unwrap();
        assert!(matches!(custom, BleUuid::U128(_)));
        assert_eq!(custom.to_string(), "6e400001-b5a3-f393-e0a9-e50e24dcca9e");
        let mut le = 0x6e40_0001_b5a3_f393_e0a9_e50e_24dc_ca9e_u128.to_le_bytes().to_vec();
        assert_eq!(BleUuid::from_le_bytes(&le), Some(custom));
        le.pop();
        assert_eq!(BleUuid::from_le_bytes(&le), None);
        assert_eq!(BleUuid::U16(0x180D).to_string(), "0x180D");
        assert_eq!("0x180D".parse::<BleUuid>().unwrap(), BleUuid::U16(0x180D));
    }
}
