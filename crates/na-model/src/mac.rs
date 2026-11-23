use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A 48-bit IEEE MAC / BSSID / Bluetooth device address.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// The first three octets: the vendor prefix (OUI / MA-L).
    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    /// The U/L bit is set: the address was not assigned by a vendor.
    /// Phones use these for privacy, and so do many rogue APs.
    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    pub fn to_u64(self) -> u64 {
        self.0.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
    }

    pub fn from_u64(v: u64) -> Self {
        let b = v.to_be_bytes();
        Self([b[2], b[3], b[4], b[5], b[6], b[7]])
    }

    /// Numeric neighbour, e.g. a router's LAN MAC is often its BSSID ± 1.
    pub fn offset(self, delta: i64) -> Self {
        let v = (self.to_u64() as i64).wrapping_add(delta) as u64 & 0xFFFF_FFFF_FFFF;
        Self::from_u64(v)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid MAC address: {0:?}")]
pub struct ParseMacError(pub String);

impl FromStr for MacAddr {
    type Err = ParseMacError;

    /// Accepts `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` or `aabbccddeeff`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseMacError(s.to_owned());
        let hex: String = s.chars().filter(|c| !matches!(c, ':' | '-' | '.')).collect();
        if hex.len() != 12 {
            return Err(err());
        }
        let mut out = [0u8; 6];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| err())?;
        }
        Ok(Self(out))
    }
}

impl From<MacAddr> for String {
    fn from(m: MacAddr) -> Self {
        m.to_string()
    }
}

impl TryFrom<String> for MacAddr {
    type Error = ParseMacError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display_round_trip() {
        let m: MacAddr = "3c-37-86-12-34-56".parse().unwrap();
        assert_eq!(m.to_string(), "3C:37:86:12:34:56");
        assert_eq!("3C3786123456".parse::<MacAddr>().unwrap(), m);
        assert!("3C:37:86:12:34".parse::<MacAddr>().is_err());
        assert!("zz:37:86:12:34:56".parse::<MacAddr>().is_err());
    }

    #[test]
    fn locally_administered_bit() {
        assert!(!"3C:37:86:12:34:56".parse::<MacAddr>().unwrap().is_locally_administered());
        assert!("3E:37:86:12:34:56".parse::<MacAddr>().unwrap().is_locally_administered());
    }

    #[test]
    fn offset_wraps_within_48_bits() {
        let m: MacAddr = "3C:37:86:12:34:56".parse().unwrap();
        assert_eq!(m.offset(-1).to_string(), "3C:37:86:12:34:55");
        let max = MacAddr([0xFF; 6]);
        assert_eq!(max.offset(1), MacAddr([0; 6]));
    }

    #[test]
    fn serde_as_string() {
        let m: MacAddr = "3C:37:86:12:34:56".parse().unwrap();
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"3C:37:86:12:34:56\"");
        assert_eq!(serde_json::from_str::<MacAddr>(&json).unwrap(), m);
    }
}
