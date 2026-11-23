//! Bluetooth LE advertising-data (AD) decoder (Core Spec Supplement, Part A).
//!
//! An advert is a sequence of `[len][type][data; len-1]` structures. The raw
//! form is kept on `BleInfo::raw_ad` for the inspector. This module turns it into fields.

use na_model::{BleUuid, ManufacturerData, ServiceData};

/// One AD structure borrowed from a raw buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdStructure<'a> {
    pub ad_type: u8,
    pub data: &'a [u8],
}

/// Iterate `[len][type][data…]` structures. Stops at a zero length (padding) or truncation.
pub fn structures(raw: &[u8]) -> impl Iterator<Item = AdStructure<'_>> {
    let mut rest = raw;
    std::iter::from_fn(move || {
        let (&len, tail) = rest.split_first()?;
        let len = usize::from(len);
        if len == 0 || tail.len() < len {
            return None;
        }
        let (body, next) = tail.split_at(len);
        rest = next;
        Some(AdStructure { ad_type: body[0], data: &body[1..] })
    })
}

/// Serialise sections back to the `[len][type][data…]` wire form.
pub fn encode<'a>(sections: impl IntoIterator<Item = (u8, &'a [u8])>) -> Vec<u8> {
    let mut out = Vec::new();
    for (t, data) in sections {
        // Extended advertising allows long data, but one AD structure tops out at 254 bytes.
        let data = &data[..data.len().min(254)];
        out.push(data.len() as u8 + 1);
        out.push(t);
        out.extend_from_slice(data);
    }
    out
}

pub fn ad_type_name(t: u8) -> &'static str {
    match t {
        0x01 => "Flags",
        0x02 => "16-bit UUIDs (incomplete)",
        0x03 => "16-bit UUIDs",
        0x04 => "32-bit UUIDs (incomplete)",
        0x05 => "32-bit UUIDs",
        0x06 => "128-bit UUIDs (incomplete)",
        0x07 => "128-bit UUIDs",
        0x08 => "Shortened local name",
        0x09 => "Complete local name",
        0x0A => "TX power level",
        0x0D => "Class of Device",
        0x10 => "Device ID",
        0x12 => "Peripheral connection interval",
        0x14 => "16-bit solicitation UUIDs",
        0x15 => "128-bit solicitation UUIDs",
        0x16 => "Service data (16-bit)",
        0x17 => "Public target address",
        0x18 => "Random target address",
        0x19 => "Appearance",
        0x1A => "Advertising interval",
        0x1B => "LE device address",
        0x1C => "LE role",
        0x1F => "32-bit solicitation UUIDs",
        0x20 => "Service data (32-bit)",
        0x21 => "Service data (128-bit)",
        0x24 => "URI",
        0x27 => "LE supported features",
        0x29 => "PB-ADV (mesh)",
        0x2A => "Mesh message",
        0x2B => "Mesh beacon",
        0x2C => "BIGInfo",
        0x2D => "Broadcast code",
        0x2E => "Resolvable set identifier",
        0x30 => "Broadcast name",
        0x31 => "Encrypted advertising data",
        0xFF => "Manufacturer specific data",
        _ => "Unknown",
    }
}

/// Fields decoded from a device's merged AD structures.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParsedAd {
    pub flags: Option<u8>,
    /// Complete local name if present, else the shortened one.
    pub local_name: Option<String>,
    pub tx_power: Option<i8>,
    pub appearance: Option<u16>,
    pub class_of_device: Option<u32>,
    pub services: Vec<BleUuid>,
    pub service_data: Vec<ServiceData>,
    pub manufacturer_data: Vec<ManufacturerData>,
}

pub fn parse<'a>(sections: impl IntoIterator<Item = AdStructure<'a>>) -> ParsedAd {
    let mut p = ParsedAd::default();
    let mut short_name = None;
    for AdStructure { ad_type, data } in sections {
        match ad_type {
            0x01 => p.flags = data.first().copied(),
            0x02 | 0x03 => push_uuids(&mut p.services, data, 2),
            0x04 | 0x05 => push_uuids(&mut p.services, data, 4),
            0x06 | 0x07 => push_uuids(&mut p.services, data, 16),
            0x08 => short_name = name(data),
            0x09 => p.local_name = name(data).or(p.local_name),
            0x0A => p.tx_power = data.first().map(|&b| b as i8),
            0x0D if data.len() >= 3 => {
                p.class_of_device = Some(u32::from_le_bytes([data[0], data[1], data[2], 0]));
            }
            0x16 => push_service_data(&mut p.service_data, data, 2),
            0x20 => push_service_data(&mut p.service_data, data, 4),
            0x21 => push_service_data(&mut p.service_data, data, 16),
            0x19 if data.len() >= 2 => p.appearance = Some(u16::from_le_bytes([data[0], data[1]])),
            0xFF if data.len() >= 2 => p.manufacturer_data.push(ManufacturerData {
                company_id: u16::from_le_bytes([data[0], data[1]]),
                data: data[2..].to_vec(),
            }),
            _ => {}
        }
    }
    if p.local_name.is_none() {
        p.local_name = short_name;
    }
    p
}

fn push_uuids(out: &mut Vec<BleUuid>, data: &[u8], width: usize) {
    for chunk in data.chunks_exact(width) {
        if let Some(u) = BleUuid::from_le_bytes(chunk)
            && !out.contains(&u)
        {
            out.push(u);
        }
    }
}

fn push_service_data(out: &mut Vec<ServiceData>, data: &[u8], width: usize) {
    if data.len() < width {
        return;
    }
    if let Some(uuid) = BleUuid::from_le_bytes(&data[..width]) {
        out.push(ServiceData { uuid, data: data[width..].to_vec() });
    }
}

/// Names are UTF-8 but often NUL-padded or truncated mid-character.
fn name(data: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(data);
    let s = s.trim_matches(|c: char| c == '\0' || c.is_whitespace() || c == '\u{FFFD}');
    (!s.is_empty()).then(|| s.to_owned())
}

/// Human-readable meaning of the Flags bits.
pub fn flag_labels(flags: u8) -> Vec<&'static str> {
    [
        (0x01, "LE limited discoverable"),
        (0x02, "LE general discoverable"),
        (0x04, "BR/EDR not supported"),
        (0x08, "LE + BR/EDR (controller)"),
        (0x10, "LE + BR/EDR (host)"),
    ]
    .into_iter()
    .filter(|(bit, _)| flags & bit != 0)
    .map(|(_, l)| l)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real-looking Tile advert: flags, 16-bit UUID list, service data, name.
    fn tile() -> Vec<u8> {
        let mut raw = vec![0x02, 0x01, 0x06, 0x03, 0x03, 0xED, 0xFE];
        raw.extend([0x0B, 0x16, 0xED, 0xFE, 0x02, 0x00, 0xCE, 0xF5, 0x4F, 0xA0, 0xA7, 0xA6]);
        raw.extend([0x05, 0x09, b'T', b'i', b'l', b'e']);
        raw
    }

    #[test]
    fn parses_common_structures() {
        let p = parse(structures(&tile()));
        assert_eq!(p.flags, Some(0x06));
        assert_eq!(p.services, vec![BleUuid::U16(0xFEED)]);
        assert_eq!(p.service_data.len(), 1);
        assert_eq!(p.service_data[0].uuid, BleUuid::U16(0xFEED));
        assert_eq!(p.service_data[0].data.len(), 8);
        assert_eq!(p.local_name.as_deref(), Some("Tile"));
        assert_eq!(flag_labels(0x06), vec!["LE general discoverable", "BR/EDR not supported"]);
    }

    #[test]
    fn manufacturer_appearance_tx_power() {
        // Apple Nearby Info, TX power −12 dBm, appearance 0x03C2 (HID mouse).
        let raw = encode([
            (0xFF, &[0x4C, 0x00, 0x10, 0x05, 0x01, 0x18][..]),
            (0x0A, &[0xF4][..]),
            (0x19, &[0xC2, 0x03][..]),
        ]);
        let p = parse(structures(&raw));
        assert_eq!(p.manufacturer_data[0].company_id, 0x004C);
        assert_eq!(p.manufacturer_data[0].data, vec![0x10, 0x05, 0x01, 0x18]);
        assert_eq!(p.tx_power, Some(-12));
        assert_eq!(p.appearance, Some(0x03C2));
    }

    #[test]
    fn complete_name_beats_shortened_and_garbage_is_safe() {
        let raw = encode([(0x08, &b"Gal"[..]), (0x09, &b"Galaxy Buds Pro\0\0"[..])]);
        assert_eq!(parse(structures(&raw)).local_name.as_deref(), Some("Galaxy Buds Pro"));
        // Truncated structure: the length claims more bytes than remain.
        let mut bad = tile();
        bad.extend([0x09, 0xFF, 0x4C]);
        assert_eq!(structures(&bad).count(), 4);
        // Zero-length padding ends the list.
        assert_eq!(structures(&[0x02, 0x01, 0x06, 0x00, 0x00]).count(), 1);
        assert_eq!(parse(structures(&[0x01, 0xFF])).manufacturer_data.len(), 0);
    }

    #[test]
    fn uuid_lists_of_every_width() {
        let u128 = 0x6e40_0001_b5a3_f393_e0a9_e50e_24dc_ca9e_u128.to_le_bytes();
        let raw = encode([
            (0x03, &[0x0D, 0x18, 0x0F, 0x18][..]),
            (0x05, &[0x2C, 0xFE, 0x00, 0x00][..]), // 32-bit form of 0xFE2C
            (0x07, &u128[..]),
        ]);
        let p = parse(structures(&raw));
        assert_eq!(p.services.len(), 4);
        assert_eq!(p.services[0], BleUuid::U16(0x180D));
        assert_eq!(p.services[2], BleUuid::U16(0xFE2C), "32-bit base UUIDs normalise to 16-bit");
        assert!(matches!(p.services[3], BleUuid::U128(_)));
        assert_eq!(encode([(0x01, &[0x06][..])]), vec![0x02, 0x01, 0x06]);
    }
}
