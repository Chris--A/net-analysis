//! 802.11 information-element parsing (beacons and probe responses).
//!
//! It decodes what device identification and evil-twin detection need:
//! - security (RSN / WPA / WEP)
//! - WPS make and model
//! - PHY generation and channel width (HT / VHT / HE / EHT)
//! - BSS load, country and vendor IEs
//!
//! It also produces a stable fingerprint over the AP's static capabilities.
//! Malformed or truncated input never panics. Parsing stops at the first bad element.

use na_model::{Akm, Cipher, Pmf, Security, WpsInfo, stable_hash};

/// One raw element. `ext_id` is set for Element ID 255 (extension elements).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Element<'a> {
    pub id: u8,
    pub ext_id: Option<u8>,
    /// Payload, excluding the extension ID byte for ID 255.
    pub data: &'a [u8],
}

/// Iterate over the elements in an IE blob.
pub fn elements(ies: &[u8]) -> impl Iterator<Item = Element<'_>> {
    let mut rest = ies;
    std::iter::from_fn(move || {
        let (&id, after) = rest.split_first()?;
        let (&len, after) = after.split_first()?;
        if after.len() < len as usize {
            rest = &[];
            return None;
        }
        let (data, tail) = after.split_at(len as usize);
        rest = tail;
        Some(match (id, data.split_first()) {
            (255, Some((&ext, payload))) => Element { id, ext_id: Some(ext), data: payload },
            _ => Element { id, ext_id: None, data },
        })
    })
}

/// Human-readable element name for the inspector.
pub fn element_name(id: u8, ext_id: Option<u8>) -> &'static str {
    match (id, ext_id) {
        (0, _) => "SSID",
        (1, _) => "Supported Rates",
        (3, _) => "DS Parameter Set",
        (5, _) => "TIM",
        (7, _) => "Country",
        (11, _) => "BSS Load",
        (32, _) => "Power Constraint",
        (35, _) => "TPC Report",
        (37, _) => "Channel Switch",
        (42, _) => "ERP",
        (45, _) => "HT Capabilities",
        (48, _) => "RSN",
        (50, _) => "Extended Rates",
        (54, _) => "Mobility Domain (802.11r)",
        (59, _) => "Operating Classes",
        (61, _) => "HT Operation",
        (70, _) => "RM Enabled Capabilities",
        (74, _) => "OBSS Scan Parameters",
        (107, _) => "Interworking",
        (108, _) => "Advertisement Protocol",
        (111, _) => "Roaming Consortium",
        (127, _) => "Extended Capabilities",
        (191, _) => "VHT Capabilities",
        (192, _) => "VHT Operation",
        (195, _) => "VHT Tx Power Envelope",
        (201, _) => "Reduced Neighbor Report",
        (221, _) => "Vendor Specific",
        (255, Some(35)) => "HE Capabilities",
        (255, Some(36)) => "HE Operation",
        (255, Some(38)) => "MU EDCA Parameter Set",
        (255, Some(39)) => "Spatial Reuse",
        (255, Some(59)) => "HE 6 GHz Band Capabilities",
        (255, Some(106)) => "EHT Operation",
        (255, Some(107)) => "Multi-Link",
        (255, Some(108)) => "EHT Capabilities",
        (255, _) => "Extension",
        _ => "Unknown",
    }
}

const OUI_IEEE: [u8; 3] = [0x00, 0x0F, 0xAC];
const OUI_MICROSOFT: [u8; 3] = [0x00, 0x50, 0xF2];
const OUI_WFA: [u8; 3] = [0x50, 0x6F, 0x9A];

/// Everything we extract from one IE blob.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParsedIes {
    pub ssid: Option<Vec<u8>>,
    pub ds_channel: Option<u8>,
    pub country: Option<String>,
    /// From the RSN element (WPA2/WPA3/OWE/Enterprise).
    pub rsn: Option<Security>,
    /// A pre-RSN WPA vendor IE is present.
    pub wpa1: bool,
    pub wps: Option<WpsInfo>,
    /// WPS primary device type (category, subcategory).
    pub wps_device_type: Option<(u16, u16)>,
    pub ht: bool,
    pub vht: bool,
    pub he: bool,
    pub eht: bool,
    /// Operating channel width in MHz (20 if nothing wider is advertised).
    pub width_mhz: u16,
    pub station_count: Option<u16>,
    pub channel_utilization: Option<u8>,
    /// Vendor IEs as OUI + vendor type.
    pub vendor_ies: Vec<[u8; 4]>,
    /// 802.11r fast transition is advertised.
    pub fast_transition: bool,
    /// Hash over static capabilities. Excludes volatile fields (TIM, BSS load,
    /// channel, WPS state), so it is stable across beacons from the same AP.
    pub fingerprint: u64,
}

impl ParsedIes {
    /// 4 = Wi-Fi 4 (n) … 7 = Wi-Fi 7 (be).
    pub fn wifi_gen(&self) -> Option<u8> {
        if self.eht {
            Some(7)
        } else if self.he {
            Some(6)
        } else if self.vht {
            Some(5)
        } else if self.ht {
            Some(4)
        } else {
            None
        }
    }

    /// Effective security. `capability` is the 802.11 capability field, whose privacy bit
    /// distinguishes WEP from open when no RSN/WPA element is present.
    pub fn security(&self, capability: u16) -> Security {
        if let Some(rsn) = &self.rsn {
            let mut s = rsn.clone();
            if self.wpa1 && !s.akms.contains(&Akm::Wpa1) {
                s.akms.push(Akm::Wpa1); // WPA/WPA2 mixed mode
            }
            return s;
        }
        if self.wpa1 {
            return Security {
                akms: vec![Akm::Wpa1],
                pairwise: vec![Cipher::Tkip],
                group: Some(Cipher::Tkip),
                pmf: Pmf::Disabled,
            };
        }
        if capability & 0x0010 != 0 {
            return Security {
                akms: vec![Akm::Wep],
                pairwise: vec![Cipher::Wep],
                group: Some(Cipher::Wep),
                pmf: Pmf::Disabled,
            };
        }
        Security::open()
    }
}

pub fn parse(ies: &[u8]) -> ParsedIes {
    let mut p = ParsedIes {
        width_mhz: 20,
        ..Default::default()
    };
    let mut wps_payload: Vec<u8> = Vec::new();
    let mut fp: Vec<u8> = Vec::with_capacity(ies.len());
    // Widths advertised by each generation's operation element; the newest wins.
    let (mut ht_w, mut vht_w, mut he_w, mut eht_w) = (None, None, None, None);

    for e in elements(ies) {
        fingerprint_element(&mut fp, &e);
        match (e.id, e.ext_id) {
            (0, _) => p.ssid = Some(e.data.to_vec()),
            (3, _) => p.ds_channel = e.data.first().copied(),
            (7, _) if e.data.len() >= 2 => {
                let cc: String = e.data[..2]
                    .iter()
                    .filter(|b| b.is_ascii_alphabetic())
                    .map(|&b| b as char)
                    .collect();
                if cc.len() == 2 {
                    p.country = Some(cc);
                }
            }
            (11, _) if e.data.len() >= 3 => {
                p.station_count = Some(u16::from_le_bytes([e.data[0], e.data[1]]));
                p.channel_utilization = Some(e.data[2]);
            }
            (45, _) => p.ht = true,
            (48, _) => p.rsn = parse_rsn(e.data),
            (54, _) => p.fast_transition = true,
            (61, _) => ht_w = ht_operation_width(e.data),
            (191, _) => p.vht = true,
            (192, _) => vht_w = vht_operation_width(e.data),
            (221, _) if e.data.len() >= 4 => {
                let tag = [e.data[0], e.data[1], e.data[2], e.data[3]];
                if !p.vendor_ies.contains(&tag) {
                    p.vendor_ies.push(tag);
                }
                match (&tag[..3], tag[3]) {
                    (oui, 1) if oui == OUI_MICROSOFT => p.wpa1 = true,
                    // WPS may be split across several IEs; concatenate before parsing.
                    (oui, 4) if oui == OUI_MICROSOFT => wps_payload.extend_from_slice(&e.data[4..]),
                    _ => {}
                }
            }
            (255, Some(35)) => p.he = true,
            (255, Some(36)) => he_w = he_operation_width(e.data),
            (255, Some(108)) => p.eht = true,
            (255, Some(106)) => eht_w = eht_operation_width(e.data),
            _ => {}
        }
    }

    if let Some(w) = eht_w.or(he_w).or(vht_w).or(ht_w) {
        p.width_mhz = w;
    }
    if !wps_payload.is_empty() {
        let (info, device_type) = parse_wps(&wps_payload);
        p.wps_device_type = device_type;
        if info != WpsInfo::default() {
            p.wps = Some(info);
        }
    }
    p.fingerprint = stable_hash(&fp);
    p
}

/// Append the stable part of an element to the fingerprint buffer.
fn fingerprint_element(fp: &mut Vec<u8>, e: &Element<'_>) {
    // TIM is in beacons but never in probe responses, and the OS cache holds
    // whichever arrived last. Counting it would split one AP into two fingerprints.
    if e.id == 5 {
        return;
    }
    fp.push(e.id);
    if let Some(x) = e.ext_id {
        fp.push(x);
    }
    let include_body = match (e.id, e.ext_id) {
        // Capabilities that are fixed by the AP's hardware, firmware and configuration.
        (1 | 45 | 48 | 50 | 54 | 70 | 127 | 191, _) => true,
        (255, Some(35 | 59 | 108)) => true,
        // For vendor IEs, the OUI and type are stable. Bodies of WPS (state changes),
        // WMM (parameter set counter) and P2P are not, so those are skipped.
        (221, _) => {
            let stable_body = e.data.len() >= 4
                && !(e.data[..3] == OUI_MICROSOFT && matches!(e.data[3], 2 | 4))
                && !(e.data[..3] == OUI_WFA && e.data[3] == 9);
            fp.extend_from_slice(&e.data[..e.data.len().min(4)]);
            stable_body
        }
        // Everything else (SSID, channel, TIM, load, operation elements…) counts by presence only.
        _ => false,
    };
    if include_body {
        fp.extend_from_slice(&(e.data.len() as u16).to_le_bytes());
        fp.extend_from_slice(e.data);
    }
}

// ---------------------------------------------------------------------------
// RSN
// ---------------------------------------------------------------------------

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        if self.0.len() < N {
            return None;
        }
        let (head, tail) = self.0.split_at(N);
        self.0 = tail;
        head.try_into().ok()
    }
    fn u16le(&mut self) -> Option<u16> {
        self.take::<2>().map(u16::from_le_bytes)
    }
    fn suite(&mut self) -> Option<[u8; 4]> {
        self.take::<4>()
    }
}

fn suite_u32(s: [u8; 4]) -> u32 {
    u32::from_be_bytes(s)
}

fn cipher(s: [u8; 4]) -> Cipher {
    if s[..3] != OUI_IEEE {
        return Cipher::Other(suite_u32(s));
    }
    match s[3] {
        1 | 5 => Cipher::Wep,
        2 => Cipher::Tkip,
        4 => Cipher::Ccmp128,
        8 => Cipher::Gcmp128,
        9 => Cipher::Gcmp256,
        10 => Cipher::Ccmp256,
        _ => Cipher::Other(suite_u32(s)),
    }
}

fn akm(s: [u8; 4]) -> Akm {
    if s[..3] != OUI_IEEE {
        return Akm::Other(suite_u32(s));
    }
    match s[3] {
        1 | 3 | 5 | 13 => Akm::Eap,
        2 | 4 | 6 => Akm::Psk,
        8 | 9 | 24 | 25 => Akm::Sae,
        11 | 12 => Akm::EapSuiteB,
        18 => Akm::Owe,
        _ => Akm::Other(suite_u32(s)),
    }
}

/// RSN element. Fields after the version are optional, and missing ones take the spec defaults.
fn parse_rsn(d: &[u8]) -> Option<Security> {
    let mut r = Reader(d);
    if r.u16le()? != 1 {
        return None;
    }
    let group = Some(r.suite().map_or(Cipher::Ccmp128, cipher));

    let mut pairwise = Vec::new();
    if let Some(n) = r.u16le() {
        for _ in 0..n {
            pairwise.push(cipher(r.suite()?));
        }
    } else {
        pairwise.push(Cipher::Ccmp128);
    }

    let mut akms = Vec::new();
    if let Some(n) = r.u16le() {
        for _ in 0..n {
            let a = akm(r.suite()?);
            if !akms.contains(&a) {
                akms.push(a);
            }
        }
    } else {
        akms.push(Akm::Eap);
    }

    let caps = r.u16le().unwrap_or(0);
    let pmf = if caps & 0x0040 != 0 {
        Pmf::Required
    } else if caps & 0x0080 != 0 {
        Pmf::Capable
    } else {
        Pmf::Disabled
    };
    Some(Security { akms, pairwise, group, pmf })
}

// ---------------------------------------------------------------------------
// Channel width from operation elements
// ---------------------------------------------------------------------------

fn ht_operation_width(d: &[u8]) -> Option<u16> {
    let info = *d.get(1)?;
    let secondary_offset = info & 0x03;
    let any_width = info & 0x04 != 0;
    Some(if any_width && matches!(secondary_offset, 1 | 3) { 40 } else { 20 })
}

fn vht_operation_width(d: &[u8]) -> Option<u16> {
    let width = *d.first()?;
    let ccfs1 = *d.get(2)?;
    match width {
        1 if ccfs1 != 0 => Some(160), // 160 MHz (or 80+80) signalled via CCFS1
        1 => Some(80),
        2 | 3 => Some(160), // deprecated 160 / 80+80 encodings
        _ => None,          // 0: defer to HT operation (20/40)
    }
}

/// HE Operation. Only the optional 6 GHz Operation Information carries a width;
/// on 2.4/5 GHz the HT/VHT elements do.
fn he_operation_width(d: &[u8]) -> Option<u16> {
    if d.len() < 6 {
        return None;
    }
    let params = u32::from_le_bytes([d[0], d[1], d[2], 0]);
    let vht_info = params & (1 << 14) != 0;
    let cohosted = params & (1 << 15) != 0;
    let six_ghz = params & (1 << 17) != 0;
    if !six_ghz {
        return None;
    }
    // params(3) + BSS colour(1) + basic HE-MCS(2)
    let mut off = 6;
    if vht_info {
        off += 3;
    }
    if cohosted {
        off += 1;
    }
    let control = *d.get(off + 1)?;
    Some(match control & 0x03 {
        0 => 20,
        1 => 40,
        2 => 80,
        _ => 160,
    })
}

fn eht_operation_width(d: &[u8]) -> Option<u16> {
    let params = *d.first()?;
    if params & 0x01 == 0 {
        return None;
    }
    // params(1) + basic EHT-MCS(4), then control
    let control = *d.get(5)?;
    Some(match control & 0x07 {
        0 => 20,
        1 => 40,
        2 => 80,
        3 => 160,
        4 => 320,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// WPS
// ---------------------------------------------------------------------------

fn parse_wps(mut d: &[u8]) -> (WpsInfo, Option<(u16, u16)>) {
    let mut info = WpsInfo::default();
    let mut device_type = None;
    while d.len() >= 4 {
        let kind = u16::from_be_bytes([d[0], d[1]]);
        let len = u16::from_be_bytes([d[2], d[3]]) as usize;
        if d.len() < 4 + len {
            break;
        }
        let value = &d[4..4 + len];
        d = &d[4 + len..];
        let text = || wps_string(value);
        match kind {
            0x1021 => info.manufacturer = text(),
            0x1023 => info.model_name = text(),
            0x1024 => info.model_number = text(),
            0x1011 => info.device_name = text(),
            0x1054 if value.len() >= 8 => {
                let category = u16::from_be_bytes([value[0], value[1]]);
                let sub = u16::from_be_bytes([value[6], value[7]]);
                device_type = Some((category, sub));
            }
            _ => {}
        }
    }
    (info, device_type)
}

/// WPS strings are often NUL-padded or filled with placeholder spaces.
fn wps_string(v: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(v);
    let s = s.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    (!s.is_empty() && s != "0" && !s.eq_ignore_ascii_case("n/a")).then(|| s.to_owned())
}

/// Human label for a WPS primary device type.
pub fn wps_device_type_label(category: u16, sub: u16) -> Option<&'static str> {
    Some(match (category, sub) {
        (1, _) => "Computer",
        (2, _) => "Input device",
        (3, _) => "Printer / scanner",
        (4, _) => "Camera",
        (5, _) => "Storage (NAS)",
        (6, 1) => "Access point",
        (6, 2) => "Router",
        (6, 3) => "Switch",
        (6, 4) => "Gateway",
        (6, 5) => "Bridge",
        (6, _) => "Network device",
        (7, _) => "Display / TV",
        (8, _) => "Media device",
        (9, _) => "Game console",
        (10, _) => "Phone",
        (11, _) => "Audio device",
        (12, _) => "Dock",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ie(id: u8, data: &[u8]) -> Vec<u8> {
        let mut v = vec![id, data.len() as u8];
        v.extend_from_slice(data);
        v
    }

    fn ext(ext_id: u8, data: &[u8]) -> Vec<u8> {
        let mut body = vec![ext_id];
        body.extend_from_slice(data);
        ie(255, &body)
    }

    fn rsn(akms: &[u8], caps: u16) -> Vec<u8> {
        let mut d = vec![1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4];
        d.extend_from_slice(&(akms.len() as u16).to_le_bytes());
        for a in akms {
            d.extend_from_slice(&[0x00, 0x0F, 0xAC, *a]);
        }
        d.extend_from_slice(&caps.to_le_bytes());
        ie(48, &d)
    }

    fn wps_attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut v = kind.to_be_bytes().to_vec();
        v.extend_from_slice(&(value.len() as u16).to_be_bytes());
        v.extend_from_slice(value);
        v
    }

    #[test]
    fn iterates_and_stops_on_truncation() {
        let mut blob = ie(0, b"Home");
        blob.extend(ie(3, &[6]));
        blob.extend([48, 20, 1, 0]); // claims 20 bytes, has 2
        let ids: Vec<u8> = elements(&blob).map(|e| e.id).collect();
        assert_eq!(ids, vec![0, 3]);
        // Never panics on garbage.
        let _ = parse(&[255]);
        let _ = parse(&[221, 2, 0, 0x50]);
        let _ = parse(&[48, 1, 1]);
    }

    #[test]
    fn wpa2_psk() {
        let p = parse(&rsn(&[2], 0));
        let s = p.security(0x0011);
        assert_eq!(s.akms, vec![Akm::Psk]);
        assert_eq!(s.pairwise, vec![Cipher::Ccmp128]);
        assert_eq!(s.pmf, Pmf::Disabled);
        assert_eq!(s.label(), "WPA2-PSK");
    }

    #[test]
    fn wpa3_transition_with_pmf_capable() {
        let s = parse(&rsn(&[8, 2], 0x0080)).security(0x0011);
        assert_eq!(s.akms, vec![Akm::Sae, Akm::Psk]);
        assert_eq!(s.pmf, Pmf::Capable);
    }

    #[test]
    fn wpa3_only_requires_pmf() {
        let s = parse(&rsn(&[8], 0x00C0)).security(0x0011);
        assert_eq!(s.akms, vec![Akm::Sae]);
        assert_eq!(s.pmf, Pmf::Required);
    }

    #[test]
    fn owe_and_enterprise_and_ft_variants() {
        assert_eq!(parse(&rsn(&[18], 0x00C0)).security(0x11).akms, vec![Akm::Owe]);
        assert_eq!(parse(&rsn(&[1, 3, 5], 0)).security(0x11).akms, vec![Akm::Eap]);
        assert_eq!(parse(&rsn(&[4, 2], 0)).security(0x11).akms, vec![Akm::Psk]);
    }

    #[test]
    fn open_wep_and_wpa1() {
        assert!(parse(&ie(0, b"Cafe")).security(0x0001).is_open());
        assert_eq!(parse(&[]).security(0x0011).akms, vec![Akm::Wep]);
        let wpa1 = ie(221, &[0x00, 0x50, 0xF2, 1, 1, 0]);
        let p = parse(&wpa1);
        assert!(p.wpa1);
        assert_eq!(p.security(0x0011).akms, vec![Akm::Wpa1]);
        // WPA/WPA2 mixed mode keeps both.
        let mut mixed = rsn(&[2], 0);
        mixed.extend(wpa1);
        assert_eq!(parse(&mixed).security(0x11).akms, vec![Akm::Psk, Akm::Wpa1]);
    }

    #[test]
    fn wps_make_model_and_type_even_when_split() {
        let mut attrs = wps_attr(0x1021, b"NETGEAR");
        attrs.extend(wps_attr(0x1023, b"RAX50\0"));
        attrs.extend(wps_attr(0x1024, b" "));
        attrs.extend(wps_attr(0x1011, b"NETGEAR RAX50"));
        attrs.extend(wps_attr(0x1054, &[0, 6, 0x00, 0x50, 0xF2, 0x04, 0, 2]));
        let (a, b) = attrs.split_at(9);
        let mut blob = ie(221, &[&[0x00, 0x50, 0xF2, 4][..], a].concat());
        blob.extend(ie(221, &[&[0x00, 0x50, 0xF2, 4][..], b].concat()));
        let p = parse(&blob);
        let w = p.wps.unwrap();
        assert_eq!(w.manufacturer.as_deref(), Some("NETGEAR"));
        assert_eq!(w.model_name.as_deref(), Some("RAX50"));
        assert_eq!(w.model_number, None, "blank placeholder dropped");
        assert_eq!(w.device_name.as_deref(), Some("NETGEAR RAX50"));
        assert_eq!(p.wps_device_type, Some((6, 2)));
        assert_eq!(wps_device_type_label(6, 2), Some("Router"));
    }

    #[test]
    fn widths_and_generations() {
        // HT 40 MHz (secondary above, any width).
        let ht40 = ie(61, &[36, 0x05, 0, 0, 0, 0]);
        assert_eq!(parse(&ht40).width_mhz, 40);
        // VHT 80 overrides HT 40.
        let mut v80 = [ie(45, &[0; 26]), ht40.clone(), ie(191, &[0; 12]), ie(192, &[1, 42, 0, 0, 0])].concat();
        let p = parse(&v80);
        assert_eq!((p.width_mhz, p.wifi_gen()), (80, Some(5)));
        // VHT 160 via CCFS1.
        v80.extend(ie(192, &[1, 42, 50, 0, 0]));
        assert_eq!(parse(&v80).width_mhz, 160);
        // HE with 6 GHz operation info: 160 MHz.
        let he6 = [ext(35, &[0; 20]), ext(36, &[0, 0, 0x02, 0, 0, 0, 37, 0x03, 47, 0, 0])].concat();
        let p = parse(&he6);
        assert_eq!((p.width_mhz, p.wifi_gen()), (160, Some(6)));
        // EHT 320.
        let eht = [ext(108, &[0; 10]), ext(106, &[0x01, 0, 0, 0, 0, 0x04, 31, 63])].concat();
        let p = parse(&eht);
        assert_eq!((p.width_mhz, p.wifi_gen()), (320, Some(7)));
        // Nothing advertised: 20 MHz, legacy.
        assert_eq!(parse(&ie(0, b"x")).width_mhz, 20);
    }

    #[test]
    fn bss_load_country_and_vendors() {
        let blob = [
            ie(7, b"CA\x20\x01\x0b\x1e"),
            ie(11, &[12, 0, 128, 0, 0]),
            ie(221, &[0x00, 0x17, 0xF2, 0x0A, 1]),
            ie(54, &[0, 0, 0]),
        ]
        .concat();
        let p = parse(&blob);
        assert_eq!(p.country.as_deref(), Some("CA"));
        assert_eq!(p.station_count, Some(12));
        assert_eq!(p.channel_utilization, Some(128));
        assert_eq!(p.vendor_ies, vec![[0x00, 0x17, 0xF2, 0x0A]]);
        assert!(p.fast_transition);
    }

    #[test]
    fn fingerprint_ignores_volatile_fields_but_not_capabilities() {
        let base = |ssid: &[u8], ch: u8, load: u8, tim: u8| {
            [
                ie(0, ssid),
                ie(1, &[0x82, 0x84, 0x8b, 0x96]),
                ie(3, &[ch]),
                ie(5, &[0, 1, 0, tim]),
                ie(11, &[load, 0, 10, 0, 0]),
                ie(45, &[0xEF, 0x01, 0x17, 0xFF]),
                rsn(&[2], 0),
                ie(221, &[0x00, 0x50, 0xF2, 2, 1, 1, load]), // WMM param set counter changes
            ]
            .concat()
        };
        let a = parse(&base(b"Home", 6, 3, 0)).fingerprint;
        let b = parse(&base(b"Home", 11, 9, 7)).fingerprint;
        assert_eq!(a, b, "channel, load, TIM and WMM counters must not change the fingerprint");
        let probe_response = [
            ie(0, b"Home"),
            ie(1, &[0x82, 0x84, 0x8b, 0x96]),
            ie(3, &[6]),
            ie(11, &[3, 0, 10, 0, 0]),
            ie(45, &[0xEF, 0x01, 0x17, 0xFF]),
            rsn(&[2], 0),
            ie(221, &[0x00, 0x50, 0xF2, 2, 1, 1, 3]),
        ]
        .concat();
        assert_eq!(a, parse(&probe_response).fingerprint, "a beacon (with TIM) and a probe response (without)");

        // Different capabilities (e.g. a hostapd clone without HT caps) change it.
        let clone = [ie(0, b"Home"), ie(1, &[0x82, 0x84, 0x8b, 0x96]), ie(3, &[6]), rsn(&[2], 0)].concat();
        assert_ne!(a, parse(&clone).fingerprint);
        // Different security changes it too.
        let open = [ie(0, b"Home"), ie(1, &[0x82, 0x84, 0x8b, 0x96]), ie(3, &[6])].concat();
        assert_ne!(parse(&clone).fingerprint, parse(&open).fingerprint);
    }
}
