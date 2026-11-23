//! Identification evidence for Wi-Fi access points.

use na_model::{ApInfo, ClaimKind, Evidence, EvidenceSource as Src, WpsInfo};

use super::OuiDb;
use crate::parse::ie::{ParsedIes, wps_device_type_label};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VendorIeKind {
    /// A brand-specific extension (Apple, Cisco…): evidence of who made the AP.
    Brand,
    /// A Wi-Fi chipset vendor (Broadcom, MediaTek…): useful context, not the brand.
    Chipset,
    /// A standards body or protocol extension (WMM, WPS, Wi-Fi Alliance…).
    Standard,
}

/// Name and kind of a vendor-specific IE, from its OUI and type.
pub fn vendor_ie_info(tag: &[u8; 4]) -> Option<(&'static str, VendorIeKind)> {
    use VendorIeKind::*;
    Some(match ([tag[0], tag[1], tag[2]], tag[3]) {
        ([0x00, 0x50, 0xF2], 1) => ("WPA (legacy)", Standard),
        ([0x00, 0x50, 0xF2], 2) => ("WMM / QoS", Standard),
        ([0x00, 0x50, 0xF2], 4) => ("WPS", Standard),
        ([0x00, 0x50, 0xF2], _) => ("Microsoft", Standard),
        ([0x50, 0x6F, 0x9A], 0x09) => ("Wi-Fi Direct (P2P)", Standard),
        ([0x50, 0x6F, 0x9A], 0x10) => ("Hotspot 2.0", Standard),
        ([0x50, 0x6F, 0x9A], 0x16) => ("MBO / OCE", Standard),
        ([0x50, 0x6F, 0x9A], 0x1C) => ("OWE transition", Standard),
        ([0x50, 0x6F, 0x9A], _) => ("Wi-Fi Alliance", Standard),
        ([0x00, 0x10, 0x18], _) => ("Broadcom", Chipset),
        ([0x00, 0x03, 0x7F], _) => ("Qualcomm Atheros", Chipset),
        ([0x8C, 0xFD, 0xF0], _) => ("Qualcomm", Chipset),
        ([0x00, 0x0C, 0x43], _) => ("Ralink / MediaTek", Chipset),
        ([0x00, 0x0C, 0xE7], _) => ("MediaTek", Chipset),
        ([0x00, 0xE0, 0x4C], _) => ("Realtek", Chipset),
        ([0x00, 0x50, 0x43], _) => ("Marvell", Chipset),
        ([0x00, 0x17, 0xF2], _) => ("Apple", Brand),
        ([0x00, 0x16, 0x32], _) => ("Samsung", Brand),
        ([0x00, 0x40, 0x96], _) => ("Cisco", Brand),
        ([0x00, 0x0B, 0x86], _) => ("Aruba", Brand),
        ([0x00, 0x13, 0x92], _) => ("Ruckus", Brand),
        _ => return None,
    })
}

/// All identification evidence derivable from one AP sighting.
pub fn ap_evidence(ap: &ApInfo, parsed: &ParsedIes, oui: &OuiDb) -> Vec<Evidence> {
    let mut ev = Vec::new();

    if let Some(vendor) = oui.lookup(ap.bssid) {
        let o = ap.bssid.oui();
        let detail = format!("BSSID prefix {:02X}:{:02X}:{:02X} = {vendor}", o[0], o[1], o[2]);
        ev.push(Evidence::new(Src::Oui, ClaimKind::Vendor, vendor, 0.55, detail));
    }

    if let Some(w) = &ap.wps {
        if let Some(m) = &w.manufacturer {
            let detail = format!("WPS Manufacturer = \"{m}\"");
            ev.push(Evidence::new(Src::Wps, ClaimKind::Vendor, m, 0.85, detail));
        }
        if let Some(model) = wps_model(w) {
            let detail = format!("WPS Model = \"{model}\"");
            ev.push(Evidence::new(Src::Wps, ClaimKind::Model, model, 0.9, detail));
        }
    }
    if let Some((cat, sub)) = parsed.wps_device_type
        && let Some(label) = wps_device_type_label(cat, sub)
    {
        let detail = format!("WPS primary device type {cat}-{sub}");
        ev.push(Evidence::new(Src::Wps, ClaimKind::DeviceType, label, 0.7, detail));
    }

    for tag in &ap.vendor_ies {
        if let Some((name, VendorIeKind::Brand)) = vendor_ie_info(tag) {
            let detail = format!("Vendor IE {:02X}:{:02X}:{:02X} ({name})", tag[0], tag[1], tag[2]);
            ev.push(Evidence::new(Src::Ie, ClaimKind::Vendor, name, 0.4, detail));
        }
    }

    ssid_heuristics(&ap.ssid, &mut ev);
    ev
}

fn wps_model(w: &WpsInfo) -> Option<String> {
    match (&w.model_name, &w.model_number) {
        (Some(name), Some(num)) if !name.contains(num.as_str()) => Some(format!("{name} {num}")),
        (Some(name), _) => Some(name.clone()),
        (None, Some(num)) => Some(num.clone()),
        (None, None) => None,
    }
}

fn ssid_heuristics(ssid: &str, ev: &mut Vec<Evidence>) {
    let mut add = |kind, value: &str, conf, why: &str| {
        ev.push(Evidence::new(Src::Heuristic, kind, value, conf, format!("SSID {why}")));
    };
    if ssid.starts_with("DIRECT-") {
        add(ClaimKind::DeviceType, "Wi-Fi Direct device", 0.5, "starts with DIRECT-");
    }
    if ssid.contains("iPhone") {
        add(ClaimKind::DeviceType, "Phone hotspot", 0.45, "contains \"iPhone\"");
        add(ClaimKind::Vendor, "Apple", 0.35, "contains \"iPhone\"");
    }
    if ["AndroidAP", "Galaxy", "Pixel_"].iter().any(|p| ssid.starts_with(p)) {
        add(ClaimKind::DeviceType, "Phone hotspot", 0.45, "matches an Android hotspot pattern");
    }
}

#[cfg(test)]
mod tests {
    use na_model::{Band, MacAddr, Security};

    use super::*;

    fn ap(ssid: &str, bssid: &str) -> ApInfo {
        ApInfo {
            ssid: ssid.into(),
            bssid: bssid.parse::<MacAddr>().unwrap(),
            channel: 6,
            band: Band::G2_4,
            width_mhz: 20,
            security: Security::open(),
            wifi_gen: None,
            beacon_interval_tu: 100,
            tsf_uptime_secs: None,
            wps: None,
            ie_fingerprint: 0,
            connected: false,
            station_count: None,
            channel_utilization: None,
            country: None,
            vendor_ies: vec![],
            raw_ies: vec![],
        }
    }

    #[test]
    fn wps_oui_and_brand_ie_evidence() {
        let oui = OuiDb::from_csv("h\nMA-L,3C3786,NETGEAR,x\n");
        let mut a = ap("HomeNet", "3C:37:86:00:00:01");
        a.wps = Some(WpsInfo {
            manufacturer: Some("NETGEAR".into()),
            model_name: Some("RAX".into()),
            model_number: Some("50".into()),
            device_name: None,
        });
        a.vendor_ies = vec![[0x00, 0x10, 0x18, 2], [0x00, 0x17, 0xF2, 0x0A]];
        let parsed = ParsedIes { wps_device_type: Some((6, 2)), ..Default::default() };
        let ev = ap_evidence(&a, &parsed, &oui);
        let has = |k: ClaimKind, v: &str| ev.iter().any(|e| e.kind == k && e.value == v);
        assert!(has(ClaimKind::Vendor, "NETGEAR"));
        assert!(has(ClaimKind::Model, "RAX 50"));
        assert!(has(ClaimKind::DeviceType, "Router"));
        assert!(has(ClaimKind::Vendor, "Apple"), "brand vendor IE");
        assert!(!has(ClaimKind::Vendor, "Broadcom"), "chipset IEs are not brand claims");
    }

    #[test]
    fn ssid_patterns() {
        let ev = ap_evidence(&ap("DIRECT-7B-HP OfficeJet", "02:00:00:00:00:01"), &ParsedIes::default(), &OuiDb::default());
        assert!(ev.iter().any(|e| e.value == "Wi-Fi Direct device"));
        let ev = ap_evidence(&ap("Sam's iPhone", "02:00:00:00:00:01"), &ParsedIes::default(), &OuiDb::default());
        assert!(ev.iter().any(|e| e.value == "Phone hotspot"));
    }
}
