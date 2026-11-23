//! Identification evidence for Bluetooth devices.
//!
//! Sources, roughly from strongest to weakest:
//! - vendor protocols inside adverts: Apple Continuity, Microsoft CDP / Swift Pair,
//!   Google Fast Pair, Eddystone / Find Hub, tracker services (Tile, Chipolo, SmartTag)
//! - GAP Appearance and Classic Class of Device
//! - company identifier and member-assigned 16-bit UUIDs
//! - the OUI of public addresses
//! - name patterns

use na_model::{BleInfo, BleUuid, BtClassicInfo, ClaimKind, Evidence, EvidenceSource as Src};

use super::{BtDb, OuiDb};
use crate::parse::ble_ad;

const APPLE: u16 = 0x004C;
const MICROSOFT: u16 = 0x0006;
const GOOGLE: u16 = 0x00E0;

/// Chip makers whose company ID often ships unchanged in third-party firmware.
const CHIPSET_COMPANIES: &[u16] = &[0x0002, 0x000D, 0x000F, 0x001D, 0x0046, 0x0059, 0x005D, 0x02E5];

/// Platform owners whose member UUIDs are sent by other brands' hardware
/// (any Android phone sends Google's), so they don't name the device maker.
const PLATFORM_UUID_OWNERS: &[&str] = &["Google", "Apple", "Microsoft"];

struct Out(Vec<Evidence>);

impl Out {
    fn add(&mut self, src: Src, kind: ClaimKind, value: &str, conf: f32, detail: impl Into<String>) {
        self.0.push(Evidence::new(src, kind, value, conf, detail));
    }
}

/// All identification evidence derivable from one BLE device's merged adverts.
pub fn ble_evidence(b: &BleInfo, db: &BtDb, oui: &OuiDb) -> Vec<Evidence> {
    let mut out = Out(Vec::new());

    if b.address_type == na_model::BleAddressType::Public
        && let Some(vendor) = oui.lookup(b.address)
    {
        let o = b.address.oui();
        let detail = format!("Public address prefix {:02X}:{:02X}:{:02X} = {vendor}", o[0], o[1], o[2]);
        out.add(Src::Oui, ClaimKind::Vendor, vendor, 0.55, detail);
    }

    for m in &b.manufacturer_data {
        match m.company_id {
            APPLE => apple::evidence(&m.data, &mut out),
            MICROSOFT => microsoft::evidence(&m.data, &mut out),
            id => {
                let Some(name) = db.company(id) else { continue };
                let (conf, note) = if CHIPSET_COMPANIES.contains(&id) {
                    (0.25, " (chip maker's ID, often reused by device firmware)")
                } else if id == GOOGLE {
                    (0.45, "")
                } else {
                    (0.5, "")
                };
                out.add(Src::BleAdv, ClaimKind::Vendor, name, conf, format!("Manufacturer data company 0x{id:04X} = {name}{note}"));
            }
        }
    }

    for s in &b.service_data {
        if let Some(u) = s.uuid.as_u16() {
            service_evidence(u, Some(&s.data), db, &mut out);
        }
    }
    for u in b.service_uuids.iter().filter_map(|u| u.as_u16()) {
        if b.service_data_for(u).is_none() {
            service_evidence(u, None, db, &mut out);
        }
    }

    if let Some(a) = b.appearance
        && let Some(t) = appearance_device_type(a)
    {
        let from_advert = ble_ad::structures(&b.raw_ad).any(|s| s.ad_type == 0x19);
        let src = if from_advert { Src::BleAdv } else { Src::BtPaired };
        out.add(src, ClaimKind::DeviceType, t, 0.75, format!("GAP appearance 0x{a:04X} = {}", appearance_label(a)));
    }

    if let Some(name) = &b.local_name {
        name_evidence(name, &mut out);
    }
    out.0
}

/// Evidence for a Bluetooth Classic device.
pub fn classic_evidence(c: &BtClassicInfo, oui: &OuiDb) -> Vec<Evidence> {
    let mut out = Out(Vec::new());
    if let Some(vendor) = oui.lookup(c.address) {
        let o = c.address.oui();
        let detail = format!("Address prefix {:02X}:{:02X}:{:02X} = {vendor}", o[0], o[1], o[2]);
        out.add(Src::Oui, ClaimKind::Vendor, vendor, 0.55, detail);
    }
    if let Some(t) = cod_device_type(c.class_of_device) {
        let detail = format!("Class of Device 0x{:06X} = {}", c.class_of_device, class_of_device_label(c.class_of_device));
        out.add(Src::BtClass, ClaimKind::DeviceType, t, 0.7, detail);
    }
    if let Some(name) = &c.name {
        name_evidence(name, &mut out);
    }
    out.0
}

/// Meaning of well-known 16-bit service UUIDs and service data.
fn service_evidence(uuid: u16, data: Option<&[u8]>, db: &BtDb, out: &mut Out) {
    let hex = format!("0x{uuid:04X}");
    match uuid {
        0xFE2C => {
            // A 3-byte model ID means "discoverable"; longer data is an account-key filter.
            let detail = match data {
                Some(d) if d.len() == 3 => {
                    format!("Google Fast Pair {hex}, model ID {:02X}{:02X}{:02X} (pairing mode)", d[0], d[1], d[2])
                }
                _ => format!("Google Fast Pair {hex} (paired, not discoverable)"),
            };
            out.add(Src::BleAdv, ClaimKind::DeviceType, "Fast Pair accessory", 0.5, detail);
        }
        0xFEAA => match data.and_then(|d| d.first()) {
            Some(0x40 | 0x41) => out.add(Src::BleAdv, ClaimKind::DeviceType, "Tracker tag", 0.6, format!("Google Find Hub network beacon ({hex})")),
            frame => {
                let kind = match frame {
                    Some(0x00) => "UID",
                    Some(0x10) => "URL",
                    Some(0x20) => "TLM",
                    Some(0x30) => "EID",
                    _ => "frame",
                };
                out.add(Src::BleAdv, ClaimKind::DeviceType, "Beacon", 0.6, format!("Eddystone {kind} ({hex})"));
            }
        },
        0xFD6F => out.add(Src::BleAdv, ClaimKind::DeviceType, "Phone", 0.5, format!("Exposure Notification service {hex}")),
        0xFEED | 0xFEEC => {
            out.add(Src::BleAdv, ClaimKind::DeviceType, "Tracker tag", 0.7, format!("Tile service {hex}"));
            out.add(Src::BleAdv, ClaimKind::Vendor, "Tile", 0.6, format!("Tile service {hex}"));
        }
        0xFE33 => {
            out.add(Src::BleAdv, ClaimKind::DeviceType, "Tracker tag", 0.6, format!("Chipolo service {hex}"));
            out.add(Src::BleAdv, ClaimKind::Vendor, "Chipolo", 0.6, format!("Chipolo service {hex}"));
        }
        0xFD5A => {
            out.add(Src::BleAdv, ClaimKind::DeviceType, "Tracker tag", 0.5, format!("Samsung SmartThings Find service {hex} (SmartTag)"));
            out.add(Src::BleAdv, ClaimKind::Vendor, "Samsung Electronics", 0.5, format!("Samsung service {hex}"));
        }
        0xFEF3 | 0xFCF1 => out.add(Src::BleAdv, ClaimKind::Os, "Android", 0.3, format!("Google Play services beacon {hex}")),
        0x180D => out.add(Src::BleAdv, ClaimKind::DeviceType, "Heart-rate sensor", 0.6, format!("Heart Rate service {hex}")),
        0x1816 | 0x1818 => out.add(Src::BleAdv, ClaimKind::DeviceType, "Bike sensor", 0.6, format!("Cycling service {hex}")),
        0x1814 => out.add(Src::BleAdv, ClaimKind::DeviceType, "Fitness sensor", 0.5, format!("Running Speed service {hex}")),
        0x1809 => out.add(Src::BleAdv, ClaimKind::DeviceType, "Thermometer", 0.6, format!("Health Thermometer service {hex}")),
        0x181A => out.add(Src::BleAdv, ClaimKind::DeviceType, "Environmental sensor", 0.5, format!("Environmental Sensing service {hex}")),
        0x1810 => out.add(Src::BleAdv, ClaimKind::DeviceType, "Blood-pressure monitor", 0.6, format!("Blood Pressure service {hex}")),
        0x1808 => out.add(Src::BleAdv, ClaimKind::DeviceType, "Glucose meter", 0.6, format!("Glucose service {hex}")),
        0x181D => out.add(Src::BleAdv, ClaimKind::DeviceType, "Weight scale", 0.6, format!("Weight Scale service {hex}")),
        0x1826 => out.add(Src::BleAdv, ClaimKind::DeviceType, "Fitness machine", 0.6, format!("Fitness Machine service {hex}")),
        0x1812 => out.add(Src::BleAdv, ClaimKind::DeviceType, "HID device", 0.4, format!("Human Interface Device service {hex}")),
        0x184E | 0x1850 | 0x1844 => out.add(Src::BleAdv, ClaimKind::DeviceType, "Headphones", 0.35, format!("LE Audio service {hex}")),
        0x1852 => out.add(Src::BleAdv, ClaimKind::DeviceType, "Audio broadcaster", 0.5, format!("Auracast broadcast announcement {hex}")),
        // Member-assigned UUIDs name the company that registered them.
        0xFC00..=0xFEFF => {
            if let Some(name) = db.uuid16(uuid)
                && !PLATFORM_UUID_OWNERS.contains(&name)
            {
                out.add(Src::BleAdv, ClaimKind::Vendor, name, 0.35, format!("Service {hex} is registered to {name}"));
            }
        }
        _ => {}
    }
}

/// Apple Continuity: `[type][len][payload]` messages inside company-0x004C data.
pub mod apple {
    use na_model::{ClaimKind, EvidenceSource as Src};

    use super::Out;

    pub struct Message<'a> {
        pub kind: u8,
        /// The declared length. It can exceed `data.len()` when an advert is truncated.
        pub declared_len: u8,
        pub data: &'a [u8],
    }

    pub fn messages(mfr: &[u8]) -> impl Iterator<Item = Message<'_>> {
        let mut rest = mfr;
        std::iter::from_fn(move || {
            let (&kind, tail) = rest.split_first()?;
            let (&len, tail) = tail.split_first()?;
            let n = usize::from(len).min(tail.len());
            let (data, next) = tail.split_at(n);
            rest = next;
            Some(Message { kind, declared_len: len, data })
        })
    }

    pub fn message_name(kind: u8) -> &'static str {
        match kind {
            0x02 => "iBeacon",
            0x03 => "AirPrint",
            0x05 => "AirDrop",
            0x06 => "HomeKit",
            0x07 => "Proximity Pairing",
            0x08 => "Hey Siri",
            0x09 => "AirPlay Target",
            0x0A => "AirPlay Source",
            0x0B => "Magic Switch",
            0x0C => "Handoff",
            0x0D => "Tethering Target",
            0x0E => "Tethering Source",
            0x0F => "Nearby Action",
            0x10 => "Nearby Info",
            0x12 => "Find My",
            _ => "Unknown",
        }
    }

    /// AirPods / Beats model from the Proximity Pairing device-model field.
    pub fn audio_model(model: u16) -> Option<&'static str> {
        Some(match model {
            0x0220 => "AirPods",
            0x0F20 => "AirPods (2nd gen)",
            0x1320 => "AirPods (3rd gen)",
            0x0E20 => "AirPods Pro",
            0x1420 => "AirPods Pro (2nd gen)",
            0x0A20 => "AirPods Max",
            0x0320 => "Powerbeats3",
            0x0B20 => "Powerbeats Pro",
            0x0C20 => "Beats Solo Pro",
            0x0520 => "BeatsX",
            0x0620 => "Beats Solo3",
            0x0920 => "Beats Studio3",
            0x1020 => "Beats Flex",
            0x1120 => "Beats Studio Buds",
            0x1220 => "Beats Fit Pro",
            0x1620 => "Beats Studio Buds+",
            0x1720 => "Beats Studio Pro",
            _ => return None,
        })
    }

    pub(super) fn evidence(mfr: &[u8], out: &mut Out) {
        for m in messages(mfr) {
            let name = message_name(m.kind);
            let detail = format!("Apple Continuity 0x{:02X} ({name})", m.kind);
            let mut add = |kind, value: &str, conf| out.add(Src::BleAdv, kind, value, conf, detail.clone());
            // Messages only Apple's own OSes send. iBeacon, HomeKit and Find My
            // also come from third-party hardware, so they don't prove the vendor.
            if matches!(m.kind, 0x05 | 0x07 | 0x08 | 0x09 | 0x0A | 0x0B | 0x0C | 0x0D | 0x0E | 0x0F | 0x10) {
                add(ClaimKind::Vendor, "Apple", 0.6);
            }
            match m.kind {
                0x02 if m.declared_len == 0x15 => add(ClaimKind::DeviceType, "Beacon", 0.7),
                0x06 => add(ClaimKind::DeviceType, "HomeKit accessory", 0.6),
                0x07 => {
                    add(ClaimKind::DeviceType, "Headphones", 0.8);
                    if m.data.len() >= 3 {
                        let model = u16::from_be_bytes([m.data[1], m.data[2]]);
                        if let Some(model_name) = audio_model(model) {
                            out.add(Src::BleAdv, ClaimKind::Model, model_name, 0.85, format!("{detail}, model 0x{model:04X}"));
                        }
                    }
                }
                0x09 => add(ClaimKind::DeviceType, "AirPlay receiver", 0.55),
                0x0B => {
                    add(ClaimKind::DeviceType, "Watch", 0.7);
                    add(ClaimKind::Model, "Apple Watch", 0.6);
                }
                0x0E => {
                    add(ClaimKind::DeviceType, "Phone", 0.7);
                    add(ClaimKind::Os, "iOS", 0.6);
                }
                0x05 | 0x0A | 0x0C | 0x0D | 0x0F | 0x10 => add(ClaimKind::DeviceType, "iPhone/iPad/Mac", 0.5),
                0x12 if m.declared_len >= 25 => {
                    out.add(Src::BleAdv, ClaimKind::DeviceType, "Tracker tag", 0.5, format!("{detail}: separated from its owner (AirTag or lost device)"));
                }
                _ => {}
            }
        }
    }

    /// Short summary for the inspector, e.g. "Nearby Info, Handoff".
    pub fn summary(mfr: &[u8]) -> String {
        let names: Vec<&str> = messages(mfr).map(|m| message_name(m.kind)).collect();
        names.join(", ")
    }
}

/// Microsoft beacons: Connected Devices Platform (CDP) and Swift Pair.
pub mod microsoft {
    use na_model::{ClaimKind, EvidenceSource as Src};

    use super::Out;

    /// (device type, OS, hardware vendor) for a CDP device-type code ([MS-CDP] 2.2.2.2.1).
    pub fn cdp_device(code: u8) -> Option<(&'static str, Option<&'static str>, Option<&'static str>)> {
        Some(match code {
            1 => ("Game console", None, Some("Microsoft")),
            6 => ("Phone", Some("iOS"), Some("Apple")),
            7 => ("Tablet", Some("iPadOS"), Some("Apple")),
            8 => ("Phone", Some("Android"), None),
            9 => ("Desktop PC", Some("Windows"), None),
            11 => ("Phone", Some("Windows"), None),
            12 => ("Computer", Some("Linux"), None),
            13 => ("IoT device", Some("Windows IoT"), None),
            14 => ("Surface Hub", Some("Windows"), Some("Microsoft")),
            15 => ("Laptop", Some("Windows"), None),
            16 => ("Tablet", Some("Windows"), None),
            _ => return None,
        })
    }

    pub(super) fn evidence(data: &[u8], out: &mut Out) {
        match data {
            [0x01, ver_type, ..] => {
                let code = ver_type & 0x1F;
                let Some((dtype, os, vendor)) = cdp_device(code) else { return };
                let detail = format!("Microsoft CDP beacon, device type {code}");
                out.add(Src::BleAdv, ClaimKind::DeviceType, dtype, 0.75, detail.clone());
                if let Some(os) = os {
                    out.add(Src::BleAdv, ClaimKind::Os, os, 0.8, detail.clone());
                }
                if let Some(v) = vendor {
                    out.add(Src::BleAdv, ClaimKind::Vendor, v, 0.5, detail);
                }
            }
            [0x03, sub, _rssi, rest @ ..] => {
                // Sub-scenario 0x01 carries a BR/EDR address and Class of Device before the name.
                let name = if *sub == 0x01 { rest.get(9..).unwrap_or_default() } else { rest };
                let name = String::from_utf8_lossy(name);
                let name = name.trim_matches(|c: char| c == '\0' || c.is_whitespace());
                if !name.is_empty() {
                    out.add(Src::BleAdv, ClaimKind::Name, name, 0.7, "Microsoft Swift Pair beacon (in pairing mode)");
                }
            }
            // Any other Microsoft payload comes from Microsoft hardware (e.g. Xbox controllers).
            [_, ..] => out.add(Src::BleAdv, ClaimKind::Vendor, "Microsoft", 0.4, "Manufacturer data company 0x0006 (Microsoft)"),
            [] => {}
        }
    }

    pub fn summary(data: &[u8]) -> Option<String> {
        match data {
            [0x01, t, ..] => Some(match cdp_device(t & 0x1F) {
                Some((dtype, os, _)) => format!("CDP beacon: {dtype}{}", os.map(|o| format!(" ({o})")).unwrap_or_default()),
                None => format!("CDP beacon, device type {}", t & 0x1F),
            }),
            [0x03, ..] => Some("Swift Pair (pairing mode)".into()),
            _ => None,
        }
    }
}

/// Decoded meaning of manufacturer data, for display.
pub fn describe_manufacturer(company: u16, data: &[u8]) -> Option<String> {
    match company {
        APPLE => Some(format!("Apple Continuity: {}", apple::summary(data))),
        MICROSOFT => microsoft::summary(data),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// GAP appearance (Assigned Numbers §2.6)
// ---------------------------------------------------------------------------

type Sub = (u8, &'static str, Option<&'static str>);
/// (category, name, device type, subcategories)
type Category = (u16, &'static str, Option<&'static str>, &'static [Sub]);

const APPEARANCE: &[Category] = &[
    (0x001, "Phone", Some("Phone"), &[]),
    (0x002, "Computer", Some("Computer"), &[
        (0x01, "Desktop", Some("Desktop PC")),
        (0x02, "Server", Some("Computer")),
        (0x03, "Laptop", Some("Laptop")),
        (0x07, "Tablet", Some("Tablet")),
        (0x09, "All-in-one", Some("Desktop PC")),
        (0x0B, "Convertible", Some("Laptop")),
        (0x0C, "Detachable", Some("Tablet")),
        (0x0E, "Mini PC", Some("Desktop PC")),
    ]),
    (0x003, "Watch", Some("Watch"), &[(0x01, "Sports watch", None), (0x02, "Smartwatch", None)]),
    (0x004, "Clock", Some("Clock"), &[]),
    (0x005, "Display", Some("Display"), &[]),
    (0x006, "Remote control", Some("Remote control"), &[]),
    (0x007, "Eyeglasses", Some("Smart glasses"), &[]),
    (0x008, "Tag", Some("Tracker tag"), &[]),
    (0x009, "Keyring", Some("Tracker tag"), &[]),
    (0x00A, "Media player", Some("Media player"), &[]),
    (0x00B, "Barcode scanner", Some("Barcode scanner"), &[]),
    (0x00C, "Thermometer", Some("Thermometer"), &[]),
    (0x00D, "Heart-rate sensor", Some("Heart-rate sensor"), &[]),
    (0x00E, "Blood pressure", Some("Blood-pressure monitor"), &[]),
    (0x00F, "Human Interface Device", Some("HID device"), &[
        (0x01, "Keyboard", Some("Keyboard")),
        (0x02, "Mouse", Some("Mouse")),
        (0x03, "Joystick", Some("Game controller")),
        (0x04, "Gamepad", Some("Game controller")),
        (0x05, "Digitizer tablet", Some("Drawing tablet")),
        (0x06, "Card reader", Some("Card reader")),
        (0x07, "Digital pen", Some("Stylus")),
        (0x08, "Barcode scanner", Some("Barcode scanner")),
        (0x09, "Touchpad", Some("Touchpad")),
        (0x0A, "Presentation remote", Some("Remote control")),
    ]),
    (0x010, "Glucose meter", Some("Glucose meter"), &[]),
    (0x011, "Running/walking sensor", Some("Fitness sensor"), &[]),
    (0x012, "Cycling", Some("Bike sensor"), &[]),
    (0x013, "Control device", Some("Control device"), &[]),
    (0x014, "Network device", Some("Network device"), &[]),
    (0x015, "Sensor", Some("Sensor"), &[]),
    (0x016, "Light fixture", Some("Light"), &[]),
    (0x017, "Fan", Some("Fan"), &[]),
    (0x018, "HVAC", Some("HVAC"), &[]),
    (0x019, "Air conditioning", Some("Air conditioner"), &[]),
    (0x01A, "Humidifier", Some("Humidifier"), &[]),
    (0x01B, "Heating", Some("Heater"), &[]),
    (0x01C, "Access control", Some("Access control"), &[]),
    (0x01D, "Motorized device", Some("Motorized device"), &[]),
    (0x01E, "Power device", Some("Power device"), &[]),
    (0x01F, "Light source", Some("Light"), &[]),
    (0x020, "Window covering", Some("Window covering"), &[]),
    (0x021, "Audio sink", Some("Speaker"), &[
        (0x01, "Standalone speaker", None),
        (0x02, "Soundbar", Some("Soundbar")),
        (0x03, "Bookshelf speaker", None),
        (0x05, "Speakerphone", None),
    ]),
    (0x022, "Audio source", Some("Audio source"), &[]),
    (0x023, "Motorized vehicle", Some("Vehicle"), &[]),
    (0x024, "Domestic appliance", Some("Appliance"), &[]),
    (0x025, "Wearable audio device", Some("Headphones"), &[
        (0x01, "Earbud", None),
        (0x02, "Headset", None),
        (0x03, "Headphones", None),
        (0x04, "Neck band", None),
    ]),
    (0x026, "Aircraft", Some("Drone"), &[]),
    (0x027, "AV equipment", Some("AV equipment"), &[]),
    (0x028, "Display equipment", Some("TV"), &[]),
    (0x029, "Hearing aid", Some("Hearing aid"), &[]),
    (0x02A, "Gaming", Some("Game console"), &[]),
    (0x02B, "Signage", Some("Signage"), &[]),
    (0x031, "Pulse oximeter", Some("Pulse oximeter"), &[]),
    (0x032, "Weight scale", Some("Weight scale"), &[]),
    (0x033, "Personal mobility device", Some("Mobility device"), &[]),
    (0x034, "Continuous glucose monitor", Some("Glucose meter"), &[]),
    (0x035, "Insulin pump", Some("Insulin pump"), &[]),
    (0x036, "Medication delivery", Some("Medical device"), &[]),
    (0x037, "Spirometer", Some("Medical device"), &[]),
    (0x051, "Outdoor sports activity", Some("Outdoor sports device"), &[]),
];

fn appearance_entry(v: u16) -> Option<(&'static Category, Option<&'static Sub>)> {
    let (cat, sub) = (v >> 6, (v & 0x3F) as u8);
    let entry = APPEARANCE.iter().find(|e| e.0 == cat)?;
    Some((entry, entry.3.iter().find(|s| s.0 == sub)))
}

/// "Human Interface Device / Mouse".
pub fn appearance_label(v: u16) -> String {
    match appearance_entry(v) {
        Some((e, Some(s))) => format!("{} / {}", e.1, s.1),
        Some((e, None)) => e.1.to_owned(),
        None if v == 0 => "Unknown".into(),
        None => format!("category {}", v >> 6),
    }
}

fn appearance_device_type(v: u16) -> Option<&'static str> {
    let (e, s) = appearance_entry(v)?;
    s.and_then(|s| s.2).or(e.2)
}

// ---------------------------------------------------------------------------
// Class of Device (Assigned Numbers §2.8)
// ---------------------------------------------------------------------------

fn cod_parts(cod: u32) -> (u8, u8) {
    (((cod >> 8) & 0x1F) as u8, ((cod >> 2) & 0x3F) as u8)
}

fn cod_major(major: u8) -> &'static str {
    match major {
        0 => "Miscellaneous",
        1 => "Computer",
        2 => "Phone",
        3 => "Network access point",
        4 => "Audio/Video",
        5 => "Peripheral",
        6 => "Imaging",
        7 => "Wearable",
        8 => "Toy",
        9 => "Health",
        _ => "Uncategorized",
    }
}

fn cod_minor(major: u8, minor: u8) -> Option<&'static str> {
    Some(match (major, minor) {
        (1, 1) => "Desktop",
        (1, 2) => "Server",
        (1, 3) => "Laptop",
        (1, 4) | (1, 5) => "Handheld",
        (1, 6) => "Wearable computer",
        (1, 7) => "Tablet",
        (2, 1) => "Cellular",
        (2, 2) => "Cordless",
        (2, 3) => "Smartphone",
        (2, 4) => "Modem / voice gateway",
        (4, 1) => "Wearable headset",
        (4, 2) => "Hands-free",
        (4, 4) => "Microphone",
        (4, 5) => "Loudspeaker",
        (4, 6) => "Headphones",
        (4, 7) => "Portable audio",
        (4, 8) => "Car audio",
        (4, 9) => "Set-top box",
        (4, 10) => "HiFi audio",
        (4, 12) => "Video camera",
        (4, 13) => "Camcorder",
        (4, 14) => "Video monitor",
        (4, 15) => "Video display and loudspeaker",
        (4, 16) => "Video conferencing",
        (4, 18) => "Gaming / toy",
        (7, 1) => "Wristwatch",
        (7, 2) => "Pager",
        (7, 3) => "Jacket",
        (7, 4) => "Helmet",
        (7, 5) => "Glasses",
        (8, 1) => "Robot",
        (8, 2) => "Vehicle",
        (8, 3) => "Doll",
        (8, 4) => "Controller",
        (8, 5) => "Game",
        (5, m) => match (m >> 4, m & 0x0F) {
            (_, 1) => "Joystick",
            (_, 2) => "Gamepad",
            (_, 3) => "Remote control",
            (_, 5) => "Digitizer tablet",
            (_, 7) => "Digital pen",
            (1, _) => "Keyboard",
            (2, _) => "Pointing device",
            (3, _) => "Keyboard + pointing device",
            _ => return None,
        },
        (6, m) if m & 0x20 != 0 => "Printer",
        (6, m) if m & 0x08 != 0 => "Camera",
        (6, m) if m & 0x10 != 0 => "Scanner",
        (6, m) if m & 0x04 != 0 => "Display",
        _ => return None,
    })
}

/// "Audio/Video · Wearable headset".
pub fn class_of_device_label(cod: u32) -> String {
    let (major, minor) = cod_parts(cod);
    match cod_minor(major, minor) {
        Some(m) => format!("{} · {m}", cod_major(major)),
        None => cod_major(major).to_owned(),
    }
}

/// Service classes advertised in the top 11 bits.
pub fn cod_services(cod: u32) -> Vec<&'static str> {
    [
        (13, "Limited discoverable"),
        (14, "LE Audio"),
        (16, "Positioning"),
        (17, "Networking"),
        (18, "Rendering"),
        (19, "Capturing"),
        (20, "Object transfer"),
        (21, "Audio"),
        (22, "Telephony"),
        (23, "Information"),
    ]
    .into_iter()
    .filter(|(bit, _)| cod & (1 << bit) != 0)
    .map(|(_, n)| n)
    .collect()
}

fn cod_device_type(cod: u32) -> Option<&'static str> {
    if cod == 0 {
        return None;
    }
    let (major, minor) = cod_parts(cod);
    Some(match (major, cod_minor(major, minor)) {
        (1, Some("Desktop")) => "Desktop PC",
        (1, Some("Laptop")) => "Laptop",
        (1, Some("Tablet")) => "Tablet",
        (1, _) => "Computer",
        (2, _) => "Phone",
        (3, _) => "Network device",
        (4, Some("Wearable headset" | "Headphones")) => "Headphones",
        (4, Some("Hands-free")) => "Hands-free device",
        (4, Some("Loudspeaker" | "Portable audio" | "HiFi audio")) => "Speaker",
        (4, Some("Car audio")) => "Car audio",
        (4, Some("Set-top box")) => "Set-top box",
        (4, Some("Video monitor" | "Video display and loudspeaker")) => "TV",
        (4, Some("Gaming / toy")) => "Game console",
        (4, _) => "Audio/video device",
        (5, Some("Joystick" | "Gamepad")) => "Game controller",
        (5, Some("Remote control")) => "Remote control",
        (5, Some("Keyboard" | "Keyboard + pointing device")) => "Keyboard",
        (5, Some("Pointing device")) => "Mouse",
        (5, _) => "Peripheral",
        (6, Some("Printer")) => "Printer",
        (6, Some("Camera")) => "Camera",
        (6, Some("Scanner")) => "Scanner",
        (6, _) => "Imaging device",
        (7, Some("Wristwatch")) => "Watch",
        (7, Some("Glasses")) => "Smart glasses",
        (7, _) => "Wearable",
        (8, _) => "Toy",
        (9, _) => "Health device",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Name patterns
// ---------------------------------------------------------------------------

enum Pat {
    Prefix(&'static str),
    Contains(&'static str),
}

/// (pattern, vendor, device type, model). Checked case-insensitively; every match adds evidence.
type NameRule = (Pat, Option<&'static str>, Option<&'static str>, Option<&'static str>);

const NAME_RULES: &[NameRule] = {
    use Pat::*;
    &[
        (Prefix("iphone"), Some("Apple"), Some("Phone"), None),
        (Prefix("ipad"), Some("Apple"), Some("Tablet"), None),
        (Contains("macbook"), Some("Apple"), Some("Laptop"), None),
        (Contains("apple watch"), Some("Apple"), Some("Watch"), Some("Apple Watch")),
        (Contains("airpods"), Some("Apple"), Some("Headphones"), None),
        (Prefix("beats"), Some("Apple"), Some("Headphones"), None),
        (Contains("galaxy buds"), Some("Samsung Electronics"), Some("Headphones"), None),
        (Contains("galaxy watch"), Some("Samsung Electronics"), Some("Watch"), None),
        (Prefix("[tv] samsung"), Some("Samsung Electronics"), Some("TV"), None),
        (Prefix("[lg]"), Some("LG Electronics"), Some("TV"), None),
        (Prefix("pixel buds"), Some("Google"), Some("Headphones"), Some("Pixel Buds")),
        (Prefix("pixel watch"), Some("Google"), Some("Watch"), Some("Pixel Watch")),
        (Prefix("wh-1000xm"), Some("Sony"), Some("Headphones"), None),
        (Prefix("wf-1000xm"), Some("Sony"), Some("Headphones"), None),
        (Contains("bose"), Some("Bose"), None, None),
        (Prefix("jbl"), Some("JBL"), None, None),
        (Prefix("jabra"), Some("Jabra"), Some("Headphones"), None),
        (Prefix("soundcore"), Some("Anker"), None, None),
        (Prefix("nothing ear"), Some("Nothing"), Some("Headphones"), None),
        (Prefix("oneplus buds"), Some("OnePlus"), Some("Headphones"), None),
        (Prefix("cmf "), Some("Nothing"), None, None),
        (Prefix("xbox wireless controller"), Some("Microsoft"), Some("Game controller"), None),
        (Contains("dualsense"), Some("Sony"), Some("Game controller"), Some("DualSense")),
        (Prefix("surface"), Some("Microsoft"), None, None),
        (Prefix("mx master"), Some("Logitech"), Some("Mouse"), None),
        (Prefix("mx anywhere"), Some("Logitech"), Some("Mouse"), None),
        (Prefix("mx keys"), Some("Logitech"), Some("Keyboard"), None),
        (Prefix("logi"), Some("Logitech"), None, None),
        (Prefix("dell "), Some("Dell"), None, None),
        (Prefix("tile"), Some("Tile"), Some("Tracker tag"), None),
        (Contains("smart band"), None, Some("Fitness band"), None),
        (Prefix("mi band"), Some("Xiaomi"), Some("Fitness band"), None),
        (Prefix("mi smart band"), Some("Xiaomi"), Some("Fitness band"), None),
        (Prefix("amazfit"), Some("Zepp"), Some("Watch"), None),
        (Prefix("fitbit"), Some("Fitbit"), Some("Fitness band"), None),
        (Prefix("forerunner"), Some("Garmin"), Some("Watch"), None),
        (Prefix("fenix"), Some("Garmin"), Some("Watch"), None),
        (Prefix("venu"), Some("Garmin"), Some("Watch"), None),
        (Prefix("vivoactive"), Some("Garmin"), Some("Watch"), None),
        (Prefix("gvh5"), Some("Govee"), Some("Thermometer"), None),
        (Prefix("govee"), Some("Govee"), None, None),
        (Prefix("echo "), Some("Amazon"), Some("Smart speaker"), None),
        (Prefix("kindle"), Some("Amazon"), Some("E-reader"), None),
        (Prefix("hue "), Some("Signify Netherlands"), Some("Light"), None),
        (Contains("mouse"), None, Some("Mouse"), None),
        (Contains("keyboard"), None, Some("Keyboard"), None),
        (Contains("buds"), None, Some("Headphones"), None),
        (Contains("headphone"), None, Some("Headphones"), None),
        (Contains("headset"), None, Some("Headphones"), None),
        (Contains("speaker"), None, Some("Speaker"), None),
        (Contains("watch"), None, Some("Watch"), None),
        (Contains("laptop"), None, Some("Laptop"), None),
        (Prefix("desktop-"), None, Some("Desktop PC"), None),
        (Contains("[tv]"), None, Some("TV"), None),
    ]
};

fn name_evidence(raw: &str, out: &mut Out) {
    // BLE companions of classic devices are often named "LE_<name>".
    let name = raw.strip_prefix("LE_").or_else(|| raw.strip_prefix("LE-")).unwrap_or(raw);
    let lower = name.to_lowercase();
    for (pat, vendor, dtype, model) in NAME_RULES {
        let hit = match pat {
            Pat::Prefix(p) => lower.starts_with(p),
            Pat::Contains(p) => lower.contains(p),
        };
        if !hit {
            continue;
        }
        let why = format!("Name \"{name}\" matches a known pattern");
        for (kind, value, conf) in [
            (ClaimKind::Vendor, vendor, 0.45),
            (ClaimKind::DeviceType, dtype, 0.45),
            (ClaimKind::Model, model, 0.5),
        ] {
            if let Some(v) = value {
                out.add(Src::Heuristic, kind, v, conf, why.clone());
            }
        }
    }
    if is_tesla_beacon(name) {
        let why = "Name matches Tesla's phone-key beacon (S + 16 hex + C/D/P/R)";
        out.add(Src::Heuristic, ClaimKind::Vendor, "Tesla", 0.6, why);
        out.add(Src::Heuristic, ClaimKind::DeviceType, "Vehicle", 0.6, why);
    }
}

/// Tesla cars advertise `S<16 hex chars><C|D|P|R>`.
fn is_tesla_beacon(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 18
        && b[0] == b'S'
        && b[1..17].iter().all(u8::is_ascii_hexdigit)
        && matches!(b[17], b'C' | b'D' | b'P' | b'R')
}

/// "0x180D Heart Rate": the UUID with its registered name, for display.
pub fn uuid_label(u: BleUuid, db: &BtDb) -> String {
    match u.as_u16().and_then(|v| db.uuid16(v)) {
        Some(name) => format!("{u} {name}"),
        None => u.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use na_model::{BleAddressType, ManufacturerData, ServiceData};

    use super::*;

    fn has(ev: &[Evidence], kind: ClaimKind, value: &str) -> bool {
        ev.iter().any(|e| e.kind == kind && e.value == value)
    }

    fn ble(mfr: &[(u16, &[u8])], service_data: &[(u16, &[u8])]) -> BleInfo {
        BleInfo {
            address: "5A:11:22:33:44:55".parse().unwrap(),
            address_type: BleAddressType::RandomResolvable,
            manufacturer_data: mfr.iter().map(|(c, d)| ManufacturerData { company_id: *c, data: d.to_vec() }).collect(),
            service_data: service_data
                .iter()
                .map(|(u, d)| ServiceData { uuid: BleUuid::U16(*u), data: d.to_vec() })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn apple_continuity() {
        // Seen in the wild: Nearby Info.
        let ev = ble_evidence(&ble(&[(APPLE, &[0x10, 0x07, 0x2E, 0x1F, 0x06, 0x7D, 0x0E, 0xBA, 0x08])], &[]), &BtDb::builtin(), &OuiDb::default());
        assert!(has(&ev, ClaimKind::Vendor, "Apple"));
        assert!(has(&ev, ClaimKind::DeviceType, "iPhone/iPad/Mac"));

        // AirPods Pro proximity pairing.
        let pp = [0x07, 0x19, 0x01, 0x0E, 0x20, 0x55, 0xAA, 0xB5, 0x31];
        let ev = ble_evidence(&ble(&[(APPLE, &pp)], &[]), &BtDb::builtin(), &OuiDb::default());
        assert!(has(&ev, ClaimKind::Model, "AirPods Pro"));
        assert!(has(&ev, ClaimKind::DeviceType, "Headphones"));

        // Find My, separated (25-byte payload). Third-party accessories use it too: no vendor claim.
        let mut fm = vec![0x12, 0x19, 0x10];
        fm.extend([0u8; 24]);
        let ev = ble_evidence(&ble(&[(APPLE, &fm)], &[]), &BtDb::builtin(), &OuiDb::default());
        assert!(has(&ev, ClaimKind::DeviceType, "Tracker tag"));
        assert!(!has(&ev, ClaimKind::Vendor, "Apple"));
        assert_eq!(apple::summary(&[0x10, 0x02, 0, 0, 0x0C, 0x01, 0]), "Nearby Info, Handoff");
    }

    #[test]
    fn microsoft_cdp_and_swift_pair() {
        // Seen in the wild: 06 00 | 01 0F 20 22 … → Windows laptop.
        let ev = ble_evidence(&ble(&[(MICROSOFT, &[0x01, 0x0F, 0x20, 0x22, 0x17, 0xBE])], &[]), &BtDb::builtin(), &OuiDb::default());
        assert!(has(&ev, ClaimKind::DeviceType, "Laptop"));
        assert!(has(&ev, ClaimKind::Os, "Windows"));
        assert!(!ev.iter().any(|e| e.kind == ClaimKind::Vendor), "CDP comes from any PC brand");

        let mut sp = vec![0x03, 0x00, 0x80];
        sp.extend(b"Surface Pen");
        let ev = ble_evidence(&ble(&[(MICROSOFT, &sp)], &[]), &BtDb::builtin(), &OuiDb::default());
        assert!(has(&ev, ClaimKind::Name, "Surface Pen"));
    }

    #[test]
    fn trackers_and_google_services() {
        let db = BtDb::builtin();
        let ev = ble_evidence(&ble(&[], &[(0xFEED, &[0x02, 0x00, 0xCE])]), &db, &OuiDb::default());
        assert!(has(&ev, ClaimKind::DeviceType, "Tracker tag"));
        assert!(has(&ev, ClaimKind::Vendor, "Tile"));

        let ev = ble_evidence(&ble(&[], &[(0xFE2C, &[0x12, 0x34, 0x56])]), &db, &OuiDb::default());
        assert!(ev.iter().any(|e| e.value == "Fast Pair accessory" && e.detail.contains("123456")));

        // Google's member UUIDs come from any Android phone, so they don't claim "Google" as maker.
        let ev = ble_evidence(&ble(&[], &[(0xFCF1, &[0x04, 0x67])]), &db, &OuiDb::default());
        assert!(has(&ev, ClaimKind::Os, "Android"));
        assert!(!has(&ev, ClaimKind::Vendor, "Google"));

        let ev = ble_evidence(&ble(&[], &[(0xFEAA, &[0x41, 0x00])]), &db, &OuiDb::default());
        assert!(ev.iter().any(|e| e.value == "Tracker tag" && e.detail.contains("Find Hub")));
    }

    #[test]
    fn appearance_and_public_address_oui() {
        let mut b = ble(&[], &[]);
        b.appearance = Some(962); // seen in the wild: Dell MS5120W via the OS
        b.connected = true;
        let ev = ble_evidence(&b, &BtDb::builtin(), &OuiDb::default());
        let mouse = ev.iter().find(|e| e.value == "Mouse").expect("mouse");
        assert_eq!(mouse.source, Src::BtPaired, "appearance came from the OS, not an advert");
        assert_eq!(appearance_label(962), "Human Interface Device / Mouse");
        assert_eq!(appearance_label(0x0040), "Phone");

        b.address = "3C:37:86:00:00:01".parse().unwrap();
        b.address_type = BleAddressType::Public;
        let oui = OuiDb::from_csv("h\nMA-L,3C3786,NETGEAR,x\n");
        assert!(has(&ble_evidence(&b, &BtDb::builtin(), &oui), ClaimKind::Vendor, "NETGEAR"));
        b.address_type = BleAddressType::RandomStatic;
        assert!(!has(&ble_evidence(&b, &BtDb::builtin(), &oui), ClaimKind::Vendor, "NETGEAR"));
    }

    #[test]
    fn class_of_device() {
        // Seen in the wild: Galaxy Buds Pro 0x240404, a laptop 0x2E410C.
        assert_eq!(class_of_device_label(0x240404), "Audio/Video · Wearable headset");
        assert_eq!(cod_services(0x240404), vec!["Rendering", "Audio"]);
        assert_eq!(class_of_device_label(0x2E410C), "Computer · Laptop");
        let c = BtClassicInfo {
            address: "80:9F:F5:00:12:34".parse().unwrap(),
            name: Some("Galaxy Buds Pro (1234)".into()),
            class_of_device: 0x240404,
            ..Default::default()
        };
        let ev = classic_evidence(&c, &OuiDb::default());
        assert!(ev.iter().any(|e| e.value == "Headphones" && e.source == Src::BtClass));
        assert!(has(&ev, ClaimKind::Vendor, "Samsung Electronics"));
        assert_eq!(class_of_device_label(0x002540), "Peripheral · Keyboard");
        assert_eq!(cod_device_type(0x000580), Some("Mouse"));
    }

    #[test]
    fn name_patterns() {
        let mut out = Out(Vec::new());
        name_evidence("LE_WH-1000XM4", &mut out);
        assert!(has(&out.0, ClaimKind::Vendor, "Sony"));
        let mut out = Out(Vec::new());
        name_evidence("S7b3c1a9f2e4d5c6aC", &mut out);
        assert!(has(&out.0, ClaimKind::DeviceType, "Vehicle"));
        assert!(!is_tesla_beacon("S7b3c1a9f2e4d5c6aX"));
    }
}
