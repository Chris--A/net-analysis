//! Bluetooth SIG assigned numbers: company identifiers and 16-bit UUIDs.
//!
//! The YAML files come from the SIG's public `assigned_numbers` repository.
//! `scripts/fetch-data` downloads them to `data/`. A small built-in table
//! covers the most common entries, so identification degrades gracefully without them.

use std::collections::HashMap;
use std::path::PathBuf;

use tracing::{info, warn};

use super::{data_dirs, short_name};

const COMPANY_FILE: &str = "company_identifiers.yaml";
const MEMBER_UUID_FILE: &str = "member_uuids.yaml";
const SERVICE_UUID_FILE: &str = "service_uuids.yaml";

const BUILTIN_COMPANIES: &[(u16, &str)] = &[
    (0x0002, "Intel"),
    (0x0006, "Microsoft"),
    (0x000D, "Texas Instruments"),
    (0x000F, "Broadcom"),
    (0x001D, "Qualcomm"),
    (0x0046, "MediaTek"),
    (0x004C, "Apple"),
    (0x0059, "Nordic Semiconductor"),
    (0x005D, "Realtek"),
    (0x0075, "Samsung Electronics"),
    (0x0087, "Garmin"),
    (0x009E, "Bose"),
    (0x00C4, "LG Electronics"),
    (0x00E0, "Google"),
    (0x012D, "Sony"),
    (0x0157, "Huami"),
    (0x0171, "Amazon"),
    (0x02E5, "Espressif Systems"),
    (0x038F, "Xiaomi"),
    (0x0499, "Ruuvi Innovations"),
];

const BUILTIN_UUIDS: &[(u16, &str)] = &[
    (0x1800, "GAP"),
    (0x1801, "GATT"),
    (0x1808, "Glucose"),
    (0x1809, "Health Thermometer"),
    (0x180A, "Device Information"),
    (0x180D, "Heart Rate"),
    (0x180F, "Battery"),
    (0x1810, "Blood Pressure"),
    (0x1812, "Human Interface Device"),
    (0x1814, "Running Speed and Cadence"),
    (0x1816, "Cycling Speed and Cadence"),
    (0x1818, "Cycling Power"),
    (0x181A, "Environmental Sensing"),
    (0x181D, "Weight Scale"),
    (0x1826, "Fitness Machine"),
    (0x1844, "Volume Control"),
    (0x184E, "Audio Stream Control"),
    (0x1850, "Published Audio Capabilities"),
    (0x1852, "Broadcast Audio Announcement"),
    (0xFCF1, "Google"),
    (0xFD59, "Samsung Electronics"),
    (0xFD5A, "Samsung Electronics"),
    (0xFD6F, "Apple"),
    (0xFE0F, "Signify Netherlands"),
    (0xFE2C, "Google"),
    (0xFE33, "Chipolo"),
    (0xFE95, "Xiaomi"),
    (0xFE9F, "Google"),
    (0xFEAA, "Google"),
    (0xFEEC, "Tile"),
    (0xFEED, "Tile"),
    (0xFEF3, "Google"),
];

pub struct BtDb {
    companies: HashMap<u16, String>,
    /// SIG services and member-assigned 16-bit UUIDs (0xFCxx–0xFExx).
    uuids: HashMap<u16, String>,
    pub sources: Vec<PathBuf>,
}

impl Default for BtDb {
    fn default() -> Self {
        Self::builtin()
    }
}

impl BtDb {
    pub fn builtin() -> Self {
        Self {
            companies: BUILTIN_COMPANIES.iter().map(|&(k, v)| (k, v.to_owned())).collect(),
            uuids: BUILTIN_UUIDS.iter().map(|&(k, v)| (k, v.to_owned())).collect(),
            sources: Vec::new(),
        }
    }

    /// Built-in table plus whichever SIG YAML files are found in the data directories.
    pub fn load_default() -> Self {
        let mut db = Self::builtin();
        let dirs = data_dirs();
        for (file, key) in [(COMPANY_FILE, "value"), (MEMBER_UUID_FILE, "uuid"), (SERVICE_UUID_FILE, "uuid")] {
            let Some(path) = dirs.iter().map(|d| d.join(file)).find(|p| p.is_file()) else {
                continue;
            };
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let entries = parse_assigned(&text, key);
                    let target = if key == "value" { &mut db.companies } else { &mut db.uuids };
                    for (id, name) in entries {
                        if let Ok(id) = u16::try_from(id) {
                            target.insert(id, name);
                        }
                    }
                    db.sources.push(path);
                }
                Err(e) => warn!(path = %path.display(), error = %e, "failed to read Bluetooth SIG data"),
            }
        }
        if db.sources.is_empty() {
            info!("no Bluetooth SIG data found (run scripts/fetch-data); using built-in table");
        } else {
            info!(companies = db.companies.len(), uuids = db.uuids.len(), "loaded Bluetooth SIG assigned numbers");
        }
        db
    }

    pub fn company(&self, id: u16) -> Option<&str> {
        self.companies.get(&id).map(String::as_str)
    }

    pub fn uuid16(&self, uuid: u16) -> Option<&str> {
        self.uuids.get(&uuid).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.companies.len() + self.uuids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Parse the SIG's simple YAML lists:
/// ```yaml
///   - value: 0x004C        (or `uuid: 0xFEED`)
///     name: 'Apple, Inc.'
/// ```
fn parse_assigned(text: &str, key: &str) -> Vec<(u32, String)> {
    let prefix = format!("{key}:");
    let mut out = Vec::new();
    let mut pending: Option<u32> = None;
    for line in text.lines() {
        let t = line.trim_start().trim_start_matches("- ").trim();
        if let Some(v) = t.strip_prefix(&prefix) {
            let v = v.trim();
            pending = v
                .strip_prefix("0x")
                .or_else(|| v.strip_prefix("0X"))
                .and_then(|h| u32::from_str_radix(h, 16).ok());
        } else if let (Some(id), Some(name)) = (pending, t.strip_prefix("name:")) {
            out.push((id, clean_name(name)));
            pending = None;
        }
    }
    out
}

/// Unquote and shorten: `'Apple, Inc.'` → `Apple`; drops "(formerly …)" notes.
fn clean_name(raw: &str) -> String {
    let s = raw.trim();
    let s = if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        s[1..s.len() - 1].replace("''", "'")
    } else if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].replace("\\\"", "\"")
    } else {
        s.to_owned()
    };
    let s = match s.find(" (") {
        Some(i) if s.ends_with(')') && i > 0 => s[..i].to_owned(),
        _ => s,
    };
    short_name(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sig_yaml_variants() {
        let companies = "company_identifiers:\n\n  - value: 0x004C\n    name: 'Apple, Inc.'\n\n  - value: 0x1152\n    name: 'Rock ''n'' Roll Ltd.'\n";
        let parsed = parse_assigned(companies, "value");
        assert_eq!(parsed, vec![(0x004C, "Apple".into()), (0x1152, "Rock 'n' Roll".into())]);

        let members = "# licence\nuuids:\n - uuid: 0xFEED\n   name: \"Tile, Inc.\"\n - uuid: 0xFE0F\n   name: Signify Netherlands B.V. (formerly Philips Lighting B.V.)\n - uuid: 0x1800\n   name: GAP\n   id: org.bluetooth.service.gap\n";
        let parsed = parse_assigned(members, "uuid");
        assert_eq!(parsed[0], (0xFEED, "Tile".into()));
        assert_eq!(parsed[1], (0xFE0F, "Signify Netherlands".into()));
        assert_eq!(parsed[2], (0x1800, "GAP".into()));
    }

    #[test]
    fn builtin_covers_the_big_names() {
        let db = BtDb::builtin();
        assert_eq!(db.company(0x004C), Some("Apple"));
        assert_eq!(db.company(0x0006), Some("Microsoft"));
        assert_eq!(db.uuid16(0xFEED), Some("Tile"));
        assert_eq!(db.uuid16(0x180D), Some("Heart Rate"));
        assert_eq!(db.company(0xFFFF), None);
    }
}
