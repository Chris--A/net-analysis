//! IEEE MAC vendor-prefix registry (MA-L, a.k.a. OUI).
//!
//! The registry CSV is not bundled. `scripts/fetch-data.ps1` or `scripts/fetch-data.sh`
//! download it to `data/oui.csv`. Set `NA_DATA_DIR` to use another directory.
//! Without it, identification still works but loses MAC-vendor evidence.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use na_model::MacAddr;
use tracing::{info, warn};

#[derive(Default)]
pub struct OuiDb {
    map: HashMap<[u8; 3], String>,
    source: Option<PathBuf>,
}

impl OuiDb {
    /// Search the usual places for `oui.csv`, or return an empty registry.
    pub fn load_default() -> Self {
        for dir in super::data_dirs() {
            let path = dir.join("oui.csv");
            if !path.is_file() {
                continue;
            }
            match Self::load(&path) {
                Ok(db) => {
                    info!(entries = db.len(), path = %path.display(), "loaded OUI registry");
                    return db;
                }
                Err(e) => warn!(path = %path.display(), error = %e, "failed to read OUI registry"),
            }
        }
        info!("no OUI registry found (run scripts/fetch-data); MAC vendor lookup disabled");
        Self::default()
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut db = Self::from_csv(&text);
        db.source = Some(path.to_owned());
        Ok(db)
    }

    /// Parse the IEEE `oui.csv` format: `Registry,Assignment,Organization Name,Organization Address`.
    pub fn from_csv(text: &str) -> Self {
        let mut map = HashMap::new();
        for line in text.lines().skip(1) {
            let fields = split_csv(line);
            let (Some(hex), Some(org)) = (fields.get(1), fields.get(2)) else {
                continue;
            };
            let hex = hex.trim();
            if hex.len() != 6 {
                continue;
            }
            let Ok(v) = u32::from_str_radix(hex, 16) else {
                continue;
            };
            let b = v.to_be_bytes();
            map.insert([b[1], b[2], b[3]], short_name(org));
        }
        Self { map, source: None }
    }

    /// Vendor for a globally-administered MAC. Randomized / locally-administered addresses have none.
    pub fn lookup(&self, mac: MacAddr) -> Option<&str> {
        if mac.is_locally_administered() {
            return None;
        }
        self.map.get(&mac.oui()).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }
}

/// Minimal CSV field splitter supporting quoted fields and `""` escapes.
fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => fields.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

/// "TP-LINK TECHNOLOGIES CO.,LTD." → "TP-LINK". "Apple, Inc." → "Apple".
pub fn short_name(org: &str) -> String {
    const SUFFIXES: &[&str] = &[
        "co.,ltd.", "co.,ltd", "co., ltd.", "co., ltd", "co.ltd", "co.ltd.", "inc.", "inc", "ltd.",
        "ltd", "limited", "llc", "l.l.c.", "gmbh", "corporation", "corporate", "corp.", "corp",
        "co.", "co", "s.a.", "s.a", "ag", "b.v.", "bv", "a/s", "ab", "oy", "s.r.l.", "srl", "pty",
        "plc", "technologies", "technology", "international", "holdings",
    ];
    let original = org.trim();
    let mut s = original.to_owned();
    loop {
        let lower = s.to_lowercase();
        let Some(suffix) = SUFFIXES.iter().find(|suf| {
            lower.ends_with(*suf) && {
                let before = lower[..lower.len() - suf.len()].chars().last();
                matches!(before, Some(' ' | ','))
            }
        }) else {
            break;
        };
        s.truncate(s.len() - suffix.len());
        let trimmed = s.trim_end_matches([' ', ',']).to_owned();
        if trimmed.is_empty() {
            break;
        }
        s = trimmed;
    }
    if s.is_empty() { original.to_owned() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = "Registry,Assignment,Organization Name,Organization Address\n\
        MA-L,3C3786,NETGEAR,350 East Plumeria Drive San Jose CA US 95134 \n\
        MA-L,F0189,Broken Row,Nowhere\n\
        MA-L,ACBC32,\"Apple, Inc.\",1 Infinite Loop Cupertino CA US 95014 \n\
        MA-L,50C7BF,\"TP-LINK TECHNOLOGIES CO.,LTD.\",\"Building 24 (floors 1,3,4,5) Shenzhen\"\n";

    #[test]
    fn parses_ieee_csv_with_quotes() {
        let db = OuiDb::from_csv(CSV);
        assert_eq!(db.len(), 3, "malformed assignment skipped");
        assert_eq!(db.lookup("3C:37:86:12:34:56".parse().unwrap()), Some("NETGEAR"));
        assert_eq!(db.lookup("AC:BC:32:00:00:01".parse().unwrap()), Some("Apple"));
        assert_eq!(db.lookup("50:C7:BF:00:00:01".parse().unwrap()), Some("TP-LINK"));
    }

    #[test]
    fn randomized_macs_have_no_vendor() {
        let db = OuiDb::from_csv(CSV);
        // 3E = 3C with the locally-administered bit set.
        assert_eq!(db.lookup("3E:37:86:12:34:56".parse().unwrap()), None);
    }

    #[test]
    fn shortens_corporate_suffixes() {
        assert_eq!(short_name("Samsung Electronics Co.,Ltd"), "Samsung Electronics");
        assert_eq!(short_name("Intel Corporate"), "Intel");
        assert_eq!(short_name("Cisco Systems, Inc"), "Cisco Systems");
        assert_eq!(short_name("Huawei Technologies Co.,Ltd"), "Huawei");
        assert_eq!(short_name("NETGEAR"), "NETGEAR");
        assert_eq!(short_name("Technology"), "Technology", "never shortens to nothing");
    }
}
