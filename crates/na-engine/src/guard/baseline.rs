//! Trusted-network baselines: what each network's legitimate access points look
//! like. Kept in a small JSON file so they survive restarts.

use std::collections::BTreeMap;
use std::path::PathBuf;

use na_model::{ApInfo, ExpectedSecurity, KnownBss, Millis, NetworkBaseline, SecurityClass, TrustSource};
use na_platform::wifi::SavedNetwork;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const FILE_VERSION: u32 = 1;
/// Fingerprints remembered per access point (firmware updates add new ones).
const MAX_FINGERPRINTS: usize = 4;

#[derive(Serialize, Deserialize)]
struct BaselineFile {
    version: u32,
    networks: Vec<NetworkBaseline>,
}

pub struct Baselines {
    networks: BTreeMap<String, NetworkBaseline>,
    path: Option<PathBuf>,
    /// Changed since the last save.
    dirty: bool,
}

impl Baselines {
    pub fn in_memory() -> Self {
        Self { networks: BTreeMap::new(), path: None, dirty: false }
    }

    /// Load from `path`. A missing file starts empty. An unreadable one is set
    /// aside as `*.bad` rather than overwritten.
    pub fn load(path: PathBuf) -> Self {
        let mut b = Self { path: Some(path.clone()), ..Self::in_memory() };
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<BaselineFile>(&text) {
                Ok(f) => {
                    b.networks = f.networks.into_iter().map(|n| (n.ssid.clone(), n)).collect();
                    info!(networks = b.networks.len(), path = %path.display(), "loaded network baselines");
                }
                Err(e) => {
                    let bad = path.with_extension("json.bad");
                    warn!(error = %e, "unreadable baseline file; moved to {}", bad.display());
                    let _ = std::fs::rename(&path, bad);
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(error = %e, path = %path.display(), "cannot read baseline file"),
        }
        b
    }

    /// Write the file if anything changed (atomically: temp file, then rename).
    pub fn save(&mut self) {
        let Some(path) = &self.path else { return };
        if !self.dirty {
            return;
        }
        let file = BaselineFile { version: FILE_VERSION, networks: self.networks.values().cloned().collect() };
        let result = (|| -> std::io::Result<()> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let tmp = path.with_extension("json.tmp");
            std::fs::write(&tmp, serde_json::to_vec_pretty(&file)?)?;
            std::fs::rename(&tmp, path)
        })();
        match result {
            Ok(()) => self.dirty = false,
            Err(e) => warn!(error = %e, path = %path.display(), "cannot save network baselines"),
        }
    }

    pub fn get(&self, ssid: &str) -> Option<&NetworkBaseline> {
        self.networks.get(ssid)
    }

    pub fn all(&self) -> impl Iterator<Item = &NetworkBaseline> {
        self.networks.values()
    }

    /// Seed expectations from the OS's saved profiles. Profiles that were deleted
    /// in the OS stop counting, but access points learned for them are kept.
    pub fn import_saved(&mut self, saved: &[SavedNetwork], now: Millis) -> usize {
        let mut imported = 0;
        for s in saved {
            let Some(class) = profile_class(&s.auth) else { continue };
            let expected = Some(ExpectedSecurity { class, auth: s.auth.clone() });
            let n = self.networks.entry(s.ssid.clone()).or_insert_with(|| NetworkBaseline::new(&s.ssid, now));
            if n.expected != expected || !n.sources.contains(&TrustSource::SavedProfile) {
                n.expected = expected;
                n.add_source(TrustSource::SavedProfile);
                self.dirty = true;
            }
            imported += 1;
        }
        let still_saved = |ssid: &str| saved.iter().any(|s| s.ssid == ssid);
        let before = self.networks.len();
        self.networks.retain(|ssid, n| {
            if !n.sources.contains(&TrustSource::SavedProfile) || still_saved(ssid) {
                return true;
            }
            n.sources.retain(|s| *s != TrustSource::SavedProfile);
            n.expected = None;
            !n.sources.is_empty()
        });
        self.dirty |= self.networks.len() != before;
        imported
    }

    /// Remember `ap` as a legitimate access point of its network. Returns true if
    /// that changed anything worth saving.
    pub fn learn(&mut self, ap: &ApInfo, source: TrustSource, now: Millis) -> bool {
        if ap.ssid.is_empty() {
            return false;
        }
        let n = self.networks.entry(ap.ssid.clone()).or_insert_with(|| NetworkBaseline::new(&ap.ssid, now));
        let mut changed = !n.sources.contains(&source);
        n.add_source(source);
        match n.known.iter_mut().find(|k| k.bssid == ap.bssid) {
            Some(k) => {
                if !k.fingerprints.contains(&ap.ie_fingerprint) {
                    if k.fingerprints.len() >= MAX_FINGERPRINTS {
                        k.fingerprints.remove(0);
                    }
                    k.fingerprints.push(ap.ie_fingerprint);
                    changed = true;
                }
                if k.security != ap.security {
                    k.security = ap.security.clone();
                    changed = true;
                }
                if source > k.source {
                    k.source = source;
                    changed = true;
                }
                k.band = ap.band;
                k.channel = ap.channel;
                k.last_seen = now;
            }
            None => {
                n.known.push(KnownBss {
                    bssid: ap.bssid,
                    security: ap.security.clone(),
                    fingerprints: vec![ap.ie_fingerprint],
                    band: ap.band,
                    channel: ap.channel,
                    source,
                    first_seen: now,
                    last_seen: now,
                });
                n.known.sort_by_key(|k| k.bssid);
                changed = true;
            }
        }
        self.dirty |= changed;
        changed
    }

    /// Note that a known access point is still around. Saved only along with
    /// other changes, or when the stored time is over an hour old.
    pub fn touch(&mut self, ap: &ApInfo, now: Millis) {
        if let Some(k) = self.networks.get_mut(&ap.ssid).and_then(|n| n.known.iter_mut().find(|k| k.bssid == ap.bssid)) {
            self.dirty |= now.saturating_sub(k.last_seen) > 3_600_000;
            k.last_seen = now;
            k.channel = ap.channel;
            k.band = ap.band;
        }
    }

    /// Record the LAN side of a network. Returns true if it changed.
    pub fn set_gateway(&mut self, ssid: &str, g: na_model::GatewayBaseline) -> bool {
        let Some(n) = self.networks.get_mut(ssid) else { return false };
        let same = n.gateway.as_ref().is_some_and(|old| old.ip == g.ip && old.mac == g.mac && old.dns == g.dns && old.dhcp_servers == g.dhcp_servers);
        if !same {
            n.gateway = Some(g);
            self.dirty = true;
        }
        !same
    }

    /// Forget the learned access points and gateway. A network that is still a
    /// saved profile keeps its expected security.
    pub fn forget(&mut self, ssid: &str) -> bool {
        let Some(n) = self.networks.get_mut(ssid) else { return false };
        if n.sources.contains(&TrustSource::SavedProfile) {
            n.known.clear();
            n.gateway = None;
            n.sources = vec![TrustSource::SavedProfile];
        } else {
            self.networks.remove(ssid);
        }
        self.dirty = true;
        true
    }
}

/// Windows profile authentication names → security class.
pub fn profile_class(auth: &str) -> Option<SecurityClass> {
    Some(match auth.to_ascii_uppercase().as_str() {
        "OPEN" | "SHARED" => SecurityClass::Open,
        "OWE" => SecurityClass::Owe,
        "WPAPSK" | "WPA2PSK" | "WPA3SAE" => SecurityClass::Personal,
        "WPA" | "WPA2" | "WPA3" | "WPA3ENT" | "WPA3ENT192" => SecurityClass::Enterprise,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{ap, wpa2};
    use super::*;

    fn saved(ssid: &str, auth: &str) -> SavedNetwork {
        SavedNetwork {
            profile: ssid.into(),
            ssid: ssid.into(),
            auth: auth.into(),
            encryption: "AES".into(),
            transition: false,
            auto_connect: true,
            hidden: false,
        }
    }

    #[test]
    fn learning_and_fingerprint_cap() {
        let mut b = Baselines::in_memory();
        let mut a = ap("Home", "3C:37:86:00:00:01", wpa2(), 1);
        assert!(b.learn(&a, TrustSource::Connected, 10));
        assert!(!b.learn(&a, TrustSource::Connected, 20), "nothing new");
        for fp in 2..=6 {
            a.ie_fingerprint = fp;
            b.learn(&a, TrustSource::Connected, 30);
        }
        let k = b.get("Home").unwrap().find(a.bssid).unwrap();
        assert_eq!(k.fingerprints, vec![3, 4, 5, 6]);
        assert_eq!(k.first_seen, 10);
        assert!(b.learn(&a, TrustSource::User, 40), "upgrading the trust source is a change");
        assert_eq!(b.get("Home").unwrap().find(a.bssid).unwrap().source, TrustSource::User);
    }

    #[test]
    fn saved_profiles_seed_and_expire() {
        let mut b = Baselines::in_memory();
        assert_eq!(b.import_saved(&[saved("Home", "WPA2PSK"), saved("Cafe", "open"), saved("X", "weird")], 0), 2);
        assert_eq!(b.get("Home").unwrap().expected_class(), Some(SecurityClass::Personal));
        b.learn(&ap("Home", "3C:37:86:00:00:01", wpa2(), 1), TrustSource::Connected, 1);

        // Both profiles deleted from the OS: Cafe disappears, Home keeps its learned AP.
        b.import_saved(&[], 2);
        assert!(b.get("Cafe").is_none());
        let home = b.get("Home").unwrap();
        assert_eq!(home.expected, None);
        assert_eq!(home.sources, vec![TrustSource::Connected]);
        assert_eq!(home.known.len(), 1);
    }

    #[test]
    fn forget_keeps_the_profile() {
        let mut b = Baselines::in_memory();
        b.import_saved(&[saved("Home", "WPA3SAE")], 0);
        b.learn(&ap("Home", "3C:37:86:00:00:01", wpa2(), 1), TrustSource::User, 1);
        b.learn(&ap("Lab", "3C:37:86:00:00:09", wpa2(), 1), TrustSource::User, 1);
        assert!(b.forget("Home") && b.forget("Lab"));
        assert!(b.get("Home").unwrap().known.is_empty());
        assert!(b.get("Lab").is_none());
    }

    #[test]
    fn file_round_trip() {
        let dir = std::env::temp_dir().join(format!("na-guard-test-{}", std::process::id()));
        let path = dir.join("guard.json");
        let mut b = Baselines::load(path.clone());
        b.learn(&ap("Home", "3C:37:86:00:00:01", wpa2(), 7), TrustSource::Connected, 1);
        b.save();
        let again = Baselines::load(path.clone());
        assert_eq!(again.get("Home").unwrap().known[0].fingerprints, vec![7]);

        std::fs::write(&path, "{ not json").unwrap();
        let broken = Baselines::load(path.clone());
        assert!(broken.get("Home").is_none());
        assert!(path.with_extension("json.bad").exists(), "bad file kept for inspection");
        let _ = std::fs::remove_dir_all(dir);
    }
}
