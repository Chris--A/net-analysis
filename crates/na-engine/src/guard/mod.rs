//! Wi-Fi threat detection: trusted-network baselines, the access-point detectors
//! (see [`detect`]) and the Karma test (see [`karma`]).
//!
//! Trust is built three ways:
//! - saved OS profiles give each network's expected security;
//! - connecting with a key (WPA2/WPA3/Enterprise) proves the AP knows that key, so
//!   the connected AP and its sibling radios are learned automatically;
//! - the user can trust a network or a single AP explicitly.

mod baseline;
pub mod detect;
pub mod karma;
#[cfg(test)]
mod testutil;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use na_model::{
    Alert, AlertKind, ApInfo, DeviceDetails, DeviceId, DeviceKey, EngineCommand, EngineEvent, GuardStatus, MacAddr,
    Millis, Observation, SecurityClass, TrustSource,
};
use na_platform::wifi::SavedNetwork;
use tracing::info;

pub use baseline::{Baselines, profile_class};
pub use detect::Finding;
pub use karma::KarmaRequest;

use crate::DeviceStore;
use crate::store::macs_related;

#[derive(Clone, Debug)]
pub struct GuardConfig {
    /// Where baselines are kept. None keeps them in memory (simulator, tests).
    pub baseline_path: Option<PathBuf>,
    /// Seed baselines from the OS's saved Wi-Fi profiles at start-up.
    pub import_saved_profiles: bool,
    /// How often to run the Karma test automatically. None: only on request.
    pub karma_interval: Option<Duration>,
    pub karma_first_after: Duration,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            baseline_path: None,
            import_saved_profiles: false,
            karma_interval: Some(Duration::from_secs(600)),
            karma_first_after: Duration::from_secs(30),
        }
    }
}

impl GuardConfig {
    /// For real scanning: baselines in the user's data folder, seeded from saved profiles.
    pub fn persistent() -> Self {
        Self {
            baseline_path: data_dir().map(|d| d.join("guard.json")),
            import_saved_profiles: true,
            ..Self::default()
        }
    }
}

/// `%LOCALAPPDATA%\net-analysis` on Windows; `$XDG_DATA_HOME/net-analysis` or
/// `~/.local/share/net-analysis` elsewhere.
pub fn data_dir() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    };
    base.map(|b| b.join("net-analysis"))
}

/// Messages to the guard from sources and helper tasks.
#[derive(Debug)]
pub enum GuardSignal {
    /// A radio source tried to send a Karma probe.
    KarmaSent { ssid: String, result: Result<(), String> },
    /// The OS's saved Wi-Fi profiles were read.
    SavedNetworks(Result<Vec<SavedNetwork>, String>),
}

/// How long the multi-SSID detector remembers the names heard from each BSSID.
const SSID_MEMORY_MS: Millis = 10 * 60_000;
/// An alert fires again only after its condition has been gone this long, or got worse.
const ALERT_QUIET_MS: Millis = 10 * 60_000;

struct Raised {
    severity: na_model::Severity,
    last_active: Millis,
}

pub struct Guard {
    baselines: Baselines,
    karma: karma::Karma,
    /// Non-empty SSIDs heard per BSSID, with when each was last heard.
    ssid_log: HashMap<MacAddr, Vec<(String, Millis)>>,
    raised: HashMap<DeviceId, Raised>,
    /// BSSIDs with an alert-worthy finding at the last tick. "Trust network" skips them.
    flagged: HashSet<MacAddr>,
    next_alert_id: u64,
    profile_import: Option<String>,
    status_changed: bool,
}

impl Guard {
    pub fn new(cfg: &GuardConfig, karma_tx: flume::Sender<KarmaRequest>, now: Millis) -> Self {
        let baselines = match &cfg.baseline_path {
            Some(p) => Baselines::load(p.clone()),
            None => Baselines::in_memory(),
        };
        Self {
            baselines,
            karma: karma::Karma::new(cfg.karma_interval, cfg.karma_first_after, karma_tx, now),
            ssid_log: HashMap::new(),
            raised: HashMap::new(),
            flagged: HashSet::new(),
            next_alert_id: 1,
            profile_import: None,
            status_changed: true,
        }
    }

    /// See each observation before the store merges it. A Karma AP may answer
    /// with a decoy name only once, and the store keeps only the latest SSID.
    pub fn observe(&mut self, obs: &Observation) {
        let DeviceDetails::Ap(ap) = &obs.details else { return };
        if ap.ssid.is_empty() {
            return;
        }
        let log = self.ssid_log.entry(ap.bssid).or_default();
        match log.iter_mut().find(|(s, _)| *s == ap.ssid) {
            Some(entry) => entry.1 = obs.at,
            None => log.push((ap.ssid.clone(), obs.at)),
        }
        if self.karma.observe(ap.bssid, &ap.ssid) {
            info!(bssid = %ap.bssid, decoy = %ap.ssid, "Karma decoy answered");
            self.status_changed = true;
        }
    }

    pub fn signal(&mut self, sig: GuardSignal, now: Millis) {
        match sig {
            GuardSignal::KarmaSent { ssid, result } => self.karma.on_sent(&ssid, result),
            GuardSignal::SavedNetworks(Ok(list)) => {
                let n = self.baselines.import_saved(&list, now);
                info!(n, "imported saved Wi-Fi profiles");
                self.profile_import = Some(format!("{n} saved Wi-Fi networks imported"));
                self.baselines.save();
                self.status_changed = true;
            }
            GuardSignal::SavedNetworks(Err(e)) => {
                self.profile_import = Some(format!("Saved networks unavailable: {e}"));
                self.status_changed = true;
            }
        }
    }

    /// Handle a guard command. Returns false for commands that belong to someone else.
    pub fn command(&mut self, cmd: &EngineCommand, store: &DeviceStore, now: Millis, radio: bool) -> bool {
        match cmd {
            EngineCommand::TrustNetwork { ssid } => {
                let clean: Vec<&ApInfo> = store
                    .devices()
                    .filter_map(|d| d.ap())
                    .filter(|a| a.ssid == *ssid && !self.flagged.contains(&a.bssid))
                    .collect();
                for ap in clean {
                    self.baselines.learn(ap, TrustSource::User, now);
                }
            }
            EngineCommand::TrustAccessPoint { bssid } => {
                let id = DeviceId::for_key(&DeviceKey::Bssid(*bssid));
                if let Some(ap) = store.get(id).and_then(|d| d.ap()) {
                    self.baselines.learn(ap, TrustSource::User, now);
                    self.raised.remove(&id);
                    self.flagged.remove(bssid);
                }
            }
            EngineCommand::ForgetNetwork { ssid } => {
                self.baselines.forget(ssid);
            }
            EngineCommand::RunKarmaTest => {
                self.karma.start(now, radio);
            }
            _ => return false,
        }
        self.baselines.save();
        self.status_changed = true;
        true
    }

    /// Re-assess every access point: risk, alerts, learning and the Karma schedule.
    pub fn tick(&mut self, store: &mut DeviceStore, now: Millis, radio: bool) -> Vec<EngineEvent> {
        for log in self.ssid_log.values_mut() {
            log.retain(|(_, at)| now.saturating_sub(*at) < SSID_MEMORY_MS);
        }
        self.ssid_log.retain(|_, l| !l.is_empty());

        let aps: Vec<(DeviceId, ApInfo)> = store.devices().filter_map(|d| d.ap().map(|a| (d.id, a.clone()))).collect();
        let assessed: Vec<(DeviceId, &ApInfo, Vec<Finding>)> =
            aps.iter().map(|(id, ap)| (*id, ap, self.assess(ap, &aps))).collect();
        self.flagged = assessed.iter().filter(|(_, _, f)| detect::primary(f).is_some()).map(|(_, a, _)| a.bssid).collect();
        self.learn(&assessed, now);

        let mut events = Vec::new();
        for (id, ap, findings) in &assessed {
            store.set_risk(*id, detect::risk(findings), findings.iter().map(|f| f.text.clone()).collect());
            let Some(p) = detect::primary(findings) else { continue };
            let severity = p.severity.expect("a primary finding has a severity");
            match self.raised.get_mut(id) {
                Some(r) if r.severity >= severity => r.last_active = now,
                _ => {
                    self.raised.insert(*id, Raised { severity, last_active: now });
                    events.push(EngineEvent::Alert(self.alert(*id, ap, findings, p, now)));
                }
            }
        }
        self.raised.retain(|_, r| now.saturating_sub(r.last_active) < ALERT_QUIET_MS);

        self.status_changed |= self.karma.tick(now, radio);
        if std::mem::take(&mut self.status_changed) {
            events.push(EngineEvent::Guard(Box::new(self.status())));
        }
        events
    }

    fn assess(&self, ap: &ApInfo, all: &[(DeviceId, ApInfo)]) -> Vec<Finding> {
        let peers: Vec<&ApInfo> = if ap.ssid.is_empty() {
            Vec::new()
        } else {
            all.iter().map(|(_, a)| a).filter(|a| a.ssid == ap.ssid && a.bssid != ap.bssid).collect()
        };
        let ssids: Vec<String> =
            self.ssid_log.get(&ap.bssid).map(|l| l.iter().map(|(s, _)| s.clone()).collect()).unwrap_or_default();
        detect::assess(
            ap,
            &detect::Context {
                baseline: self.baselines.get(&ap.ssid),
                peers: &peers,
                karma_decoys: self.karma.decoys_answered_by(ap.bssid),
                ssids: &ssids,
            },
        )
    }

    /// Learn the AP this machine is connected to (with a key), and its sibling radios.
    fn learn(&mut self, assessed: &[(DeviceId, &ApInfo, Vec<Finding>)], now: Millis) {
        let clean = |f: &[Finding]| detect::primary(f).is_none();
        let mut changed = false;
        for (_, ap, findings) in assessed {
            if !clean(findings) {
                continue;
            }
            if !(ap.connected && SecurityClass::of(&ap.security).authenticated()) {
                self.baselines.touch(ap, now);
                continue;
            }
            changed |= self.baselines.learn(ap, TrustSource::Connected, now);
            // Other radios of the same router sit next to it in MAC space and share its settings.
            for (_, sib, sf) in assessed {
                let sibling = sib.ssid == ap.ssid
                    && sib.bssid != ap.bssid
                    && macs_related(sib.bssid, ap.bssid)
                    && sib.bssid.is_locally_administered() == ap.bssid.is_locally_administered()
                    && sib.security == ap.security
                    && clean(sf);
                if sibling && self.baselines.get(&ap.ssid).is_some_and(|b| b.find(sib.bssid).is_none()) {
                    changed |= self.baselines.learn(sib, TrustSource::Connected, now);
                }
            }
        }
        if changed {
            self.baselines.save();
            self.status_changed = true;
        }
    }

    fn alert(&mut self, id: DeviceId, ap: &ApInfo, findings: &[Finding], p: &Finding, now: Millis) -> Alert {
        let ssid = ap.display_ssid();
        let (title, explanation) = match p.kind {
            AlertKind::KarmaAp => (
                format!("Karma/MANA rogue access point {}", ap.bssid),
                "This access point answers for networks that don't exist. Karma/MANA attack tools do that \
                 so phones and laptops join them automatically, believing it's a network they know. Don't \
                 connect to it.",
            ),
            AlertKind::SecurityDowngrade => (
                format!("Security downgrade on \"{ssid}\""),
                "An access point is using a trusted network's name with weaker security than the real one. \
                 Devices that join it can have their traffic watched or altered, and a weaker handshake can \
                 expose the Wi-Fi password to cracking.",
            ),
            AlertKind::MultiSsid => (
                format!("One radio, several networks: {}", ap.bssid),
                "One radio keeps announcing different network names. Rogue access points that impersonate \
                 networks (Karma/MANA) answer with whatever name a device asks for.",
            ),
            AlertKind::PmfMissing => (
                format!("\"{ssid}\" access point without management-frame protection"),
                "This access point of a trusted network doesn't protect management frames like the known ones \
                 do. Without it, an attacker can disconnect devices and push them towards a rogue AP.",
            ),
            _ => (
                format!("Possible evil twin of \"{ssid}\""),
                "This access point uses the name of a network you trust (or one nearby), but doesn't look \
                 like its legitimate access points. Evil-twin APs do this so devices connect to them \
                 instead.",
            ),
        };
        let mut devices = vec![id];
        if let Some(b) = self.baselines.get(&ap.ssid) {
            devices.extend(b.known.iter().map(|k| DeviceId::for_key(&DeviceKey::Bssid(k.bssid))).filter(|d| *d != id));
        }
        let alert = Alert {
            id: self.next_alert_id,
            at: now,
            severity: p.severity.expect("a primary finding has a severity"),
            kind: p.kind,
            devices,
            title,
            explanation: explanation.into(),
            findings: findings.iter().map(|f| f.text.clone()).collect(),
        };
        self.next_alert_id += 1;
        alert
    }

    pub fn status(&self) -> GuardStatus {
        GuardStatus {
            networks: self.baselines.all().cloned().collect(),
            karma: self.karma.status(),
            profile_import: self.profile_import.clone(),
        }
    }

    /// Save anything outstanding (e.g. last-seen times) before the engine stops.
    pub fn shutdown(&mut self) {
        self.baselines.save();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use na_model::{Band, KarmaOutcome, Security, Severity};

    use super::testutil::{ap, obs, wpa2};
    use super::*;
    use crate::StalePolicy;

    fn guard() -> (Guard, DeviceStore, flume::Receiver<KarmaRequest>) {
        let (tx, rx) = flume::unbounded();
        let cfg = GuardConfig { karma_interval: None, ..GuardConfig::default() };
        (Guard::new(&cfg, tx, 0), DeviceStore::new(StalePolicy::default()), rx)
    }

    fn feed(g: &mut Guard, s: &mut DeviceStore, ap: &ApInfo, at: Millis) {
        let o = obs(ap, at);
        g.observe(&o);
        s.ingest(o);
    }

    fn alerts(events: &[EngineEvent]) -> Vec<&Alert> {
        events
            .iter()
            .filter_map(|e| match e {
                EngineEvent::Alert(a) => Some(a),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn learns_on_connect_then_catches_the_twin_once() {
        let (mut g, mut s, _rx) = guard();
        let mut main = ap("Home", "3C:37:86:12:34:56", wpa2(), 0xAA);
        main.connected = true;
        main.tsf_uptime_secs = Some(30 * 86_400);
        let mut radio24 = ap("Home", "3C:37:86:12:34:57", wpa2(), 0xA2);
        radio24.band = Band::G2_4;
        feed(&mut g, &mut s, &main, 1_000);
        feed(&mut g, &mut s, &radio24, 1_000);
        let events = g.tick(&mut s, 1_000, true);
        assert!(alerts(&events).is_empty());
        let home = g.status().networks.into_iter().find(|n| n.ssid == "Home").unwrap();
        assert_eq!(home.known.len(), 2, "connected AP and its 2.4 GHz sibling learned");

        let mut twin = ap("Home", "3E:37:86:12:34:56", Security::open(), 0xBB);
        twin.tsf_uptime_secs = Some(60);
        feed(&mut g, &mut s, &twin, 2_000);
        let events = g.tick(&mut s, 2_000, true);
        let a = alerts(&events);
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].severity, a[0].kind), (Severity::Critical, AlertKind::SecurityDowngrade));
        assert_eq!(a[0].findings.len(), 4);
        assert_eq!(a[0].devices.len(), 3, "the twin plus the two legitimate APs");
        let twin_id = DeviceId::for_key(&DeviceKey::Bssid(twin.bssid));
        assert!(s.get(twin_id).unwrap().risk > 0.8);
        assert!(alerts(&g.tick(&mut s, 3_000, true)).is_empty(), "no repeat while it persists");

        // The user vouches for it: the risk goes and the network's baseline now includes it.
        g.command(&EngineCommand::TrustAccessPoint { bssid: twin.bssid }, &s, 4_000, true);
        g.tick(&mut s, 5_000, true);
        assert_eq!(s.get(twin_id).unwrap().risk, 0.0);
    }

    #[test]
    fn trust_network_skips_flagged_aps() {
        let (mut g, mut s, _rx) = guard();
        let a = ap("Cafe", "3C:37:86:00:00:01", wpa2(), 1);
        let rogue = ap("Cafe", "02:00:00:00:00:66", Security::open(), 2);
        feed(&mut g, &mut s, &a, 1);
        feed(&mut g, &mut s, &rogue, 1);
        let events = g.tick(&mut s, 1, true);
        assert_eq!(alerts(&events)[0].severity, Severity::Medium, "mixed security, no baseline");
        g.command(&EngineCommand::TrustNetwork { ssid: "Cafe".into() }, &s, 2, true);
        let cafe = g.status().networks.into_iter().find(|n| n.ssid == "Cafe").unwrap();
        assert_eq!(cafe.known.iter().map(|k| k.bssid).collect::<Vec<_>>(), vec![a.bssid]);
        // Now it's a proper downgrade against a trusted baseline.
        let events = g.tick(&mut s, 3, true);
        assert_eq!(alerts(&events)[0].severity, Severity::Critical);
    }

    #[test]
    fn karma_responder_is_flagged() {
        let (tx, rx) = flume::unbounded();
        let cfg = GuardConfig { karma_interval: Some(Duration::from_secs(600)), karma_first_after: Duration::ZERO, ..Default::default() };
        let mut g = Guard::new(&cfg, tx, 0);
        let mut s = DeviceStore::new(StalePolicy::default());
        g.tick(&mut s, 0, true);
        let req = rx.try_recv().expect("first test starts immediately");
        g.signal(GuardSignal::KarmaSent { ssid: req.ssid.clone(), result: Ok(()) }, 10);

        let rogue = ap("Free WiFi", "02:13:37:00:00:01", Security::open(), 9);
        feed(&mut g, &mut s, &rogue, 100);
        feed(&mut g, &mut s, &ap(&req.ssid, "02:13:37:00:00:01", Security::open(), 9), 200);
        feed(&mut g, &mut s, &rogue, 300); // the store shows its beacon name again
        let events = g.tick(&mut s, 1_000, true);
        let a = alerts(&events);
        assert_eq!((a[0].severity, a[0].kind), (Severity::Critical, AlertKind::KarmaAp));
        assert!(a[0].findings.iter().any(|f| f.contains(&req.ssid)));

        g.tick(&mut s, 20_000, true);
        let status = g.status();
        assert_eq!(status.karma.last.unwrap().outcome, KarmaOutcome::Responders(vec![rogue.bssid]));
    }
}
