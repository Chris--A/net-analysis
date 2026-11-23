//! The Karma test. Probe for a random network name that can't exist and watch who
//! answers. A normal AP only answers for its own name; Karma/MANA rogue APs answer
//! for whatever a device asks, so phones auto-join them believing they're home.
//!
//! The probe itself is an ordinary directed probe request, the same kind every
//! phone sends constantly. The Wi-Fi (or simulator) source sends it; the result
//! shows up as a BSS with the decoy name in the normal scan results.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::time::Duration;

use na_model::{KarmaOutcome, KarmaResult, KarmaStatus, MacAddr, Millis};

/// Ask the radio source to send a directed probe for `ssid`.
#[derive(Clone, Debug)]
pub struct KarmaRequest {
    pub ssid: String,
    /// Requests older than [`KarmaRequest::STALE_MS`] are dropped unsent.
    pub at: Millis,
}

impl KarmaRequest {
    pub const STALE_MS: Millis = 20_000;

    pub fn is_stale(&self, now: Millis) -> bool {
        now.saturating_sub(self.at) > Self::STALE_MS
    }
}

/// How long to listen for answers after the first probe.
const LISTEN_MS: Millis = 15_000;
/// A second probe, in case the driver was busy with a scan.
const REPEAT_AFTER_MS: Millis = 6_000;
/// Answers can arrive late via the OS scan cache, so decoys stay "live" this long.
const DECOY_TTL_MS: Millis = 10 * 60_000;

struct Run {
    decoy: String,
    started: Millis,
    repeated: bool,
    sent: bool,
    error: Option<String>,
}

pub struct Karma {
    interval: Option<Duration>,
    next_at: Option<Millis>,
    run: Option<Run>,
    /// Decoys probed recently, with when.
    decoys: Vec<(String, Millis)>,
    /// BSSIDs that answered, and the decoys they answered for.
    responders: HashMap<MacAddr, Vec<String>>,
    last: Option<KarmaResult>,
    tx: flume::Sender<KarmaRequest>,
}

impl Karma {
    pub fn new(interval: Option<Duration>, first_after: Duration, tx: flume::Sender<KarmaRequest>, now: Millis) -> Self {
        Self {
            next_at: interval.map(|_| now + first_after.as_millis() as Millis),
            interval,
            run: None,
            decoys: Vec::new(),
            responders: HashMap::new(),
            last: None,
            tx,
        }
    }

    /// Start a test now. Returns false (and records a failure) when no radio can send it.
    pub fn start(&mut self, now: Millis, radio: bool) -> bool {
        if self.run.is_some() {
            return false;
        }
        let decoy = decoy_name();
        if !radio {
            self.last = Some(KarmaResult {
                at: now,
                decoy,
                outcome: KarmaOutcome::Failed("no Wi-Fi scanner is running".into()),
            });
            self.schedule(now);
            return true;
        }
        let _ = self.tx.try_send(KarmaRequest { ssid: decoy.clone(), at: now });
        self.decoys.push((decoy.clone(), now));
        self.run = Some(Run { decoy, started: now, repeated: false, sent: false, error: None });
        true
    }

    fn schedule(&mut self, now: Millis) {
        self.next_at = self.interval.map(|i| now + i.as_millis() as Millis);
    }

    /// Returns true when the visible status changed.
    pub fn tick(&mut self, now: Millis, radio: bool) -> bool {
        self.decoys.retain(|(_, at)| now.saturating_sub(*at) < DECOY_TTL_MS);
        if self.run.is_none() {
            return match self.next_at {
                Some(t) if now >= t => self.start(now, radio),
                _ => false,
            };
        }
        let run = self.run.as_mut().expect("checked");
        let elapsed = now.saturating_sub(run.started);
        if elapsed < LISTEN_MS {
            if !run.repeated && elapsed >= REPEAT_AFTER_MS {
                run.repeated = true;
                let _ = self.tx.try_send(KarmaRequest { ssid: run.decoy.clone(), at: now });
            }
            return false;
        }
        let run = self.run.take().expect("checked");
        let answered = self.answered(&run.decoy);
        let outcome = if !answered.is_empty() {
            KarmaOutcome::Responders(answered)
        } else if run.sent {
            KarmaOutcome::NoResponse
        } else {
            KarmaOutcome::Failed(run.error.unwrap_or_else(|| "the Wi-Fi scanner didn't send the probe".into()))
        };
        self.last = Some(KarmaResult { at: now, decoy: run.decoy, outcome });
        self.schedule(now);
        true
    }

    /// The radio source reports whether it could send the probe.
    pub fn on_sent(&mut self, ssid: &str, result: Result<(), String>) {
        if let Some(run) = self.run.as_mut().filter(|r| r.decoy == ssid) {
            match result {
                Ok(()) => run.sent = true,
                Err(e) => run.error = Some(e),
            }
        }
    }

    /// Check a sighting. Returns true if it's a (new) answer to a decoy.
    pub fn observe(&mut self, bssid: MacAddr, ssid: &str) -> bool {
        if !self.decoys.iter().any(|(d, _)| d == ssid) {
            return false;
        }
        let list = self.responders.entry(bssid).or_default();
        if list.iter().any(|d| d == ssid) {
            return false;
        }
        list.push(ssid.to_owned());
        // A late answer to a finished test still counts.
        if let Some(last) = self.last.as_mut().filter(|l| l.decoy == ssid) {
            match &mut last.outcome {
                KarmaOutcome::Responders(v) if !v.contains(&bssid) => v.push(bssid),
                KarmaOutcome::Responders(_) => {}
                other => *other = KarmaOutcome::Responders(vec![bssid]),
            }
        }
        true
    }

    pub fn decoys_answered_by(&self, bssid: MacAddr) -> &[String] {
        self.responders.get(&bssid).map_or(&[], Vec::as_slice)
    }

    fn answered(&self, decoy: &str) -> Vec<MacAddr> {
        let mut v: Vec<MacAddr> =
            self.responders.iter().filter(|(_, d)| d.iter().any(|x| x == decoy)).map(|(m, _)| *m).collect();
        v.sort();
        v
    }

    pub fn status(&self) -> KarmaStatus {
        KarmaStatus { running: self.run.is_some(), last: self.last.clone(), next_at: self.next_at }
    }
}

/// A plausible but random network name, e.g. `Lounge-3F9A1C`.
pub fn decoy_name() -> String {
    const WORDS: [&str; 8] = ["Home", "Guest", "Office", "Lounge", "Studio", "Cabin", "Loft", "Garden"];
    let r = RandomState::new().hash_one(std::time::SystemTime::now());
    format!("{}-{:06X}", WORDS[(r % 8) as usize], (r >> 8) & 0xFF_FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn karma() -> (Karma, flume::Receiver<KarmaRequest>) {
        let (tx, rx) = flume::unbounded();
        (Karma::new(Some(Duration::from_secs(600)), Duration::from_secs(30), tx, 0), rx)
    }

    #[test]
    fn decoys_look_plausible_and_differ() {
        let (a, b) = (decoy_name(), decoy_name());
        assert_ne!(a, b);
        let (word, hex) = a.split_once('-').unwrap();
        assert!(word.chars().all(|c| c.is_ascii_alphabetic()) && hex.len() == 6, "{a}");
    }

    #[test]
    fn clean_run() {
        let (mut k, rx) = karma();
        assert!(!k.tick(10_000, true), "not due yet");
        assert!(k.tick(30_000, true), "first run starts");
        let req = rx.try_recv().unwrap();
        k.on_sent(&req.ssid, Ok(()));
        assert!(k.status().running);
        k.tick(36_000, true);
        assert_eq!(rx.try_recv().unwrap().ssid, req.ssid, "probe repeated");
        assert!(!k.observe("3C:37:86:00:00:01".parse().unwrap(), "HomeNet"), "ordinary SSIDs ignored");
        assert!(k.tick(45_000, true));
        let s = k.status();
        assert!(!s.running);
        assert_eq!(s.last.unwrap().outcome, KarmaOutcome::NoResponse);
        assert_eq!(s.next_at, Some(645_000));
    }

    #[test]
    fn responder_and_late_answers() {
        let (mut k, rx) = karma();
        k.start(0, true);
        let decoy = rx.try_recv().unwrap().ssid;
        let rogue: MacAddr = "02:13:37:00:00:01".parse().unwrap();
        assert!(k.observe(rogue, &decoy));
        assert!(!k.observe(rogue, &decoy), "counted once");
        k.tick(LISTEN_MS, true);
        assert_eq!(k.status().last.unwrap().outcome, KarmaOutcome::Responders(vec![rogue]));
        assert_eq!(k.decoys_answered_by(rogue), std::slice::from_ref(&decoy));

        // Next run: nothing sent (driver refused), but a late answer arrives afterwards.
        k.start(100_000, true);
        let decoy2 = rx.try_recv().unwrap().ssid;
        k.on_sent(&decoy2, Err("busy".into()));
        k.tick(100_000 + LISTEN_MS, true);
        assert_eq!(k.status().last.unwrap().outcome, KarmaOutcome::Failed("busy".into()));
        let late: MacAddr = "02:13:37:00:00:02".parse().unwrap();
        k.observe(late, &decoy2);
        assert_eq!(k.status().last.unwrap().outcome, KarmaOutcome::Responders(vec![late]));
    }

    #[test]
    fn no_radio_fails_fast() {
        let (mut k, rx) = karma();
        assert!(k.start(5, false));
        assert!(rx.try_recv().is_err());
        assert!(matches!(k.status().last.unwrap().outcome, KarmaOutcome::Failed(_)));
        assert!(!k.status().running);
    }
}
