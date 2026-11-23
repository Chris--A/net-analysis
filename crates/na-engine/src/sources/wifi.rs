//! Wi-Fi access-point scanning. It turns the platform's raw BSS list into
//! [`Observation`]s with decoded IEs and identification evidence.
//!
//! The platform scanner is blocking and not `Send`, so it lives on a dedicated
//! blocking thread for the lifetime of the source.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use na_model::{
    ApInfo, DeviceDetails, DeviceKey, MacAddr, Millis, Observation, SourceKind, SourceState,
    now_millis,
};
use na_platform::wifi::{RawBss, WifiError, frequency_to_channel, open_scanner};
use tracing::{debug, warn};

use super::{BoxFuture, Source, SourceCtx, SourceDeps};
use crate::guard::GuardSignal;
use crate::identify::{OuiDb, ap_evidence};
use crate::parse::ie;

#[derive(Clone, Debug)]
pub struct WifiConfig {
    /// How often to ask the driver for a fresh scan. Windows throttles more frequent requests.
    pub scan_interval: Duration,
    /// How often to read the OS's BSS cache.
    pub poll_interval: Duration,
}

impl Default for WifiConfig {
    fn default() -> Self {
        Self {
            scan_interval: Duration::from_secs(10),
            poll_interval: Duration::from_secs(2),
        }
    }
}

pub struct WifiSource {
    cfg: WifiConfig,
    deps: SourceDeps,
}

impl WifiSource {
    pub fn new(cfg: WifiConfig, deps: SourceDeps) -> Self {
        Self { cfg, deps }
    }
}

impl Source for WifiSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Wifi
    }

    fn run(self: Box<Self>, ctx: SourceCtx) -> BoxFuture<anyhow::Result<()>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || scan_loop(&self.cfg, &self.deps, &ctx))
                .await
                .map_err(|e| anyhow!("Wi-Fi scan thread panicked: {e}"))?
        })
    }
}

fn scan_loop(cfg: &WifiConfig, deps: &SourceDeps, ctx: &SourceCtx) -> anyhow::Result<()> {
    let oui: &OuiDb = &deps.oui;
    let mut scanner = match open_scanner() {
        Ok(s) => s,
        Err(WifiError::Unsupported(why)) => {
            ctx.report(SourceState::Unavailable(why));
            while !ctx.cancel.is_cancelled() {
                ctx.sleep_blocking(Duration::from_secs(1));
            }
            return Ok(());
        }
        Err(e) => return Err(anyhow!(e)),
    };

    let mut last_scan: Option<Instant> = None;
    let mut blocked = false;
    // A Karma probe waiting for the radio (the driver refuses scans while one is running).
    let mut karma: Option<crate::guard::KarmaRequest> = None;
    // Last frame-receive time per BSSID, so a cached (not re-heard) entry isn't reported again.
    let mut last_rx: HashMap<MacAddr, Millis> = HashMap::new();

    while !ctx.cancel.is_cancelled() {
        if karma.is_none() && last_scan.is_none_or(|t| t.elapsed() >= cfg.scan_interval) {
            if let Err(e) = scanner.trigger_scan(None) {
                debug!(error = %e, "scan request failed");
            }
            last_scan = Some(Instant::now());
        }

        // Karma test: a directed probe for the guard's decoy name. While the radio is
        // busy (ERROR_BUSY) it waits for the next loop instead of failing the test.
        while let Ok(req) = deps.karma.try_recv() {
            karma = Some(req);
        }
        if let Some(req) = karma.take() {
            match scanner.trigger_scan(Some(req.ssid.as_bytes())) {
                Err(WifiError::Os { code: 170, .. }) if !req.is_stale(now_millis()) => karma = Some(req),
                result => {
                    let result = result.map_err(|e| e.to_string());
                    debug!(decoy = %req.ssid, ?result, "Karma probe");
                    let _ = deps.guard.send(GuardSignal::KarmaSent { ssid: req.ssid, result });
                    last_scan = Some(Instant::now()); // a directed scan is a scan too
                }
            }
        }

        let connected: HashSet<MacAddr> = scanner
            .interfaces()
            .map(|ifs| ifs.into_iter().filter_map(|i| i.connected_bssid).collect())
            .unwrap_or_default();

        match scanner.bss_list() {
            Ok(list) => {
                if blocked {
                    ctx.report(SourceState::Running);
                    blocked = false;
                }
                for raw in list {
                    let rx = raw.received_at_ms.unwrap_or_else(now_millis);
                    if last_rx.insert(raw.bssid, rx) == Some(rx) {
                        continue;
                    }
                    if let Some(obs) = observation(&raw, rx, &connected, oui)
                        && ctx.sink.blocking_send(obs).is_err()
                    {
                        return Ok(()); // engine shutting down
                    }
                }
            }
            Err(e @ (WifiError::PermissionDenied(_) | WifiError::NoInterface)) => {
                if !blocked {
                    warn!(error = %e, "Wi-Fi scanning blocked; will keep retrying");
                    ctx.report(SourceState::Unavailable(e.to_string()));
                    blocked = true;
                }
            }
            Err(e) => warn!(error = %e, "Wi-Fi poll failed"),
        }

        ctx.sleep_blocking(cfg.poll_interval);
    }
    Ok(())
}

/// Decode one raw BSS into an observation. Returns None for unknown frequencies.
pub(crate) fn observation(
    raw: &RawBss,
    at: Millis,
    connected: &HashSet<MacAddr>,
    oui: &OuiDb,
) -> Option<Observation> {
    let (band, channel) = frequency_to_channel(raw.frequency_khz)?;
    let parsed = ie::parse(&raw.ies);
    let ap = ApInfo {
        ssid: decode_ssid(&raw.ssid),
        bssid: raw.bssid,
        channel,
        band,
        width_mhz: parsed.width_mhz,
        security: parsed.security(raw.capability),
        wifi_gen: parsed.wifi_gen(),
        beacon_interval_tu: raw.beacon_interval_tu,
        tsf_uptime_secs: plausible_uptime(raw.tsf_us),
        wps: parsed.wps.clone(),
        ie_fingerprint: parsed.fingerprint,
        connected: connected.contains(&raw.bssid),
        station_count: parsed.station_count,
        channel_utilization: parsed.channel_utilization,
        country: parsed.country.clone(),
        vendor_ies: parsed.vendor_ies.clone(),
        raw_ies: raw.ies.clone(),
    };
    let evidence = ap_evidence(&ap, &parsed, oui);
    Some(Observation {
        key: DeviceKey::Bssid(raw.bssid),
        at,
        rssi: Some(raw.rssi_dbm.clamp(-127, 0) as i16),
        details: DeviceDetails::Ap(ap),
        evidence,
        links: Vec::new(),
    })
}

/// TSF → uptime, rejecting values no real radio reaches. Apple devices (and some
/// privacy-focused APs) randomize the TSF, producing "uptimes" of centuries.
fn plausible_uptime(tsf_us: u64) -> Option<u64> {
    const MAX_PLAUSIBLE_SECS: u64 = 5 * 365 * 86_400;
    let secs = tsf_us / 1_000_000;
    (tsf_us > 0 && secs <= MAX_PLAUSIBLE_SECS).then_some(secs)
}

/// Hidden networks report an empty or all-zero SSID.
fn decode_ssid(bytes: &[u8]) -> String {
    if bytes.iter().all(|&b| b == 0) {
        return String::new();
    }
    String::from_utf8_lossy(bytes).trim_end_matches('\0').to_owned()
}

#[cfg(test)]
mod tests {
    use na_model::{Akm, Band, ClaimKind};

    use super::*;

    fn raw(ssid: &[u8], ies: Vec<u8>) -> RawBss {
        RawBss {
            interface: "test".into(),
            ssid: ssid.to_vec(),
            bssid: "3C:37:86:12:34:56".parse().unwrap(),
            rssi_dbm: -52,
            frequency_khz: 5_220_000,
            beacon_interval_tu: 100,
            capability: 0x0011,
            tsf_us: 3 * 86_400 * 1_000_000,
            received_at_ms: Some(1_000),
            ies,
        }
    }

    #[test]
    fn decodes_a_real_looking_bss() {
        // RSN WPA2-PSK + WPS manufacturer.
        let mut ies = vec![48, 20, 1, 0, 0, 0x0F, 0xAC, 4, 1, 0, 0, 0x0F, 0xAC, 4, 1, 0, 0, 0x0F, 0xAC, 2, 0, 0];
        let wps = [0x00, 0x50, 0xF2, 4, 0x10, 0x21, 0, 7, b'N', b'E', b'T', b'G', b'E', b'A', b'R'];
        ies.push(221);
        ies.push(wps.len() as u8);
        ies.extend_from_slice(&wps);

        let oui = OuiDb::from_csv("h\nMA-L,3C3786,NETGEAR,x\n");
        let connected = HashSet::from([raw(b"", vec![]).bssid]);
        let obs = observation(&raw(b"HomeNet", ies), 1_000, &connected, &oui).unwrap();
        let DeviceDetails::Ap(ap) = &obs.details else { panic!("not an AP") };
        assert_eq!((ap.band, ap.channel), (Band::G5, 44));
        assert_eq!(ap.ssid, "HomeNet");
        assert_eq!(ap.security.akms, vec![Akm::Psk]);
        assert_eq!(ap.tsf_uptime_secs, Some(3 * 86_400));
        assert!(ap.connected);
        assert_eq!(obs.rssi, Some(-52));
        let vendor_votes = obs.evidence.iter().filter(|e| e.kind == ClaimKind::Vendor && e.value == "NETGEAR").count();
        assert_eq!(vendor_votes, 2, "OUI + WPS both vote for the vendor");
    }

    #[test]
    fn randomized_tsf_is_not_an_uptime() {
        assert_eq!(plausible_uptime(0), None);
        assert_eq!(plausible_uptime(90 * 86_400 * 1_000_000), Some(90 * 86_400));
        // Seen in the wild from an iPhone hotspot: ~425,924 days.
        assert_eq!(plausible_uptime(425_924 * 86_400 * 1_000_000), None);
    }

    #[test]
    fn hidden_ssid_and_unknown_frequency() {
        let mut r = raw(&[0, 0, 0], vec![]);
        let obs = observation(&r, 1, &HashSet::new(), &OuiDb::default()).unwrap();
        let DeviceDetails::Ap(ap) = &obs.details else { panic!() };
        assert_eq!(ap.ssid, "");
        assert_eq!(ap.security.akms, vec![Akm::Wep], "privacy bit without RSN = WEP");
        r.frequency_khz = 900_000;
        assert!(observation(&r, 1, &HashSet::new(), &OuiDb::default()).is_none());
    }
}
