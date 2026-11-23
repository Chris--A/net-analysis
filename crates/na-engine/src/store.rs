use std::collections::{HashMap, HashSet};

use na_model::{
    Device, DeviceDetails, DeviceId, DeviceKey, DeviceKind, EngineEvent, LanInfo, MacAddr, Millis,
    Observation, RSSI_HISTORY_LEN, RssiSample,
};

use crate::StalePolicy;
use crate::identify;

/// Weight of a new RSSI sample in the exponential moving average.
const RSSI_ALPHA: f32 = 0.35;

/// The engine's single source of truth: merges observations into devices and
/// tracks which ones changed since the last flush.
pub struct DeviceStore {
    devices: HashMap<DeviceId, Device>,
    dirty: HashSet<DeviceId>,
    /// Devices merged away (e.g. an IP-keyed LAN host promoted to its MAC), not yet reported.
    removed: Vec<DeviceId>,
    stale: StalePolicy,
}

impl DeviceStore {
    pub fn new(stale: StalePolicy) -> Self {
        Self {
            devices: HashMap::new(),
            dirty: HashSet::new(),
            removed: Vec::new(),
            stale,
        }
    }

    pub fn get(&self, id: DeviceId) -> Option<&Device> {
        self.devices.get(&id)
    }

    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    pub fn ingest(&mut self, obs: Observation) {
        let id = DeviceId::for_key(&obs.key);
        let is_new = !self.devices.contains_key(&id);
        // A LAN host first seen only by IP is folded into its MAC-keyed device once ARP resolves it.
        let promoted = match (&obs.key, &obs.details) {
            (DeviceKey::LanMac(_), DeviceDetails::Lan(lan)) => self.take_ip_twins(lan),
            _ => Vec::new(),
        };
        let dev = self
            .devices
            .entry(id)
            .or_insert_with(|| Device::new(obs.key.clone(), obs.at));
        let mut evidence_changed = false;
        for old in promoted {
            dev.first_seen = dev.first_seen.min(old.first_seen);
            if let DeviceDetails::Lan(old_lan) = old.details {
                match &mut dev.details {
                    DeviceDetails::Lan(cur) => {
                        let mut merged = old_lan;
                        merged.merge(cur);
                        *cur = merged;
                    }
                    slot => *slot = DeviceDetails::Lan(old_lan),
                }
            }
            for e in old.evidence {
                if !dev.evidence.iter().any(|x| x.source == e.source && x.kind == e.kind && x.value == e.value) {
                    dev.evidence.push(e);
                    evidence_changed = true;
                }
            }
        }

        dev.last_seen = dev.last_seen.max(obs.at);

        if let Some(raw) = obs.rssi {
            dev.rssi = Some(match dev.rssi {
                Some(prev) => {
                    (f32::from(prev) * (1.0 - RSSI_ALPHA) + f32::from(raw) * RSSI_ALPHA).round()
                        as i16
                }
                None => raw,
            });
            dev.rssi_history.push_back(RssiSample { at: obs.at, dbm: raw });
            while dev.rssi_history.len() > RSSI_HISTORY_LEN {
                dev.rssi_history.pop_front();
            }
        }

        match (&mut dev.details, obs.details) {
            (_, DeviceDetails::None) => {}
            // LAN facts arrive piecemeal from many protocols, so union them.
            (DeviceDetails::Lan(cur), DeviceDetails::Lan(new)) => cur.merge(&new),
            // Beacons usually omit the WPS make/model that probe responses carry,
            // so keep the last known WPS info rather than flapping.
            (DeviceDetails::Ap(cur), DeviceDetails::Ap(new)) => {
                let prev_wps = cur.wps.take();
                *cur = new;
                if cur.wps.is_none() {
                    cur.wps = prev_wps;
                }
            }
            // Radio sources report the full current state each time.
            (slot, new) => *slot = new,
        }

        for e in obs.evidence {
            match dev
                .evidence
                .iter_mut()
                .find(|x| x.source == e.source && x.kind == e.kind && x.value == e.value)
            {
                Some(existing) => {
                    if e.confidence > existing.confidence {
                        existing.confidence = e.confidence;
                        evidence_changed = true;
                    }
                    existing.detail = e.detail;
                }
                None => {
                    dev.evidence.push(e);
                    evidence_changed = true;
                }
            }
        }
        if evidence_changed {
            dev.identity = identify::classify(&dev.evidence);
        }

        for key in &obs.links {
            let link = DeviceId::for_key(key);
            if link != id && !dev.links.contains(&link) {
                dev.links.push(link);
            }
        }

        self.dirty.insert(id);
        if is_new {
            self.correlate(id);
        }
    }

    fn take_ip_twins(&mut self, lan: &LanInfo) -> Vec<Device> {
        let mut out = Vec::new();
        for ip in &lan.ips {
            let twin = DeviceId::for_key(&DeviceKey::LanIp(*ip));
            if let Some(d) = self.devices.remove(&twin) {
                self.dirty.remove(&twin);
                self.removed.push(twin);
                out.push(d);
            }
        }
        out
    }

    /// Link a new AP or LAN host to devices of the other kind whose MAC is a near
    /// neighbour. A router's LAN MAC and its BSSIDs are usually a few apart, or
    /// identical (phone hotspots).
    fn correlate(&mut self, id: DeviceId) {
        let Some(dev) = self.devices.get(&id) else { return };
        let (Some(mac), kind) = (link_mac(dev), dev.kind) else { return };
        let partners: Vec<DeviceId> = self
            .devices
            .values()
            .filter(|d| {
                matches!(
                    (kind, d.kind),
                    (DeviceKind::AccessPoint, DeviceKind::LanHost) | (DeviceKind::LanHost, DeviceKind::AccessPoint)
                ) && link_mac(d).is_some_and(|m| macs_related(mac, m))
            })
            .map(|d| d.id)
            .collect();
        for p in partners {
            for (a, b) in [(id, p), (p, id)] {
                if let Some(d) = self.devices.get_mut(&a)
                    && !d.links.contains(&b)
                {
                    d.links.push(b);
                    self.dirty.insert(a);
                }
            }
        }
    }

    /// Snapshots of every device changed since the last call, after any merge removals.
    pub fn drain_updates(&mut self) -> Vec<EngineEvent> {
        let mut events: Vec<EngineEvent> = self.removed.drain(..).map(EngineEvent::DeviceRemoved).collect();
        events.extend(
            self.dirty
                .drain()
                .filter_map(|id| self.devices.get(&id))
                .map(|d| EngineEvent::DeviceUpserted(Box::new(d.clone()))),
        );
        events
    }

    /// Forget devices not seen within their kind's timeout.
    pub fn sweep_stale(&mut self, now: Millis) -> Vec<EngineEvent> {
        let stale = self.stale;
        let gone: Vec<DeviceId> = self
            .devices
            .values()
            .filter(|d| now.saturating_sub(d.last_seen) > stale.timeout_ms(d.kind))
            .map(|d| d.id)
            .collect();
        for id in &gone {
            self.devices.remove(id);
            self.dirty.remove(id);
        }
        gone.into_iter().map(EngineEvent::DeviceRemoved).collect()
    }
}

fn link_mac(d: &Device) -> Option<MacAddr> {
    match d.key {
        DeviceKey::Bssid(m) | DeviceKey::LanMac(m) => Some(m),
        _ => None,
    }
}

/// Same OUI (ignoring the locally-administered bit) and within ±8 in the low 24 bits.
fn macs_related(a: MacAddr, b: MacAddr) -> bool {
    let low = |m: MacAddr| i64::from(u32::from_be_bytes([0, m.0[3], m.0[4], m.0[5]]));
    (a.0[0] | 0x02) == (b.0[0] | 0x02) && a.0[1..3] == b.0[1..3] && (low(a) - low(b)).abs() <= 8
}

impl StalePolicy {
    fn timeout_ms(&self, kind: DeviceKind) -> Millis {
        let d = match kind {
            DeviceKind::Ble => self.bluetooth,
            DeviceKind::BtClassic => self.bt_classic,
            DeviceKind::AccessPoint | DeviceKind::WifiClient => self.wifi,
            DeviceKind::LanHost => self.lan,
        };
        d.as_millis() as Millis
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use na_model::{ClaimKind, DeviceKey, Evidence, EvidenceSource, LanInfo, MacAddr};

    use super::*;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    fn obs(key: DeviceKey, at: Millis, rssi: Option<i16>) -> Observation {
        Observation {
            key,
            at,
            rssi,
            details: DeviceDetails::None,
            evidence: vec![],
            links: vec![],
        }
    }

    fn store() -> DeviceStore {
        DeviceStore::new(StalePolicy {
            bluetooth: Duration::from_secs(10),
            bt_classic: Duration::from_secs(50),
            wifi: Duration::from_secs(20),
            lan: Duration::from_secs(100),
        })
    }

    #[test]
    fn merges_by_key_and_smooths_rssi() {
        let mut s = store();
        let k = DeviceKey::Ble(mac("11:22:33:44:55:66"));
        s.ingest(obs(k.clone(), 1_000, Some(-60)));
        s.ingest(obs(k.clone(), 2_000, Some(-80)));
        assert_eq!(s.len(), 1);
        let d = s.get(DeviceId::for_key(&k)).unwrap();
        assert_eq!(d.rssi_history.len(), 2);
        assert_eq!(d.rssi, Some(-67)); // -60*0.65 + -80*0.35
        assert_eq!(d.first_seen, 1_000);
        assert_eq!(d.last_seen, 2_000);
    }

    #[test]
    fn lan_details_are_unioned() {
        let mut s = store();
        let k = DeviceKey::LanMac(mac("00:11:32:00:00:01"));
        let mut a = obs(k.clone(), 1, None);
        a.details = DeviceDetails::Lan(LanInfo {
            open_ports: vec![445],
            ..Default::default()
        });
        let mut b = obs(k.clone(), 2, None);
        b.details = DeviceDetails::Lan(LanInfo {
            open_ports: vec![22],
            hostname: Some("nas".into()),
            ..Default::default()
        });
        s.ingest(a);
        s.ingest(b);
        let lan = s.get(DeviceId::for_key(&k)).unwrap().lan().unwrap().clone();
        assert_eq!(lan.open_ports, vec![22, 445]);
        assert_eq!(lan.hostname.as_deref(), Some("nas"));
    }

    #[test]
    fn evidence_is_deduplicated_and_classified() {
        let mut s = store();
        let k = DeviceKey::Bssid(mac("3C:37:86:12:34:56"));
        for _ in 0..3 {
            let mut o = obs(k.clone(), 1, Some(-50));
            o.evidence = vec![Evidence::new(
                EvidenceSource::Wps,
                ClaimKind::Model,
                "RAX50",
                0.9,
                "WPS model name",
            )];
            s.ingest(o);
        }
        let d = s.get(DeviceId::for_key(&k)).unwrap();
        assert_eq!(d.evidence.len(), 1);
        assert_eq!(d.identity.model.as_ref().unwrap().value, "RAX50");
    }

    #[test]
    fn ip_keyed_lan_host_is_promoted_to_its_mac() {
        let mut s = store();
        let ip: std::net::IpAddr = "192.168.1.31".parse().unwrap();
        let mut a = obs(DeviceKey::LanIp(ip), 1, None);
        a.details = DeviceDetails::Lan(LanInfo {
            ips: vec![ip],
            services: vec!["_googlecast._tcp".into()],
            ..Default::default()
        });
        a.evidence = vec![Evidence::new(EvidenceSource::Mdns, ClaimKind::DeviceType, "Media streamer", 0.7, "x")];
        s.ingest(a);
        s.drain_updates();

        let mac = mac("F4:F5:D8:00:00:31");
        let mut b = obs(DeviceKey::LanMac(mac), 5, None);
        b.details = DeviceDetails::Lan(LanInfo { mac: Some(mac), ips: vec![ip], ..Default::default() });
        s.ingest(b);
        let events = s.drain_updates();
        assert!(matches!(events[0], EngineEvent::DeviceRemoved(_)), "IP twin removed first");
        assert_eq!(s.len(), 1);
        let d = s.get(DeviceId::for_key(&DeviceKey::LanMac(mac))).unwrap();
        assert_eq!(d.first_seen, 1);
        assert_eq!(d.lan().unwrap().services, vec!["_googlecast._tcp".to_string()]);
        assert_eq!(d.identity.device_type.as_ref().unwrap().value, "Media streamer");
    }

    #[test]
    fn gateway_links_to_its_access_points() {
        let mut s = store();
        // Seen in the wild: a phone hotspot uses the same MAC for both.
        s.ingest(obs(DeviceKey::Bssid(mac("3A:5C:00:12:34:56")), 1, Some(-48)));
        s.ingest(obs(DeviceKey::Bssid(mac("3C:37:86:12:34:57")), 1, Some(-50)));
        s.ingest(obs(DeviceKey::Bssid(mac("3C:37:86:99:00:00")), 1, Some(-50)));
        s.ingest(obs(DeviceKey::LanMac(mac("3A:5C:00:12:34:56")), 2, None));
        s.ingest(obs(DeviceKey::LanMac(mac("3C:37:86:12:34:55")), 2, None));
        let hotspot = s.get(DeviceId::for_key(&DeviceKey::LanMac(mac("3A:5C:00:12:34:56")))).unwrap();
        assert_eq!(hotspot.links, vec![DeviceId::for_key(&DeviceKey::Bssid(mac("3A:5C:00:12:34:56")))]);
        let router = s.get(DeviceId::for_key(&DeviceKey::LanMac(mac("3C:37:86:12:34:55")))).unwrap();
        assert_eq!(router.links.len(), 1, "BSSID+2 links, a distant serial doesn't");
        let ap = s.get(DeviceId::for_key(&DeviceKey::Bssid(mac("3C:37:86:12:34:57")))).unwrap();
        assert_eq!(ap.links, vec![router.id], "links go both ways");
    }

    #[test]
    fn sweep_uses_per_kind_timeouts() {
        let mut s = store();
        s.ingest(obs(DeviceKey::Ble(mac("11:22:33:44:55:66")), 0, Some(-70)));
        s.ingest(obs(DeviceKey::LanMac(mac("00:11:32:00:00:01")), 0, None));
        s.drain_updates();
        let removed = s.sweep_stale(15_000);
        assert_eq!(removed.len(), 1, "BLE expires at 10s, LAN survives until 100s");
        assert_eq!(s.len(), 1);
        assert!(s.drain_updates().is_empty());
    }
}
