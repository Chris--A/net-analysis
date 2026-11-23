use std::collections::{HashMap, HashSet};

use na_model::{
    Device, DeviceDetails, DeviceId, DeviceKind, EngineEvent, Millis, Observation,
    RSSI_HISTORY_LEN, RssiSample,
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
    stale: StalePolicy,
}

impl DeviceStore {
    pub fn new(stale: StalePolicy) -> Self {
        Self {
            devices: HashMap::new(),
            dirty: HashSet::new(),
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
        let dev = self
            .devices
            .entry(id)
            .or_insert_with(|| Device::new(obs.key.clone(), obs.at));

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
            // Radio sources report the full current state each time.
            (slot, new) => *slot = new,
        }

        let mut evidence_changed = false;
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
    }

    /// Snapshots of every device changed since the last call.
    pub fn drain_updates(&mut self) -> Vec<EngineEvent> {
        self.dirty
            .drain()
            .filter_map(|id| self.devices.get(&id))
            .map(|d| EngineEvent::DeviceUpserted(Box::new(d.clone())))
            .collect()
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

impl StalePolicy {
    fn timeout_ms(&self, kind: DeviceKind) -> Millis {
        let d = match kind {
            DeviceKind::Ble | DeviceKind::BtClassic => self.bluetooth,
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
