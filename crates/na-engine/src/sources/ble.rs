//! Bluetooth scanning: LE advertisements (continuous), connected LE devices
//! (polled), and Classic devices (polled, plus a periodic discovery inquiry).
//!
//! Devices advertise many times a second, often splitting their data between
//! the advert and the scan response. Each device's AD structures are merged
//! and its RSSI is averaged, then one observation per device is emitted per
//! flush interval. That keeps the store, and the frontend, at a calm ~1 Hz per device.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use na_model::{
    BleAddressType, BleInfo, BtClassicInfo, DeviceDetails, DeviceKey, MacAddr, Millis,
    Observation, SourceKind, SourceState, now_millis,
};
use na_platform::bluetooth::{
    self, AdSection, AddressKind, BtError, ConnectedLe, LeCallback, LeEvent, LeScanner, RawAdvert,
    ScanDuty,
};
use tracing::{debug, info, warn};

use super::{BoxFuture, Source, SourceCtx};
use crate::identify::{BtDb, OuiDb, ble_evidence, classic_evidence};
use crate::parse::ble_ad;

#[derive(Clone, Debug)]
pub struct BleConfig {
    /// Scan continuously instead of the OS's Wi-Fi-friendly duty cycle.
    pub low_latency: bool,
    /// How often merged adverts are turned into observations.
    pub flush_interval: Duration,
    /// How often connected/paired devices are polled.
    pub connected_poll: Duration,
    /// How often to run a Classic discovery inquiry (None disables it). Inquiry
    /// briefly takes the radio away from Wi-Fi on combo chips, so keep it infrequent.
    pub inquiry_interval: Option<Duration>,
    pub inquiry_length: Duration,
}

impl Default for BleConfig {
    fn default() -> Self {
        Self {
            low_latency: false,
            flush_interval: Duration::from_secs(1),
            connected_poll: Duration::from_secs(10),
            inquiry_interval: Some(Duration::from_secs(90)),
            inquiry_length: Duration::from_secs(5),
        }
    }
}

/// An advert section not repeated for this long is dropped from the merged view.
const SECTION_TTL: Duration = Duration::from_secs(60);
/// Forget a device's merge state after this much silence.
const ACCUM_TTL: Duration = Duration::from_secs(120);
const RETRY: Duration = Duration::from_secs(5);

pub struct BleSource {
    cfg: BleConfig,
    oui: Arc<OuiDb>,
    bt: Arc<BtDb>,
}

impl BleSource {
    pub fn new(cfg: BleConfig, oui: Arc<OuiDb>, bt: Arc<BtDb>) -> Self {
        Self { cfg, oui, bt }
    }
}

impl Source for BleSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Ble
    }

    fn run(self: Box<Self>, ctx: SourceCtx) -> BoxFuture<anyhow::Result<()>> {
        Box::pin(async move {
            let ctx = Arc::new(ctx);
            let this = Arc::new(*self);
            let (le_this, le_ctx) = (this.clone(), ctx.clone());
            let le = tokio::task::spawn_blocking(move || le_loop(&le_this, &le_ctx));
            let classic = tokio::task::spawn_blocking(move || classic_loop(&this, &ctx));
            let (le, classic) = tokio::join!(le, classic);
            classic.map_err(|e| anyhow!("Bluetooth Classic thread panicked: {e}"))?;
            le.map_err(|e| anyhow!("Bluetooth LE thread panicked: {e}"))?
        })
    }
}

// ---------------------------------------------------------------------------
// LE
// ---------------------------------------------------------------------------

/// Everything known about one LE device at a moment, ready to decode.
#[derive(Clone, Debug, Default)]
pub(crate) struct BleSighting {
    pub address: MacAddr,
    pub address_type: BleAddressType,
    /// AD structures as `(type, data)`.
    pub sections: Vec<(u8, Vec<u8>)>,
    pub rssi: Option<i16>,
    pub tx_power: Option<i8>,
    pub connectable: bool,
    pub paired: bool,
    pub connected: bool,
    /// Name and appearance the OS read over GATT, for connected devices.
    pub os_name: Option<String>,
    pub os_appearance: Option<u16>,
}

/// Decode a sighting into an observation with identification evidence.
pub(crate) fn observation(s: &BleSighting, at: Millis, db: &BtDb, oui: &OuiDb) -> Observation {
    let raw_ad = ble_ad::encode(s.sections.iter().map(|(t, d)| (*t, d.as_slice())));
    let p = ble_ad::parse(ble_ad::structures(&raw_ad));
    let info = BleInfo {
        address: s.address,
        address_type: s.address_type,
        local_name: p.local_name.or_else(|| s.os_name.clone()),
        manufacturer_data: p.manufacturer_data,
        service_uuids: p.services,
        service_data: p.service_data,
        tx_power: p.tx_power.or(s.tx_power),
        appearance: p.appearance.or(s.os_appearance),
        flags: p.flags,
        connectable: s.connectable,
        paired: s.paired,
        connected: s.connected,
        raw_ad,
    };
    let evidence = ble_evidence(&info, db, oui);
    Observation {
        key: DeviceKey::Ble(s.address),
        at,
        rssi: s.rssi,
        details: DeviceDetails::Ble(info),
        evidence,
        links: Vec::new(),
    }
}

fn address_type(addr: MacAddr, kind: AddressKind) -> BleAddressType {
    match kind {
        AddressKind::Public => BleAddressType::Public,
        AddressKind::Random => BleAddressType::from_random(addr),
        AddressKind::Unknown => BleAddressType::Unknown,
    }
}

/// Which merged slot an AD structure lands in. Manufacturer and service data
/// are keyed by company / UUID. Apple's are also keyed by Continuity message
/// type, because iPhones rotate through several.
fn section_key(s: &AdSection) -> (u8, u32) {
    let d = &s.data;
    let le16 = |i: usize| d.get(i..i + 2).map_or(0, |b| u32::from(u16::from_le_bytes([b[0], b[1]])));
    let disc = match s.ad_type {
        0xFF => {
            let company = le16(0);
            let sub = if company == 0x004C { d.get(2).copied().map_or(0, u32::from) } else { 0 };
            company | (sub << 16)
        }
        0x16 => le16(0),
        0x20 | 0x21 => d.get(..4).map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        _ => 0,
    };
    (s.ad_type, disc)
}

struct Accum {
    address_type: BleAddressType,
    sections: HashMap<(u8, u32), (Vec<u8>, Instant)>,
    rssi_sum: i32,
    rssi_n: i32,
    tx_power: Option<i8>,
    connectable: bool,
    connected: Option<ConnectedLe>,
    last_heard: Instant,
    dirty: bool,
}

impl Accum {
    fn new(address_type: BleAddressType, now: Instant) -> Self {
        Self {
            address_type,
            sections: HashMap::new(),
            rssi_sum: 0,
            rssi_n: 0,
            tx_power: None,
            connectable: false,
            connected: None,
            last_heard: now,
            dirty: true,
        }
    }

    fn ingest(&mut self, adv: RawAdvert, now: Instant) {
        self.last_heard = now;
        self.dirty = true;
        // Windows reports -127 when it has no measurement.
        if (-126..=20).contains(&adv.rssi_dbm) {
            self.rssi_sum += i32::from(adv.rssi_dbm);
            self.rssi_n += 1;
        }
        if let Some(tx) = adv.tx_power_dbm.and_then(|t| i8::try_from(t).ok()) {
            self.tx_power = Some(tx);
        }
        self.connectable |= adv.connectable && !adv.scan_response;
        for s in adv.sections {
            let key = section_key(&s);
            self.sections.insert(key, (s.data, now));
        }
    }

    /// Snapshot as a sighting, resetting the RSSI window.
    fn take_sighting(&mut self, address: MacAddr) -> BleSighting {
        let mut sections: Vec<_> = self.sections.iter().map(|(k, (d, _))| (*k, d.clone())).collect();
        sections.sort_by_key(|(k, _)| *k);
        let rssi = (self.rssi_n > 0).then(|| (self.rssi_sum / self.rssi_n) as i16);
        self.rssi_sum = 0;
        self.rssi_n = 0;
        self.dirty = false;
        BleSighting {
            address,
            address_type: self.address_type,
            sections: sections.into_iter().map(|((t, _), d)| (t, d)).collect(),
            rssi,
            tx_power: self.tx_power,
            connectable: self.connectable,
            paired: self.connected.is_some(),
            connected: self.connected.is_some(),
            os_name: self.connected.as_ref().and_then(|c| c.name.clone()),
            os_appearance: self.connected.as_ref().and_then(|c| c.appearance),
        }
    }
}

/// Reports source state only when it changes.
struct Status<'a> {
    ctx: &'a SourceCtx,
    blocked: Option<String>,
}

impl Status<'_> {
    fn blocked(&mut self, why: String) {
        if self.blocked.as_deref() != Some(why.as_str()) {
            warn!(reason = %why, "Bluetooth LE scanning unavailable; will keep retrying");
            self.ctx.report(SourceState::Unavailable(why.clone()));
            self.blocked = Some(why);
        }
    }

    fn running(&mut self) {
        if self.blocked.take().is_some() {
            info!("Bluetooth LE scanning resumed");
            self.ctx.report(SourceState::Running);
        }
    }
}

fn start_scanner(cfg: &BleConfig, cb: LeCallback) -> Result<Box<dyn LeScanner>, BtError> {
    let adapter = bluetooth::adapter_info()?;
    if !adapter.low_energy {
        return Err(BtError::Unsupported("this adapter doesn't support Bluetooth LE".into()));
    }
    if !adapter.radio_on {
        return Err(BtError::RadioOff);
    }
    let duty = if cfg.low_latency { ScanDuty::LowLatency } else { ScanDuty::Balanced };
    let mut scanner = bluetooth::open_le_scanner(duty)?;
    scanner.start(cb)?;
    Ok(scanner)
}

fn le_loop(src: &BleSource, ctx: &SourceCtx) -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel::<LeEvent>();
    let cb: LeCallback = Arc::new(move |ev| {
        let _ = tx.send(ev);
    });
    let mut scanner: Option<Box<dyn LeScanner>> = None;
    let mut status = Status { ctx, blocked: None };
    let mut accums: HashMap<MacAddr, Accum> = HashMap::new();
    let start = Instant::now();
    let (mut next_retry, mut next_poll, mut next_flush) = (start, start, start + src.cfg.flush_interval);

    while !ctx.cancel.is_cancelled() {
        let now = Instant::now();
        if scanner.is_none() && now >= next_retry {
            match start_scanner(&src.cfg, cb.clone()) {
                Ok(s) => {
                    scanner = Some(s);
                    status.running();
                }
                Err(BtError::Unsupported(why)) => {
                    status.blocked(why);
                    while !ctx.cancel.is_cancelled() {
                        ctx.sleep_blocking(Duration::from_secs(1));
                    }
                    return Ok(());
                }
                Err(e) => {
                    status.blocked(e.to_string());
                    next_retry = now + RETRY;
                }
            }
        }

        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(first) => {
                for ev in std::iter::once(first).chain(rx.try_iter()) {
                    match ev {
                        LeEvent::Advert(adv) => {
                            let now = Instant::now();
                            let kind = address_type(adv.address, adv.address_kind);
                            accums.entry(adv.address).or_insert_with(|| Accum::new(kind, now)).ingest(adv, now);
                        }
                        LeEvent::Stopped(e) => {
                            scanner = None;
                            status.blocked(e.to_string());
                            next_retry = Instant::now() + RETRY;
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
        }

        let now = Instant::now();
        if now >= next_poll {
            poll_connected(&mut accums, now);
            next_poll = now + src.cfg.connected_poll;
        }
        if now >= next_flush {
            if !flush(&mut accums, src, ctx, now) {
                break; // engine shutting down
            }
            next_flush = now + src.cfg.flush_interval;
        }
    }
    if let Some(mut s) = scanner {
        s.stop();
    }
    Ok(())
}

fn poll_connected(accums: &mut HashMap<MacAddr, Accum>, now: Instant) {
    let list = match bluetooth::connected_le_devices() {
        Ok(l) => l,
        Err(e) => {
            debug!(error = %e, "connected LE device poll failed");
            return;
        }
    };
    for (addr, acc) in accums.iter_mut() {
        if acc.connected.is_some() && !list.iter().any(|c| c.address == *addr) {
            acc.connected = None;
            acc.dirty = true;
        }
    }
    for dev in list {
        let kind = address_type(dev.address, dev.address_kind);
        let acc = accums.entry(dev.address).or_insert_with(|| Accum::new(kind, now));
        acc.last_heard = now;
        acc.dirty = true;
        acc.connected = Some(dev);
    }
}

/// Emit one observation per changed device. Returns false if the engine has gone away.
fn flush(accums: &mut HashMap<MacAddr, Accum>, src: &BleSource, ctx: &SourceCtx, now: Instant) -> bool {
    let at = now_millis();
    for (addr, acc) in accums.iter_mut() {
        acc.sections.retain(|_, (_, t)| now.duration_since(*t) < SECTION_TTL);
        if !acc.dirty {
            continue;
        }
        let obs = observation(&acc.take_sighting(*addr), at, &src.bt, &src.oui);
        if ctx.sink.blocking_send(obs).is_err() {
            return false;
        }
    }
    accums.retain(|_, a| a.connected.is_some() || now.duration_since(a.last_heard) < ACCUM_TTL);
    true
}

// ---------------------------------------------------------------------------
// Classic
// ---------------------------------------------------------------------------

pub(crate) fn classic_observation(info: BtClassicInfo, at: Millis, oui: &OuiDb) -> Observation {
    let evidence = classic_evidence(&info, oui);
    Observation {
        key: DeviceKey::BtClassic(info.address),
        at,
        rssi: None,
        // A dual-mode device often advertises LE from the same public address.
        links: vec![DeviceKey::Ble(info.address)],
        details: DeviceDetails::BtClassic(info),
        evidence,
    }
}

fn classic_loop(src: &BleSource, ctx: &SourceCtx) {
    let cfg = &src.cfg;
    let mut next_poll = Instant::now();
    // Let LE scanning settle before the first inquiry.
    let mut next_inquiry = Instant::now() + Duration::from_secs(5);
    let mut warned = false;

    while !ctx.cancel.is_cancelled() {
        let now = Instant::now();
        let inquiry = cfg.inquiry_interval.is_some() && now >= next_inquiry;
        if inquiry || now >= next_poll {
            let started = now_millis();
            match bluetooth::classic_devices(inquiry.then_some(cfg.inquiry_length)) {
                Ok(list) => {
                    let finished = now_millis();
                    for d in list {
                        // Cached entries keep old (sometimes odd) timestamps. Only ones
                        // stamped during this inquiry actually answered it.
                        let discovered = inquiry
                            && d.last_seen_ms.is_some_and(|t| t + 5_000 >= started && t <= finished + 5_000);
                        if !(d.connected || discovered) {
                            continue;
                        }
                        let info = BtClassicInfo {
                            address: d.address,
                            name: d.name,
                            class_of_device: d.class_of_device,
                            paired: d.remembered,
                            connected: d.connected,
                            discoverable: discovered,
                        };
                        if ctx.sink.blocking_send(classic_observation(info, finished, &src.oui)).is_err() {
                            return;
                        }
                    }
                }
                Err(BtError::Unsupported(_)) => return,
                Err(e) => {
                    if !warned {
                        warn!(error = %e, "Bluetooth Classic poll failed");
                        warned = true;
                    }
                }
            }
            next_poll = Instant::now() + cfg.connected_poll;
            if let (true, Some(every)) = (inquiry, cfg.inquiry_interval) {
                next_inquiry = Instant::now() + every;
            }
        }
        ctx.sleep_blocking(Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use na_model::ClaimKind;

    use super::*;

    fn advert(sections: &[(u8, &[u8])], rssi: i16, scan_response: bool) -> RawAdvert {
        RawAdvert {
            address: "4B:00:00:12:34:58".parse().unwrap(),
            address_kind: AddressKind::Random,
            rssi_dbm: rssi,
            tx_power_dbm: None,
            connectable: true,
            scan_response,
            sections: sections.iter().map(|(t, d)| AdSection { ad_type: *t, data: d.to_vec() }).collect(),
            received_at_ms: 0,
        }
    }

    #[test]
    fn advert_and_scan_response_merge_into_one_device() {
        let now = Instant::now();
        let addr: MacAddr = "4B:00:00:12:34:58".parse().unwrap();
        let mut acc = Accum::new(BleAddressType::from_random(addr), now);
        // Seen in the wild: Apple Nearby Info + TX power in the advert…
        acc.ingest(advert(&[(0x01, &[0x1A]), (0x0A, &[0x0C]), (0xFF, &[0x4C, 0x00, 0x10, 0x07, 0x2E, 0x1F])], -70, false), now);
        // …the name in the scan response, and a second Continuity message type.
        acc.ingest(advert(&[(0x09, b"Sam's MacBook")], -60, true), now);
        acc.ingest(advert(&[(0xFF, &[0x4C, 0x00, 0x0C, 0x0E, 0x00])], -62, false), now);

        let s = acc.take_sighting(addr);
        assert_eq!(s.rssi, Some(-64), "window mean of -70, -60, -62");
        assert_eq!(s.address_type, BleAddressType::RandomResolvable);
        assert!(s.connectable);
        let obs = observation(&s, 1, &BtDb::builtin(), &OuiDb::default());
        let DeviceDetails::Ble(b) = &obs.details else { panic!() };
        assert_eq!(b.local_name.as_deref(), Some("Sam's MacBook"));
        assert_eq!(b.manufacturer_data.len(), 2, "both Apple message types kept");
        assert_eq!(b.tx_power, Some(12));
        assert!(obs.evidence.iter().any(|e| e.kind == ClaimKind::DeviceType && e.value == "Laptop"));
        // The RSSI window resets after each flush.
        assert_eq!(acc.take_sighting(addr).rssi, None);
    }

    #[test]
    fn invalid_rssi_is_ignored_and_connected_devices_use_os_details() {
        let now = Instant::now();
        let addr: MacAddr = "CA:00:00:12:34:57".parse().unwrap();
        let mut acc = Accum::new(BleAddressType::from_random(addr), now);
        acc.ingest(advert(&[], -127, false), now);
        acc.connected = Some(ConnectedLe {
            address: addr,
            address_kind: AddressKind::Random,
            name: Some("Dell Mouse MS5120W".into()),
            appearance: Some(962),
        });
        let s = acc.take_sighting(addr);
        assert_eq!(s.rssi, None);
        let obs = observation(&s, 1, &BtDb::builtin(), &OuiDb::default());
        let DeviceDetails::Ble(b) = &obs.details else { panic!() };
        assert!(b.connected && b.paired);
        assert_eq!(b.address_type, BleAddressType::RandomStatic);
        assert_eq!(b.local_name.as_deref(), Some("Dell Mouse MS5120W"));
        assert!(obs.evidence.iter().any(|e| e.value == "Mouse"));
        assert!(obs.evidence.iter().any(|e| e.value == "Dell"));
    }

    #[test]
    fn classic_observation_links_to_le_twin() {
        let info = BtClassicInfo {
            address: "80:9F:F5:00:12:34".parse().unwrap(),
            name: Some("Galaxy Buds Pro (1234)".into()),
            class_of_device: 0x240404,
            paired: true,
            connected: true,
            discoverable: false,
        };
        let obs = classic_observation(info, 5, &OuiDb::default());
        assert_eq!(obs.key, DeviceKey::BtClassic("80:9F:F5:00:12:34".parse().unwrap()));
        assert_eq!(obs.links, vec![DeviceKey::Ble("80:9F:F5:00:12:34".parse().unwrap())]);
        assert!(obs.rssi.is_none());
    }
}
