//! Synthetic device generator. It lets the UI, classifier and guard detectors be built
//! and tested without radios, drivers or admin rights.
//!
//! It models a home network (mesh router, LAN hosts), neighbouring APs, BLE
//! devices that come and go, and an **evil twin** of the home SSID that appears
//! after `evil_twin_after`. The twin has an open network, a locally-administered BSSID,
//! a fresh TSF uptime and a minimal IE set. All vendor prefixes are synthetic.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use na_model::{
    Akm, ApInfo, Band, BleInfo, Cipher, ClaimKind, DeviceDetails, DeviceKey, Evidence,
    EvidenceSource as Src, LanInfo, MacAddr, Observation, Pmf, Security, SourceKind, WpsInfo,
    now_millis, stable_hash,
};
use tokio_util::sync::CancellationToken;

use super::{BoxFuture, ObservationSink, Source};

#[derive(Clone, Debug)]
pub struct SimConfig {
    pub seed: u64,
    pub tick: Duration,
    /// Additional random devices for load testing the frontend.
    pub extra_devices: usize,
    /// When the evil-twin AP appears (None disables it).
    pub evil_twin_after: Option<Duration>,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            seed: 0x5EED_2026,
            tick: Duration::from_secs(1),
            extra_devices: 0,
            evil_twin_after: Some(Duration::from_secs(20)),
        }
    }
}

pub struct SimSource {
    cfg: SimConfig,
}

impl SimSource {
    pub fn new(cfg: SimConfig) -> Self {
        Self { cfg }
    }
}

impl Source for SimSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Sim
    }

    fn run(
        self: Box<Self>,
        sink: ObservationSink,
        cancel: CancellationToken,
    ) -> BoxFuture<anyhow::Result<()>> {
        Box::pin(async move {
            let mut world = SimWorld::new(&self.cfg);
            let start = tokio::time::Instant::now();
            let mut tick = tokio::time::interval(self.cfg.tick);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    _ = tick.tick() => {
                        for obs in world.step(start.elapsed()) {
                            if sink.send(obs).await.is_err() {
                                return Ok(());
                            }
                        }
                    }
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// World model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Presence {
    Always,
    After(f32),
    /// Present for the first `on` fraction of every `period` seconds.
    Cycle { period: f32, on: f32, phase: f32 },
}

impl Presence {
    fn is_present(self, t: f32) -> bool {
        match self {
            Presence::Always => true,
            Presence::After(s) => t >= s,
            Presence::Cycle { period, on, phase } => (t / period + phase).fract() < on,
        }
    }
}

struct SimDevice {
    key: DeviceKey,
    details: DeviceDetails,
    evidence: Vec<Evidence>,
    links: Vec<DeviceKey>,
    /// Mean signal level; None for wired-only devices.
    base_rssi: Option<f32>,
    rssi: f32,
    presence: Presence,
    /// AP uptime at sim start (may be negative for APs that boot later).
    tsf_offset_secs: Option<i64>,
}

impl SimDevice {
    fn new(key: DeviceKey, details: DeviceDetails, base_rssi: Option<f32>) -> Self {
        Self {
            key,
            details,
            evidence: Vec::new(),
            links: Vec::new(),
            base_rssi,
            rssi: base_rssi.unwrap_or(0.0),
            presence: Presence::Always,
            tsf_offset_secs: None,
        }
    }

    fn ev(mut self, src: Src, kind: ClaimKind, value: &str, conf: f32, detail: &str) -> Self {
        self.evidence.push(Evidence::new(src, kind, value, conf, detail));
        self
    }

    fn presence(mut self, p: Presence) -> Self {
        self.presence = p;
        self
    }

    fn link(mut self, key: DeviceKey) -> Self {
        self.links.push(key);
        self
    }

    fn tsf(mut self, offset_secs: i64) -> Self {
        self.tsf_offset_secs = Some(offset_secs);
        self
    }

    fn edit_ap(mut self, f: impl FnOnce(&mut ApInfo)) -> Self {
        if let DeviceDetails::Ap(ap) = &mut self.details {
            f(ap);
        }
        self
    }
}

pub(crate) struct SimWorld {
    devices: Vec<SimDevice>,
    rng: Rng,
}

impl SimWorld {
    pub(crate) fn new(cfg: &SimConfig) -> Self {
        let mut rng = Rng(cfg.seed);
        let mut devices = Vec::new();
        build_home(&mut devices, cfg);
        build_neighbour_aps(&mut devices, &mut rng);
        build_ble(&mut devices, &mut rng);
        build_extra(&mut devices, &mut rng, cfg.extra_devices);
        Self { devices, rng }
    }

    pub(crate) fn step(&mut self, elapsed: Duration) -> Vec<Observation> {
        let now = now_millis();
        let t = elapsed.as_secs_f32();
        let rng = &mut self.rng;
        let mut out = Vec::with_capacity(self.devices.len());
        for d in &mut self.devices {
            if !d.presence.is_present(t) {
                continue;
            }
            let rssi = d.base_rssi.map(|base| {
                // Mean-reverting random walk.
                d.rssi += (base - d.rssi) * 0.25 + rng.normal() * 2.5;
                d.rssi = d.rssi.clamp(-100.0, -20.0);
                d.rssi.round() as i16
            });
            let mut details = d.details.clone();
            if let (DeviceDetails::Ap(ap), Some(off)) = (&mut details, d.tsf_offset_secs) {
                ap.tsf_uptime_secs = Some((off + elapsed.as_secs() as i64).max(0) as u64);
            }
            out.push(Observation {
                key: d.key.clone(),
                at: now,
                rssi,
                details,
                evidence: d.evidence.clone(),
                links: d.links.clone(),
            });
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

const DAY: i64 = 86_400;

/// Deterministic synthetic vendor prefix (globally-administered, unicast).
fn sim_mac(vendor: &str, n: u32) -> MacAddr {
    let h = stable_hash(vendor.as_bytes());
    let n = n.to_be_bytes();
    MacAddr([(h >> 16) as u8 & 0xFC, (h >> 8) as u8, h as u8, n[1], n[2], n[3]])
}

fn oui_detail(mac: MacAddr, vendor: &str) -> String {
    let o = mac.oui();
    format!("OUI {:02X}:{:02X}:{:02X} → {vendor} (synthetic)", o[0], o[1], o[2])
}

fn sec(akms: &[Akm], pmf: Pmf) -> Security {
    let open = akms.iter().all(|a| *a == Akm::Open);
    Security {
        akms: akms.to_vec(),
        pairwise: if open { vec![] } else { vec![Cipher::Ccmp128] },
        group: (!open).then_some(Cipher::Ccmp128),
        pmf,
    }
}

fn open() -> Security {
    Security::open()
}
fn owe() -> Security {
    sec(&[Akm::Owe], Pmf::Required)
}
fn wpa2() -> Security {
    sec(&[Akm::Psk], Pmf::Disabled)
}
fn wpa3() -> Security {
    sec(&[Akm::Sae], Pmf::Required)
}
fn wpa3_transition() -> Security {
    sec(&[Akm::Sae, Akm::Psk], Pmf::Capable)
}
fn enterprise() -> Security {
    sec(&[Akm::Eap], Pmf::Capable)
}

#[allow(clippy::too_many_arguments)]
fn ap(
    ssid: &str,
    bssid: MacAddr,
    band: Band,
    channel: u16,
    width_mhz: u16,
    security: Security,
    wifi_gen: u8,
    rssi: f32,
    ie_fingerprint: u64,
) -> SimDevice {
    let info = ApInfo {
        ssid: ssid.into(),
        bssid,
        channel,
        band,
        width_mhz,
        security,
        wifi_gen: Some(wifi_gen),
        beacon_interval_tu: 100,
        tsf_uptime_secs: None,
        wps: None,
        ie_fingerprint,
        connected: false,
    };
    SimDevice::new(DeviceKey::Bssid(bssid), DeviceDetails::Ap(info), Some(rssi))
}

fn lan(mac: MacAddr, ip: [u8; 4], hostname: Option<&str>, ports: &[u16], services: &[&str]) -> SimDevice {
    let info = LanInfo {
        mac: Some(mac),
        ips: vec![IpAddr::V4(Ipv4Addr::from(ip))],
        hostname: hostname.map(Into::into),
        open_ports: ports.to_vec(),
        services: services.iter().map(|s| (*s).to_owned()).collect(),
        is_gateway: false,
        is_self: false,
    };
    SimDevice::new(DeviceKey::LanMac(mac), DeviceDetails::Lan(info), None)
}

fn edit_lan(mut d: SimDevice, f: impl FnOnce(&mut LanInfo)) -> SimDevice {
    if let DeviceDetails::Lan(l) = &mut d.details {
        f(l);
    }
    d
}

fn build_home(out: &mut Vec<SimDevice>, cfg: &SimConfig) {
    let vendor = "NETGEAR";
    let main = sim_mac(vendor, 0x12_3456);
    let radio24 = main.offset(1);
    let satellite = sim_mac(vendor, 0x12_4010);
    let gateway = main.offset(-1);
    let fp = stable_hash(b"netgear-rax50-he-wps");
    let wps = WpsInfo {
        manufacturer: Some("NETGEAR".into()),
        model_name: Some("RAX50".into()),
        model_number: Some("RAX50".into()),
        device_name: Some("NETGEAR RAX50".into()),
    };

    let router_ev = |d: SimDevice, mac: MacAddr| {
        d.ev(Src::Oui, ClaimKind::Vendor, vendor, 0.6, &oui_detail(mac, vendor))
            .ev(Src::Wps, ClaimKind::Vendor, "NETGEAR", 0.85, "WPS Manufacturer = \"NETGEAR\"")
            .ev(Src::Wps, ClaimKind::Model, "RAX50", 0.9, "WPS Model Name = \"RAX50\"")
            .ev(Src::Ie, ClaimKind::DeviceType, "Wi-Fi router", 0.6, "WPS registrar + HE capabilities in beacon")
    };

    for (bssid, band, ch, width, rssi) in [
        (main, Band::G5, 44, 80, -48.0),
        (radio24, Band::G2_4, 6, 20, -52.0),
        (satellite, Band::G5, 149, 80, -67.0),
    ] {
        let wps = wps.clone();
        let d = ap("HomeNet", bssid, band, ch, width, wpa3_transition(), 6, rssi, fp)
            .tsf(12 * DAY + 3_600)
            .edit_ap(|a| {
                a.wps = Some(wps);
                a.connected = bssid == main;
            });
        out.push(router_ev(d, bssid));
    }

    if let Some(after) = cfg.evil_twin_after {
        let s = after.as_secs_f32();
        let mut twin_mac = main;
        twin_mac.0[0] |= 0x02; // same address with the U/L bit flipped
        out.push(
            ap("HomeNet", twin_mac, Band::G2_4, 6, 20, open(), 4, -41.0, stable_hash(b"hostapd-minimal"))
                .presence(Presence::After(s))
                .tsf(-(s as i64))
                .ev(Src::Ie, ClaimKind::DeviceType, "Wi-Fi AP", 0.3, "Minimal IE set: no WPS, no vendor IEs (hostapd-like)"),
        );
    }

    // --- LAN ---
    let home_aps = [main, radio24, satellite];
    let mut gw = edit_lan(
        lan(gateway, [192, 168, 1, 1], Some("router.lan"), &[53, 80, 443], &["_http._tcp"]),
        |l| l.is_gateway = true,
    )
    .ev(Src::Oui, ClaimKind::Vendor, vendor, 0.6, &oui_detail(gateway, vendor))
    .ev(Src::Ssdp, ClaimKind::DeviceType, "Router", 0.8, "UPnP urn:schemas-upnp-org:device:InternetGatewayDevice:1")
    .ev(Src::Heuristic, ClaimKind::Model, "RAX50", 0.5, "LAN MAC is BSSID−1 of 'HomeNet' AP whose WPS model is RAX50")
    .ev(Src::Banner, ClaimKind::Vendor, "NETGEAR", 0.4, "HTTP Server: NETGEAR");
    for b in home_aps {
        gw = gw.link(DeviceKey::Bssid(b));
    }
    out.push(gw);

    let pc = sim_mac("Intel", 0x0A_0B0C);
    out.push(
        edit_lan(lan(pc, [192, 168, 1, 23], Some("DESKTOP-NA01"), &[135, 139, 445], &[]), |l| {
            l.is_self = true
        })
        .ev(Src::NetBios, ClaimKind::Name, "DESKTOP-NA01", 0.9, "NBSTAT name DESKTOP-NA01<00>")
        .ev(Src::Oui, ClaimKind::Vendor, "Intel", 0.4, &oui_detail(pc, "Intel (NIC)"))
        .ev(Src::Banner, ClaimKind::Os, "Windows", 0.7, "MSRPC on 135, SMB 3.1.1 on 445")
        .ev(Src::Heuristic, ClaimKind::DeviceType, "PC", 0.6, "This machine"),
    );

    let nas = sim_mac("Synology", 0x00_0001);
    out.push(
        lan(nas, [192, 168, 1, 10], Some("nas"), &[22, 80, 443, 445, 5000, 5001], &["_smb._tcp", "_http._tcp", "_afpovertcp._tcp"])
            .ev(Src::Oui, ClaimKind::Vendor, "Synology", 0.6, &oui_detail(nas, "Synology"))
            .ev(Src::Ssdp, ClaimKind::Vendor, "Synology", 0.8, "UPnP manufacturer = Synology")
            .ev(Src::Ssdp, ClaimKind::Model, "DS920+", 0.85, "UPnP modelName = DS920+")
            .ev(Src::Mdns, ClaimKind::DeviceType, "NAS", 0.7, "_afpovertcp._tcp + _smb._tcp")
            .ev(Src::Banner, ClaimKind::Os, "Synology DSM 7", 0.6, "HTTP :5000 title 'Synology DiskStation'"),
    );

    let cast = sim_mac("Google", 0x31_0031);
    out.push(
        lan(cast, [192, 168, 1, 31], None, &[8008, 8009, 8443], &["_googlecast._tcp"])
            .ev(Src::Oui, ClaimKind::Vendor, "Google", 0.6, &oui_detail(cast, "Google"))
            .ev(Src::Mdns, ClaimKind::Name, "Living Room TV", 0.9, "TXT fn=Living Room TV")
            .ev(Src::Mdns, ClaimKind::DeviceType, "Media streamer", 0.8, "_googlecast._tcp")
            .ev(Src::Mdns, ClaimKind::Model, "Chromecast with Google TV", 0.85, "TXT md=Chromecast"),
    );

    let tv = sim_mac("LG Electronics", 0x32_0032);
    out.push(
        lan(tv, [192, 168, 1, 32], None, &[3000, 3001], &["_airplay._tcp"])
            .ev(Src::Ssdp, ClaimKind::Vendor, "LG Electronics", 0.8, "UPnP manufacturer = LG Electronics")
            .ev(Src::Ssdp, ClaimKind::Model, "OLED55C2", 0.8, "UPnP modelName = OLED55C2")
            .ev(Src::Ssdp, ClaimKind::DeviceType, "TV", 0.8, "UPnP MediaRenderer:1, webOS user agent")
            .ev(Src::Ssdp, ClaimKind::Os, "webOS", 0.7, "SERVER: WebOS/6.0 UPnP/1.0"),
    );

    let printer = sim_mac("HP", 0x40_0040);
    out.push(
        lan(printer, [192, 168, 1, 40], Some("HP4A2B1C"), &[80, 443, 631, 9100], &["_ipp._tcp", "_pdl-datastream._tcp"])
            .ev(Src::Oui, ClaimKind::Vendor, "HP", 0.6, &oui_detail(printer, "HP"))
            .ev(Src::Mdns, ClaimKind::DeviceType, "Printer", 0.9, "_ipp._tcp")
            .ev(Src::Mdns, ClaimKind::Model, "OfficeJet Pro 9015", 0.85, "TXT ty=HP OfficeJet Pro 9015"),
    );

    let mut iphone = sim_mac("phone-random", 0x50_0050);
    iphone.0[0] |= 0x02; // private Wi-Fi address
    out.push(
        lan(iphone, [192, 168, 1, 50], Some("iPhone"), &[62078], &["_apple-mobdev2._tcp"])
            .ev(Src::Banner, ClaimKind::DeviceType, "Phone", 0.7, "TCP 62078 (lockdownd) open")
            .ev(Src::Mdns, ClaimKind::Vendor, "Apple", 0.6, "_apple-mobdev2._tcp")
            .ev(Src::Mdns, ClaimKind::Os, "iOS", 0.7, "_apple-mobdev2._tcp"),
    );

    let hue = sim_mac("Signify", 0x60_0060);
    out.push(
        lan(hue, [192, 168, 1, 60], Some("Philips-hue"), &[80, 443], &["_hue._tcp"])
            .ev(Src::Oui, ClaimKind::Vendor, "Signify", 0.6, &oui_detail(hue, "Signify"))
            .ev(Src::Mdns, ClaimKind::DeviceType, "Smart home hub", 0.85, "_hue._tcp")
            .ev(Src::Mdns, ClaimKind::Model, "Hue Bridge", 0.8, "_hue._tcp TXT modelid=BSB002"),
    );

    let plug = sim_mac("Espressif", 0x70_0070);
    out.push(
        lan(plug, [192, 168, 1, 70], Some("ESP_3A1F2C"), &[6668], &[])
            .ev(Src::Oui, ClaimKind::Vendor, "Espressif", 0.5, &oui_detail(plug, "Espressif (Wi-Fi chip)"))
            .ev(Src::Banner, ClaimKind::DeviceType, "Smart plug", 0.5, "TCP 6668 open (Tuya local protocol)"),
    );

    let cam = sim_mac("Reolink", 0x80_0080);
    out.push(
        lan(cam, [192, 168, 1, 80], None, &[80, 554, 9000], &["_http._tcp"])
            .ev(Src::Banner, ClaimKind::DeviceType, "IP camera", 0.75, "RTSP on 554")
            .ev(Src::Banner, ClaimKind::Vendor, "Reolink", 0.6, "HTTP title 'Reolink'"),
    );

    let pi = sim_mac("Raspberry Pi", 0x90_0090);
    out.push(
        lan(pi, [192, 168, 1, 90], Some("raspberrypi"), &[22, 8123], &["_home-assistant._tcp", "_ssh._tcp"])
            .ev(Src::Oui, ClaimKind::Vendor, "Raspberry Pi", 0.7, &oui_detail(pi, "Raspberry Pi Trading"))
            .ev(Src::Banner, ClaimKind::Os, "Linux (Debian)", 0.7, "SSH banner OpenSSH_9.2p1 Debian")
            .ev(Src::Heuristic, ClaimKind::DeviceType, "Single-board computer", 0.6, "Raspberry Pi OUI"),
    );

    let xbox = sim_mac("Microsoft", 0x33_0033);
    out.push(
        lan(xbox, [192, 168, 1, 33], Some("XBOX"), &[3074], &[])
            .ev(Src::Oui, ClaimKind::Vendor, "Microsoft", 0.6, &oui_detail(xbox, "Microsoft"))
            .ev(Src::Banner, ClaimKind::DeviceType, "Game console", 0.6, "TCP 3074 (Xbox Live)"),
    );
}

/// (SSID, vendor, band, channel, width MHz, security, Wi-Fi generation, RSSI, device type)
type NeighbourRow = (
    &'static str,
    &'static str,
    Band,
    u16,
    u16,
    fn() -> Security,
    u8,
    f32,
    Option<&'static str>,
);

fn build_neighbour_aps(out: &mut Vec<SimDevice>, rng: &mut Rng) {
    let table: &[NeighbourRow] = &[
        ("TELUS2047", "Arris", Band::G2_4, 1, 20, wpa2, 5, -71.0, Some("ISP gateway")),
        ("TELUS2047", "Arris", Band::G5, 36, 80, wpa2, 5, -77.0, Some("ISP gateway")),
        ("Linksys03561", "Linksys", Band::G5, 149, 80, wpa2, 5, -79.0, None),
        ("DIRECT-7B-HP OfficeJet Pro", "HP", Band::G2_4, 6, 20, wpa2, 4, -64.0, Some("Printer (Wi-Fi Direct)")),
        ("xfinitywifi", "Arris", Band::G2_4, 11, 20, open, 5, -83.0, Some("Public hotspot")),
        ("Cafe Guest", "Ubiquiti", Band::G5, 157, 40, owe, 6, -84.0, None),
        ("Pixel_4412", "Google", Band::G5, 161, 80, wpa3, 6, -69.0, Some("Phone hotspot")),
        ("BELL431", "Sagemcom", Band::G5, 52, 80, wpa2, 5, -76.0, Some("ISP gateway")),
        ("SmartLife-7A1C", "Espressif", Band::G2_4, 3, 20, open, 4, -66.0, Some("IoT setup AP")),
        ("Office-Corp", "Cisco Meraki", Band::G5, 100, 40, enterprise, 6, -86.0, Some("Enterprise AP")),
        ("Office-Corp", "Cisco Meraki", Band::G6, 37, 160, enterprise, 6, -89.0, Some("Enterprise AP")),
        ("ASUS_88_6G", "ASUSTek", Band::G6, 5, 160, wpa3, 6, -73.0, Some("Wi-Fi router")),
        ("", "TP-Link", Band::G2_4, 9, 20, wpa2, 4, -82.0, None),
        ("STARLINK", "SpaceX", Band::G5, 40, 80, wpa2, 6, -80.0, Some("Satellite router")),
        ("eero-4F2A", "eero", Band::G5, 60, 80, wpa3_transition, 6, -74.0, Some("Mesh node")),
        ("eero-4F2A", "eero", Band::G2_4, 1, 20, wpa3_transition, 6, -70.0, Some("Mesh node")),
    ];
    for (i, &(ssid, vendor, band, ch, width, security, wifi_gen, rssi, dtype)) in table.iter().enumerate() {
        let bssid = sim_mac(vendor, 0x0100 + i as u32);
        let fp = stable_hash(format!("{vendor}-{wifi_gen}").as_bytes());
        let uptime = (rng.range(1.0, 60.0) * DAY as f32) as i64;
        let mut d = ap(ssid, bssid, band, ch, width, security(), wifi_gen, rssi, fp)
            .tsf(uptime)
            .ev(Src::Oui, ClaimKind::Vendor, vendor, 0.55, &oui_detail(bssid, vendor));
        if let Some(t) = dtype {
            d = d.ev(Src::Ie, ClaimKind::DeviceType, t, 0.5, "Inferred from SSID pattern and IEs");
        }
        out.push(d);
    }
}

struct BleSpec {
    name: Option<&'static str>,
    company: Option<u16>,
    mfr: &'static [u8],
    services: &'static [&'static str],
    rssi: f32,
    /// (period seconds, fraction present). None = always present.
    cycle: Option<(f32, f32)>,
    vendor: Option<&'static str>,
    dtype: Option<&'static str>,
    model: Option<&'static str>,
    os: Option<&'static str>,
    detail: &'static str,
}

const BLE_DEFAULT: BleSpec = BleSpec {
    name: None,
    company: None,
    mfr: &[],
    services: &[],
    rssi: -80.0,
    cycle: None,
    vendor: None,
    dtype: None,
    model: None,
    os: None,
    detail: "",
};

fn build_ble(out: &mut Vec<SimDevice>, rng: &mut Rng) {
    let specs = [
        BleSpec { company: Some(0x004C), mfr: &[0x10, 0x05, 0x01, 0x18, 0x6E, 0x2A, 0x0B], rssi: -58.0, vendor: Some("Apple"), dtype: Some("Phone"), os: Some("iOS"), detail: "Apple Continuity 0x10 (Nearby Info)", ..BLE_DEFAULT },
        BleSpec { company: Some(0x004C), mfr: &[0x07, 0x19, 0x01, 0x0E, 0x20, 0x55, 0xAA], rssi: -62.0, vendor: Some("Apple"), dtype: Some("Headphones"), model: Some("AirPods Pro"), detail: "Apple Continuity 0x07 (Proximity Pairing), model 0x200E", ..BLE_DEFAULT },
        BleSpec { company: Some(0x004C), mfr: &[0x12, 0x19, 0x10], rssi: -84.0, vendor: Some("Apple"), dtype: Some("Tracker"), model: Some("Find My accessory"), detail: "Apple Continuity 0x12 (Offline Finding)", ..BLE_DEFAULT },
        BleSpec { company: Some(0x0075), mfr: &[0x42, 0x09, 0x81, 0x02], rssi: -71.0, cycle: Some((90.0, 0.7)), vendor: Some("Samsung"), dtype: Some("Phone"), os: Some("Android"), detail: "Company ID 0x0075 (Samsung)", ..BLE_DEFAULT },
        BleSpec { name: Some("Galaxy Buds2 (4F2A)"), company: Some(0x0075), rssi: -74.0, vendor: Some("Samsung"), dtype: Some("Headphones"), model: Some("Galaxy Buds2"), detail: "Local name + company ID 0x0075", ..BLE_DEFAULT },
        BleSpec { services: &["0xFE2C"], rssi: -77.0, cycle: Some((60.0, 0.5)), vendor: Some("Google"), dtype: Some("Headphones"), model: Some("Pixel Buds Pro"), detail: "Google Fast Pair service 0xFE2C", ..BLE_DEFAULT },
        BleSpec { name: Some("Tile"), services: &["0xFEED"], rssi: -85.0, vendor: Some("Tile"), dtype: Some("Tracker"), detail: "Service 0xFEED (Tile)", ..BLE_DEFAULT },
        BleSpec { name: Some("Bose QC45"), company: Some(0x009E), rssi: -79.0, cycle: Some((120.0, 0.6)), vendor: Some("Bose"), dtype: Some("Headphones"), model: Some("QuietComfort 45"), detail: "Company ID 0x009E (Bose)", ..BLE_DEFAULT },
        BleSpec { name: Some("WH-1000XM5"), company: Some(0x012D), rssi: -88.0, cycle: Some((45.0, 0.35)), vendor: Some("Sony"), dtype: Some("Headphones"), model: Some("WH-1000XM5"), detail: "Company ID 0x012D (Sony)", ..BLE_DEFAULT },
        BleSpec { name: Some("Xbox Wireless Controller"), company: Some(0x0006), rssi: -66.0, vendor: Some("Microsoft"), dtype: Some("Game controller"), detail: "Local name + company ID 0x0006", ..BLE_DEFAULT },
        BleSpec { company: Some(0x0006), mfr: &[0x01, 0x09, 0x20, 0x02], rssi: -55.0, vendor: Some("Microsoft"), dtype: Some("Windows PC"), os: Some("Windows"), detail: "Microsoft CDP beacon (company 0x0006, scenario 0x01)", ..BLE_DEFAULT },
        BleSpec { name: Some("[LG] webOS TV OLED55C2"), company: Some(0x00C4), rssi: -70.0, vendor: Some("LG Electronics"), dtype: Some("TV"), model: Some("OLED55C2"), os: Some("webOS"), detail: "Local name + company ID 0x00C4", ..BLE_DEFAULT },
        BleSpec { name: Some("Hue color lamp"), services: &["0xFE0F"], rssi: -68.0, vendor: Some("Signify"), dtype: Some("Smart bulb"), detail: "Service 0xFE0F (Signify / Philips Hue)", ..BLE_DEFAULT },
        BleSpec { name: Some("GVH5075_8F2B"), rssi: -81.0, vendor: Some("Govee"), dtype: Some("Thermometer"), model: Some("H5075"), detail: "Local name pattern GVH5075_*", ..BLE_DEFAULT },
        BleSpec { name: Some("Mi Smart Band 6"), services: &["0xFE95"], rssi: -76.0, cycle: Some((70.0, 0.5)), vendor: Some("Xiaomi"), dtype: Some("Wearable"), model: Some("Mi Smart Band 6"), detail: "Service 0xFE95 (Xiaomi MiBeacon)", ..BLE_DEFAULT },
        BleSpec { name: Some("Forerunner 255"), company: Some(0x0087), rssi: -83.0, cycle: Some((100.0, 0.4)), vendor: Some("Garmin"), dtype: Some("Wearable"), model: Some("Forerunner 255"), detail: "Company ID 0x0087 (Garmin)", ..BLE_DEFAULT },
        BleSpec { name: Some("S7b3c1a9f2e4d5c6aC"), rssi: -90.0, cycle: Some((150.0, 0.3)), vendor: Some("Tesla"), dtype: Some("Vehicle"), detail: "Local name matches Tesla phone-key beacon pattern", ..BLE_DEFAULT },
        BleSpec { rssi: -86.0, cycle: Some((40.0, 0.5)), ..BLE_DEFAULT },
        BleSpec { rssi: -91.0, cycle: Some((55.0, 0.4)), ..BLE_DEFAULT },
        BleSpec { company: Some(0x004C), mfr: &[0x10, 0x05, 0x0B], rssi: -89.0, cycle: Some((35.0, 0.45)), vendor: Some("Apple"), detail: "Apple Continuity 0x10 (Nearby Info)", ..BLE_DEFAULT },
        BleSpec { rssi: -94.0, cycle: Some((80.0, 0.3)), ..BLE_DEFAULT },
    ];

    for spec in specs {
        let address = random_ble_address(rng);
        let info = BleInfo {
            address,
            random_address: true,
            local_name: spec.name.map(Into::into),
            company_id: spec.company,
            manufacturer_data: spec.mfr.to_vec(),
            service_uuids: spec.services.iter().map(|s| (*s).to_owned()).collect(),
            tx_power: None,
            appearance: None,
            connectable: spec.name.is_some(),
        };
        let mut d = SimDevice::new(DeviceKey::Ble(address), DeviceDetails::Ble(info), Some(spec.rssi));
        if let Some((period, on)) = spec.cycle {
            d = d.presence(Presence::Cycle { period, on, phase: rng.f32() });
        }
        for (kind, value, conf) in [
            (ClaimKind::Vendor, spec.vendor, 0.7),
            (ClaimKind::DeviceType, spec.dtype, 0.6),
            (ClaimKind::Model, spec.model, 0.7),
            (ClaimKind::Os, spec.os, 0.5),
        ] {
            if let Some(v) = value {
                d = d.ev(Src::BleAdv, kind, v, conf, spec.detail);
            }
        }
        out.push(d);
    }
}

fn random_ble_address(rng: &mut Rng) -> MacAddr {
    let b = rng.next_u64().to_be_bytes();
    // Resolvable private address: top two bits 01.
    MacAddr([(b[0] & 0x3F) | 0x40, b[1], b[2], b[3], b[4], b[5]])
}

fn build_extra(out: &mut Vec<SimDevice>, rng: &mut Rng, count: usize) {
    for i in 0..count {
        match i % 10 {
            0..=6 => {
                let address = random_ble_address(rng);
                let info = BleInfo { address, random_address: true, ..Default::default() };
                let period = rng.range(20.0, 120.0);
                let on = rng.range(0.3, 0.9);
                let phase = rng.f32();
                out.push(
                    SimDevice::new(DeviceKey::Ble(address), DeviceDetails::Ble(info), Some(rng.range(-98.0, -60.0)))
                        .presence(Presence::Cycle { period, on, phase }),
                );
            }
            7 | 8 => {
                let (band, ch, width) = match rng.next_u64() % 3 {
                    0 => (Band::G2_4, [1, 6, 11][(rng.next_u64() % 3) as usize], 20),
                    1 => (Band::G5, [36, 44, 52, 100, 149, 157][(rng.next_u64() % 6) as usize], 80),
                    _ => (Band::G6, [5, 21, 37, 53, 69][(rng.next_u64() % 5) as usize], 160),
                };
                let bssid = sim_mac("extra-ap", 0x10_0000 + i as u32);
                let ssid = format!("Net-{:04X}", rng.next_u64() & 0xFFFF);
                out.push(ap(&ssid, bssid, band, ch, width, wpa2(), 5, rng.range(-95.0, -65.0), 0).tsf(DAY));
            }
            _ => {
                let mac = sim_mac("extra-lan", i as u32);
                let n = i / 10;
                out.push(lan(mac, [10, 0, (n / 250) as u8, (n % 250 + 1) as u8], None, &[], &[]));
            }
        }
    }
}

/// SplitMix64: tiny, fast, deterministic — plenty for simulation noise.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 1).
    fn f32(&mut self) -> f32 {
        (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32
    }

    fn range(&mut self, lo: f32, hi: f32) -> f32 {
        lo + (hi - lo) * self.f32()
    }

    /// Approximately standard normal (Irwin–Hall, n = 4).
    fn normal(&mut self) -> f32 {
        let s: f32 = (0..4).map(|_| self.f32()).sum();
        (s - 2.0) * 1.732
    }
}

#[cfg(test)]
mod tests {
    use na_model::DeviceKind;

    use super::*;

    #[test]
    fn evil_twin_appears_on_schedule() {
        let cfg = SimConfig { evil_twin_after: Some(Duration::from_secs(20)), ..Default::default() };
        let mut w = SimWorld::new(&cfg);
        let home_aps = |obs: &[Observation]| {
            obs.iter()
                .filter_map(|o| match &o.details {
                    DeviceDetails::Ap(a) if a.ssid == "HomeNet" => Some(a.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

        let before = home_aps(&w.step(Duration::from_secs(5)));
        assert_eq!(before.len(), 3);
        assert!(before.iter().all(|a| !a.security.is_open()));

        let after = home_aps(&w.step(Duration::from_secs(25)));
        assert_eq!(after.len(), 4);
        let twin = after.iter().find(|a| a.security.is_open()).expect("twin present");
        assert!(twin.bssid.is_locally_administered());
        assert_eq!(twin.tsf_uptime_secs, Some(5));
        assert!(twin.wps.is_none());
    }

    #[test]
    fn world_contains_every_device_class() {
        let mut w = SimWorld::new(&SimConfig { extra_devices: 100, ..Default::default() });
        let obs = w.step(Duration::from_secs(1));
        for kind in [DeviceKind::AccessPoint, DeviceKind::Ble, DeviceKind::LanHost] {
            assert!(obs.iter().any(|o| o.key.kind() == kind), "missing {kind:?}");
        }
        // LAN hosts are wired: no RSSI.
        assert!(obs.iter().filter(|o| o.key.kind() == DeviceKind::LanHost).all(|o| o.rssi.is_none()));
    }

    #[test]
    fn deterministic_for_a_seed() {
        let cfg = SimConfig::default();
        let a: Vec<_> = SimWorld::new(&cfg).step(Duration::from_secs(1)).into_iter().map(|o| (o.key, o.rssi)).collect();
        let b: Vec<_> = SimWorld::new(&cfg).step(Duration::from_secs(1)).into_iter().map(|o| (o.key, o.rssi)).collect();
        assert_eq!(a, b);
    }
}
