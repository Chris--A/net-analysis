//! Synthetic device generator. It lets the UI, classifier and guard detectors be built
//! and tested without radios, drivers or admin rights.
//!
//! It models a home network (mesh router, LAN hosts), neighbouring APs, BLE
//! devices that come and go, and an **evil twin** of the home SSID that appears
//! after `evil_twin_after`. The twin has an open network, a locally-administered BSSID,
//! a fresh TSF uptime and a minimal IE set. A **Karma AP** (after `karma_ap_after`)
//! rotates through several network names and answers the guard's decoy probes.
//! All vendor prefixes are synthetic.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use na_model::{
    Akm, ApInfo, Band, Banner, BleAddressType, BtClassicInfo, Cipher, ClaimKind, DeviceDetails,
    DeviceKey, Evidence, EvidenceSource as Src, LanInfo, MacAddr, MdnsService, NetbiosInfo,
    Observation, Pmf, Security, SourceKind, UpnpInfo, WpsInfo, now_millis, stable_hash,
};

use super::ble::{BleSighting, classic_observation, observation as ble_observation};
use super::{BoxFuture, Source, SourceCtx, SourceDeps};
use crate::guard::GuardSignal;
use crate::identify::{BtDb, OuiDb, lan_evidence};

#[derive(Clone, Debug)]
pub struct SimConfig {
    pub seed: u64,
    pub tick: Duration,
    /// Additional random devices for load testing the frontend.
    pub extra_devices: usize,
    /// When the evil-twin AP appears (None disables it).
    pub evil_twin_after: Option<Duration>,
    /// When the Karma AP appears (None disables it).
    pub karma_ap_after: Option<Duration>,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            seed: 0x5EED_2026,
            tick: Duration::from_secs(1),
            extra_devices: 0,
            evil_twin_after: Some(Duration::from_secs(20)),
            karma_ap_after: Some(Duration::from_secs(5)),
        }
    }
}

pub struct SimSource {
    cfg: SimConfig,
    deps: SourceDeps,
}

impl SimSource {
    pub fn new(cfg: SimConfig, deps: SourceDeps) -> Self {
        Self { cfg, deps }
    }
}

impl Source for SimSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Sim
    }

    fn run(self: Box<Self>, ctx: SourceCtx) -> BoxFuture<anyhow::Result<()>> {
        Box::pin(async move {
            let mut world = SimWorld::new(&self.cfg, &self.deps.bt);
            let start = tokio::time::Instant::now();
            let mut tick = tokio::time::interval(self.cfg.tick);
            loop {
                let batch = tokio::select! {
                    _ = ctx.cancel.cancelled() => return Ok(()),
                    _ = tick.tick() => world.step(start.elapsed()),
                    Ok(req) = self.deps.karma.recv_async() => {
                        let answers = world.karma_probe(&req.ssid);
                        let _ = self.deps.guard.send(GuardSignal::KarmaSent { ssid: req.ssid, result: Ok(()) });
                        answers
                    }
                };
                for obs in batch {
                    if ctx.sink.send(obs).await.is_err() {
                        return Ok(());
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
    /// Network names this AP rotates through (a MANA-style rogue AP).
    ssid_cycle: Vec<&'static str>,
    /// Answers directed probes for any name (Karma).
    karma: bool,
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
            ssid_cycle: Vec::new(),
            karma: false,
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
    /// Seconds since start, as of the last step.
    t: f32,
}

impl SimWorld {
    pub(crate) fn new(cfg: &SimConfig, bt: &BtDb) -> Self {
        let mut rng = Rng(cfg.seed);
        let mut devices = Vec::new();
        build_home(&mut devices, cfg);
        build_neighbour_aps(&mut devices, &mut rng);
        build_ble(&mut devices, &mut rng, bt);
        build_bt_classic(&mut devices);
        build_rogues(&mut devices, cfg);
        build_extra(&mut devices, &mut rng, cfg.extra_devices, bt);
        Self { devices, rng, t: 0.0 }
    }

    /// Karma APs that are present answer a directed probe for any name.
    pub(crate) fn karma_probe(&self, ssid: &str) -> Vec<Observation> {
        self.devices
            .iter()
            .filter(|d| d.karma && d.presence.is_present(self.t))
            .filter_map(|d| {
                let DeviceDetails::Ap(ap) = &d.details else { return None };
                let mut answer = ap.clone();
                answer.ssid = ssid.to_owned();
                Some(Observation {
                    key: d.key.clone(),
                    at: now_millis(),
                    rssi: Some(d.rssi.round() as i16),
                    details: DeviceDetails::Ap(answer),
                    evidence: d.evidence.clone(),
                    links: Vec::new(),
                })
            })
            .collect()
    }

    pub(crate) fn step(&mut self, elapsed: Duration) -> Vec<Observation> {
        let now = now_millis();
        let t = elapsed.as_secs_f32();
        self.t = t;
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
            if let (DeviceDetails::Ap(ap), false) = (&mut details, d.ssid_cycle.is_empty()) {
                ap.ssid = d.ssid_cycle[(elapsed.as_secs() / 4) as usize % d.ssid_cycle.len()].to_owned();
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
    format!("OUI {:02X}:{:02X}:{:02X} = {vendor} (synthetic)", o[0], o[1], o[2])
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
        station_count: None,
        channel_utilization: None,
        country: None,
        vendor_ies: Vec::new(),
        raw_ies: Vec::new(),
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
        ..Default::default()
    };
    SimDevice::new(DeviceKey::LanMac(mac), DeviceDetails::Lan(info), None)
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
    // Hosts describe themselves the way real ones do (UPnP, mDNS TXT, NetBIOS,
    // banners). Identification runs through the same rules as live discovery. The
    // synthetic MAC prefixes aren't in the OUI registry, so their vendor votes are added by hand.
    let home_aps = [main, radio24, satellite];
    let oui = OuiDb::default();
    let host = |info: LanInfo| {
        let mac = info.mac.expect("sim LAN hosts have a MAC");
        let evidence = lan_evidence(&info, &oui);
        let mut d = SimDevice::new(DeviceKey::LanMac(mac), DeviceDetails::Lan(info), None);
        d.evidence = evidence;
        d
    };
    let ip = |last: u8| vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))];
    let svc = |instance: &str, service: &str, port: u16, txt: &[&str]| MdnsService {
        instance: instance.into(),
        service: service.into(),
        port: Some(port),
        txt: txt.iter().map(|t| (*t).to_owned()).collect(),
    };
    let banner = |port: u16, text: &str| Banner { port, text: text.into() };
    let wifi = Some("Wi-Fi".to_owned());

    let mut gw = host(LanInfo {
        mac: Some(gateway),
        ips: ip(1),
        hostname: Some("routerlogin".into()),
        open_ports: vec![53, 80, 443],
        upnp: Some(UpnpInfo {
            friendly_name: Some("NETGEAR RAX50".into()),
            manufacturer: Some("NETGEAR".into()),
            model_name: Some("RAX50".into()),
            model_number: Some("RAX50".into()),
            model_description: Some("NETGEAR Nighthawk AX6 WiFi Router".into()),
            device_type: Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1".into()),
            server: Some("Linux/4.1.52 UPnP/1.0 MiniUPnPd/2.1".into()),
            advertised: vec!["upnp:rootdevice".into(), "urn:schemas-upnp-org:device:InternetGatewayDevice:1".into()],
        }),
        banners: vec![banner(80, "Server: lighttpd/1.4.59 · title: NETGEAR Router RAX50")],
        interface: wifi.clone(),
        is_gateway: true,
        ..Default::default()
    })
    .ev(Src::Oui, ClaimKind::Vendor, vendor, 0.6, &oui_detail(gateway, vendor));
    for b in home_aps {
        gw = gw.link(DeviceKey::Bssid(b));
    }
    out.push(gw);

    let pc = sim_mac("Intel", 0x0A_0B0C);
    out.push(
        host(LanInfo {
            mac: Some(pc),
            ips: ip(23),
            hostname: Some("DESKTOP-NA01".into()),
            open_ports: vec![135, 139, 445],
            netbios: Some(NetbiosInfo { name: Some("DESKTOP-NA01".into()), group: Some("WORKGROUP".into()), file_server: true }),
            interface: wifi.clone(),
            is_self: true,
            ..Default::default()
        })
        .ev(Src::Oui, ClaimKind::Vendor, "Intel", 0.4, &oui_detail(pc, "Intel (NIC)")),
    );

    let nas = sim_mac("Synology", 0x00_0001);
    out.push(
        host(LanInfo {
            mac: Some(nas),
            ips: ip(10),
            hostname: Some("nas".into()),
            open_ports: vec![22, 80, 443, 445, 5000, 5001],
            services: vec!["_smb._tcp".into(), "_afpovertcp._tcp".into(), "_http._tcp".into()],
            mdns: vec![svc("nas", "_smb._tcp", 445, &[]), svc("nas", "_http._tcp", 5000, &["vendor=Synology", "model=DS920+"])],
            upnp: Some(UpnpInfo {
                friendly_name: Some("nas (DS920+)".into()),
                manufacturer: Some("Synology".into()),
                model_name: Some("DS920+".into()),
                device_type: Some("urn:schemas-upnp-org:device:Basic:1".into()),
                server: Some("Synology/DSM/192.168.1.10".into()),
                ..Default::default()
            }),
            banners: vec![
                banner(22, "SSH-2.0-OpenSSH_8.2"),
                banner(5000, "Server: nginx · title: Synology DiskStation - nas"),
            ],
            netbios: Some(NetbiosInfo { name: Some("NAS".into()), group: Some("WORKGROUP".into()), file_server: true }),
            interface: wifi.clone(),
            ..Default::default()
        })
        .ev(Src::Oui, ClaimKind::Vendor, "Synology", 0.6, &oui_detail(nas, "Synology")),
    );

    let cast = sim_mac("Google", 0x31_0031);
    out.push(
        host(LanInfo {
            mac: Some(cast),
            ips: ip(31),
            open_ports: vec![8008, 8009, 8443],
            services: vec!["_googlecast._tcp".into()],
            mdns: vec![svc(
                "Chromecast-6d8e2f1a",
                "_googlecast._tcp",
                8009,
                &["id=6d8e2f1a", "md=Chromecast with Google TV", "fn=Living Room TV", "ve=05", "ca=463365"],
            )],
            interface: wifi.clone(),
            ..Default::default()
        })
        .ev(Src::Oui, ClaimKind::Vendor, "Google", 0.6, &oui_detail(cast, "Google")),
    );

    let tv = sim_mac("LG Electronics", 0x32_0032);
    out.push(host(LanInfo {
        mac: Some(tv),
        ips: ip(32),
        hostname: Some("LGwebOSTV".into()),
        open_ports: vec![3000, 3001],
        services: vec!["_airplay._tcp".into()],
        mdns: vec![svc("[LG] webOS TV OLED55C2", "_airplay._tcp", 7000, &["manufacturer=LG Electronics", "model=OLED55C2PUA"])],
        upnp: Some(UpnpInfo {
            friendly_name: Some("[LG] webOS TV OLED55C2".into()),
            manufacturer: Some("LG Electronics".into()),
            model_name: Some("OLED55C2PUA".into()),
            device_type: Some("urn:schemas-upnp-org:device:MediaRenderer:1".into()),
            server: Some("WebOS/6.0 UPnP/1.0".into()),
            advertised: vec!["urn:dial-multiscreen-org:service:dial:1".into()],
            ..Default::default()
        }),
        interface: wifi.clone(),
        ..Default::default()
    }));

    let printer = sim_mac("HP", 0x40_0040);
    out.push(
        host(LanInfo {
            mac: Some(printer),
            ips: ip(40),
            hostname: Some("HP4A2B1C".into()),
            open_ports: vec![80, 443, 631, 9100],
            services: vec!["_ipp._tcp".into(), "_pdl-datastream._tcp".into(), "_uscan._tcp".into()],
            mdns: vec![svc(
                "HP OfficeJet Pro 9015 [4A2B1C]",
                "_ipp._tcp",
                631,
                &["ty=HP OfficeJet Pro 9015", "usb_MFG=HP", "usb_MDL=OfficeJet Pro 9015", "product=(HP OfficeJet Pro 9015)"],
            )],
            interface: wifi.clone(),
            ..Default::default()
        })
        .ev(Src::Oui, ClaimKind::Vendor, "HP", 0.6, &oui_detail(printer, "HP")),
    );

    let mut iphone = sim_mac("phone-random", 0x50_0050);
    iphone.0[0] |= 0x02; // private Wi-Fi address
    out.push(host(LanInfo {
        mac: Some(iphone),
        ips: ip(50),
        hostname: Some("Sams-iPhone".into()),
        open_ports: vec![62078],
        services: vec!["_apple-mobdev2._tcp".into(), "_companion-link._tcp".into()],
        mdns: vec![svc("Sam's iPhone", "_companion-link._tcp", 49_152, &["rpMd=iPhone15,2", "rpVr=620.21"])],
        interface: wifi.clone(),
        ..Default::default()
    }));

    let hue = sim_mac("Signify", 0x60_0060);
    out.push(
        host(LanInfo {
            mac: Some(hue),
            ips: ip(60),
            hostname: Some("Philips-hue".into()),
            open_ports: vec![80, 443],
            services: vec!["_hue._tcp".into()],
            mdns: vec![svc("Hue Bridge - 1A2B3C", "_hue._tcp", 443, &["bridgeid=001788fffe1a2b3c", "modelid=BSB002"])],
            upnp: Some(UpnpInfo {
                friendly_name: Some("Hue Bridge (192.168.1.60)".into()),
                manufacturer: Some("Signify".into()),
                model_name: Some("Philips hue bridge 2015".into()),
                model_number: Some("BSB002".into()),
                device_type: Some("urn:schemas-upnp-org:device:Basic:1".into()),
                ..Default::default()
            }),
            interface: wifi.clone(),
            ..Default::default()
        })
        .ev(Src::Oui, ClaimKind::Vendor, "Signify", 0.6, &oui_detail(hue, "Signify")),
    );

    let plug = sim_mac("Espressif", 0x70_0070);
    out.push(
        host(LanInfo {
            mac: Some(plug),
            ips: ip(70),
            hostname: Some("ESP_3A1F2C".into()),
            open_ports: vec![6668],
            interface: wifi.clone(),
            ..Default::default()
        })
        .ev(Src::Oui, ClaimKind::Vendor, "Espressif", 0.5, &oui_detail(plug, "Espressif (Wi-Fi chip)")),
    );

    let cam = sim_mac("Reolink", 0x80_0080);
    out.push(host(LanInfo {
        mac: Some(cam),
        ips: ip(80),
        open_ports: vec![80, 554, 9000],
        banners: vec![banner(80, "Server: nginx · title: Reolink")],
        interface: wifi.clone(),
        ..Default::default()
    }));

    let pi = sim_mac("Raspberry Pi", 0x90_0090);
    out.push(
        host(LanInfo {
            mac: Some(pi),
            ips: ip(90),
            hostname: Some("raspberrypi".into()),
            open_ports: vec![22, 8123],
            services: vec!["_home-assistant._tcp".into(), "_ssh._tcp".into()],
            mdns: vec![svc("Home", "_home-assistant._tcp", 8123, &["version=2026.11.1", "base_url=http://192.168.1.90:8123"])],
            banners: vec![banner(22, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3")],
            interface: wifi.clone(),
            ..Default::default()
        })
        .ev(Src::Oui, ClaimKind::Vendor, "Raspberry Pi", 0.7, &oui_detail(pi, "Raspberry Pi Trading")),
    );

    let xbox = sim_mac("Microsoft", 0x33_0033);
    out.push(
        host(LanInfo {
            mac: Some(xbox),
            ips: ip(33),
            hostname: Some("XBOX".into()),
            open_ports: vec![3074],
            interface: wifi,
            ..Default::default()
        })
        .ev(Src::Oui, ClaimKind::Vendor, "Microsoft", 0.6, &oui_detail(xbox, "Microsoft")),
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

/// One synthetic BLE device, described by what it actually advertises. It is decoded
/// by the same code as real adverts, so the sim exercises the identification rules.
struct BleSpec {
    name: Option<&'static str>,
    /// (company ID, data after the company ID)
    mfr: Option<(u16, &'static [u8])>,
    services: &'static [u16],
    /// (16-bit UUID, data)
    service_data: Option<(u16, &'static [u8])>,
    appearance: Option<u16>,
    tx_power: Option<i8>,
    /// Random static instead of a rotating private address (accessories, tags).
    static_addr: bool,
    /// Paired and connected to this host (no adverts: the OS supplies name/appearance).
    connected: bool,
    rssi: f32,
    /// (period seconds, fraction present). None = always present.
    cycle: Option<(f32, f32)>,
}

const BLE_DEFAULT: BleSpec = BleSpec {
    name: None,
    mfr: None,
    services: &[],
    service_data: None,
    appearance: None,
    tx_power: None,
    static_addr: false,
    connected: false,
    rssi: -80.0,
    cycle: None,
};

/// Apple Find My "separated" payload: 25 bytes after the type/length header.
const FIND_MY: &[u8] = &[
    0x12, 0x19, 0x10, 0x5C, 0x2B, 0x71, 0xA0, 0x93, 0x4E, 0x11, 0xD2, 0x05, 0x6B, 0x3A, 0xF7, 0x88,
    0x14, 0xC9, 0x02, 0x67, 0xEE, 0x31, 0x9D, 0x40, 0xAB, 0x00, 0x01,
];
/// AirPods Pro Proximity Pairing (model 0x0E20).
const AIRPODS_PRO: &[u8] = &[
    0x07, 0x19, 0x01, 0x0E, 0x20, 0x2B, 0x99, 0x8F, 0x01, 0x00, 0x05, 0x6A, 0x1D, 0x42, 0x90, 0x33,
    0xC1, 0x7E, 0x08, 0x5F, 0x21, 0xD4, 0xA2, 0x6C, 0x10, 0x3B, 0x77,
];
/// iPhone: Nearby Info followed by Handoff.
const IPHONE: &[u8] = &[
    0x10, 0x05, 0x01, 0x18, 0x6E, 0x2A, 0x0B, 0x0C, 0x0E, 0x00, 0x51, 0x7D, 0x93, 0x02, 0xFE, 0x11,
    0x4A, 0x6C, 0x2D, 0xB0, 0x07,
];

fn build_ble(out: &mut Vec<SimDevice>, rng: &mut Rng, bt: &BtDb) {
    let specs = [
        BleSpec { mfr: Some((0x004C, IPHONE)), tx_power: Some(12), rssi: -58.0, ..BLE_DEFAULT },
        BleSpec { mfr: Some((0x004C, AIRPODS_PRO)), rssi: -62.0, ..BLE_DEFAULT },
        BleSpec { mfr: Some((0x004C, FIND_MY)), static_addr: true, rssi: -84.0, ..BLE_DEFAULT },
        // Samsung phone: Samsung data plus the Google Play services beacon.
        BleSpec {
            mfr: Some((0x0075, &[0x42, 0x09, 0x81, 0x02, 0x14, 0x15, 0x03, 0x21])),
            service_data: Some((0xFCF1, &[0x04, 0x67, 0x53, 0x23, 0xCD, 0xC9])),
            rssi: -71.0,
            cycle: Some((90.0, 0.7)),
            ..BLE_DEFAULT
        },
        BleSpec { name: Some("Galaxy Buds2 (4F2A)"), mfr: Some((0x0075, &[0x42, 0x09, 0x81, 0x02])), rssi: -74.0, ..BLE_DEFAULT },
        BleSpec { name: Some("Pixel Buds Pro"), service_data: Some((0xFE2C, &[0x71, 0x7F, 0x41])), rssi: -77.0, cycle: Some((60.0, 0.5)), ..BLE_DEFAULT },
        BleSpec {
            name: Some("Tile"),
            services: &[0xFEED],
            service_data: Some((0xFEED, &[0x02, 0x00, 0xCE, 0xF5, 0x4F, 0xA0, 0xA7, 0xA6])),
            static_addr: true,
            rssi: -85.0,
            ..BLE_DEFAULT
        },
        BleSpec { name: Some("LE-Bose QC45"), mfr: Some((0x009E, &[0x01, 0x07])), appearance: Some(0x0943), rssi: -79.0, cycle: Some((120.0, 0.6)), ..BLE_DEFAULT },
        BleSpec { name: Some("LE_WH-1000XM5"), mfr: Some((0x012D, &[0x04, 0x00, 0x01])), rssi: -88.0, cycle: Some((45.0, 0.35)), ..BLE_DEFAULT },
        BleSpec { name: Some("Xbox Wireless Controller"), mfr: Some((0x0006, &[0x00, 0x00])), appearance: Some(0x03C4), static_addr: true, rssi: -66.0, ..BLE_DEFAULT },
        // Windows desktop: Microsoft CDP beacon, device type 9.
        BleSpec { mfr: Some((0x0006, &[0x01, 0x09, 0x20, 0x02, 0x9A, 0x3C, 0x51, 0xE0])), rssi: -55.0, ..BLE_DEFAULT },
        BleSpec { name: Some("[LG] webOS TV OLED55C2"), mfr: Some((0x00C4, &[0x02, 0x01])), rssi: -70.0, ..BLE_DEFAULT },
        BleSpec { name: Some("Hue color lamp"), services: &[0xFE0F], static_addr: true, rssi: -68.0, ..BLE_DEFAULT },
        BleSpec { name: Some("GVH5075_8F2B"), mfr: Some((0xEC88, &[0x00, 0x03, 0x6B, 0x2A, 0x5D, 0x00])), static_addr: true, rssi: -81.0, ..BLE_DEFAULT },
        BleSpec { name: Some("Mi Smart Band 6"), service_data: Some((0xFE95, &[0x30, 0x58, 0x52, 0x2A])), rssi: -76.0, cycle: Some((70.0, 0.5)), ..BLE_DEFAULT },
        BleSpec { name: Some("Forerunner 255"), mfr: Some((0x0087, &[0x01, 0x00])), rssi: -83.0, cycle: Some((100.0, 0.4)), ..BLE_DEFAULT },
        BleSpec { name: Some("Polar H10 8A2B3C"), services: &[0x180D], static_addr: true, rssi: -87.0, cycle: Some((110.0, 0.5)), ..BLE_DEFAULT },
        BleSpec { name: Some("S7b3c1a9f2e4d5c6aC"), rssi: -90.0, cycle: Some((150.0, 0.3)), ..BLE_DEFAULT },
        BleSpec { name: Some("Dell Mouse MS5120W"), appearance: Some(0x03C2), static_addr: true, connected: true, ..BLE_DEFAULT },
        BleSpec { rssi: -86.0, cycle: Some((40.0, 0.5)), ..BLE_DEFAULT },
        BleSpec { rssi: -91.0, cycle: Some((55.0, 0.4)), ..BLE_DEFAULT },
        BleSpec { mfr: Some((0x004C, &[0x10, 0x05, 0x0B, 0x1C, 0x3D, 0x9A, 0x40])), rssi: -89.0, cycle: Some((35.0, 0.45)), ..BLE_DEFAULT },
        BleSpec { rssi: -94.0, cycle: Some((80.0, 0.3)), ..BLE_DEFAULT },
    ];

    let oui = OuiDb::default();
    for spec in specs {
        let address = if spec.static_addr { static_ble_address(rng) } else { random_ble_address(rng) };
        let advertised = |v: Option<u16>| v.filter(|_| !spec.connected);
        let mut sections: Vec<(u8, Vec<u8>)> = Vec::new();
        if !spec.connected {
            sections.push((0x01, vec![0x1A]));
        }
        if !spec.services.is_empty() {
            sections.push((0x03, spec.services.iter().flat_map(|u| u.to_le_bytes()).collect()));
        }
        if let Some((uuid, data)) = spec.service_data {
            sections.push((0x16, uuid.to_le_bytes().iter().chain(data).copied().collect()));
        }
        if let Some((company, data)) = spec.mfr {
            sections.push((0xFF, company.to_le_bytes().iter().chain(data).copied().collect()));
        }
        if let Some(a) = advertised(spec.appearance) {
            sections.push((0x19, a.to_le_bytes().to_vec()));
        }
        if let (Some(n), false) = (spec.name, spec.connected) {
            sections.push((0x09, n.as_bytes().to_vec()));
        }
        let sighting = BleSighting {
            address,
            address_type: BleAddressType::from_random(address),
            sections,
            rssi: None,
            tx_power: spec.tx_power,
            connectable: spec.name.is_some(),
            paired: spec.connected,
            connected: spec.connected,
            os_name: spec.name.filter(|_| spec.connected).map(Into::into),
            os_appearance: spec.appearance.filter(|_| spec.connected),
        };
        let obs = ble_observation(&sighting, 0, bt, &oui);
        // Connected devices don't advertise, so they have no RSSI.
        let base_rssi = (!spec.connected).then_some(spec.rssi);
        let mut d = SimDevice::new(obs.key, obs.details, base_rssi);
        d.evidence = obs.evidence;
        if let Some((period, on)) = spec.cycle {
            d = d.presence(Presence::Cycle { period, on, phase: rng.f32() });
        }
        out.push(d);
    }
}

fn build_bt_classic(out: &mut Vec<SimDevice>) {
    let oui = OuiDb::default();
    let devices = [
        // Paired headphones, connected.
        (sim_mac("Samsung", 0x00_1234), "Galaxy Buds Pro (1234)", 0x24_0404, true, true, false, Presence::Always),
        // A neighbour's laptop with its Bluetooth settings open (discoverable).
        (sim_mac("Intel", 0x8F_F072), "LAPTOP-CIGDPDU1", 0x2E_410C, false, false, true, Presence::Cycle { period: 200.0, on: 0.6, phase: 0.1 }),
        (sim_mac("JBL", 0x00_4411), "JBL Flip 6", 0x24_0414, false, false, true, Presence::Cycle { period: 240.0, on: 0.5, phase: 0.6 }),
    ];
    for (address, name, cod, paired, connected, discoverable, presence) in devices {
        let info = BtClassicInfo { address, name: Some(name.into()), class_of_device: cod, paired, connected, discoverable };
        let obs = classic_observation(info, 0, &oui);
        let mut d = SimDevice::new(obs.key, obs.details, None).presence(presence);
        d.evidence = obs.evidence;
        d.links = obs.links;
        out.push(d);
    }
}

fn random_ble_address(rng: &mut Rng) -> MacAddr {
    let b = rng.next_u64().to_be_bytes();
    // Resolvable private address: top two bits 01.
    MacAddr([(b[0] & 0x3F) | 0x40, b[1], b[2], b[3], b[4], b[5]])
}

fn static_ble_address(rng: &mut Rng) -> MacAddr {
    let b = rng.next_u64().to_be_bytes();
    // Random static address: top two bits 11.
    MacAddr([b[0] | 0xC0, b[1], b[2], b[3], b[4], b[5]])
}

/// A MANA-style rogue AP: open, locally-administered BSSID, cycling through
/// common public network names, and answering probes for any name.
fn build_rogues(out: &mut Vec<SimDevice>, cfg: &SimConfig) {
    let Some(after) = cfg.karma_ap_after else { return };
    let s = after.as_secs_f32();
    let mut bssid = sim_mac("rogue-radio", 0x13_3700);
    bssid.0[0] |= 0x02;
    let mut d = ap("Airport Free WiFi", bssid, Band::G2_4, 11, 20, open(), 4, -58.0, stable_hash(b"hostapd-mana"))
        .presence(Presence::After(s))
        .tsf(-(s as i64))
        .ev(Src::Ie, ClaimKind::DeviceType, "Wi-Fi AP", 0.3, "Minimal IE set: no WPS, no vendor IEs (hostapd-like)");
    d.ssid_cycle = vec!["Airport Free WiFi", "Hotel Guest", "CoffeeShop"];
    d.karma = true;
    out.push(d);
}

fn build_extra(out: &mut Vec<SimDevice>, rng: &mut Rng, count: usize, bt: &BtDb) {
    let oui = OuiDb::default();
    for i in 0..count {
        match i % 10 {
            0..=6 => {
                let address = random_ble_address(rng);
                let sighting = BleSighting {
                    address,
                    address_type: BleAddressType::from_random(address),
                    sections: vec![(0x01, vec![0x1A])],
                    ..Default::default()
                };
                let obs = ble_observation(&sighting, 0, bt, &oui);
                let period = rng.range(20.0, 120.0);
                let on = rng.range(0.3, 0.9);
                let phase = rng.f32();
                out.push(
                    SimDevice::new(obs.key, obs.details, Some(rng.range(-98.0, -60.0)))
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
        let mut w = SimWorld::new(&cfg, &BtDb::builtin());
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
    fn karma_ap_cycles_names_and_answers_probes() {
        let cfg = SimConfig { karma_ap_after: Some(Duration::from_secs(5)), ..Default::default() };
        let mut w = SimWorld::new(&cfg, &BtDb::builtin());
        let rogue_ssids = |obs: &[Observation]| {
            obs.iter()
                .filter_map(|o| match &o.details {
                    DeviceDetails::Ap(a) if a.bssid.is_locally_administered() && a.channel == 11 => Some(a.ssid.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        assert!(rogue_ssids(&w.step(Duration::from_secs(1))).is_empty(), "not there yet");
        assert!(w.karma_probe("Lounge-123456").is_empty(), "absent APs don't answer");
        let names: std::collections::HashSet<String> =
            (6..18).flat_map(|s| rogue_ssids(&w.step(Duration::from_secs(s)))).collect();
        assert_eq!(names.len(), 3, "{names:?}");
        let answers = w.karma_probe("Lounge-123456");
        assert_eq!(answers.len(), 1);
        assert!(matches!(&answers[0].details, DeviceDetails::Ap(a) if a.ssid == "Lounge-123456"));
    }

    #[test]
    fn world_contains_every_device_class() {
        let mut w = SimWorld::new(&SimConfig { extra_devices: 100, ..Default::default() }, &BtDb::builtin());
        let obs = w.step(Duration::from_secs(1));
        for kind in [DeviceKind::AccessPoint, DeviceKind::Ble, DeviceKind::BtClassic, DeviceKind::LanHost] {
            assert!(obs.iter().any(|o| o.key.kind() == kind), "missing {kind:?}");
        }
        // LAN hosts are wired: no RSSI.
        assert!(obs.iter().filter(|o| o.key.kind() == DeviceKind::LanHost).all(|o| o.rssi.is_none()));
    }

    #[test]
    fn ble_devices_are_identified_by_the_real_decoders() {
        // Inspect the whole world: some devices are on presence cycles and absent right now.
        let w = SimWorld::new(&SimConfig::default(), &BtDb::builtin());
        let types: Vec<&str> = w
            .devices
            .iter()
            .filter(|d| matches!(d.key, DeviceKey::Ble(_) | DeviceKey::BtClassic(_)))
            .flat_map(|d| d.evidence.iter())
            .filter(|e| e.kind == ClaimKind::DeviceType)
            .map(|e| e.value.as_str())
            .collect();
        for expected in ["Headphones", "Tracker tag", "Desktop PC", "Mouse", "Vehicle", "Heart-rate sensor", "Laptop"] {
            assert!(types.contains(&expected), "no {expected} in {types:?}");
        }
    }

    #[test]
    fn lan_hosts_are_identified_by_the_real_rules() {
        let w = SimWorld::new(&SimConfig::default(), &BtDb::builtin());
        let types: Vec<String> = w
            .devices
            .iter()
            .filter(|d| matches!(d.key, DeviceKey::LanMac(_)))
            .filter_map(|d| crate::identify::classify(&d.evidence).device_type.map(|c| c.value))
            .collect();
        for expected in ["Router", "Printer", "Media streamer", "NAS", "IP camera", "TV", "Smart home hub", "Game console"] {
            assert!(types.iter().any(|t| t == expected), "no {expected} in {types:?}");
        }
    }

    #[test]
    fn deterministic_for_a_seed() {
        let cfg = SimConfig::default();
        let db = BtDb::builtin();
        let a: Vec<_> = SimWorld::new(&cfg, &db).step(Duration::from_secs(1)).into_iter().map(|o| (o.key, o.rssi)).collect();
        let b: Vec<_> = SimWorld::new(&cfg, &db).step(Duration::from_secs(1)).into_iter().map(|o| (o.key, o.rssi)).collect();
        assert_eq!(a, b);
    }
}
