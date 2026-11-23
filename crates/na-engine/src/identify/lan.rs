//! Identification evidence for LAN hosts.
//!
//! Strongest first: UPnP descriptions and mDNS TXT records (devices describing
//! themselves), then service types, NetBIOS, banners, the MAC OUI, open ports and
//! host-name patterns.

use na_model::{ClaimKind, Evidence, EvidenceSource as Src, LanInfo};

use super::{OuiDb, short_name};

struct Out(Vec<Evidence>);

impl Out {
    fn add(&mut self, src: Src, kind: ClaimKind, value: &str, conf: f32, detail: impl Into<String>) {
        let value = value.trim();
        if !value.is_empty() {
            self.0.push(Evidence::new(src, kind, value, conf, detail));
        }
    }

    /// (vendor, device type, OS) triple, each optional.
    fn triple(&mut self, src: Src, t: Hint, conf: f32, detail: &str) {
        let (vendor, dtype, os) = t;
        if let Some(v) = vendor {
            self.add(src, ClaimKind::Vendor, v, conf, detail);
        }
        if let Some(d) = dtype {
            self.add(src, ClaimKind::DeviceType, d, conf, detail);
        }
        if let Some(o) = os {
            self.add(src, ClaimKind::Os, o, conf, detail);
        }
    }
}

/// (vendor, device type, OS)
type Hint = (Option<&'static str>, Option<&'static str>, Option<&'static str>);

pub fn lan_evidence(info: &LanInfo, oui: &OuiDb) -> Vec<Evidence> {
    let mut out = Out(Vec::new());

    if let Some(mac) = info.mac
        && let Some(vendor) = oui.lookup(mac)
    {
        let o = mac.oui();
        out.add(Src::Oui, ClaimKind::Vendor, vendor, 0.55, format!("MAC prefix {:02X}:{:02X}:{:02X} = {vendor}", o[0], o[1], o[2]));
    }

    if info.is_self {
        let os = if cfg!(windows) { "Windows" } else if cfg!(target_os = "linux") { "Linux" } else { "macOS" };
        out.add(Src::Heuristic, ClaimKind::DeviceType, "Computer", 0.6, "This machine");
        out.add(Src::Heuristic, ClaimKind::Os, os, 0.95, "This machine");
        if let Some(h) = &info.hostname {
            out.add(Src::Heuristic, ClaimKind::Name, h, 0.9, "This machine's host name");
        }
    }
    if info.is_gateway {
        // Phone hotspots use randomized MACs. Real routers have vendor-assigned ones.
        match info.mac {
            Some(m) if m.is_locally_administered() => {
                out.add(Src::Heuristic, ClaimKind::DeviceType, "Router", 0.25, "Default gateway (randomized MAC: likely a phone hotspot)");
            }
            _ => out.add(Src::Heuristic, ClaimKind::DeviceType, "Router", 0.55, "Default gateway of this network"),
        }
    }

    if let Some(h) = &info.hostname {
        hostname_evidence(h, &mut out);
    }
    mdns_evidence(info, &mut out);
    upnp_evidence(info, &mut out);

    if let Some(nb) = &info.netbios {
        let detail = format!(
            "NetBIOS name {}{}",
            nb.name.as_deref().unwrap_or("?"),
            nb.group.as_ref().map(|g| format!(", workgroup {g}")).unwrap_or_default()
        );
        if let Some(n) = &nb.name {
            out.add(Src::NetBios, ClaimKind::Name, n, 0.8, detail.clone());
        }
        // Samba (NAS, Linux) answers too, so this is only a lean.
        out.add(Src::NetBios, ClaimKind::Os, "Windows", 0.3, detail);
    }

    for &port in &info.open_ports {
        if let Some((hint, conf, why)) = port_hint(port) {
            out.triple(Src::Banner, hint, conf, &format!("TCP {port} open ({why})"));
        }
    }
    for b in &info.banners {
        banner_evidence(b.port, &b.text, &mut out);
    }
    out.0
}

// ---------------------------------------------------------------------------
// mDNS / DNS-SD
// ---------------------------------------------------------------------------

/// Service type → (hint, confidence).
fn service_hint(service: &str) -> Option<(Hint, f32)> {
    Some(match service {
        "_googlecast._tcp" => ((None, Some("Media streamer"), None), 0.7),
        "_airplay._tcp" | "_raop._tcp" => ((None, Some("AirPlay receiver"), None), 0.4),
        "_ipp._tcp" | "_ipps._tcp" | "_printer._tcp" | "_pdl-datastream._tcp" => ((None, Some("Printer"), None), 0.85),
        "_scanner._tcp" | "_uscan._tcp" | "_uscans._tcp" => ((None, Some("Scanner"), None), 0.5),
        "_hap._tcp" | "_hap._udp" => ((None, Some("HomeKit accessory"), None), 0.6),
        "_hue._tcp" => ((None, Some("Smart home hub"), None), 0.8),
        "_sonos._tcp" => ((Some("Sonos"), Some("Speaker"), None), 0.8),
        "_spotify-connect._tcp" => ((None, Some("Speaker"), None), 0.3),
        "_apple-mobdev2._tcp" => ((Some("Apple"), Some("iPhone/iPad"), Some("iOS")), 0.6),
        "_companion-link._tcp" => ((Some("Apple"), Some("iPhone/iPad/Mac"), None), 0.45),
        "_sleep-proxy._udp" | "_airport._tcp" => ((Some("Apple"), None, None), 0.5),
        "_matter._tcp" | "_matterc._udp" => ((None, Some("Matter device"), None), 0.5),
        "_meshcop._udp" | "_trel._udp" => ((None, Some("Thread border router"), None), 0.5),
        "_esphomelib._tcp" => ((None, Some("IoT device"), Some("ESPHome")), 0.7),
        "_home-assistant._tcp" => ((None, Some("Smart home hub"), None), 0.8),
        "_workstation._tcp" => ((None, Some("Computer"), Some("Linux")), 0.45),
        "_amzn-wplay._tcp" => ((Some("Amazon"), Some("Media streamer"), Some("Fire OS")), 0.6),
        "_androidtvremote2._tcp" => ((None, Some("TV"), Some("Android TV")), 0.6),
        "_octoprint._tcp" => ((None, Some("3D printer"), None), 0.7),
        "_plexmediasvr._tcp" => ((None, Some("Media server"), None), 0.6),
        "_rfb._tcp" | "_ssh._tcp" | "_sftp-ssh._tcp" => ((None, Some("Computer"), None), 0.25),
        "_miio._udp" => ((Some("Xiaomi"), Some("IoT device"), None), 0.6),
        "_nearbypresence._tcp" | "_googlezone._tcp" => ((None, None, Some("Android")), 0.35),
        _ => return None,
    })
}

/// Apple model identifiers (`MacBookPro18,3`, `AppleTV11,1`, `AudioAccessory5,1`…).
fn apple_model(id: &str) -> Option<Hint> {
    const APPLE: Option<&str> = Some("Apple");
    let starts = |p: &str| id.starts_with(p);
    Some(if starts("MacBook") {
        (APPLE, Some("Laptop"), Some("macOS"))
    } else if starts("iMac") || starts("Macmini") || starts("MacPro") || starts("Mac1") {
        (APPLE, Some("Desktop PC"), Some("macOS"))
    } else if starts("AppleTV") {
        (APPLE, Some("Media streamer"), Some("tvOS"))
    } else if starts("AudioAccessory") {
        (APPLE, Some("Smart speaker"), None)
    } else if starts("iPhone") {
        (APPLE, Some("Phone"), Some("iOS"))
    } else if starts("iPad") {
        (APPLE, Some("Tablet"), Some("iPadOS"))
    } else if starts("Watch") {
        (APPLE, Some("Watch"), Some("watchOS"))
    } else {
        return None;
    })
}

fn mdns_evidence(info: &LanInfo, out: &mut Out) {
    for s in &info.services {
        if let Some((hint, conf)) = service_hint(s) {
            out.triple(Src::Mdns, hint, conf, &format!("Advertises {s}"));
        }
    }
    for m in &info.mdns {
        let detail = |k: &str, v: &str| format!("{} TXT {k}={v}", m.service);
        // Chromecast / Cast-enabled devices.
        if let Some(v) = m.txt_value("md") {
            out.add(Src::Mdns, ClaimKind::Model, v, 0.85, detail("md", v));
        }
        if let Some(v) = m.txt_value("fn") {
            out.add(Src::Mdns, ClaimKind::Name, v, 0.85, detail("fn", v));
        }
        // Apple model identifiers: device-info, AirPlay, companion link.
        for key in ["model", "am", "rpMd"] {
            let Some(v) = m.txt_value(key) else { continue };
            match apple_model(v) {
                Some(hint) => {
                    out.triple(Src::Mdns, hint, 0.7, &detail(key, v));
                    out.add(Src::Mdns, ClaimKind::Model, v, 0.6, detail(key, v));
                }
                // Third-party AirPlay devices put their own model here.
                None if key == "am" || key == "model" => out.add(Src::Mdns, ClaimKind::Model, v, 0.5, detail(key, v)),
                None => {}
            }
        }
        // IPP printers.
        if let Some(v) = m.txt_value("ty") {
            out.add(Src::Mdns, ClaimKind::Model, v, 0.85, detail("ty", v));
        }
        for key in ["usb_MFG", "manufacturer"] {
            if let Some(v) = m.txt_value(key) {
                out.add(Src::Mdns, ClaimKind::Vendor, &short_name(v), 0.75, detail(key, v));
                break;
            }
        }
        if let Some(v) = m.txt_value("product") {
            let p = v.trim_matches(['(', ')']);
            out.add(Src::Mdns, ClaimKind::Model, p, 0.8, detail("product", v));
        }
    }
}

// ---------------------------------------------------------------------------
// UPnP / SSDP
// ---------------------------------------------------------------------------

fn upnp_evidence(info: &LanInfo, out: &mut Out) {
    let Some(u) = &info.upnp else { return };
    if let Some(n) = &u.friendly_name {
        out.add(Src::Ssdp, ClaimKind::Name, n, 0.8, format!("UPnP friendlyName = \"{n}\""));
    }
    if let Some(m) = &u.manufacturer {
        out.add(Src::Ssdp, ClaimKind::Vendor, &short_name(m), 0.8, format!("UPnP manufacturer = \"{m}\""));
    }
    let model = match (&u.model_name, &u.model_number) {
        (Some(n), Some(num)) if !n.contains(num.as_str()) && num.len() < 24 => Some(format!("{n} {num}")),
        (Some(n), _) => Some(n.clone()),
        (None, Some(num)) => Some(num.clone()),
        _ => None,
    };
    if let Some(model) = model {
        out.add(Src::Ssdp, ClaimKind::Model, &model, 0.8, format!("UPnP modelName = \"{model}\""));
    }
    let types = u.device_type.iter().chain(u.advertised.iter());
    for t in types {
        if let Some((dtype, conf)) = upnp_type(t) {
            out.add(Src::Ssdp, ClaimKind::DeviceType, dtype, conf, format!("UPnP {t}"));
        }
    }
    if let Some(server) = &u.server {
        let s = server.to_ascii_lowercase();
        let os = [
            ("windows", "Windows", 0.5),
            ("darwin", "macOS", 0.4),
            ("android", "Android", 0.45),
            ("webos", "webOS", 0.6),
            ("tizen", "Tizen", 0.6),
            ("roku", "Roku OS", 0.6),
            ("linux", "Linux", 0.25),
        ]
        .into_iter()
        .find(|(k, _, _)| s.contains(k));
        if let Some((_, os, conf)) = os {
            out.add(Src::Ssdp, ClaimKind::Os, os, conf, format!("SSDP SERVER: {server}"));
            // These only ship on TVs.
            if matches!(os, "webOS" | "Tizen") {
                out.add(Src::Ssdp, ClaimKind::DeviceType, "TV", 0.55, format!("SSDP SERVER: {server} (a TV OS)"));
            }
        }
    }
}

fn upnp_type(t: &str) -> Option<(&'static str, f32)> {
    let l = t.to_ascii_lowercase();
    let has = |p: &str| l.contains(p);
    Some(if has("internetgatewaydevice") || has("wanconnectiondevice") || has("wandevice") {
        ("Router", 0.85)
    } else if has("wfadevice") {
        ("Router", 0.5)
    } else if has("zoneplayer") {
        ("Speaker", 0.8)
    } else if has("device:printer") {
        ("Printer", 0.8)
    } else if has("mediaserver") {
        ("Media server", 0.55)
    } else if l == "roku:ecp" {
        ("Media streamer", 0.55)
    } else if has("dial-multiscreen") {
        // DIAL: smart TVs and streaming sticks alike.
        ("Media streamer", 0.4)
    } else if has("mediarenderer") {
        ("Media renderer", 0.45)
    } else if has("urn:belkin:device") {
        ("Smart plug", 0.6)
    } else {
        return None;
    })
}

// ---------------------------------------------------------------------------
// Ports, banners, host names
// ---------------------------------------------------------------------------

fn port_hint(port: u16) -> Option<(Hint, f32, &'static str)> {
    Some(match port {
        62078 => ((Some("Apple"), Some("iPhone/iPad"), Some("iOS")), 0.7, "iOS lockdownd"),
        3389 => ((None, Some("Computer"), Some("Windows")), 0.6, "Remote Desktop"),
        445 | 139 => ((None, None, Some("Windows")), 0.25, "SMB file sharing"),
        554 => ((None, Some("IP camera"), None), 0.55, "RTSP video"),
        631 | 9100 | 515 => ((None, Some("Printer"), None), 0.7, "printing"),
        8008 | 8009 => ((None, Some("Media streamer"), None), 0.55, "Google Cast"),
        7000 => ((None, Some("AirPlay receiver"), None), 0.35, "AirPlay"),
        1883 | 8883 => ((None, Some("IoT hub"), None), 0.4, "MQTT"),
        8123 => ((None, Some("Smart home hub"), None), 0.6, "Home Assistant"),
        32400 => ((None, Some("Media server"), None), 0.6, "Plex"),
        6668 => ((None, Some("Smart plug"), None), 0.45, "Tuya local protocol"),
        3074 => ((None, Some("Game console"), None), 0.5, "Xbox Live"),
        _ => return None,
    })
}

/// (lower-case pattern, hint, confidence)
const BANNER_RULES: &[(&str, Hint, f32)] = &[
    ("openssh_for_windows", (None, None, Some("Windows")), 0.8),
    ("raspbian", (None, Some("Single-board computer"), Some("Linux (Raspberry Pi OS)")), 0.75),
    ("ubuntu", (None, None, Some("Linux (Ubuntu)")), 0.7),
    ("debian", (None, None, Some("Linux (Debian)")), 0.7),
    ("freebsd", (None, None, Some("FreeBSD")), 0.7),
    ("dropbear", (None, None, Some("Embedded Linux")), 0.5),
    ("rosssh", (Some("MikroTik"), Some("Router"), Some("RouterOS")), 0.8),
    ("routeros", (Some("MikroTik"), Some("Router"), Some("RouterOS")), 0.8),
    ("microsoft-iis", (None, None, Some("Windows")), 0.6),
    ("microsoft-httpapi", (None, None, Some("Windows")), 0.5),
    ("openwrt", (None, Some("Router"), Some("OpenWrt")), 0.7),
    ("luci", (None, Some("Router"), Some("OpenWrt")), 0.6),
    ("synology", (Some("Synology"), Some("NAS"), Some("Synology DSM")), 0.7),
    ("qnap", (Some("QNAP"), Some("NAS"), None), 0.7),
    ("truenas", (None, Some("NAS"), Some("TrueNAS")), 0.7),
    ("unraid", (None, Some("NAS"), Some("Unraid")), 0.7),
    ("proxmox", (None, Some("Server"), Some("Proxmox VE")), 0.7),
    ("home assistant", (None, Some("Smart home hub"), None), 0.7),
    ("pi-hole", (None, Some("DNS filter"), None), 0.6),
    ("unifi", (Some("Ubiquiti"), None, None), 0.6),
    ("reolink", (Some("Reolink"), Some("IP camera"), None), 0.7),
    ("hikvision", (Some("Hikvision"), Some("IP camera"), None), 0.7),
    ("dahua", (Some("Dahua"), Some("IP camera"), None), 0.7),
    ("laserjet", (Some("HP"), Some("Printer"), None), 0.7),
    ("officejet", (Some("HP"), Some("Printer"), None), 0.7),
    ("epson", (Some("Epson"), Some("Printer"), None), 0.6),
    ("plex", (None, Some("Media server"), None), 0.5),
    ("jellyfin", (None, Some("Media server"), None), 0.6),
];

fn banner_evidence(port: u16, text: &str, out: &mut Out) {
    let lower = text.to_ascii_lowercase();
    for (pat, hint, conf) in BANNER_RULES {
        if lower.contains(pat) {
            out.triple(Src::Banner, *hint, *conf, &format!("TCP {port}: {}", truncate(text, 80)));
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_owned() } else { format!("{}…", s.chars().take(n).collect::<String>()) }
}

enum Pat {
    Prefix(&'static str),
    Contains(&'static str),
}

const HOSTNAME_RULES: &[(Pat, Hint)] = {
    use Pat::*;
    &[
        (Prefix("desktop-"), (None, Some("Desktop PC"), Some("Windows"))),
        (Prefix("laptop-"), (None, Some("Laptop"), Some("Windows"))),
        (Contains("iphone"), (Some("Apple"), Some("Phone"), Some("iOS"))),
        (Contains("ipad"), (Some("Apple"), Some("Tablet"), Some("iPadOS"))),
        (Contains("macbook"), (Some("Apple"), Some("Laptop"), Some("macOS"))),
        (Contains("imac"), (Some("Apple"), Some("Desktop PC"), Some("macOS"))),
        (Contains("mac-mini"), (Some("Apple"), Some("Desktop PC"), Some("macOS"))),
        (Contains("apple-tv"), (Some("Apple"), Some("Media streamer"), Some("tvOS"))),
        (Contains("appletv"), (Some("Apple"), Some("Media streamer"), Some("tvOS"))),
        (Contains("homepod"), (Some("Apple"), Some("Smart speaker"), None)),
        (Prefix("android-"), (None, Some("Phone"), Some("Android"))),
        (Prefix("android_"), (None, Some("Phone"), Some("Android"))),
        (Prefix("galaxy"), (Some("Samsung Electronics"), Some("Phone"), Some("Android"))),
        (Prefix("pixel"), (Some("Google"), Some("Phone"), Some("Android"))),
        (Prefix("raspberrypi"), (Some("Raspberry Pi"), Some("Single-board computer"), Some("Linux"))),
        (Prefix("esp_"), (Some("Espressif"), Some("IoT device"), None)),
        (Prefix("esp-"), (Some("Espressif"), Some("IoT device"), None)),
        (Prefix("tasmota"), (None, Some("Smart plug"), Some("Tasmota"))),
        (Prefix("shelly"), (Some("Shelly"), Some("Smart switch"), None)),
        (Contains("chromecast"), (Some("Google"), Some("Media streamer"), None)),
        (Prefix("lgwebostv"), (Some("LG Electronics"), Some("TV"), Some("webOS"))),
        (Contains("bravia"), (Some("Sony"), Some("TV"), None)),
        (Prefix("roku"), (Some("Roku"), Some("Media streamer"), Some("Roku OS"))),
        (Prefix("sonos"), (Some("Sonos"), Some("Speaker"), None)),
        (Prefix("philips-hue"), (Some("Signify Netherlands"), Some("Smart home hub"), None)),
        (Prefix("xbox"), (Some("Microsoft"), Some("Game console"), None)),
        (Contains("playstation"), (Some("Sony"), Some("Game console"), None)),
        (Prefix("ps4"), (Some("Sony"), Some("Game console"), None)),
        (Prefix("ps5"), (Some("Sony"), Some("Game console"), None)),
        (Prefix("nintendo"), (Some("Nintendo"), Some("Game console"), None)),
        (Prefix("epson"), (Some("Epson"), Some("Printer"), None)),
        (Prefix("brn"), (Some("Brother"), Some("Printer"), None)),
        (Prefix("brw"), (Some("Brother"), Some("Printer"), None)),
        (Prefix("npi"), (Some("HP"), Some("Printer"), None)),
        (Prefix("amazon-"), (Some("Amazon"), None, None)),
        (Prefix("echo"), (Some("Amazon"), Some("Smart speaker"), None)),
    ]
};

fn hostname_evidence(host: &str, out: &mut Out) {
    let lower = host.to_ascii_lowercase();
    let detail = format!("Host name \"{host}\" matches a known pattern");
    for (pat, hint) in HOSTNAME_RULES {
        let hit = match pat {
            Pat::Prefix(p) => lower.starts_with(p),
            Pat::Contains(p) => lower.contains(p),
        };
        if hit {
            out.triple(Src::Heuristic, *hint, 0.45, &detail);
        }
    }
    // HP printers default to "HP" + the last six hex digits of their MAC.
    if lower.len() == 8 && lower.starts_with("hp") && lower[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        out.triple(Src::Heuristic, (Some("HP"), Some("Printer"), None), 0.5, &detail);
    }
}

#[cfg(test)]
mod tests {
    use na_model::{Banner, MdnsService, NetbiosInfo, UpnpInfo};

    use super::*;

    fn has(ev: &[Evidence], kind: ClaimKind, value: &str) -> bool {
        ev.iter().any(|e| e.kind == kind && e.value == value)
    }

    #[test]
    fn chromecast_via_mdns() {
        let info = LanInfo {
            services: vec!["_googlecast._tcp".into()],
            mdns: vec![MdnsService {
                instance: "Chromecast-1a2b".into(),
                service: "_googlecast._tcp".into(),
                port: Some(8009),
                txt: vec!["md=Chromecast".into(), "fn=Living Room TV".into()],
            }],
            ..Default::default()
        };
        let ev = lan_evidence(&info, &OuiDb::default());
        assert!(has(&ev, ClaimKind::DeviceType, "Media streamer"));
        assert!(has(&ev, ClaimKind::Model, "Chromecast"));
        assert!(has(&ev, ClaimKind::Name, "Living Room TV"));
    }

    #[test]
    fn apple_model_identifiers() {
        let info = LanInfo {
            mdns: vec![MdnsService {
                instance: "Sam's MacBook Pro".into(),
                service: "_device-info._tcp".into(),
                port: None,
                txt: vec!["model=MacBookPro18,3".into()],
            }],
            ..Default::default()
        };
        let ev = lan_evidence(&info, &OuiDb::default());
        assert!(has(&ev, ClaimKind::DeviceType, "Laptop"));
        assert!(has(&ev, ClaimKind::Os, "macOS"));
        assert!(has(&ev, ClaimKind::Model, "MacBookPro18,3"));
    }

    #[test]
    fn router_via_upnp_and_gateway() {
        let info = LanInfo {
            is_gateway: true,
            upnp: Some(UpnpInfo {
                friendly_name: Some("NETGEAR RAX50".into()),
                manufacturer: Some("NETGEAR, Inc.".into()),
                model_name: Some("RAX50".into()),
                device_type: Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1".into()),
                server: Some("Linux/4.1 UPnP/1.0 MiniUPnPd/2.1".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ev = lan_evidence(&info, &OuiDb::default());
        assert!(has(&ev, ClaimKind::Vendor, "NETGEAR"));
        assert!(has(&ev, ClaimKind::Model, "RAX50"));
        assert_eq!(ev.iter().filter(|e| e.value == "Router").count(), 2, "gateway + IGD");
        assert!(has(&ev, ClaimKind::Os, "Linux"));
    }

    #[test]
    fn windows_pc_from_netbios_hostname_and_ports() {
        let info = LanInfo {
            hostname: Some("DESKTOP-NA01".into()),
            netbios: Some(NetbiosInfo { name: Some("DESKTOP-NA01".into()), group: Some("WORKGROUP".into()), file_server: true }),
            open_ports: vec![445, 3389],
            banners: vec![Banner { port: 22, text: "SSH-2.0-OpenSSH_for_Windows_9.5".into() }],
            ..Default::default()
        };
        let ev = lan_evidence(&info, &OuiDb::default());
        assert!(has(&ev, ClaimKind::Name, "DESKTOP-NA01"));
        assert!(has(&ev, ClaimKind::DeviceType, "Desktop PC"));
        let windows_votes = ev.iter().filter(|e| e.kind == ClaimKind::Os && e.value == "Windows").count();
        assert!(windows_votes >= 4, "hostname, NetBIOS, RDP, SMB, SSH banner");
    }

    #[test]
    fn printers_and_cameras() {
        let info = LanInfo {
            hostname: Some("HP4A2B1C".into()),
            services: vec!["_ipp._tcp".into()],
            mdns: vec![MdnsService {
                instance: "HP OfficeJet Pro 9015 [4A2B1C]".into(),
                service: "_ipp._tcp".into(),
                port: Some(631),
                txt: vec!["ty=HP OfficeJet Pro 9015".into(), "usb_MFG=HP".into(), "product=(HP OfficeJet Pro 9015)".into()],
            }],
            ..Default::default()
        };
        let ev = lan_evidence(&info, &OuiDb::default());
        assert!(has(&ev, ClaimKind::DeviceType, "Printer"));
        assert!(has(&ev, ClaimKind::Model, "HP OfficeJet Pro 9015"));
        assert!(has(&ev, ClaimKind::Vendor, "HP"));

        let cam = LanInfo {
            open_ports: vec![554, 80],
            banners: vec![Banner { port: 80, text: "Server: nginx · title: Reolink".into() }],
            ..Default::default()
        };
        let ev = lan_evidence(&cam, &OuiDb::default());
        assert!(has(&ev, ClaimKind::DeviceType, "IP camera"));
        assert!(has(&ev, ClaimKind::Vendor, "Reolink"));
    }

    #[test]
    fn phone_hotspot_gateway_is_a_phone() {
        // Seen in the wild: an Android hotspot answering mDNS as the gateway.
        let info = LanInfo {
            mac: Some("3A:5C:00:12:34:56".parse().unwrap()),
            hostname: Some("Android_A1B2C3D4".into()),
            services: vec!["_nearbypresence._tcp".into()],
            is_gateway: true,
            ..Default::default()
        };
        let id = crate::identify::classify(&lan_evidence(&info, &OuiDb::default()));
        assert_eq!(id.device_type.unwrap().value, "Phone");
        assert_eq!(id.os.unwrap().value, "Android");
    }

    #[test]
    fn self_host_and_oui() {
        let oui = OuiDb::from_csv("h\nMA-L,3C3786,Intel Corporate,x\n");
        let info = LanInfo {
            mac: Some("3C:37:86:00:00:23".parse().unwrap()),
            hostname: Some("DESKTOP-NA01".into()),
            is_self: true,
            ..Default::default()
        };
        let ev = lan_evidence(&info, &oui);
        assert!(has(&ev, ClaimKind::Vendor, "Intel"));
        assert!(has(&ev, ClaimKind::Name, "DESKTOP-NA01"));
        // A randomized MAC has no vendor.
        let private = LanInfo { mac: Some("3E:37:86:00:00:23".parse().unwrap()), ..Default::default() };
        assert!(lan_evidence(&private, &oui).is_empty());
    }
}
