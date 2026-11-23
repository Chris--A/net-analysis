//! `na`: headless front end for the engine. Used for debugging, scripting and
//! cross-checking scanner output against OS tools (`netsh`, `iw`, `arp -a`).

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::{Parser, Subcommand};
use na_engine::identify::ble::describe_manufacturer;
use na_engine::{BleConfig, BtDb, Engine, EngineConfig, GuardConfig, LanConfig, SimConfig};
use na_model::{
    Alert, Device, DeviceDetails, DeviceId, EngineEvent, GuardStatus, KarmaOutcome, SourceKind, SourceState,
};

#[derive(Parser)]
#[command(name = "na", version, about = "Wireless & LAN device analyzer (headless)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the built-in simulator and print the devices it produces.
    Sim {
        /// How long to collect for.
        #[arg(long, default_value_t = 5)]
        secs: u64,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// Add N random devices (load testing).
        #[arg(long, default_value_t = 0)]
        extra: usize,
        /// Seconds until the evil-twin AP appears (0 disables it).
        #[arg(long, default_value_t = 3)]
        twin_after: u64,
    },
    /// Scan nearby Bluetooth LE and Classic devices with this machine's adapter.
    Ble {
        /// How long to collect for.
        #[arg(long, default_value_t = 15)]
        secs: u64,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// Scan continuously instead of the Wi-Fi-friendly duty cycle (more adverts).
        #[arg(long)]
        fast: bool,
        /// Skip the Classic discovery inquiry (only report connected Classic devices).
        #[arg(long)]
        no_inquiry: bool,
    },
    /// Discover hosts on the local network (ARP table, mDNS, SSDP/UPnP, NetBIOS).
    Lan {
        /// How long to collect for.
        #[arg(long, default_value_t = 12)]
        secs: u64,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// Also sweep the subnet and check a short list of TCP ports with banner grabs.
        /// Only on networks you own or are authorized to test.
        #[arg(long)]
        active: bool,
    },
    /// Check nearby Wi-Fi for evil twins, downgrades and Karma APs against your trusted networks.
    Guard {
        /// How long to watch (the Karma test needs about 17 s).
        #[arg(long, default_value_t = 20)]
        secs: u64,
        /// Emit JSON instead of a report.
        #[arg(long)]
        json: bool,
        /// Use the simulator (evil twin + Karma AP) instead of the real adapter.
        #[arg(long)]
        sim: bool,
        /// Skip the Karma test (no probe for a decoy network name is sent).
        #[arg(long)]
        no_karma: bool,
        /// Skip the rogue-DHCP check (no DHCP Discover is sent).
        #[arg(long)]
        no_dhcp: bool,
    },
    /// Capture ARP, DHCP and TCP SYNs (Npcap/libpcap) and show what each host revealed.
    Capture {
        /// How long to capture for.
        #[arg(long, default_value_t = 30)]
        secs: u64,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Scan nearby Wi-Fi access points with this machine's adapter.
    Wifi {
        /// How long to collect for (Windows needs a few seconds per scan).
        #[arg(long, default_value_t = 8)]
        secs: u64,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().cmd {
        Cmd::Sim { secs, json, extra, twin_after } => {
            let cfg = EngineConfig {
                sources: vec![SourceKind::Sim],
                sim: SimConfig {
                    extra_devices: extra,
                    evil_twin_after: (twin_after > 0).then(|| Duration::from_secs(twin_after)),
                    ..SimConfig::default()
                },
                ..EngineConfig::default()
            };
            let snapshot = collect(cfg, Duration::from_secs(secs))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot.to_json())?);
            } else {
                snapshot.print_table();
            }
        }
        Cmd::Ble { secs, json, fast, no_inquiry } => {
            let cfg = EngineConfig {
                sources: vec![SourceKind::Ble],
                ble: BleConfig {
                    low_latency: fast,
                    // Inquire once, right at the start of a short run.
                    inquiry_interval: (!no_inquiry).then_some(Duration::from_secs(600)),
                    ..BleConfig::default()
                },
                ..EngineConfig::default()
            };
            let snapshot = collect(cfg, Duration::from_secs(secs))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot.to_json())?);
            } else {
                snapshot.print_ble_table();
            }
        }
        Cmd::Lan { secs, json, active } => {
            let cfg = EngineConfig {
                sources: vec![SourceKind::Lan],
                lan: LanConfig { active, ..LanConfig::default() },
                ..EngineConfig::default()
            };
            let snapshot = collect(cfg, Duration::from_secs(secs))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot.to_json())?);
            } else {
                snapshot.print_lan_table();
            }
        }
        Cmd::Guard { secs, json, sim, no_karma, no_dhcp } => {
            let mut guard = if sim { GuardConfig::default() } else { GuardConfig::persistent() };
            guard.karma_interval = (!no_karma).then_some(Duration::from_secs(3600));
            guard.karma_first_after = Duration::from_secs(2);
            guard.dhcp_interval = (!no_dhcp).then_some(Duration::from_secs(3600));
            guard.dhcp_first_after = Duration::from_secs(4);
            let cfg = EngineConfig {
                sources: if sim {
                    vec![SourceKind::Sim]
                } else {
                    vec![SourceKind::Wifi, SourceKind::Lan, SourceKind::Capture]
                },
                sim: SimConfig {
                    evil_twin_after: Some(Duration::from_secs(4)),
                    karma_ap_after: Some(Duration::from_secs(1)),
                    arp_spoof_after: Some(Duration::from_secs(6)),
                    ..SimConfig::default()
                },
                guard,
                ..EngineConfig::default()
            };
            let snapshot = collect(cfg, Duration::from_secs(secs))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot.to_json())?);
            } else {
                snapshot.print_guard();
            }
        }
        Cmd::Capture { secs, json } => {
            let cfg = EngineConfig { sources: vec![SourceKind::Capture], ..EngineConfig::default() };
            let snapshot = collect(cfg, Duration::from_secs(secs))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot.to_json())?);
            } else {
                snapshot.print_capture_table();
            }
        }
        Cmd::Wifi { secs, json } => {
            let cfg = EngineConfig {
                sources: vec![SourceKind::Wifi],
                ..EngineConfig::default()
            };
            let snapshot = collect(cfg, Duration::from_secs(secs))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot.to_json())?);
            } else {
                snapshot.print_wifi_table();
            }
        }
    }
    Ok(())
}

struct Snapshot {
    devices: HashMap<DeviceId, Device>,
    alerts: Vec<Alert>,
    sources: BTreeMap<SourceKind, SourceState>,
    guard: Option<GuardStatus>,
}

fn collect(cfg: EngineConfig, dur: Duration) -> Result<Snapshot> {
    let engine = Engine::spawn(cfg)?;
    let mut snap = Snapshot {
        devices: HashMap::new(),
        alerts: Vec::new(),
        sources: BTreeMap::new(),
        guard: None,
    };
    let deadline = Instant::now() + dur;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match engine.events().recv_timeout(left) {
            Ok(EngineEvent::DeviceUpserted(d)) => {
                snap.devices.insert(d.id, *d);
            }
            Ok(EngineEvent::DeviceRemoved(id)) => {
                snap.devices.remove(&id);
            }
            Ok(EngineEvent::Alert(a)) => snap.alerts.push(a),
            Ok(EngineEvent::SourceStatus { source, state }) => {
                snap.sources.insert(source, state);
            }
            Ok(EngineEvent::Guard(g)) => snap.guard = Some(*g),
            Err(_) => break,
        }
    }
    Ok(snap)
}

impl Snapshot {
    fn sorted(&self) -> Vec<&Device> {
        let mut v: Vec<&Device> = self.devices.values().collect();
        v.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then(b.rssi.unwrap_or(i16::MIN).cmp(&a.rssi.unwrap_or(i16::MIN)))
                .then_with(|| a.display_name().cmp(&b.display_name()))
        });
        v
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "sources": self.sources.iter().map(|(k, v)| (k.label(), format!("{v:?}"))).collect::<BTreeMap<_, _>>(),
            "devices": self.sorted(),
            "alerts": self.alerts,
            "guard": self.guard,
        })
    }

    fn print_table(&self) {
        for (k, v) in &self.sources {
            eprintln!("source {:<8} {v:?}", k.label());
        }
        println!("KIND           RSSI  NAME                         KEY                 IDENTITY / DETAILS");
        for d in self.sorted() {
            let rssi = d.rssi.map(|r| r.to_string()).unwrap_or_else(|| "-".into());
            let mut extra = d.identity.summary().unwrap_or_default();
            if let Some(ap) = d.ap() {
                extra = format!(
                    "{extra}  [{} ch{} {}]",
                    ap.band.label(),
                    ap.channel,
                    ap.security.label()
                );
            }
            println!(
                "{:<13} {:>5}  {:<28} {:<19} {}",
                d.kind.label(),
                rssi,
                truncate(&d.display_name(), 28),
                d.key.to_string(),
                extra
            );
        }
        println!("\n{} devices, {} alerts", self.devices.len(), self.alerts.len());
        self.print_alerts();
    }

    fn print_alerts(&self) {
        for a in &self.alerts {
            println!("[{}] {}", a.severity.label(), a.title);
            println!("    {}", a.explanation);
            for f in &a.findings {
                println!("    - {f}");
            }
        }
    }

    fn print_guard(&self) {
        for (k, v) in &self.sources {
            eprintln!("source {:<8} {v:?}", k.label());
        }
        let Some(g) = &self.guard else {
            println!("(no guard status received)");
            return;
        };
        if let Some(msg) = &g.profile_import {
            println!("{msg}");
        }
        let learned: Vec<_> = g.networks.iter().filter(|n| !n.known.is_empty()).collect();
        println!(
            "{} trusted networks, {} with known access points",
            g.networks.len(),
            learned.len()
        );
        for n in learned {
            let expects = n.expected.as_ref().map_or("-", |e| e.auth.as_str());
            let aps: Vec<String> =
                n.known.iter().map(|k| format!("{} ({}, {} ch{})", k.bssid, k.source.label(), k.band.label(), k.channel)).collect();
            println!("  {:<28} {:<9} {}", truncate(&n.ssid, 28), expects, aps.join(", "));
        }

        match &g.karma.last {
            Some(r) => match &r.outcome {
                KarmaOutcome::NoResponse => println!("Karma test: probed for \"{}\"; no access point answered.", r.decoy),
                KarmaOutcome::Responders(v) => {
                    let who: Vec<String> = v.iter().map(ToString::to_string).collect();
                    println!("Karma test: probed for \"{}\"; ANSWERED BY {}", r.decoy, who.join(", "));
                }
                KarmaOutcome::Failed(why) => println!("Karma test: couldn't run ({why})"),
            },
            None if g.karma.running => println!("Karma test: still listening (use a longer --secs)"),
            None => println!("Karma test: not run"),
        }

        match g.gateway {
            Some((ip, mac)) => println!("Gateway: {ip} at {mac}"),
            None => println!("Gateway: unknown"),
        }
        match (&g.dhcp.last, g.dhcp.running) {
            (_, true) => println!("DHCP check: still listening"),
            (Some(r), _) => match &r.error {
                Some(e) => println!("DHCP check: couldn't run ({e})"),
                None if r.servers.is_empty() => println!("DHCP check: Discover sent, no server answered"),
                None => {
                    let s: Vec<String> = r
                        .servers
                        .iter()
                        .map(|s| {
                            let routers: Vec<String> = s.routers.iter().map(ToString::to_string).collect();
                            format!("{} ({}, router {})", s.server, s.mac, routers.join("/"))
                        })
                        .collect();
                    println!("DHCP check: {} server(s): {}", s.len(), s.join("; "));
                }
            },
            (None, false) => println!("DHCP check: not run"),
        }
        let lan: Vec<&Device> = self.sorted().into_iter().filter(|d| d.lan().is_some() && d.risk > 0.0).collect();
        if !lan.is_empty() {
            println!("\nLAN devices with findings:");
            for d in lan {
                println!("  {:>3.0}%  {:<24} {}", d.risk * 100.0, truncate(&d.display_name(), 24), d.key);
                for r in &d.risk_reasons {
                    println!("        - {r}");
                }
            }
        }

        let aps: Vec<&Device> = self.sorted().into_iter().filter(|d| d.ap().is_some()).collect();
        let mut risky: Vec<&&Device> = aps.iter().filter(|d| d.risk > 0.0).collect();
        risky.sort_by(|a, b| b.risk.total_cmp(&a.risk));
        println!("\n{} access points checked, {} with findings", aps.len(), risky.len());
        for d in risky {
            let ap = d.ap().expect("filtered");
            println!(
                "  {:>3.0}%  {:<24} {:<18} {}",
                d.risk * 100.0,
                truncate(ap.display_ssid(), 24),
                ap.bssid,
                ap.security.label()
            );
            for r in &d.risk_reasons {
                println!("        - {r}");
            }
        }
        println!("\n{} alerts", self.alerts.len());
        self.print_alerts();
    }
}

impl Snapshot {
    #[allow(clippy::print_literal)] // aligned header
    fn print_wifi_table(&self) {
        for (k, v) in &self.sources {
            eprintln!("source {:<8} {v:?}", k.label());
        }
        println!(
            "{:<17} {:>4}  {:<24} {:<8} {:>4} {:>4}  {:<5} {:<20} {:>6}  IDENTITY",
            "BSSID", "dBm", "SSID", "BAND", "CH", "MHz", "GEN", "SECURITY", "UPTIME"
        );
        for d in self.sorted() {
            let Some(ap) = d.ap() else {
                continue;
            };
            let mut bssid = ap.bssid.to_string();
            if ap.bssid.is_locally_administered() {
                bssid.push('*');
            }
            let uptime = ap.tsf_uptime_secs.map_or_else(|| "-".into(), |s| format!("{}d", s / 86_400));
            let generation = ap.wifi_gen.map_or_else(|| "-".into(), |g| format!("WiFi{g}"));
            let mut ssid = truncate(ap.display_ssid(), 24);
            if ap.connected {
                ssid = truncate(&format!("{ssid} ●"), 24);
            }
            println!(
                "{:<18}{:>4}  {:<24} {:<8} {:>4} {:>4}  {:<5} {:<20} {:>6}  {}",
                bssid,
                d.rssi.unwrap_or_default(),
                ssid,
                ap.band.label(),
                ap.channel,
                ap.width_mhz,
                generation,
                truncate(&ap.security.label(), 20),
                uptime,
                d.identity.summary().unwrap_or_default()
            );
        }
        println!("\n{} access points  (* = locally-administered BSSID, ● = connected)", self.devices.len());
    }
}

impl Snapshot {
    #[allow(clippy::print_literal)] // aligned header
    fn print_ble_table(&self) {
        for (k, v) in &self.sources {
            eprintln!("source {:<8} {v:?}", k.label());
        }
        let db = BtDb::load_default();
        println!(
            "{:<17} {:<7} {:>4}  {:<26} {:<34} {}",
            "ADDRESS", "TYPE", "dBm", "NAME", "IDENTITY", "DECODED"
        );
        for d in self.sorted() {
            let (addr, kind, decoded, flags) = match &d.details {
                DeviceDetails::Ble(b) => {
                    let mut decoded: Vec<String> = b
                        .manufacturer_data
                        .iter()
                        .map(|m| {
                            describe_manufacturer(m.company_id, &m.data).unwrap_or_else(|| {
                                let who = db.company(m.company_id).unwrap_or("unknown");
                                format!("mfr 0x{:04X} ({who})", m.company_id)
                            })
                        })
                        .collect();
                    decoded.extend(b.service_data.iter().map(|s| {
                        let who = s.uuid.as_u16().and_then(|u| db.uuid16(u)).unwrap_or("");
                        format!("svc {} {who}", s.uuid).trim_end().to_owned()
                    }));
                    if let Some(a) = b.appearance {
                        decoded.push(format!("appearance {}", na_engine::identify::appearance_label(a)));
                    }
                    (b.address, b.address_type.short(), decoded.join("; "), (b.paired, b.connected))
                }
                DeviceDetails::BtClassic(c) => {
                    let mut decoded = na_engine::identify::class_of_device_label(c.class_of_device);
                    if c.discoverable {
                        decoded.push_str("; discoverable");
                    }
                    (c.address, "classic", decoded, (c.paired, c.connected))
                }
                _ => continue,
            };
            let rssi = d.rssi.map_or_else(|| "-".into(), |r| r.to_string());
            let mut name = d.display_name();
            if name == d.key.to_string() {
                name.clear();
            }
            let marks = match flags {
                (_, true) => " ●",
                (true, false) => " ○",
                _ => "",
            };
            println!(
                "{:<17} {:<7} {:>4}  {:<26} {:<34} {}",
                addr.to_string(),
                kind,
                rssi,
                truncate(&format!("{name}{marks}"), 26),
                truncate(&d.identity.summary().unwrap_or_default(), 34),
                decoded
            );
        }
        let le = self.devices.values().filter(|d| d.ble().is_some()).count();
        println!(
            "\n{le} LE + {} Classic devices  (● connected, ○ paired; rpa/nrpa = rotating private address)",
            self.devices.len() - le
        );
    }
}

impl Snapshot {
    #[allow(clippy::print_literal)] // aligned header
    fn print_lan_table(&self) {
        for (k, v) in &self.sources {
            eprintln!("source {:<8} {v:?}", k.label());
        }
        println!("{:<15} {:<18} {:<24} {:<36} {}", "IP", "MAC", "NAME", "IDENTITY", "SEEN VIA");
        let mut hosts: Vec<&Device> = self.devices.values().filter(|d| d.lan().is_some()).collect();
        hosts.sort_by_key(|d| d.lan().and_then(|l| l.ips.first().copied()));
        for d in hosts {
            let Some(l) = d.lan() else { continue };
            let ip = l.ips.iter().find(|ip| ip.is_ipv4()).map_or_else(|| "-".into(), |ip| ip.to_string());
            let mac = l.mac.map_or_else(
                || "-".into(),
                |m| format!("{m}{}", if m.is_locally_administered() { "*" } else { "" }),
            );
            let mut via: Vec<String> = Vec::new();
            if l.is_self {
                via.push("this machine".into());
            }
            if l.is_gateway {
                via.push("gateway".into());
            }
            if !l.services.is_empty() {
                via.push(format!("mDNS {}", l.services.join(" ")));
            }
            if let Some(u) = &l.upnp {
                via.push(format!("UPnP {}", u.model_name.as_deref().or(u.server.as_deref()).unwrap_or("")));
            }
            if let Some(nb) = &l.netbios {
                via.push(format!("NetBIOS {}", nb.name.as_deref().unwrap_or("")));
            }
            if !l.open_ports.is_empty() {
                let p: Vec<String> = l.open_ports.iter().map(u16::to_string).collect();
                via.push(format!("ports {}", p.join(",")));
            }
            if let Some(i) = &l.interface {
                via.push(format!("on {i}"));
            }
            println!(
                "{:<15} {:<18} {:<24} {:<36} {}",
                ip,
                mac,
                truncate(&d.display_name(), 24),
                truncate(&d.identity.summary().unwrap_or_default(), 36),
                via.join("; ")
            );
        }
        println!("\n{} hosts  (* = randomized / private MAC)", self.devices.len());
    }
}

impl Snapshot {
    fn print_capture_table(&self) {
        for (k, v) in &self.sources {
            eprintln!("source {:<8} {v:?}", k.label());
        }
        println!("{:<18} {:<16} {:<34} {:<28} IDENTITY", "MAC", "IP", "DHCP (vendor class / request list)", "TCP SYN");
        let mut n = 0;
        for d in self.sorted() {
            let Some(lan) = d.lan() else { continue };
            n += 1;
            let ip = lan.ips.first().map(ToString::to_string).unwrap_or_default();
            let dhcp = lan.dhcp.as_ref().map_or(String::new(), |f| {
                format!("{} [{}]", f.vendor_class.as_deref().unwrap_or("-"), f.prl_text())
            });
            let tcp = lan.tcp.as_ref().map_or(String::new(), |t| {
                format!("ttl{} w{} {}", t.initial_ttl, t.window, t.layout)
            });
            let mut mac = d.key.to_string();
            if lan.mac.is_some_and(|m| m.is_locally_administered()) {
                mac.push('*');
            }
            println!(
                "{:<18} {:<16} {:<34} {:<28} {}",
                mac,
                ip,
                truncate(&dhcp, 34),
                truncate(&tcp, 28),
                d.identity.summary().unwrap_or_default()
            );
        }
        println!("\n{n} hosts seen by capture  (* = randomized MAC)");
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(n - 1).collect();
        t.push('…');
        t
    }
}
