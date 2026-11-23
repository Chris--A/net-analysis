//! `na`: headless front end for the engine. Used for debugging, scripting and
//! cross-checking scanner output against OS tools (`netsh`, `iw`, `arp -a`).

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::{Parser, Subcommand};
use na_engine::identify::ble::describe_manufacturer;
use na_engine::{BleConfig, BtDb, Engine, EngineConfig, SimConfig};
use na_model::{Alert, Device, DeviceDetails, DeviceId, EngineEvent, SourceKind, SourceState};

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
}

fn collect(cfg: EngineConfig, dur: Duration) -> Result<Snapshot> {
    let engine = Engine::spawn(cfg)?;
    let mut snap = Snapshot {
        devices: HashMap::new(),
        alerts: Vec::new(),
        sources: BTreeMap::new(),
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
        for a in &self.alerts {
            println!("[{}] {}: {}", a.severity.label(), a.title, a.explanation);
        }
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

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(n - 1).collect();
        t.push('…');
        t
    }
}
