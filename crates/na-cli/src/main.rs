//! `na`: headless front end for the engine. Used for debugging, scripting and
//! cross-checking scanner output against OS tools (`netsh`, `iw`, `arp -a`).

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::{Parser, Subcommand};
use na_engine::{Engine, EngineConfig, SimConfig};
use na_model::{Alert, Device, DeviceId, EngineEvent, SourceKind, SourceState};

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

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(n - 1).collect();
        t.push('…');
        t
    }
}
