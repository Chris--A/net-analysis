use std::collections::HashMap;
use std::thread::JoinHandle;
use std::time::Duration;

use na_model::{EngineCommand, EngineEvent, SourceKind, SourceState, now_millis};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::guard::{Guard, GuardConfig, GuardSignal};
use crate::identify::{BtDb, OuiDb};
use crate::sources::{self, ObservationSink, SourceCtx, SourceDeps};
use crate::{BleConfig, CaptureConfig, DeviceStore, LanConfig, SimConfig, WifiConfig};

/// How long each device class may go unseen before it is dropped.
#[derive(Clone, Copy, Debug)]
pub struct StalePolicy {
    /// LE devices are re-heard every second while present.
    pub bluetooth: Duration,
    /// Classic devices are only re-confirmed by the periodic inquiry, so they need longer.
    pub bt_classic: Duration,
    pub wifi: Duration,
    pub lan: Duration,
}

impl Default for StalePolicy {
    fn default() -> Self {
        Self {
            bluetooth: Duration::from_secs(30),
            bt_classic: Duration::from_secs(240),
            wifi: Duration::from_secs(60),
            // Quiet hosts are only re-confirmed by discovery rounds and ARP traffic.
            lan: Duration::from_secs(600),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// Sources to start immediately.
    pub sources: Vec<SourceKind>,
    pub sim: SimConfig,
    pub wifi: WifiConfig,
    pub ble: BleConfig,
    pub lan: LanConfig,
    pub capture: CaptureConfig,
    pub guard: GuardConfig,
    /// How often changed devices are pushed to the frontend.
    pub flush_interval: Duration,
    pub stale: StalePolicy,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            sources: vec![SourceKind::Sim],
            sim: SimConfig::default(),
            wifi: WifiConfig::default(),
            ble: BleConfig::default(),
            lan: LanConfig::default(),
            capture: CaptureConfig::default(),
            guard: GuardConfig::default(),
            flush_interval: Duration::from_millis(200),
            stale: StalePolicy::default(),
        }
    }
}

impl EngineConfig {
    /// Real scanners (simulator excluded). Capture reports itself unavailable
    /// when Npcap/libpcap is missing.
    pub fn real_sources() -> Vec<SourceKind> {
        vec![SourceKind::Wifi, SourceKind::Ble, SourceKind::Lan, SourceKind::Capture]
    }
}

pub struct Engine;

impl Engine {
    /// Start the engine on its own OS thread with a private tokio runtime.
    /// The returned handle shuts it down when dropped.
    pub fn spawn(cfg: EngineConfig) -> anyhow::Result<EngineHandle> {
        let (cmd_tx, cmd_rx) = flume::unbounded();
        let (evt_tx, evt_rx) = flume::unbounded();
        let thread = std::thread::Builder::new()
            .name("na-engine".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_name("na-engine-worker")
                    .enable_all()
                    .build()
                    .expect("failed to build engine runtime");
                rt.block_on(run(cfg, cmd_rx, evt_tx));
            })?;
        Ok(EngineHandle {
            commands: cmd_tx,
            events: evt_rx,
            thread: Some(thread),
        })
    }
}

/// The frontend's end of the engine: send commands, drain events.
pub struct EngineHandle {
    commands: flume::Sender<EngineCommand>,
    events: flume::Receiver<EngineEvent>,
    thread: Option<JoinHandle<()>>,
}

impl EngineHandle {
    pub fn send(&self, cmd: EngineCommand) {
        // The engine only goes away on shutdown, so a failed send is harmless.
        let _ = self.commands.send(cmd);
    }

    pub fn events(&self) -> &flume::Receiver<EngineEvent> {
        &self.events
    }

    /// All events queued right now, without blocking.
    pub fn drain(&self) -> flume::TryIter<'_, EngineEvent> {
        self.events.try_iter()
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        let _ = self.commands.send(EngineCommand::Shutdown);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

struct RunningSource {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

async fn run(
    cfg: EngineConfig,
    cmd_rx: flume::Receiver<EngineCommand>,
    evt_tx: flume::Sender<EngineEvent>,
) {
    let (obs_tx, mut obs_rx) = tokio::sync::mpsc::channel(4096);
    let mut store = DeviceStore::new(cfg.stale);
    let mut running: HashMap<SourceKind, RunningSource> = HashMap::new();
    let (oui, bt) = tokio::join!(
        tokio::task::spawn_blocking(OuiDb::load_default),
        tokio::task::spawn_blocking(BtDb::load_default),
    );
    let (lan_active, lan_active_rx) = tokio::sync::watch::channel(cfg.lan.active);
    let (karma_tx, karma_rx) = flume::bounded(4);
    let (guard_tx, guard_rx) = flume::unbounded();
    let (dhcp_tx, dhcp_rx) = flume::bounded(4);
    let mut guard = Guard::new(&cfg.guard, karma_tx, dhcp_tx, now_millis());
    if cfg.guard.import_saved_profiles {
        let tx = guard_tx.clone();
        tokio::task::spawn_blocking(move || {
            let saved = na_platform::wifi::open_scanner()
                .and_then(|mut s| s.saved_networks())
                .map_err(|e| e.to_string());
            let _ = tx.send(GuardSignal::SavedNetworks(saved));
        });
    }
    let spawner = Spawner {
        cfg: &cfg,
        deps: SourceDeps {
            oui: std::sync::Arc::new(oui.unwrap_or_default()),
            bt: std::sync::Arc::new(bt.unwrap_or_default()),
            lan_active: lan_active_rx,
            karma: karma_rx,
            guard: guard_tx,
            dhcp_probe: dhcp_rx,
        },
        obs_tx: &obs_tx,
        evt_tx: &evt_tx,
    };

    for kind in &cfg.sources {
        spawner.start(*kind, &mut running);
    }

    let mut flush = tokio::time::interval(cfg.flush_interval);
    let mut sweep = tokio::time::interval(Duration::from_secs(1));
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!("engine started");
    loop {
        tokio::select! {
            Some(obs) = obs_rx.recv() => {
                guard.observe(&obs);
                store.ingest(obs);
            }
            Ok(sig) = guard_rx.recv_async() => guard.signal(sig, now_millis()),
            cmd = cmd_rx.recv_async() => match cmd {
                Ok(EngineCommand::SetSourceEnabled { source, enabled: true }) => {
                    spawner.start(source, &mut running);
                }
                Ok(EngineCommand::SetSourceEnabled { source, enabled: false }) => {
                    if let Some(r) = running.remove(&source) {
                        r.cancel.cancel();
                    }
                }
                Ok(EngineCommand::SetActiveProbes { enabled }) => {
                    info!(enabled, "LAN active probing");
                    let _ = lan_active.send(enabled);
                }
                Ok(EngineCommand::Shutdown) | Err(_) => break,
                Ok(other) => {
                    let (radio, capture) = (radio_running(&running), capture_running(&running));
                    if guard.command(&other, &store, now_millis(), radio, capture) {
                        // Show the effect (risk, trust status) right away.
                        if !send_all(&evt_tx, guard.tick(&mut store, now_millis(), radio, capture)) { break; }
                    }
                }
            },
            _ = flush.tick() => {
                if !send_all(&evt_tx, store.drain_updates()) { break; }
            }
            _ = sweep.tick() => {
                running.retain(|_, r| !r.task.is_finished());
                let now = now_millis();
                if !send_all(&evt_tx, store.sweep_stale(now)) { break; }
                let events = guard.tick(&mut store, now, radio_running(&running), capture_running(&running));
                if !send_all(&evt_tx, events) { break; }
            }
        }
    }

    guard.shutdown();
    for (_, r) in running.drain() {
        r.cancel.cancel();
        let _ = r.task.await;
    }
    info!("engine stopped");
}

/// A source that can send Karma probes is up.
fn radio_running(running: &HashMap<SourceKind, RunningSource>) -> bool {
    [SourceKind::Wifi, SourceKind::Sim]
        .iter()
        .any(|k| running.get(k).is_some_and(|r| !r.task.is_finished()))
}

/// A source that can send the rogue-DHCP check is up.
fn capture_running(running: &HashMap<SourceKind, RunningSource>) -> bool {
    [SourceKind::Capture, SourceKind::Sim]
        .iter()
        .any(|k| running.get(k).is_some_and(|r| !r.task.is_finished()))
}

/// Returns false once the frontend has gone away.
fn send_all(tx: &flume::Sender<EngineEvent>, events: Vec<EngineEvent>) -> bool {
    events.into_iter().all(|e| tx.send(e).is_ok())
}

/// Everything needed to start a source task.
struct Spawner<'a> {
    cfg: &'a EngineConfig,
    deps: SourceDeps,
    obs_tx: &'a ObservationSink,
    evt_tx: &'a flume::Sender<EngineEvent>,
}

impl Spawner<'_> {
    fn start(&self, kind: SourceKind, running: &mut HashMap<SourceKind, RunningSource>) {
        if running.get(&kind).is_some_and(|r| !r.task.is_finished()) {
            return;
        }
        let status = move |state| EngineEvent::SourceStatus { source: kind, state };

        let source = match sources::make_source(kind, self.cfg, &self.deps) {
            Ok(s) => s,
            Err(reason) => {
                warn!(?kind, %reason, "source unavailable");
                let _ = self.evt_tx.send(status(SourceState::Unavailable(reason)));
                return;
            }
        };

        let cancel = CancellationToken::new();
        let evt = self.evt_tx.clone();
        let ctx = SourceCtx::new(kind, self.obs_tx.clone(), cancel.clone(), self.evt_tx.clone());
        let task = tokio::spawn(async move {
            let _ = evt.send(status(SourceState::Running));
            let state = match source.run(ctx).await {
                Ok(()) => SourceState::Stopped,
                Err(e) => {
                    warn!(?kind, error = %e, "source failed");
                    SourceState::Failed(format!("{e:#}"))
                }
            };
            let _ = evt.send(status(state));
        });
        running.insert(kind, RunningSource { cancel, task });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_engine_produces_devices_and_shuts_down() {
        let cfg = EngineConfig {
            sim: SimConfig {
                tick: Duration::from_millis(20),
                ..SimConfig::default()
            },
            flush_interval: Duration::from_millis(20),
            ..EngineConfig::default()
        };
        let handle = Engine::spawn(cfg).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut upserts = 0;
        let mut saw_running = false;
        while std::time::Instant::now() < deadline && upserts < 20 {
            match handle.events().recv_timeout(Duration::from_millis(100)) {
                Ok(EngineEvent::DeviceUpserted(_)) => upserts += 1,
                Ok(EngineEvent::SourceStatus {
                    source: SourceKind::Sim,
                    state: SourceState::Running,
                }) => saw_running = true,
                _ => {}
            }
        }
        assert!(saw_running);
        assert!(upserts >= 20, "only got {upserts} upserts");
        drop(handle); // must join cleanly
    }
}
