//! Observation sources. Each scanner (Wi-Fi, BLE, LAN, capture, simulator)
//! runs as an independent task and pushes [`Observation`]s into the store.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use na_model::{EngineEvent, Observation, SourceKind, SourceState};
use tokio_util::sync::CancellationToken;

use crate::EngineConfig;
use crate::guard::{GuardSignal, KarmaRequest};
use crate::identify::{BtDb, OuiDb};

pub mod ble;
pub mod lan;
pub mod sim;
pub mod wifi;

pub type ObservationSink = tokio::sync::mpsc::Sender<Observation>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Everything a running source gets from the engine.
pub struct SourceCtx {
    pub sink: ObservationSink,
    pub cancel: CancellationToken,
    kind: SourceKind,
    events: flume::Sender<EngineEvent>,
}

impl SourceCtx {
    pub(crate) fn new(
        kind: SourceKind,
        sink: ObservationSink,
        cancel: CancellationToken,
        events: flume::Sender<EngineEvent>,
    ) -> Self {
        Self { sink, cancel, kind, events }
    }

    /// Report a state change while running (e.g. permission lost, then regained).
    pub fn report(&self, state: SourceState) {
        let _ = self.events.send(EngineEvent::SourceStatus { source: self.kind, state });
    }

    /// Sleep for `d`, waking early on cancellation. For blocking (non-async) sources.
    pub fn sleep_blocking(&self, d: std::time::Duration) {
        let deadline = std::time::Instant::now() + d;
        while !self.cancel.is_cancelled() {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            std::thread::sleep(left.min(std::time::Duration::from_millis(100)));
        }
    }
}

/// Shared, read-only resources sources may need.
#[derive(Clone)]
pub struct SourceDeps {
    pub oui: Arc<OuiDb>,
    pub bt: Arc<BtDb>,
    /// Live LAN active-probing switch (see `EngineCommand::SetActiveProbes`).
    pub lan_active: tokio::sync::watch::Receiver<bool>,
    /// Karma test probes for whichever radio source is running (Wi-Fi or simulator).
    pub karma: flume::Receiver<KarmaRequest>,
    /// Reports back to the guard.
    pub guard: flume::Sender<GuardSignal>,
}

pub trait Source: Send + 'static {
    fn kind(&self) -> SourceKind;

    /// Run until `ctx.cancel` fires or the sink closes. Returning `Err` marks the source as failed.
    fn run(self: Box<Self>, ctx: SourceCtx) -> BoxFuture<anyhow::Result<()>>;
}

/// Build the source for `kind`, or explain why it can't run here.
pub fn make_source(
    kind: SourceKind,
    cfg: &EngineConfig,
    deps: &SourceDeps,
) -> Result<Box<dyn Source>, String> {
    match kind {
        SourceKind::Sim => Ok(Box::new(sim::SimSource::new(cfg.sim.clone(), deps.clone()))),
        SourceKind::Wifi => Ok(Box::new(wifi::WifiSource::new(cfg.wifi.clone(), deps.clone()))),
        SourceKind::Ble => Ok(Box::new(ble::BleSource::new(cfg.ble.clone(), deps.oui.clone(), deps.bt.clone()))),
        SourceKind::Lan => Ok(Box::new(lan::LanSource::new(cfg.lan.clone(), deps.oui.clone(), deps.lan_active.clone()))),
        SourceKind::Capture => Err("not implemented yet (milestone M5)".into()),
    }
}
