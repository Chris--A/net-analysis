//! Observation sources. Each scanner (Wi-Fi, BLE, LAN, capture, simulator)
//! runs as an independent task and pushes [`Observation`]s into the store.

use std::future::Future;
use std::pin::Pin;

use na_model::{Observation, SourceKind};
use tokio_util::sync::CancellationToken;

use crate::EngineConfig;

pub mod sim;

pub type ObservationSink = tokio::sync::mpsc::Sender<Observation>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub trait Source: Send + 'static {
    fn kind(&self) -> SourceKind;

    /// Run until `cancel` fires or the sink closes. Returning `Err` marks the source as failed.
    fn run(
        self: Box<Self>,
        sink: ObservationSink,
        cancel: CancellationToken,
    ) -> BoxFuture<anyhow::Result<()>>;
}

/// Build the source for `kind`, or explain why it can't run here.
pub fn make_source(kind: SourceKind, cfg: &EngineConfig) -> Result<Box<dyn Source>, String> {
    match kind {
        SourceKind::Sim => Ok(Box::new(sim::SimSource::new(cfg.sim.clone()))),
        SourceKind::Wifi => Err("not implemented yet (milestone M1)".into()),
        SourceKind::Ble => Err("not implemented yet (milestone M2)".into()),
        SourceKind::Lan => Err("not implemented yet (milestone M3)".into()),
        SourceKind::Capture => Err("not implemented yet (milestone M5)".into()),
    }
}
