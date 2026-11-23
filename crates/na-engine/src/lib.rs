//! The headless engine: runs scanners on a background tokio runtime, merges
//! their observations into devices, identifies them, and streams
//! [`EngineEvent`](na_model::EngineEvent)s to whichever frontend is attached.

mod engine;
pub mod identify;
pub mod parse;
pub mod sources;
mod store;

pub use engine::{Engine, EngineConfig, EngineHandle, StalePolicy};
pub use identify::{BtDb, OuiDb};
pub use sources::ble::BleConfig;
pub use sources::sim::SimConfig;
pub use sources::wifi::WifiConfig;
pub use store::DeviceStore;
