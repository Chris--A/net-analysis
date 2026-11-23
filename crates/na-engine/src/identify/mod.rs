//! Device identification. Each source contributes weighted [`Evidence`](na_model::Evidence),
//! and the classifier combines it into an [`Identity`](na_model::Identity).

use std::path::PathBuf;

pub mod ble;
mod bt_sig;
mod classifier;
pub mod fingerprint;
mod lan;
mod oui;
mod wifi;

pub use ble::{appearance_label, ble_evidence, class_of_device_label, classic_evidence};
pub use bt_sig::BtDb;
pub use classifier::classify;
pub use lan::lan_evidence;
pub use oui::{OuiDb, short_name};
pub use wifi::{VendorIeKind, ap_evidence, vendor_ie_info};

/// Where reference data (`oui.csv`, Bluetooth SIG YAML) is looked for, in order:
/// `$NA_DATA_DIR`, `./data`, then `data/` next to the binary and up to four
/// levels above it (so `target/debug/…` finds the workspace's `data/`).
pub(crate) fn data_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(d) = std::env::var_os("NA_DATA_DIR") {
        dirs.push(PathBuf::from(d));
    }
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd.join("data"));
    }
    if let Ok(exe) = std::env::current_exe() {
        for dir in exe.ancestors().skip(1).take(4) {
            dirs.push(dir.join("data"));
        }
    }
    dirs
}
