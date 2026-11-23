//! Device identification. Each source contributes weighted [`Evidence`](na_model::Evidence);
//! the classifier combines it into an [`Identity`](na_model::Identity).
//!
//! Per-source decoders (OUI, WPS, mDNS, SSDP, BLE, DHCP, TCP fingerprints)
//! land here in later milestones.

mod classifier;

pub use classifier::classify;
