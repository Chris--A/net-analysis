//! Wire-format decoders. Pure functions with no OS access, so they're tested on every platform.

pub mod ble_ad;
pub mod dhcp;
pub mod dns;
pub mod ie;
pub mod netbios;
pub mod packet;
pub mod upnp;
