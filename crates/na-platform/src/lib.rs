//! OS-specific access to radios and the network stack, behind portable traits.
//!
//! Everything here is blocking and returns raw OS-level data. Decoding
//! (information elements, vendor lookup, identification) happens in `na-engine`,
//! so it is shared by every platform and unit-testable anywhere.

pub mod bluetooth;
pub mod net;
pub mod wifi;
