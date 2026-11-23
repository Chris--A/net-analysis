use super::{WifiError, WifiScanner};

pub fn open() -> Result<Box<dyn WifiScanner>, WifiError> {
    #[cfg(target_os = "linux")]
    let why = "Linux support (nl80211) arrives in milestone M6";
    #[cfg(not(target_os = "linux"))]
    let why = "no backend for this operating system";
    Err(WifiError::Unsupported(why.into()))
}
