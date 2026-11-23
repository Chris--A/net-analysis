//! Builders shared by the guard tests.

use na_model::{Akm, ApInfo, Band, DeviceDetails, DeviceKey, MacAddr, Millis, Observation, Pmf, Security};

pub fn ap(ssid: &str, bssid: &str, security: Security, fp: u64) -> ApInfo {
    ApInfo {
        ssid: ssid.into(),
        bssid: bssid.parse::<MacAddr>().unwrap(),
        channel: 36,
        band: Band::G5,
        width_mhz: 80,
        security,
        wifi_gen: Some(6),
        beacon_interval_tu: 100,
        tsf_uptime_secs: None,
        wps: None,
        ie_fingerprint: fp,
        connected: false,
        station_count: None,
        channel_utilization: None,
        country: None,
        vendor_ies: vec![],
        raw_ies: vec![],
    }
}

pub fn wpa2() -> Security {
    Security { akms: vec![Akm::Psk], pmf: Pmf::Capable, ..Default::default() }
}

pub fn wpa3() -> Security {
    Security { akms: vec![Akm::Sae], pmf: Pmf::Required, ..Default::default() }
}

pub fn obs(ap: &ApInfo, at: Millis) -> Observation {
    Observation {
        key: DeviceKey::Bssid(ap.bssid),
        at,
        rssi: Some(-50),
        details: DeviceDetails::Ap(ap.clone()),
        evidence: vec![],
        links: vec![],
    }
}
