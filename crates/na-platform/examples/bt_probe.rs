//! Raw Bluetooth platform probe:
//! `cargo run -p na-platform --example bt_probe [secs] [fast] [inquiry]`.
//! Prints the adapter state, connected/paired devices and raw advertisements,
//! without any decoding. Handy when the engine shows nothing.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use na_platform::bluetooth::{self, LeEvent, ScanDuty};

#[derive(Default)]
struct Seen {
    adverts: usize,
    scan_responses: usize,
    rssi: i16,
    types: std::collections::BTreeSet<u8>,
    detail: String,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let secs: u64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(6);
    let duty = if args.iter().any(|a| a == "fast") { ScanDuty::LowLatency } else { ScanDuty::Balanced };
    let inquiry = args.iter().any(|a| a == "inquiry");
    println!("now (UTC ms) = {}", na_model::now_millis());

    match bluetooth::adapter_info() {
        Ok(a) => println!("adapter: LE={} classic={} radio_on={}", a.low_energy, a.classic, a.radio_on),
        Err(e) => {
            println!("adapter: {e}");
            return;
        }
    }

    match bluetooth::connected_le_devices() {
        Ok(list) => {
            for d in list {
                println!("connected LE: {} {:?} name={:?} appearance={:?}", d.address, d.address_kind, d.name, d.appearance);
            }
        }
        Err(e) => println!("connected LE: {e}"),
    }

    let inquiry_time = inquiry.then(|| Duration::from_secs(5));
    match bluetooth::classic_devices(inquiry_time) {
        Ok(list) => {
            for d in list {
                println!(
                    "classic: {} name={:?} cod={:06X} connected={} remembered={} last_seen={:?}",
                    d.address, d.name, d.class_of_device, d.connected, d.remembered, d.last_seen_ms
                );
            }
        }
        Err(e) => println!("classic: {e}"),
    }

    let seen: Arc<Mutex<BTreeMap<String, Seen>>> = Arc::default();
    let sink = seen.clone();
    let mut scanner = match bluetooth::open_le_scanner(duty) {
        Ok(s) => s,
        Err(e) => {
            println!("LE scanner: {e}");
            return;
        }
    };
    let started = scanner.start(Arc::new(move |ev| match ev {
        LeEvent::Advert(a) => {
            let mut m = sink.lock().unwrap();
            let e = m.entry(format!("{} {:?}", a.address, a.address_kind)).or_default();
            if a.scan_response {
                e.scan_responses += 1;
            } else {
                e.adverts += 1;
            }
            e.rssi = a.rssi_dbm;
            e.types.extend(a.sections.iter().map(|s| s.ad_type));
            if let Some(s) = a.sections.iter().find(|s| s.ad_type == 0xFF || s.ad_type == 0x16) {
                let hex: Vec<String> = s.data.iter().take(12).map(|b| format!("{b:02X}")).collect();
                e.detail = format!("{:02X}: {}", s.ad_type, hex.join(" "));
            }
        }
        LeEvent::Stopped(e) => println!("LE scan stopped: {e}"),
    }));
    if let Err(e) = started {
        println!("LE start: {e}");
        return;
    }
    std::thread::sleep(Duration::from_secs(secs));
    scanner.stop();
    let m = seen.lock().unwrap();
    let mut total = 0;
    for (addr, s) in m.iter() {
        total += s.adverts + s.scan_responses;
        let types: Vec<String> = s.types.iter().map(|t| format!("{t:02X}")).collect();
        println!(
            "{addr:<26} {:>4} adv {:>3} rsp {:>4} dBm  types=[{}]  {}",
            s.adverts, s.scan_responses, s.rssi, types.join(" "), s.detail
        );
    }
    println!("{} LE devices, {total} PDUs in {secs}s ({duty:?})", m.len());
}
