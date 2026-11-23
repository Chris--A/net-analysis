//! Raw capture check: library version, devices, then ARP/DHCP packet counts on
//! the default interface. `cargo run -p na-platform --example cap_probe [secs]`

use std::time::{Duration, Instant};

use na_platform::{capture, net};

fn main() {
    let secs: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    match capture::library_version() {
        Ok(v) => println!("{v}"),
        Err(e) => return println!("capture unavailable: {e}"),
    }
    for d in capture::devices().unwrap_or_default() {
        println!("  {}  {}", d.name, d.description.unwrap_or_default());
    }
    let Some(iface) = net::interfaces().into_iter().next() else { return println!("no default interface") };
    let dev = match capture::device_for_interface(&iface.id) {
        Ok(d) => d,
        Err(e) => return println!("{e}"),
    };
    println!("default interface {} -> {dev}", iface.name);
    let mut cap = match capture::Capture::open(&dev, "arp or (udp and (port 67 or port 68))", 250) {
        Ok(c) => c,
        Err(e) => return println!("open failed: {e}"),
    };
    let (mut arp, mut dhcp) = (0, 0);
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        match cap.next_packet() {
            Ok(Some(p)) if p.data.len() > 13 && p.data[12..14] == [0x08, 0x06] => arp += 1,
            Ok(Some(_)) => dhcp += 1,
            Ok(None) => {}
            Err(e) => return println!("read failed: {e}"),
        }
    }
    println!("{secs}s: {arp} ARP, {dhcp} DHCP packets");
}
