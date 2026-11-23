//! Diagnostic for the rogue-DHCP check: send one Discover on the default
//! interface and print every DHCP packet seen for a few seconds.
//! `cargo run -p na-engine --example dhcp_check`

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use na_engine::parse::{dhcp, packet};
use na_model::MacAddr;
use na_platform::{capture, net};

fn main() {
    let iface = net::interfaces().into_iter().next().expect("no default interface");
    let mac = iface.mac.expect("interface has no MAC");
    let dev = capture::device_for_interface(&iface.id).expect("no capture device");
    let mut cap = capture::Capture::open(&dev, "udp and (port 67 or port 68)", 200).expect("open");
    let xid = 0x4E41_1235;
    // The frame must come from our own MAC (the AP drops anything else), but the
    // DHCP client hardware address can be a fresh, random one.
    let chaddr = if std::env::args().any(|a| a == "--own") { mac } else { MacAddr([0x02, 0x4E, 0x41, 0x12, 0x34, 0x56]) };
    println!("chaddr {chaddr}");
    let frame = packet::udp_frame(
        mac,
        MacAddr([0xFF; 6]),
        (Ipv4Addr::UNSPECIFIED, 68),
        (Ipv4Addr::BROADCAST, 67),
        &dhcp::discover(chaddr, xid),
    );
    println!("{}: sending Discover xid {xid:08x} from {mac} ({} bytes): {:?}", iface.name, frame.len(), cap.send(&frame));
    let end = Instant::now() + Duration::from_secs(8);
    while Instant::now() < end {
        if let Ok(Some(p)) = cap.next_packet() {
            let Some(eth) = packet::ethernet(p.data) else { continue };
            let Some(ip) = packet::ipv4(eth.payload) else { continue };
            let Some(u) = packet::udp(ip.payload) else { continue };
            match dhcp::parse(u.payload) {
                Some(m) => println!(
                    "  {} -> {}  {}:{} -> {}:{}  op {} type {:?} xid {:08x} server {:?} routers {:?}",
                    eth.src, eth.dst, ip.src, u.src_port, ip.dst, u.dst_port, m.op, m.msg_type(), m.xid, m.server_id(), m.routers()
                ),
                None => println!("  {} -> {} unparsed DHCP-port packet, {} bytes", eth.src, eth.dst, u.payload.len()),
            }
        }
    }
}
