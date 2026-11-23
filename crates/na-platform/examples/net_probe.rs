//! Raw network platform probe: `cargo run -p na-platform --example net_probe`.
//! Prints local interfaces (with gateway and DNS) and the OS neighbor table.

fn main() {
    println!("hostname: {:?}", na_platform::net::hostname());
    println!("system: {:?}", na_platform::net::system_model());
    for i in na_platform::net::interfaces() {
        let addrs: Vec<String> = i.ipv4.iter().map(|c| format!("{}/{}", c.addr, c.prefix)).collect();
        println!(
            "iface #{} {:?} {:?} default={} mac={:?} ipv4=[{}] gw={:?} gw_mac={:?} dns={:?}",
            i.index,
            i.name,
            i.kind,
            i.is_default,
            i.mac.map(|m| m.to_string()),
            addrs.join(", "),
            i.gateway,
            i.gateway_mac.map(|m| m.to_string()),
            i.dns_servers
        );
    }
    match na_platform::net::neighbors() {
        Ok(list) => {
            for n in list {
                println!("neighbor {:<15} {}  if#{} {:?}", n.ip.to_string(), n.mac, n.interface_index, n.state);
            }
        }
        Err(e) => println!("neighbors: {e}"),
    }
}
