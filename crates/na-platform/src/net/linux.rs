use super::{NetError, Neighbor, NeighborState};

/// `/proc/net/arp`: `IP address  HW type  Flags  HW address  Mask  Device`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn neighbors() -> Result<Vec<Neighbor>, NetError> {
    let text = std::fs::read_to_string("/proc/net/arp").map_err(|e| NetError::Io(e.to_string()))?;
    Ok(parse_proc_arp(&text, |dev| {
        std::fs::read_to_string(format!("/sys/class/net/{dev}/ifindex"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }))
}

fn parse_proc_arp(text: &str, ifindex: impl Fn(&str) -> u32) -> Vec<Neighbor> {
    const ATF_COM: u32 = 0x02; // completed entry
    const ATF_PERM: u32 = 0x04;
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let [ip, _hw, flags, mac, _mask, dev] = f.as_slice() else { return None };
            let flags = u32::from_str_radix(flags.trim_start_matches("0x"), 16).ok()?;
            if flags & ATF_COM == 0 {
                return None;
            }
            Some(Neighbor {
                ip: ip.parse().ok()?,
                mac: mac.parse().ok()?,
                interface_index: ifindex(dev),
                // The kernel's ARP view has no reachability state here; treat completed entries as fresh.
                state: if flags & ATF_PERM != 0 { NeighborState::Permanent } else { NeighborState::Reachable },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn parses_proc_net_arp() {
        let text = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.1.1      0x1         0x2         3c:37:86:12:34:55     *        eth0\n\
                    192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        eth0\n\
                    192.168.1.10     0x1         0x6         00:11:32:aa:bb:cc     *        eth0\n";
        let n = parse_proc_arp(text, |_| 2);
        assert_eq!(n.len(), 2, "incomplete entry skipped");
        assert_eq!(n[0].ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(n[1].state, NeighborState::Permanent);
        assert_eq!(n[0].interface_index, 2);
    }
}
