//! LAN-side threats: gateway impersonation (ARP spoofing), gateway changes,
//! rogue DHCP servers and DNS changes.
//!
//! Inputs: ARP and DHCP packets from the capture source, the OS's own view of
//! the gateway from the LAN source (so gateway changes are caught even without
//! Npcap), and the rogue-DHCP check: one Discover, never followed by a Request.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use na_model::{
    AlertKind, DhcpCheckResult, DhcpCheckStatus, DhcpServerSeen, GatewayBaseline, MacAddr, Millis, Severity,
};

use super::detect::Finding;

/// Facts the capture source (or simulator) reports.
#[derive(Clone, Debug)]
pub enum NetEvent {
    /// Where this machine is: refreshed periodically.
    Context {
        own_mac: Option<MacAddr>,
        own_ip: Option<Ipv4Addr>,
        gateway: Option<Ipv4Addr>,
        dns: Vec<IpAddr>,
    },
    /// An ARP packet in which `mac` says it has `ip`.
    Arp { ip: Ipv4Addr, mac: MacAddr, at: Millis },
    /// A DHCP server's Offer or Ack, to us or (passively) to anyone.
    DhcpServer { seen: DhcpServerSeen, at: Millis },
    /// The capture source tried to send the check's Discover.
    DhcpProbeSent { xid: u32, result: Result<(), String> },
}

/// Ask the capture source to send a DHCP Discover with this transaction id.
#[derive(Clone, Debug)]
pub struct DhcpProbeRequest {
    pub xid: u32,
    pub at: Millis,
}

impl DhcpProbeRequest {
    pub fn is_stale(&self, now: Millis) -> bool {
        now.saturating_sub(self.at) > 20_000
    }
}

/// A finding about the device with this MAC.
#[derive(Clone, Debug)]
pub struct NetFinding {
    pub mac: MacAddr,
    pub title: String,
    pub finding: Finding,
}

#[derive(Clone, Copy, Debug)]
struct Claim {
    mac: MacAddr,
    first: Millis,
    last: Millis,
}

/// How long ARP claims and DHCP servers are remembered.
const CLAIM_MEMORY_MS: Millis = 5 * 60_000;
const SERVER_MEMORY_MS: Millis = 15 * 60_000;
/// Two claimants both heard within this window are "both active".
const ACTIVE_MS: Millis = 120_000;
const DHCP_LISTEN_MS: Millis = 6_000;
/// Discovers get lost (Wi-Fi, busy servers): one repeat if nothing has answered by then.
const DHCP_REPEAT_MS: Millis = 2_500;

/// First-hop redundancy virtual MACs (VRRP, HSRP): shared by design.
fn is_virtual_router(mac: MacAddr) -> bool {
    let m = mac.0;
    (m[..4] == [0x00, 0x00, 0x5E, 0x00] && matches!(m[4], 0x01 | 0x02)) || m[..5] == [0x00, 0x00, 0x0C, 0x07, 0xAC]
}

struct Run {
    xid: u32,
    started: Millis,
    repeated: bool,
    sent: bool,
    error: Option<String>,
}

pub struct NetWatch {
    pub own_mac: Option<MacAddr>,
    pub own_ip: Option<Ipv4Addr>,
    pub gateway_ip: Option<Ipv4Addr>,
    pub dns: Vec<IpAddr>,
    claims: HashMap<Ipv4Addr, Vec<Claim>>,
    servers: Vec<(DhcpServerSeen, Millis)>,
    interval: Option<Duration>,
    next_at: Option<Millis>,
    run: Option<Run>,
    last: Option<DhcpCheckResult>,
    tx: flume::Sender<DhcpProbeRequest>,
    next_xid: u32,
}

impl NetWatch {
    pub fn new(interval: Option<Duration>, first_after: Duration, tx: flume::Sender<DhcpProbeRequest>, now: Millis) -> Self {
        Self {
            own_mac: None,
            own_ip: None,
            gateway_ip: None,
            dns: Vec::new(),
            claims: HashMap::new(),
            servers: Vec::new(),
            next_at: interval.map(|_| now + first_after.as_millis() as Millis),
            interval,
            run: None,
            last: None,
            tx,
            next_xid: (now as u32) ^ 0x4E41_0000,
        }
    }

    /// Returns true when the visible status changed.
    pub fn event(&mut self, e: NetEvent) -> bool {
        match e {
            NetEvent::Context { own_mac, own_ip, gateway, dns } => {
                let changed = self.gateway_ip != gateway;
                self.own_mac = own_mac.or(self.own_mac);
                self.own_ip = own_ip.or(self.own_ip);
                self.gateway_ip = gateway;
                self.dns = dns;
                changed
            }
            NetEvent::Arp { ip, mac, at } => {
                self.claim(ip, mac, at);
                false
            }
            NetEvent::DhcpServer { seen, at } => {
                self.servers.retain(|(s, _)| !(s.server == seen.server && s.mac == seen.mac));
                self.servers.push((seen, at));
                false
            }
            NetEvent::DhcpProbeSent { xid, result } => {
                if let Some(run) = self.run.as_mut().filter(|r| r.xid == xid) {
                    match result {
                        Ok(()) => run.sent = true,
                        Err(e) => run.error = Some(e),
                    }
                }
                false
            }
        }
    }

    /// `mac` says it has `ip` (ARP, or the OS neighbor table for the gateway).
    pub fn claim(&mut self, ip: Ipv4Addr, mac: MacAddr, at: Millis) {
        if ip.is_unspecified() || mac.is_multicast() || mac.0 == [0; 6] {
            return;
        }
        let list = self.claims.entry(ip).or_default();
        match list.iter_mut().find(|c| c.mac == mac) {
            Some(c) => c.last = c.last.max(at),
            None => list.push(Claim { mac, first: at, last: at }),
        }
    }

    /// The MAC answering for the gateway: the longest-standing claimant that is
    /// still active (so a spoofer that joins later never takes its place here),
    /// else the most recent one.
    pub fn gateway_mac(&self) -> Option<MacAddr> {
        let ip = self.gateway_ip?;
        let claims = self.claims.get(&ip)?;
        let newest = claims.iter().map(|c| c.last).max()?;
        claims
            .iter()
            .filter(|c| newest.saturating_sub(c.last) < ACTIVE_MS)
            .min_by_key(|c| c.first)
            .map(|c| c.mac)
    }

    pub fn start_check(&mut self, now: Millis, capture: bool) -> bool {
        if self.run.is_some() {
            return false;
        }
        if !capture {
            self.last = Some(DhcpCheckResult {
                at: now,
                servers: Vec::new(),
                error: Some("packet capture isn't running".into()),
            });
            self.next_at = self.interval.map(|i| now + i.as_millis() as Millis);
            return true;
        }
        self.next_xid = self.next_xid.wrapping_add(0x9E37_79B9);
        let xid = self.next_xid;
        let _ = self.tx.try_send(DhcpProbeRequest { xid, at: now });
        self.run = Some(Run { xid, started: now, repeated: false, sent: false, error: None });
        true
    }

    /// Housekeeping and the check's schedule. Returns true when the status changed.
    pub fn tick(&mut self, now: Millis, capture: bool) -> bool {
        for list in self.claims.values_mut() {
            list.retain(|c| now.saturating_sub(c.last) < CLAIM_MEMORY_MS);
        }
        self.claims.retain(|_, l| !l.is_empty());
        self.servers.retain(|(_, at)| now.saturating_sub(*at) < SERVER_MEMORY_MS);

        let Some(run) = &self.run else {
            return match self.next_at {
                Some(t) if now >= t => self.start_check(now, capture),
                _ => false,
            };
        };
        let elapsed = now.saturating_sub(run.started);
        if elapsed < DHCP_LISTEN_MS {
            let answered = self.servers.iter().any(|(_, at)| *at >= run.started);
            if !run.repeated && !answered && elapsed >= DHCP_REPEAT_MS {
                let xid = run.xid;
                let _ = self.tx.try_send(DhcpProbeRequest { xid, at: now });
                if let Some(r) = self.run.as_mut() {
                    r.repeated = true;
                }
            }
            return false;
        }
        let run = self.run.take().expect("checked");
        let servers: Vec<DhcpServerSeen> = self
            .servers
            .iter()
            .filter(|(_, at)| *at >= run.started)
            .map(|(s, _)| s.clone())
            .collect();
        let error = match (&servers.is_empty(), run.sent) {
            (false, _) | (true, true) => None,
            (true, false) => Some(run.error.unwrap_or_else(|| "the capture source didn't send the Discover".into())),
        };
        self.last = Some(DhcpCheckResult { at: now, servers, error });
        self.next_at = self.interval.map(|i| now + i.as_millis() as Millis);
        true
    }

    pub fn status(&self) -> DhcpCheckStatus {
        DhcpCheckStatus { running: self.run.is_some(), last: self.last.clone(), next_at: self.next_at }
    }

    /// DHCP servers heard recently, one per server identifier.
    pub fn servers(&self) -> Vec<DhcpServerSeen> {
        let mut v: Vec<DhcpServerSeen> = Vec::new();
        for (s, _) in &self.servers {
            if !v.iter().any(|x| x.server == s.server) {
                v.push(s.clone());
            }
        }
        v
    }

    /// What's normal for the network right now, for learning a baseline.
    pub fn snapshot(&self, now: Millis) -> Option<GatewayBaseline> {
        let ip = self.gateway_ip?;
        Some(GatewayBaseline {
            ip,
            mac: self.gateway_mac()?,
            dns: self.dns.iter().filter(|d| d.is_ipv4()).copied().collect(),
            dhcp_servers: self.servers().iter().filter(|s| s.routers.contains(&ip)).map(|s| s.server).collect(),
            learned: now,
        })
    }

    /// Accept the current state as normal: forget competing claims for the gateway.
    pub fn accept_gateway(&mut self) {
        if let (Some(ip), Some(mac)) = (self.gateway_ip, self.gateway_mac())
            && let Some(list) = self.claims.get_mut(&ip)
        {
            list.retain(|c| c.mac == mac);
        }
        if let Some(ip) = self.gateway_ip {
            self.servers.retain(|(s, _)| s.routers.contains(&ip));
        }
    }

    /// Every current finding. `baseline` is the connected network's learned LAN side.
    pub fn assess(&self, now: Millis, baseline: Option<(&str, &GatewayBaseline)>) -> Vec<NetFinding> {
        let mut out = Vec::new();
        self.gateway_claims(now, baseline, &mut out);
        self.own_ip_claims(now, &mut out);
        self.conflicts(now, &mut out);
        self.dhcp(baseline.map(|(_, b)| b), &mut out);
        self.dns_change(baseline, &mut out);
        out
    }

    fn gateway_claims(&self, now: Millis, baseline: Option<(&str, &GatewayBaseline)>, out: &mut Vec<NetFinding>) {
        let Some(gw) = self.gateway_ip else { return };
        let claims: Vec<&Claim> = self.claims.get(&gw).map(|l| l.iter().filter(|c| !is_virtual_router(c.mac)).collect()).unwrap_or_default();
        let known = baseline.filter(|(_, b)| b.ip == gw).map(|(_, b)| b.mac);
        // The legitimate gateway: the learned one, else whoever claimed it first.
        let original = known.or_else(|| claims.iter().min_by_key(|c| c.first).map(|c| c.mac));
        let Some(original) = original else { return };
        let orig_claim = claims.iter().find(|c| c.mac == original);
        for c in claims.iter().filter(|c| c.mac != original) {
            let both_active = orig_claim.is_some_and(|o| now.saturating_sub(o.last) < ACTIVE_MS)
                && now.saturating_sub(c.last) < ACTIVE_MS;
            let finding = if both_active {
                Finding::new(
                    AlertKind::ArpSpoof,
                    Severity::Critical,
                    0.9,
                    format!(
                        "Claims to be the gateway {gw}, which {original} also claims right now. Two devices \
                         answering for the gateway is the signature of ARP spoofing: traffic meant for the \
                         router goes through {} instead.",
                        c.mac
                    ),
                )
            } else {
                Finding::new(
                    AlertKind::GatewayChange,
                    Severity::High,
                    0.5,
                    match baseline {
                        Some((ssid, _)) if known.is_some() => format!(
                            "On \"{ssid}\" the gateway {gw} has been {original}; now {} answers for it. A new \
                             router does this, and so does an attacker taking over the gateway's address.",
                            c.mac
                        ),
                        _ => format!(
                            "The gateway {gw} was {original} and is now {}. A new router does this, and so does \
                             an attacker taking over the gateway's address.",
                            c.mac
                        ),
                    },
                )
            };
            let title = if both_active {
                format!("ARP spoofing: {} claims to be the gateway", c.mac)
            } else {
                format!("Gateway changed to {}", c.mac)
            };
            out.push(NetFinding { mac: c.mac, title, finding });
        }
    }

    fn own_ip_claims(&self, now: Millis, out: &mut Vec<NetFinding>) {
        let (Some(ip), Some(own)) = (self.own_ip, self.own_mac) else { return };
        for c in self.claims.get(&ip).into_iter().flatten() {
            if c.mac != own && now.saturating_sub(c.last) < ACTIVE_MS {
                out.push(NetFinding {
                    mac: c.mac,
                    title: format!("{} claims this computer's address", c.mac),
                    finding: Finding::new(
                        AlertKind::ArpSpoof,
                        Severity::High,
                        0.6,
                        format!(
                            "Claims {ip}, this computer's address. Either two devices were given the same address, \
                             or someone is intercepting traffic meant for this computer."
                        ),
                    ),
                });
            }
        }
    }

    fn conflicts(&self, now: Millis, out: &mut Vec<NetFinding>) {
        for (ip, list) in &self.claims {
            if Some(*ip) == self.gateway_ip || Some(*ip) == self.own_ip {
                continue;
            }
            let active: Vec<&Claim> = list
                .iter()
                .filter(|c| !is_virtual_router(c.mac) && now.saturating_sub(c.last) < ACTIVE_MS / 2)
                .collect();
            let Some(oldest) = active.iter().min_by_key(|c| c.first) else { continue };
            for c in active.iter().filter(|c| c.mac != oldest.mac) {
                out.push(NetFinding {
                    mac: c.mac,
                    title: format!("Address conflict on {ip}"),
                    finding: Finding::new(
                        AlertKind::ArpSpoof,
                        Severity::Medium,
                        0.3,
                        format!(
                            "Claims {ip}, which {} also claims within the same minute: an address conflict, or one \
                             device impersonating the other.",
                            oldest.mac
                        ),
                    ),
                });
            }
        }
    }

    fn dhcp(&self, baseline: Option<&GatewayBaseline>, out: &mut Vec<NetFinding>) {
        let servers = self.servers();
        if servers.is_empty() {
            return;
        }
        let gw = self.gateway_ip;
        // The network's own server: learned, else one that hands out our gateway, else the first heard.
        let legit: Vec<Ipv4Addr> = match baseline.filter(|b| !b.dhcp_servers.is_empty()) {
            Some(b) => b.dhcp_servers.clone(),
            None => servers
                .iter()
                .find(|s| gw.is_some_and(|g| s.routers.contains(&g)))
                .or(servers.first())
                .map(|s| vec![s.server])
                .unwrap_or_default(),
        };
        let reference = servers.iter().find(|s| legit.contains(&s.server));
        for s in servers.iter().filter(|s| !legit.contains(&s.server)) {
            let differs = match reference {
                Some(r) => r.routers != s.routers || r.dns != s.dns,
                None => gw.is_some_and(|g| !s.routers.contains(&g)),
            };
            let (severity, weight, why) = if differs {
                (
                    Severity::High,
                    0.7,
                    format!(
                        "hands out router {} and DNS {}{}. Devices that take its offer send their traffic or \
                         their name lookups through it.",
                        list(&s.routers),
                        list(&s.dns),
                        reference.map_or(String::new(), |r| format!(
                            ", where the network's server {} gives router {} and DNS {}",
                            r.server,
                            list(&r.routers),
                            list(&r.dns)
                        ))
                    ),
                )
            } else {
                (
                    Severity::Medium,
                    0.3,
                    "gives the same router and DNS as the network's server: often a redundant pair or a second \
                     router left in its default mode."
                        .to_owned(),
                )
            };
            out.push(NetFinding {
                mac: s.mac,
                title: format!("Rogue DHCP server {}", s.server),
                finding: Finding::new(
                    AlertKind::RogueDhcp,
                    severity,
                    weight,
                    format!("A second DHCP server ({}, {}) is answering. It {why}", s.server, s.mac),
                ),
            });
        }
    }

    fn dns_change(&self, baseline: Option<(&str, &GatewayBaseline)>, out: &mut Vec<NetFinding>) {
        let Some((ssid, b)) = baseline else { return };
        let (Some(gw_mac), false) = (self.gateway_mac(), b.dns.is_empty()) else { return };
        let mut now_dns: Vec<IpAddr> = self.dns.iter().filter(|d| d.is_ipv4()).copied().collect();
        let mut was = b.dns.clone();
        now_dns.sort();
        was.sort();
        if !now_dns.is_empty() && now_dns != was {
            out.push(NetFinding {
                mac: gw_mac,
                title: format!("DNS servers changed on \"{ssid}\""),
                finding: Finding::new(
                    AlertKind::GatewayChange,
                    Severity::Medium,
                    0.2,
                    format!(
                        "This computer now resolves names through {}, but on \"{ssid}\" it used {}. Changed DNS \
                         servers can redirect websites.",
                        list(&now_dns),
                        list(&was)
                    ),
                ),
            });
        }
    }
}

fn list<T: ToString>(v: &[T]) -> String {
    if v.is_empty() {
        return "none".into();
    }
    v.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    const GW: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const ME: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 23);

    fn watch() -> (NetWatch, flume::Receiver<DhcpProbeRequest>) {
        let (tx, rx) = flume::unbounded();
        let mut w = NetWatch::new(None, Duration::ZERO, tx, 0);
        w.event(NetEvent::Context {
            own_mac: Some(mac("3C:37:86:00:00:23")),
            own_ip: Some(ME),
            gateway: Some(GW),
            dns: vec![IpAddr::V4(GW)],
        });
        (w, rx)
    }

    fn kinds(f: &[NetFinding]) -> Vec<(AlertKind, Option<Severity>, MacAddr)> {
        f.iter().map(|n| (n.finding.kind, n.finding.severity, n.mac)).collect()
    }

    #[test]
    fn two_gateways_at_once_is_spoofing_one_after_the_other_is_a_change() {
        let (mut w, _) = watch();
        let real = mac("3C:37:86:00:00:01");
        let evil = mac("02:66:66:00:00:01");
        w.claim(GW, real, 1_000);
        assert!(w.assess(1_000, None).is_empty());
        w.claim(GW, evil, 5_000);
        w.claim(GW, real, 6_000);
        assert_eq!(kinds(&w.assess(6_000, None)), vec![(AlertKind::ArpSpoof, Some(Severity::Critical), evil)]);
        // The real one goes quiet for good: a change of gateway, not a fight over it.
        w.claim(GW, evil, 200_000);
        assert_eq!(kinds(&w.assess(200_000, None)), vec![(AlertKind::GatewayChange, Some(Severity::High), evil)]);
        assert_eq!(w.gateway_mac(), Some(evil));
    }

    #[test]
    fn learned_gateway_wins_and_vrrp_is_ignored() {
        let (mut w, _) = watch();
        let replacement = mac("3C:37:86:00:00:99");
        let base = GatewayBaseline { ip: GW, mac: mac("3C:37:86:00:00:01"), dns: vec![], dhcp_servers: vec![], learned: 0 };
        w.claim(GW, replacement, 1_000);
        let f = w.assess(1_000, Some(("Home", &base)));
        assert_eq!(kinds(&f), vec![(AlertKind::GatewayChange, Some(Severity::High), replacement)]);
        assert!(f[0].finding.text.contains("On \"Home\""));

        let (mut w, _) = watch();
        w.claim(GW, mac("3C:37:86:00:00:01"), 1_000);
        w.claim(GW, mac("00:00:5E:00:01:07"), 1_000);
        assert!(w.assess(1_000, None).is_empty(), "VRRP virtual MAC shares the address by design");
    }

    #[test]
    fn own_address_and_conflicts() {
        let (mut w, _) = watch();
        let other = mac("02:66:66:00:00:02");
        w.claim(ME, other, 1_000);
        w.claim(Ipv4Addr::new(192, 168, 1, 50), mac("3C:37:86:00:00:50"), 1_000);
        w.claim(Ipv4Addr::new(192, 168, 1, 50), mac("3C:37:86:00:00:51"), 2_000);
        let mut k = kinds(&w.assess(2_000, None));
        k.sort_by_key(|x| x.1);
        assert_eq!(
            k,
            vec![
                (AlertKind::ArpSpoof, Some(Severity::Medium), mac("3C:37:86:00:00:51")),
                (AlertKind::ArpSpoof, Some(Severity::High), other),
            ]
        );
        w.tick(CLAIM_MEMORY_MS + 10_000, false);
        assert!(w.assess(CLAIM_MEMORY_MS + 10_000, None).is_empty(), "old claims are forgotten");
    }

    #[test]
    fn dhcp_check_finds_a_rogue_server() {
        let (tx, rx) = flume::unbounded();
        let mut w = NetWatch::new(Some(Duration::from_secs(600)), Duration::ZERO, tx, 0);
        w.event(NetEvent::Context { own_mac: None, own_ip: Some(ME), gateway: Some(GW), dns: vec![] });
        assert!(w.tick(0, true), "check starts");
        let req = rx.try_recv().unwrap();
        w.event(NetEvent::DhcpProbeSent { xid: req.xid, result: Ok(()) });
        let legit = DhcpServerSeen { server: GW, mac: mac("3C:37:86:00:00:01"), routers: vec![GW], dns: vec![GW] };
        let evil_ip = Ipv4Addr::new(192, 168, 1, 66);
        let rogue = DhcpServerSeen { server: evil_ip, mac: mac("02:66:66:00:00:01"), routers: vec![evil_ip], dns: vec![evil_ip] };
        w.event(NetEvent::DhcpServer { seen: legit.clone(), at: 500 });
        w.event(NetEvent::DhcpServer { seen: rogue.clone(), at: 700 });
        assert!(w.tick(DHCP_LISTEN_MS, true), "check finishes");
        let last = w.status().last.unwrap();
        assert_eq!((last.servers.len(), last.error), (2, None));
        let f = w.assess(DHCP_LISTEN_MS, None);
        assert_eq!(kinds(&f), vec![(AlertKind::RogueDhcp, Some(Severity::High), rogue.mac)]);
        assert!(f[0].finding.text.contains("router 192.168.1.66"));

        // Without capture, the check reports that it couldn't run.
        let (tx, _rx) = flume::unbounded();
        let mut w = NetWatch::new(None, Duration::ZERO, tx, 0);
        w.start_check(5, false);
        assert!(w.status().last.unwrap().error.is_some());
    }

    #[test]
    fn dns_change_against_the_baseline() {
        let (mut w, _) = watch();
        w.claim(GW, mac("3C:37:86:00:00:01"), 1_000);
        let base = GatewayBaseline {
            ip: GW,
            mac: mac("3C:37:86:00:00:01"),
            dns: vec![IpAddr::V4(GW)],
            dhcp_servers: vec![GW],
            learned: 0,
        };
        assert!(w.assess(1_000, Some(("Home", &base))).is_empty());
        w.dns = vec![IpAddr::V4(Ipv4Addr::new(45, 77, 1, 1))];
        assert_eq!(kinds(&w.assess(1_000, Some(("Home", &base))))[0].0, AlertKind::GatewayChange);
    }
}
