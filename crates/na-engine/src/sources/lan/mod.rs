//! LAN discovery.
//!
//! **Passive / standard** (always on):
//! - interfaces, this host and the default gateway
//! - the OS neighbor (ARP) table
//! - mDNS / DNS-SD and SSDP discovery rounds (multicast, like any OS does)
//! - NetBIOS name queries to hosts already seen
//!
//! **Active** (opt-in, see [`EngineCommand::SetActiveProbes`]): a subnet
//! sweep, plus a check of a short fixed list of TCP ports with banner grabs on
//! each host. Only use it on networks you own or may test.
//!
//! Facts are merged per IPv4 address. A host is emitted keyed by MAC once the
//! neighbor table resolves it, or by IP if it can't be (the store promotes the IP
//! device to the MAC one when the MAC turns up later).
//!
//! [`EngineCommand::SetActiveProbes`]: na_model::EngineCommand::SetActiveProbes

mod discovery;
mod probe;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use na_model::{
    Banner, ClaimKind, DeviceDetails, DeviceKey, Evidence, EvidenceSource, LanInfo, MdnsService,
    Millis, NetbiosInfo, Observation, SourceKind, SourceState, UpnpInfo, now_millis,
};
use na_platform::net::{self, LocalInterface, NeighborState};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior, interval};
use tracing::{info, warn};

pub use probe::PROBE_PORTS;

use super::{BoxFuture, Source, SourceCtx};
use crate::identify::{OuiDb, lan_evidence, short_name};

#[derive(Clone, Debug)]
pub struct LanConfig {
    /// Start with active probing enabled. It can be toggled at runtime.
    pub active: bool,
    pub interface_poll: Duration,
    pub neighbor_poll: Duration,
    pub mdns_interval: Duration,
    pub ssdp_interval: Duration,
    pub netbios_interval: Duration,
    pub sweep_interval: Duration,
    pub probe_interval: Duration,
    /// Subnets with more hosts than this only sweep the /24 around this machine.
    pub max_sweep_hosts: usize,
}

impl Default for LanConfig {
    fn default() -> Self {
        Self {
            active: false,
            interface_poll: Duration::from_secs(30),
            neighbor_poll: Duration::from_secs(5),
            mdns_interval: Duration::from_secs(60),
            ssdp_interval: Duration::from_secs(120),
            netbios_interval: Duration::from_secs(600),
            sweep_interval: Duration::from_secs(300),
            probe_interval: Duration::from_secs(1800),
            max_sweep_hosts: 1024,
        }
    }
}

/// A fact learned by a discovery task.
pub(crate) enum Finding {
    Mdns { ip: Ipv4Addr, hostname: Option<String>, services: Vec<String>, instances: Vec<MdnsService> },
    Upnp { ip: Ipv4Addr, info: UpnpInfo },
    Netbios { ip: Ipv4Addr, info: NetbiosInfo },
    Ports { ip: Ipv4Addr, open: Vec<u16>, banners: Vec<Banner> },
}

pub struct LanSource {
    cfg: LanConfig,
    oui: Arc<OuiDb>,
    active: watch::Receiver<bool>,
}

impl LanSource {
    pub fn new(cfg: LanConfig, oui: Arc<OuiDb>, active: watch::Receiver<bool>) -> Self {
        Self { cfg, oui, active }
    }
}

impl Source for LanSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Lan
    }

    fn run(self: Box<Self>, ctx: SourceCtx) -> BoxFuture<anyhow::Result<()>> {
        Box::pin(async move {
            let (tx, mut rx) = mpsc::channel(256);
            let active = self.active.clone();
            let mut lan = Lan::new(*self, tx).await;
            let mut tick = interval(Duration::from_millis(500));
            tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ctx.cancel.cancelled() => break,
                    Some(f) = rx.recv() => lan.apply(f),
                    _ = tick.tick() => {
                        while lan.tasks.try_join_next().is_some() {}
                        let is_active = *active.borrow(); // don't hold the watch guard across .await
                        lan.tick(is_active, &ctx).await;
                        if !lan.flush(&ctx).await {
                            break;
                        }
                    }
                }
            }
            lan.tasks.abort_all();
            Ok(())
        })
    }
}

struct Host {
    info: LanInfo,
    first_seen: Instant,
    /// Last confirmation that the host is present (Unix ms). Unconfirmed hosts aren't emitted.
    seen_ms: Option<Millis>,
    emitted_ms: Millis,
    dirty: bool,
    netbios_at: Option<Instant>,
    probed_at: Option<Instant>,
    nudged_at: Option<Instant>,
}

impl Host {
    fn new(ip: Ipv4Addr) -> Self {
        Self {
            info: LanInfo { ips: vec![IpAddr::V4(ip)], ..Default::default() },
            first_seen: Instant::now(),
            seen_ms: None,
            emitted_ms: 0,
            dirty: true,
            netbios_at: None,
            probed_at: None,
            nudged_at: None,
        }
    }

    /// The host is present right now. Re-emit at most every 30 s just for liveness.
    fn confirm(&mut self) {
        let now = now_millis();
        self.seen_ms = Some(now);
        if now.saturating_sub(self.emitted_ms) > 30_000 {
            self.dirty = true;
        }
    }
}

/// Firmware-reported maker and model of this machine. The NIC's OUI only names the Wi-Fi module.
fn self_evidence() -> Vec<Evidence> {
    let (vendor, model) = net::system_model();
    let mut ev = Vec::new();
    if let Some(v) = vendor {
        let detail = format!("This machine's firmware: manufacturer \"{v}\"");
        ev.push(Evidence::new(EvidenceSource::Heuristic, ClaimKind::Vendor, short_name(&v), 0.9, detail));
    }
    if let Some(m) = model {
        let detail = format!("This machine's firmware: product \"{m}\"");
        ev.push(Evidence::new(EvidenceSource::Heuristic, ClaimKind::Model, m.as_str(), 0.9, detail));
    }
    ev
}

struct Lan {
    cfg: LanConfig,
    oui: Arc<OuiDb>,
    tx: mpsc::Sender<Finding>,
    ifaces: Vec<LocalInterface>,
    hosts: HashMap<Ipv4Addr, Host>,
    nudger: Option<UdpSocket>,
    tasks: JoinSet<()>,
    hostname: Option<String>,
    /// This machine's maker/model from firmware, added to the self host's evidence.
    self_evidence: Vec<Evidence>,
    blocked: bool,
    was_active: bool,
    next_iface: Instant,
    next_neighbors: Instant,
    next_mdns: Instant,
    next_ssdp: Instant,
    next_sweep: Instant,
}

impl Lan {
    async fn new(src: LanSource, tx: mpsc::Sender<Finding>) -> Self {
        let now = Instant::now();
        Self {
            cfg: src.cfg,
            oui: src.oui,
            tx,
            ifaces: Vec::new(),
            hosts: HashMap::new(),
            nudger: UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok(),
            tasks: JoinSet::new(),
            hostname: net::hostname(),
            self_evidence: tokio::task::spawn_blocking(self_evidence).await.unwrap_or_default(),
            blocked: false,
            was_active: false,
            next_iface: now,
            next_neighbors: now,
            // Give the neighbor table a head start so replies can be keyed by MAC.
            next_mdns: now + Duration::from_secs(1),
            next_ssdp: now + Duration::from_secs(2),
            next_sweep: now,
        }
    }

    fn is_local(&self, ip: Ipv4Addr) -> bool {
        self.ifaces.iter().any(|i| i.ipv4.iter().any(|c| c.contains(ip)))
    }

    fn is_own(&self, ip: Ipv4Addr) -> bool {
        self.ifaces.iter().any(|i| i.ipv4.iter().any(|c| c.addr == ip))
    }

    fn host(&mut self, ip: Ipv4Addr) -> &mut Host {
        self.hosts.entry(ip).or_insert_with(|| Host::new(ip))
    }

    async fn tick(&mut self, active: bool, ctx: &SourceCtx) {
        let now = Instant::now();
        if now >= self.next_iface {
            self.refresh_interfaces(ctx).await;
            self.next_iface = now + self.cfg.interface_poll;
        }
        if self.ifaces.is_empty() {
            return;
        }
        if now >= self.next_neighbors {
            self.poll_neighbors().await;
            self.next_neighbors = now + self.cfg.neighbor_poll;
        }
        let locals: Vec<Ipv4Addr> = self.ifaces.iter().flat_map(|i| i.ipv4.iter().map(|c| c.addr)).collect();
        if now >= self.next_mdns {
            for &ip in &locals {
                self.tasks.spawn(discovery::mdns_round(ip, self.tx.clone()));
            }
            self.next_mdns = now + self.cfg.mdns_interval;
        }
        if now >= self.next_ssdp {
            for &ip in &locals {
                self.tasks.spawn(discovery::ssdp_round(ip, self.tx.clone()));
            }
            self.next_ssdp = now + self.cfg.ssdp_interval;
        }

        // NetBIOS name queries to hosts we've seen. A few per tick, so it never bursts.
        let due: Vec<Ipv4Addr> = self
            .hosts
            .iter()
            .filter(|(ip, h)| {
                h.seen_ms.is_some()
                    && !h.info.is_self
                    && h.netbios_at.is_none_or(|t| t.elapsed() > self.cfg.netbios_interval)
                    && self.is_local(**ip)
            })
            .map(|(ip, _)| *ip)
            .take(4)
            .collect();
        for ip in due {
            self.host(ip).netbios_at = Some(now);
            self.tasks.spawn(discovery::netbios_query(ip, self.tx.clone()));
        }

        // Resolve MACs for hosts that announced themselves before ARP knew them.
        let unresolved: Vec<Ipv4Addr> = self
            .hosts
            .iter()
            .filter(|(ip, h)| {
                h.info.mac.is_none()
                    && !h.info.is_self
                    && h.nudged_at.is_none_or(|t| t.elapsed() > Duration::from_secs(30))
                    && self.is_local(**ip)
            })
            .map(|(ip, _)| *ip)
            .collect();
        if !unresolved.is_empty() {
            for &ip in &unresolved {
                self.host(ip).nudged_at = Some(now);
            }
            if let Some(sock) = &self.nudger {
                probe::nudge(sock, unresolved, Duration::ZERO).await;
            }
            self.next_neighbors = self.next_neighbors.min(now + Duration::from_millis(1500));
        }

        if active {
            if !self.was_active {
                info!("LAN active probing enabled");
                self.next_sweep = now;
            }
            if now >= self.next_sweep {
                self.sweep();
                self.next_sweep = now + self.cfg.sweep_interval;
                self.next_neighbors = self.next_neighbors.min(now + Duration::from_secs(3));
            }
            let due: Vec<Ipv4Addr> = self
                .hosts
                .iter()
                .filter(|(ip, h)| {
                    h.seen_ms.is_some()
                        && !h.info.is_self
                        && h.probed_at.is_none_or(|t| t.elapsed() > self.cfg.probe_interval)
                        && self.is_local(**ip)
                })
                .map(|(ip, _)| *ip)
                .take(2)
                .collect();
            for ip in due {
                self.host(ip).probed_at = Some(now);
                self.tasks.spawn(probe::probe_host(ip, self.tx.clone()));
            }
        } else if self.was_active {
            info!("LAN active probing disabled");
        }
        self.was_active = active;
    }

    /// Nudge every host address on each local subnet (bounded by `max_sweep_hosts`).
    fn sweep(&mut self) {
        let mut targets: Vec<Ipv4Addr> = Vec::new();
        for iface in &self.ifaces {
            for c in &iface.ipv4 {
                let cidr = if c.hosts().take(self.cfg.max_sweep_hosts + 1).count() > self.cfg.max_sweep_hosts {
                    net::Ipv4Cidr { addr: c.addr, prefix: 24 }
                } else {
                    *c
                };
                targets.extend(cidr.hosts().filter(|ip| *ip != c.addr));
            }
        }
        info!(hosts = targets.len(), "LAN sweep");
        self.tasks.spawn(async move {
            if let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await {
                probe::nudge(&sock, targets, Duration::from_millis(4)).await;
            }
        });
    }

    async fn refresh_interfaces(&mut self, ctx: &SourceCtx) {
        self.ifaces = tokio::task::spawn_blocking(net::interfaces).await.unwrap_or_default();
        if self.ifaces.is_empty() {
            if !self.blocked {
                warn!("no IPv4 network connection");
                ctx.report(SourceState::Unavailable("no IPv4 network connection".into()));
                self.blocked = true;
            }
            return;
        }
        if self.blocked {
            ctx.report(SourceState::Running);
            self.blocked = false;
        }

        // This machine, keyed by the default interface; every local address is listed.
        let own_ips: Vec<IpAddr> = self.ifaces.iter().flat_map(|i| i.ipv4.iter().map(|c| IpAddr::V4(c.addr))).collect();
        let default = self.ifaces[0].clone();
        if let Some(primary) = default.ipv4.first().map(|c| c.addr) {
            let hostname = self.hostname.clone();
            let h = self.host(primary);
            let fresh = LanInfo {
                mac: default.mac,
                ips: own_ips,
                hostname,
                interface: Some(default.name.clone()),
                is_self: true,
                ..Default::default()
            };
            if h.info.mac != fresh.mac || !h.info.is_self {
                h.dirty = true;
            }
            h.info.merge(&fresh);
            h.confirm();
        }
        for iface in &self.ifaces.clone() {
            let Some(gw) = iface.gateway else { continue };
            let h = self.host(gw);
            if !h.info.is_gateway || (iface.gateway_mac.is_some() && h.info.mac != iface.gateway_mac) {
                h.dirty = true;
            }
            h.info.merge(&LanInfo {
                mac: iface.gateway_mac,
                interface: Some(iface.name.clone()),
                is_gateway: true,
                ..Default::default()
            });
            h.confirm(); // we route through it
        }
    }

    async fn poll_neighbors(&mut self) {
        let Ok(Ok(list)) = tokio::task::spawn_blocking(net::neighbors).await else { return };
        let mut verify = Vec::new();
        for n in list {
            let Some(iface) = self.ifaces.iter().find(|i| i.index == n.interface_index) else { continue };
            let Some(cidr) = iface.ipv4.iter().find(|c| c.contains(n.ip)) else { continue };
            if n.ip == cidr.addr || n.ip == cidr.broadcast() {
                continue;
            }
            let name = iface.name.clone();
            let h = self.host(n.ip);
            if h.info.mac != Some(n.mac) {
                h.info.mac = Some(n.mac);
                h.dirty = true;
            }
            if h.info.interface.is_none() {
                h.info.interface = Some(name);
            }
            match n.state {
                NeighborState::Reachable | NeighborState::Permanent => h.confirm(),
                // A stale entry may be hours old. Check it is still there before showing it.
                NeighborState::Stale if h.seen_ms.is_none() && h.nudged_at.is_none() => {
                    h.nudged_at = Some(Instant::now());
                    verify.push(n.ip);
                }
                NeighborState::Stale => {}
            }
        }
        if !verify.is_empty() {
            if let Some(sock) = &self.nudger {
                probe::nudge(sock, verify, Duration::ZERO).await;
            }
            self.next_neighbors = self.next_neighbors.min(Instant::now() + Duration::from_millis(1500));
        }
    }

    fn apply(&mut self, f: Finding) {
        let (ip, update) = match f {
            Finding::Mdns { ip, hostname, services, instances } => {
                (ip, LanInfo { hostname, services, mdns: instances, ..Default::default() })
            }
            Finding::Upnp { ip, info } => (ip, LanInfo { upnp: Some(info), ..Default::default() }),
            Finding::Netbios { ip, info } => (ip, LanInfo { netbios: Some(info), ..Default::default() }),
            Finding::Ports { ip, open, banners } => (ip, LanInfo { open_ports: open, banners, ..Default::default() }),
        };
        // Our own replies (mDNS from this machine) belong on the self host.
        let target = if self.is_own(ip) {
            self.hosts.iter().find(|(_, h)| h.info.is_self).map(|(k, _)| *k).unwrap_or(ip)
        } else {
            ip
        };
        let h = self.host(target);
        let before = h.info.clone();
        h.info.merge(&update);
        if h.info != before {
            h.dirty = true;
        }
        h.confirm();
    }

    /// Emit changed hosts. Returns false once the engine has gone away.
    async fn flush(&mut self, ctx: &SourceCtx) -> bool {
        let now = now_millis();
        let locals: Vec<_> = self.ifaces.iter().flat_map(|i| i.ipv4.clone()).collect();
        let mut out = Vec::new();
        for (ip, h) in &mut self.hosts {
            let Some(seen) = h.seen_ms else { continue };
            if !h.dirty {
                continue;
            }
            let local = locals.iter().any(|c| c.contains(*ip));
            let key = match h.info.mac {
                Some(mac) => DeviceKey::LanMac(mac),
                // Give ARP a moment before settling for an IP-keyed device.
                None if !local || h.first_seen.elapsed() > Duration::from_secs(3) => DeviceKey::LanIp(IpAddr::V4(*ip)),
                None => continue,
            };
            h.dirty = false;
            h.emitted_ms = now;
            let mut evidence = lan_evidence(&h.info, &self.oui);
            if h.info.is_self {
                evidence.extend(self.self_evidence.iter().cloned());
            }
            out.push(Observation {
                key,
                at: seen,
                rssi: None,
                details: DeviceDetails::Lan(h.info.clone()),
                evidence,
                links: Vec::new(),
            });
        }
        for obs in out {
            if ctx.sink.send(obs).await.is_err() {
                return false;
            }
        }
        // Forget hosts unconfirmed for 15 minutes (the store has dropped them by then).
        self.hosts.retain(|_, h| {
            h.info.is_self || h.info.is_gateway || h.seen_ms.is_none_or(|s| now.saturating_sub(s) < 900_000)
        });
        self.hosts.retain(|_, h| h.seen_ms.is_some() || h.first_seen.elapsed() < Duration::from_secs(120));
        true
    }
}
