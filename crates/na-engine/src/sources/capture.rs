//! Packet capture source (Npcap / libpcap) on the default interface.
//!
//! It only reads what reaches this machine anyway: broadcast ARP and DHCP, and
//! TCP connection attempts to it. That yields
//! - passive discovery (every ARP sender) and OS fingerprints (DHCP requests, TCP SYNs);
//! - the guard's LAN checks: who claims which address, and which DHCP servers answer.
//!
//! The only packet it sends is the rogue-DHCP check's Discover, when the guard asks.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use na_model::{DeviceDetails, DeviceKey, DhcpServerSeen, LanInfo, MacAddr, Observation, SourceKind, SourceState, now_millis};
use na_platform::capture::{Capture, CaptureError, device_for_interface};
use na_platform::net::{self, LocalInterface};
use tracing::{debug, info, warn};

use super::{BoxFuture, Source, SourceCtx, SourceDeps};
use crate::guard::{GuardSignal, NetEvent};
use crate::identify::lan_evidence;
use crate::parse::{dhcp, packet};

/// ARP, DHCP, and TCP SYNs without ACK.
const FILTER: &str = "arp or (udp and (port 67 or port 68)) or (tcp and (tcp[13] & 0x12 = 0x02))";

#[derive(Clone, Debug)]
pub struct CaptureConfig {
    /// How often to re-read the interface (address, gateway, DNS) and report it.
    pub context_interval: Duration,
    /// How often accumulated host details are pushed to the store.
    pub flush_interval: Duration,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self { context_interval: Duration::from_secs(30), flush_interval: Duration::from_secs(2) }
    }
}

pub struct CaptureSource {
    cfg: CaptureConfig,
    deps: SourceDeps,
}

impl CaptureSource {
    pub fn new(cfg: CaptureConfig, deps: SourceDeps) -> Self {
        Self { cfg, deps }
    }
}

impl Source for CaptureSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Capture
    }

    fn run(self: Box<Self>, ctx: SourceCtx) -> BoxFuture<anyhow::Result<()>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || capture_loop(&self.cfg, &self.deps, &ctx))
                .await
                .map_err(|e| anyhow!("capture thread panicked: {e}"))?
        })
    }
}

fn capture_loop(cfg: &CaptureConfig, deps: &SourceDeps, ctx: &SourceCtx) -> anyhow::Result<()> {
    let mut last_problem = String::new();
    let mut report = |state: SourceState| {
        let key = format!("{state:?}");
        if key != last_problem {
            ctx.report(state);
            last_problem = key;
        }
    };
    while !ctx.cancel.is_cancelled() {
        let Some(iface) = net::interfaces().into_iter().next() else {
            report(SourceState::Unavailable("no IPv4 network connection".into()));
            ctx.sleep_blocking(Duration::from_secs(5));
            continue;
        };
        let opened = device_for_interface(&iface.id).and_then(|dev| Capture::open(&dev, FILTER, 250).map(|c| (dev, c)));
        let (dev, cap) = match opened {
            Ok(x) => x,
            Err(e @ (CaptureError::NotInstalled(_) | CaptureError::PermissionDenied(_) | CaptureError::NoDevice(_))) => {
                report(SourceState::Unavailable(e.to_string()));
                ctx.sleep_blocking(Duration::from_secs(30));
                continue;
            }
            Err(e) => {
                warn!(error = %e, "capture open failed");
                report(SourceState::Unavailable(e.to_string()));
                ctx.sleep_blocking(Duration::from_secs(10));
                continue;
            }
        };
        info!(interface = %iface.name, device = %dev, "capturing");
        report(SourceState::Running);
        let mut session = Session::new(iface, cap, cfg, deps, ctx);
        if session.run().is_err() {
            return Ok(()); // engine shutting down
        }
        ctx.sleep_blocking(Duration::from_secs(2));
    }
    Ok(())
}

/// One open capture on one interface.
struct Session<'a> {
    iface: LocalInterface,
    cap: Capture,
    cfg: &'a CaptureConfig,
    deps: &'a SourceDeps,
    ctx: &'a SourceCtx,
    /// Host details gathered since the last flush.
    pending: HashMap<MacAddr, LanInfo>,
    /// Transaction ids of our own Discovers, so we don't fingerprint ourselves.
    own_xids: HashSet<u32>,
}

/// The engine went away.
struct Closed;

impl<'a> Session<'a> {
    fn new(iface: LocalInterface, cap: Capture, cfg: &'a CaptureConfig, deps: &'a SourceDeps, ctx: &'a SourceCtx) -> Self {
        Self { iface, cap, cfg, deps, ctx, pending: HashMap::new(), own_xids: HashSet::new() }
    }

    fn signal(&self, e: NetEvent) {
        let _ = self.deps.guard.send(GuardSignal::Net(e));
    }

    fn context(&self) {
        self.signal(NetEvent::Context {
            own_mac: self.iface.mac,
            own_ip: self.iface.ipv4.first().map(|c| c.addr),
            gateway: self.iface.gateway,
            dns: self.iface.dns_servers.clone(),
        });
    }

    fn run(&mut self) -> Result<(), Closed> {
        self.context();
        let mut last_context = Instant::now();
        let mut last_flush = Instant::now();
        while !self.ctx.cancel.is_cancelled() {
            if last_context.elapsed() >= self.cfg.context_interval {
                last_context = Instant::now();
                match net::interfaces().into_iter().next() {
                    Some(i) if i.id == self.iface.id => {
                        self.iface = i;
                        self.context();
                    }
                    _ => return Ok(()), // default route moved: reopen on the new interface
                }
            }
            while let Ok(req) = self.deps.dhcp_probe.try_recv() {
                if !req.is_stale(now_millis()) {
                    self.send_discover(req.xid);
                }
            }
            match self.cap.next_packet() {
                Ok(Some(p)) => {
                    // Receive time, not Npcap's packet clock: that one can drift from the
                    // system clock, and guard timings compare against now_millis().
                    let (ts, data) = (now_millis(), p.data.to_vec());
                    self.packet(&data, ts);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(error = %e, "capture read failed; reopening");
                    return Ok(());
                }
            }
            if last_flush.elapsed() >= self.cfg.flush_interval {
                last_flush = Instant::now();
                self.flush()?;
            }
        }
        Ok(())
    }

    /// The frame comes from our own MAC (an AP drops anything else), but the DHCP
    /// client address is a fresh, locally-administered one: servers (phone
    /// hotspots, for one) ignore a repeat Discover from a client that already
    /// holds a lease, while every server answers a new client.
    fn send_discover(&mut self, xid: u32) {
        let result = match self.iface.mac {
            Some(mac) => {
                let x = xid.to_be_bytes();
                let client = MacAddr([0x02, 0x4E, x[0], x[1], x[2], x[3]]);
                let frame = packet::udp_frame(
                    mac,
                    MacAddr([0xFF; 6]),
                    (Ipv4Addr::UNSPECIFIED, 68),
                    (Ipv4Addr::BROADCAST, 67),
                    &dhcp::discover(client, xid),
                );
                self.cap.send(&frame).map_err(|e| e.to_string())
            }
            None => Err("the interface has no MAC address".into()),
        };
        debug!(xid, ?result, "DHCP check Discover");
        self.own_xids.insert(xid);
        self.signal(NetEvent::DhcpProbeSent { xid, result });
    }

    fn on_subnet(&self, ip: Ipv4Addr) -> bool {
        self.iface.ipv4.iter().any(|c| c.contains(ip))
    }

    fn host(&mut self, mac: MacAddr) -> &mut LanInfo {
        let interface = Some(self.iface.name.clone());
        self.pending.entry(mac).or_insert_with(|| LanInfo { mac: Some(mac), interface, ..Default::default() })
    }

    fn add_ip(&mut self, mac: MacAddr, ip: Ipv4Addr) {
        if self.on_subnet(ip) {
            let h = self.host(mac);
            if !h.ips.contains(&IpAddr::V4(ip)) {
                h.ips.push(IpAddr::V4(ip));
            }
        }
    }

    fn packet(&mut self, frame: &[u8], ts: u64) {
        let Some(eth) = packet::ethernet(frame) else { return };
        match eth.ethertype {
            packet::ETHERTYPE_ARP => {
                let Some(arp) = packet::arp(eth.payload) else { return };
                if arp.is_probe() {
                    return;
                }
                self.signal(NetEvent::Arp { ip: arp.sender_ip, mac: arp.sender_mac, at: ts });
                self.add_ip(arp.sender_mac, arp.sender_ip);
            }
            packet::ETHERTYPE_IPV4 => {
                let Some(ip) = packet::ipv4(eth.payload) else { return };
                match ip.proto {
                    packet::PROTO_UDP => self.udp(&eth, &ip, ts),
                    packet::PROTO_TCP if Some(eth.src) != self.iface.mac && self.on_subnet(ip.src) => {
                        // Only hosts on this subnet: a routed SYN carries the router's MAC.
                        if let Some(sig) = packet::tcp_syn(&ip) {
                            self.add_ip(eth.src, ip.src);
                            self.host(eth.src).tcp = Some(sig);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn udp(&mut self, eth: &packet::Ethernet<'_>, ip: &packet::Ipv4<'_>, ts: u64) {
        let Some(u) = packet::udp(ip.payload) else { return };
        if !matches!((u.src_port, u.dst_port), (67, 68) | (68, 67)) {
            return;
        }
        let Some(msg) = dhcp::parse(u.payload) else {
            debug!(src = %eth.src, len = u.payload.len(), "unparsed DHCP packet");
            return;
        };
        debug!(src = %eth.src, op = msg.op, kind = ?msg.msg_type(), xid = msg.xid, "DHCP");
        match (msg.op, msg.msg_type()) {
            (1, _) => {
                if self.own_xids.contains(&msg.xid) {
                    return;
                }
                if let Some(fp) = msg.fingerprint() {
                    self.host(msg.chaddr).dhcp = Some(fp);
                }
            }
            (2, Some(dhcp::OFFER | dhcp::ACK)) => {
                let seen = DhcpServerSeen {
                    server: msg.server_id().unwrap_or(ip.src),
                    mac: eth.src,
                    routers: msg.routers(),
                    dns: msg.dns(),
                };
                self.add_ip(eth.src, ip.src);
                self.signal(NetEvent::DhcpServer { seen, at: ts });
            }
            _ => {}
        }
    }

    fn flush(&mut self) -> Result<(), Closed> {
        let now = now_millis();
        for (mac, info) in self.pending.drain() {
            let evidence = lan_evidence(&info, &self.deps.oui);
            let obs = Observation {
                key: DeviceKey::LanMac(mac),
                at: now,
                rssi: None,
                details: DeviceDetails::Lan(info),
                evidence,
                links: Vec::new(),
            };
            self.ctx.sink.blocking_send(obs).map_err(|_| Closed)?;
        }
        Ok(())
    }
}
