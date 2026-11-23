//! Standard discovery protocols: mDNS / DNS-SD, SSDP + UPnP descriptions, NetBIOS.
//!
//! Each round is a short-lived task that reports [`Finding`]s. mDNS uses one-shot
//! queries from an ephemeral port (RFC 6762 §5.1), so responders reply by
//! unicast and we never compete with the OS for port 5353.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use na_model::{MdnsService, NetbiosInfo, UpnpInfo};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout_at};
use tracing::debug;

use super::Finding;
use super::probe::http_get;
use crate::parse::dns::{self, Name, RData};
use crate::parse::{netbios, upnp};

const MDNS_GROUP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);
const SSDP_GROUP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);

/// Service types queried directly every round, on top of the `_services` enumeration
/// (some responders don't answer the enumeration).
const COMMON_TYPES: &[&str] = &[
    "_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp",
    "_pdl-datastream._tcp", "_uscan._tcp", "_scanner._tcp", "_hap._tcp", "_hue._tcp", "_sonos._tcp",
    "_spotify-connect._tcp", "_smb._tcp", "_afpovertcp._tcp", "_device-info._tcp", "_companion-link._tcp",
    "_apple-mobdev2._tcp", "_sleep-proxy._udp", "_matter._tcp", "_matterc._udp", "_meshcop._udp",
    "_esphomelib._tcp", "_home-assistant._tcp", "_workstation._tcp", "_ssh._tcp", "_http._tcp",
    "_amzn-wplay._tcp", "_androidtvremote2._tcp", "_octoprint._tcp", "_plexmediasvr._tcp", "_rfb._tcp",
];

pub(super) fn multicast_socket(local: Ipv4Addr, ttl: u32) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_multicast_if_v4(&local)?;
    s.set_multicast_ttl_v4(ttl)?;
    s.bind(&SocketAddrV4::new(local, 0).into())?;
    s.set_nonblocking(true)?;
    UdpSocket::from_std(s.into())
}

/// Receive datagrams until `deadline`. Windows reports ICMP "port unreachable"
/// as a recv error on UDP sockets; those are skipped.
async fn recv_until(sock: &UdpSocket, deadline: Instant, mut f: impl FnMut(&[u8], SocketAddr)) {
    let mut buf = vec![0u8; 9000];
    loop {
        match timeout_at(deadline, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => f(&buf[..n], from),
            Ok(Err(_)) => continue,
            Err(_) => return,
        }
    }
}

// ---------------------------------------------------------------------------
// mDNS
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MdnsHost {
    hostname: Option<String>,
    services: BTreeSet<String>,
    instances: BTreeMap<(String, String), MdnsService>,
}

pub(super) async fn mdns_round(local: Ipv4Addr, tx: mpsc::Sender<Finding>) {
    let sock = match multicast_socket(local, 255) {
        Ok(s) => s,
        Err(e) => {
            debug!(%local, error = %e, "mDNS socket failed");
            return;
        }
    };
    let mut hosts: HashMap<Ipv4Addr, MdnsHost> = HashMap::new();
    let mut enumerated: BTreeSet<String> = BTreeSet::new();

    let mut names: Vec<String> = vec!["_services._dns-sd._udp.local".into()];
    names.extend(COMMON_TYPES.iter().map(|t| format!("{t}.local")));
    send_queries(&sock, &names).await;
    recv_until(&sock, Instant::now() + Duration::from_millis(2500), |pkt, from| {
        absorb(pkt, from, &mut hosts, &mut enumerated);
    })
    .await;

    // Second round: types only learned from the enumeration.
    let extra: Vec<String> = enumerated
        .iter()
        .filter(|t| !COMMON_TYPES.contains(&t.as_str()))
        .take(24)
        .map(|t| format!("{t}.local"))
        .collect();
    if !extra.is_empty() {
        send_queries(&sock, &extra).await;
        recv_until(&sock, Instant::now() + Duration::from_millis(1500), |pkt, from| {
            absorb(pkt, from, &mut hosts, &mut enumerated);
        })
        .await;
    }

    for (ip, h) in hosts {
        let finding = Finding::Mdns {
            ip,
            hostname: h.hostname,
            services: h.services.into_iter().collect(),
            instances: h.instances.into_values().collect(),
        };
        if tx.send(finding).await.is_err() {
            return;
        }
    }
}

async fn send_queries(sock: &UdpSocket, names: &[String]) {
    for chunk in names.chunks(12) {
        let qs: Vec<(&str, u16)> = chunk.iter().map(|n| (n.as_str(), dns::TYPE_PTR)).collect();
        let _ = sock.send_to(&dns::query(&qs, true), MDNS_GROUP).await;
    }
}

/// Fold one response into the per-responder tables. Records are credited to
/// the responder's address. Hosts only answer for their own services, except
/// sleep proxies, whose A records name another address.
fn absorb(pkt: &[u8], from: SocketAddr, hosts: &mut HashMap<Ipv4Addr, MdnsHost>, enumerated: &mut BTreeSet<String>) {
    let IpAddr::V4(ip) = from.ip() else { return };
    let Some(records) = dns::parse(pkt) else { return };
    let h = hosts.entry(ip).or_default();
    let instance = |h: &mut MdnsHost, name: &Name| {
        name.service_instance().map(|(inst, svc)| {
            h.services.insert(svc.clone());
            h.instances.entry((inst.clone(), svc.clone())).or_insert_with(|| MdnsService {
                instance: inst,
                service: svc,
                ..Default::default()
            })
        })
        .is_some()
    };
    for r in &records {
        match &r.data {
            RData::Ptr(target) if r.name.eq_ignore_case("_services._dns-sd._udp.local") => {
                if let Some(t) = target.service_type() {
                    enumerated.insert(t.clone());
                    h.services.insert(t);
                }
            }
            RData::Ptr(target) if r.name.service_type().is_some() => {
                instance(h, target);
            }
            RData::Srv { port, target } => {
                if instance(h, &r.name)
                    && let Some((inst, svc)) = r.name.service_instance()
                    && let Some(m) = h.instances.get_mut(&(inst, svc))
                {
                    m.port = Some(*port);
                }
                if let Some(host) = target.host() {
                    h.hostname.get_or_insert_with(|| host.to_owned());
                }
            }
            RData::Txt(entries) => {
                if instance(h, &r.name)
                    && let Some((inst, svc)) = r.name.service_instance()
                    && let Some(m) = h.instances.get_mut(&(inst, svc))
                {
                    m.txt = entries.iter().filter(|e| e.contains('=')).take(32).cloned().collect();
                }
            }
            RData::A(addr) if *addr == ip => {
                if let Some(host) = r.name.host() {
                    h.hostname = Some(host.to_owned());
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// SSDP / UPnP
// ---------------------------------------------------------------------------

pub(super) async fn ssdp_round(local: Ipv4Addr, tx: mpsc::Sender<Finding>) {
    let sock = match multicast_socket(local, 2) {
        Ok(s) => s,
        Err(e) => {
            debug!(%local, error = %e, "SSDP socket failed");
            return;
        }
    };
    let search = upnp::m_search("ssdp:all", 2);
    for _ in 0..2 {
        let _ = sock.send_to(search.as_bytes(), SSDP_GROUP).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    let mut found: HashMap<Ipv4Addr, (UpnpInfo, BTreeSet<String>)> = HashMap::new();
    recv_until(&sock, Instant::now() + Duration::from_secs(3), |pkt, from| {
        let IpAddr::V4(ip) = from.ip() else { return };
        let Some(reply) = std::str::from_utf8(pkt).ok().and_then(upnp::parse_ssdp) else { return };
        let (info, locations) = found.entry(ip).or_default();
        if info.server.is_none() {
            info.server = reply.server;
        }
        if let Some(st) = reply.st
            && !info.advertised.contains(&st)
            && info.advertised.len() < 24
        {
            info.advertised.push(st);
        }
        if let Some(loc) = reply.location {
            locations.insert(loc);
        }
    })
    .await;

    let mut fetches = tokio::task::JoinSet::new();
    for (ip, (mut info, locations)) in found {
        let tx = tx.clone();
        fetches.spawn(async move {
            // Only fetch descriptions the responder serves itself, never third-party URLs.
            for url in locations.iter().take(2) {
                let Some((host, port, path)) = upnp::split_http_url(url) else { continue };
                if host.parse::<Ipv4Addr>().ok() != Some(ip) {
                    continue;
                }
                let addr = SocketAddr::from((ip, port));
                if let Some(resp) = http_get(addr, &host, &path, Duration::from_millis(2500)).await
                    && resp.status == 200
                {
                    let d = upnp::parse_description(&String::from_utf8_lossy(&resp.body));
                    if d.friendly_name.is_some() || d.manufacturer.is_some() {
                        info = UpnpInfo { server: info.server, advertised: info.advertised, ..d };
                        break;
                    }
                }
            }
            let _ = tx.send(Finding::Upnp { ip, info }).await;
        });
    }
    while fetches.join_next().await.is_some() {}
}

// ---------------------------------------------------------------------------
// NetBIOS
// ---------------------------------------------------------------------------

pub(super) async fn netbios_query(ip: Ipv4Addr, tx: mpsc::Sender<Finding>) {
    let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else { return };
    let id = (u32::from(ip) & 0xFFFF) as u16;
    if sock.send_to(&netbios::nbstat_query(id), (ip, 137)).await.is_err() {
        return;
    }
    let mut result: Option<NetbiosInfo> = None;
    recv_until(&sock, Instant::now() + Duration::from_millis(1500), |pkt, from| {
        if result.is_none()
            && from.ip() == IpAddr::V4(ip)
            && let Some(r) = netbios::parse_nbstat(pkt)
        {
            result = Some(r.summary());
        }
    })
    .await;
    if let Some(info) = result.filter(|i| i.name.is_some()) {
        let _ = tx.send(Finding::Netbios { ip, info }).await;
    }
}
