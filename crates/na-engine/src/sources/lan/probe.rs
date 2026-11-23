//! Unicast helpers: HTTP GET, ARP "nudges", and the opt-in active probes
//! (subnet sweep, TCP port check, banner grab).
//!
//! A nudge is a 1-byte UDP datagram to the discard port. Sending it makes the
//! OS resolve the address with ARP, and the reply lands in the neighbor table
//! we already read. This works the same on every OS, with no raw sockets or admin rights.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use na_model::Banner;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::Finding;
use crate::parse::upnp::{HttpResponse, parse_http};

const HTTP_MAX: usize = 96 * 1024;

/// Minimal HTTP/1.1 GET with `Connection: close`. None on any failure.
pub(super) async fn http_get(addr: SocketAddr, host: &str, path: &str, limit: Duration) -> Option<HttpResponse> {
    let work = async {
        let mut s = TcpStream::connect(addr).await.ok()?;
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}:{}\r\nUser-Agent: net-analysis/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            addr.port()
        );
        s.write_all(req.as_bytes()).await.ok()?;
        let mut buf = Vec::with_capacity(8192);
        let mut chunk = [0u8; 8192];
        loop {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() >= HTTP_MAX {
                        break;
                    }
                }
            }
        }
        parse_http(&buf)
    };
    timeout(limit, work).await.ok().flatten()
}

/// Ask the OS to ARP-resolve each address (see module docs).
pub(super) async fn nudge(sock: &UdpSocket, ips: impl IntoIterator<Item = Ipv4Addr>, gap: Duration) {
    for ip in ips {
        let _ = sock.send_to(&[0], (ip, 9)).await;
        if !gap.is_zero() {
            tokio::time::sleep(gap).await;
        }
    }
}

/// Ports checked by the active probe. A small, fixed list of identifying services, not a port scan.
pub const PROBE_PORTS: &[u16] = &[
    21, 22, 23, 53, 80, 139, 443, 445, 548, 554, 631, 1883, 3389, 5000, 7000, 8008, 8009, 8080, 8123,
    8443, 9100, 32400, 62078,
];

/// Check [`PROBE_PORTS`] on one host and grab banners from the open ones.
pub(super) async fn probe_host(ip: Ipv4Addr, tx: mpsc::Sender<Finding>) {
    let mut open = Vec::new();
    for chunk in PROBE_PORTS.chunks(8) {
        let mut set = tokio::task::JoinSet::new();
        for &port in chunk {
            set.spawn(async move {
                let ok = timeout(Duration::from_millis(700), TcpStream::connect((ip, port))).await;
                matches!(ok, Ok(Ok(_))).then_some(port)
            });
        }
        while let Some(r) = set.join_next().await {
            if let Ok(Some(p)) = r {
                open.push(p);
            }
        }
    }
    open.sort_unstable();

    let mut banners = Vec::new();
    for &port in &open {
        let text = match port {
            21..=23 => greeting(ip, port).await, // FTP, SSH, Telnet
            80 | 5000 | 8080 | 8123 | 32400 => http_banner(ip, port).await,
            _ => None,
        };
        if let Some(text) = text {
            banners.push(Banner { port, text });
        }
    }
    let _ = tx.send(Finding::Ports { ip, open, banners }).await;
}

/// First line a service sends on connect (SSH, FTP, Telnet).
async fn greeting(ip: Ipv4Addr, port: u16) -> Option<String> {
    let work = async {
        let mut s = TcpStream::connect((ip, port)).await.ok()?;
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf).await.ok()?;
        let text = String::from_utf8_lossy(&buf[..n]);
        let line = text.lines().next()?.trim();
        (!line.is_empty()).then(|| line.chars().filter(|c| !c.is_control()).collect())
    };
    timeout(Duration::from_millis(1500), work).await.ok().flatten()
}

/// "Server: nginx · title: Router Login".
async fn http_banner(ip: Ipv4Addr, port: u16) -> Option<String> {
    let resp = http_get(SocketAddr::from((ip, port)), &ip.to_string(), "/", Duration::from_secs(2)).await?;
    let parts: Vec<String> = [
        resp.header("server").map(|s| format!("Server: {s}")),
        resp.title().map(|t| format!("title: {t}")),
    ]
    .into_iter()
    .flatten()
    .collect();
    (!parts.is_empty()).then(|| parts.join(" · "))
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    /// Serve one connection: read the request, write `reply`.
    async fn serve_once(reply: &'static [u8], read_first: bool) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            if read_first {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
            }
            s.write_all(reply).await.unwrap();
        });
        port
    }

    #[tokio::test]
    async fn http_get_dechunks_and_reads_title() {
        let reply = b"HTTP/1.1 200 OK\r\nServer: test/1.0\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n<title>\r\nD\r\nHello</title>\r\n0\r\n\r\n";
        let port = serve_once(reply, true).await;
        let r = http_get(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), "127.0.0.1", "/", Duration::from_secs(2))
            .await
            .expect("response");
        assert_eq!(r.status, 200);
        assert_eq!(r.header("server"), Some("test/1.0"));
        assert_eq!(r.title().as_deref(), Some("Hello"));
    }

    #[tokio::test]
    async fn greeting_reads_the_first_line() {
        let port = serve_once(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\nmore\r\n", false).await;
        assert_eq!(greeting(Ipv4Addr::LOCALHOST, port).await.as_deref(), Some("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"));
    }

    #[tokio::test]
    async fn closed_port_is_none() {
        let port = {
            let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            l.local_addr().unwrap().port()
        }; // dropped: nothing listens there now
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        assert!(http_get(addr, "127.0.0.1", "/", Duration::from_millis(500)).await.is_none());
    }
}
