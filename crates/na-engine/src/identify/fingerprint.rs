//! Passive OS fingerprints from packet capture: what a DHCP client asks for, and
//! how a TCP stack opens connections. The rule tables are our own, built from
//! each OS's documented or long-observed defaults; they give an OS family, not a
//! version.

use na_model::{ClaimKind, DhcpFingerprint, Evidence, EvidenceSource as Src, TcpSignature};

/// DHCP option 60 (vendor class) prefixes.
const VENDOR_CLASS: &[(&str, &str, f32)] = &[
    ("MSFT 5.0", "Windows", 0.6),
    ("android-dhcp", "Android", 0.7),
    ("udhcp", "Linux", 0.45), // BusyBox: routers, cameras, other embedded Linux
    ("dhcpcd", "Linux", 0.5),
];

/// Option 55 (parameter request list) layouts, matched as prefixes.
const PRL: &[(&[u8], &str, f32)] = &[
    (&[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252], "Windows", 0.55),
    (&[1, 121, 3, 6, 15, 108, 114, 119, 252, 95, 44, 46], "iOS", 0.45), // iOS/macOS 14+
    (&[1, 121, 3, 6, 15, 119, 252, 95, 44, 46], "macOS", 0.4),
    (&[1, 3, 6, 15, 26, 28, 51, 58, 59, 43], "Android", 0.5),
    (&[1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42], "Linux", 0.45), // ISC dhclient
];

pub fn dhcp_evidence(fp: &DhcpFingerprint) -> Vec<Evidence> {
    let mut out = Vec::new();
    if let Some(vc) = &fp.vendor_class
        && let Some((prefix, os, conf)) = VENDOR_CLASS.iter().find(|(p, ..)| vc.starts_with(p))
    {
        out.push(Evidence::new(Src::Dhcp, ClaimKind::Os, *os, *conf, format!("DHCP vendor class \"{vc}\" ({prefix})")));
        if *os == "Android" {
            out.push(Evidence::new(Src::Dhcp, ClaimKind::DeviceType, "Phone", 0.3, format!("DHCP vendor class \"{vc}\"")));
        }
    }
    if let Some((_, os, conf)) = PRL.iter().find(|(p, ..)| fp.prl.starts_with(p)) {
        out.push(Evidence::new(Src::Dhcp, ClaimKind::Os, *os, *conf, format!("DHCP request list {}", fp.prl_text())));
    }
    if let Some(h) = &fp.hostname {
        out.push(Evidence::new(Src::Dhcp, ClaimKind::Name, h, 0.55, "DHCP host name (option 12)"));
    }
    out
}

pub fn tcp_evidence(sig: &TcpSignature) -> Vec<Evidence> {
    let detail = format!(
        "TCP SYN: TTL {} (initial {}), window {}, options {}",
        sig.ttl, sig.initial_ttl, sig.window, sig.layout
    );
    let guess = match (sig.initial_ttl, sig.layout.as_str()) {
        (128, "M,N,W,N,N,S") => Some(("Windows", 0.5)),
        (64, "M,N,W,N,N,T,S,E") | (64, "M,N,W,N,N,T,S") => Some(("macOS", 0.4)), // also iOS
        (64, "M,S,T,N,W") => Some(("Linux", 0.4)),                               // also Android
        _ => None,
    };
    guess.map_or_else(Vec::new, |(os, conf)| vec![Evidence::new(Src::TcpFingerprint, ClaimKind::Os, os, conf, detail)])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(ev: &[Evidence]) -> Vec<&str> {
        ev.iter().filter(|e| e.kind == ClaimKind::Os).map(|e| e.value.as_str()).collect()
    }

    #[test]
    fn dhcp_clients() {
        let win = DhcpFingerprint {
            vendor_class: Some("MSFT 5.0".into()),
            prl: vec![1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
            hostname: Some("DESKTOP-1".into()),
        };
        let ev = dhcp_evidence(&win);
        assert_eq!(os(&ev), vec!["Windows", "Windows"]);
        assert!(ev.iter().any(|e| e.kind == ClaimKind::Name && e.value == "DESKTOP-1"));

        let android = DhcpFingerprint { vendor_class: Some("android-dhcp-14".into()), ..Default::default() };
        assert_eq!(os(&dhcp_evidence(&android)), vec!["Android"]);

        let unknown = DhcpFingerprint { prl: vec![1, 3, 6], ..Default::default() };
        assert!(dhcp_evidence(&unknown).is_empty());
    }

    #[test]
    fn tcp_stacks() {
        let sig = |ttl: u8, layout: &str| TcpSignature {
            ttl,
            initial_ttl: [32u8, 64, 128, 255].into_iter().find(|&t| ttl <= t).unwrap(),
            window: 65535,
            layout: layout.into(),
            ..Default::default()
        };
        assert_eq!(os(&tcp_evidence(&sig(127, "M,N,W,N,N,S"))), vec!["Windows"]);
        assert_eq!(os(&tcp_evidence(&sig(63, "M,S,T,N,W"))), vec!["Linux"]);
        assert_eq!(os(&tcp_evidence(&sig(64, "M,N,W,N,N,T,S,E"))), vec!["macOS"]);
        assert!(tcp_evidence(&sig(255, "M")).is_empty());
    }
}
