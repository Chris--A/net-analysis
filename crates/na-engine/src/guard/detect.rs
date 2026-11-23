//! The access-point detectors. Each looks at one AP in the context of its
//! network's baseline and its same-name peers, and returns plain-language findings.
//!
//! Some findings are only *corroborating* (no severity): a randomized BSSID or a
//! freshly booted radio is common on legitimate networks, so these add weight and
//! context to a real finding but never raise an alert on their own.

use na_model::{AlertKind, ApInfo, NetworkBaseline, Pmf, SecurityClass, Severity};

#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub kind: AlertKind,
    /// None: corroborating only.
    pub severity: Option<Severity>,
    /// Contribution to the risk score (noisy-OR).
    pub weight: f32,
    pub text: String,
}

impl Finding {
    pub(crate) fn new(kind: AlertKind, severity: Severity, weight: f32, text: String) -> Self {
        Self { kind, severity: Some(severity), weight, text }
    }

    fn corroborating(kind: AlertKind, weight: f32, text: String) -> Self {
        Self { kind, severity: None, weight, text }
    }
}

pub struct Context<'a> {
    pub baseline: Option<&'a NetworkBaseline>,
    /// Other access points visible right now with the same SSID.
    pub peers: &'a [&'a ApInfo],
    /// Random network names this BSSID answered for during Karma tests.
    pub karma_decoys: &'a [String],
    /// Distinct non-empty SSIDs heard from this BSSID recently, the current one included.
    pub ssids: &'a [String],
}

pub fn assess(ap: &ApInfo, cx: &Context) -> Vec<Finding> {
    let mut out = Vec::new();
    karma(ap, cx, &mut out);
    multi_ssid(ap, cx, &mut out);
    if !ap.ssid.is_empty() {
        match cx.baseline.filter(|b| b.expected_class().is_some()) {
            Some(b) => {
                downgrade(ap, b, &mut out);
                pmf(ap, b, &mut out);
                unknown_bssid(ap, b, cx, &mut out);
            }
            None => mixed_security(ap, cx, &mut out),
        }
    }
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.weight.total_cmp(&a.weight)));
    out
}

/// The finding that decides the alert, if any finding is alert-worthy.
pub fn primary(findings: &[Finding]) -> Option<&Finding> {
    findings
        .iter()
        .filter(|f| f.severity.is_some())
        .max_by(|a, b| a.severity.cmp(&b.severity).then(a.weight.total_cmp(&b.weight)))
}

/// Noisy-OR of the weights. Corroborating findings alone score zero.
pub fn risk(findings: &[Finding]) -> f32 {
    if primary(findings).is_none() {
        return 0.0;
    }
    1.0 - findings.iter().map(|f| 1.0 - f.weight.clamp(0.0, 1.0)).product::<f32>()
}

/// 5. Answered a directed probe for a network that doesn't exist.
fn karma(_ap: &ApInfo, cx: &Context, out: &mut Vec<Finding>) {
    if let Some(decoy) = cx.karma_decoys.first() {
        out.push(Finding::new(
            AlertKind::KarmaAp,
            Severity::Critical,
            0.95,
            format!(
                "Answered a probe for \"{decoy}\", a random network name that doesn't exist. Only \
                 Karma/MANA-style rogue access points do that."
            ),
        ));
    }
}

/// 6. One radio announcing several network names.
fn multi_ssid(ap: &ApInfo, cx: &Context, out: &mut Vec<Finding>) {
    let n = cx.ssids.len();
    if n < 2 {
        return;
    }
    let names: Vec<String> = cx.ssids.iter().take(6).map(|s| format!("\"{s}\"")).collect();
    let (severity, weight) = if n >= 3 { (Severity::High, 0.6) } else { (Severity::Medium, 0.35) };
    out.push(Finding::new(
        AlertKind::MultiSsid,
        severity,
        weight,
        format!(
            "{} has announced {n} different network names recently ({}). Legitimate access points use a \
             separate BSSID for each network.",
            ap.bssid,
            names.join(", ")
        ),
    ));
}

/// 2. Weaker security than the network normally has.
fn downgrade(ap: &ApInfo, b: &NetworkBaseline, out: &mut Vec<Finding>) {
    let Some(expected) = b.expected_class() else { return };
    let class = SecurityClass::of(&ap.security);
    let was = b.find(ap.bssid).map(|k| k.security.label());
    let clone_note = match &was {
        Some(prev) if *prev != ap.security.label() => {
            format!(" This exact BSSID used to advertise {prev}: the router was reconfigured, or a clone is copying its address.")
        }
        _ => String::new(),
    };
    // OWE transition mode pairs an open BSS with a hidden OWE one, legitimately.
    let owe_transition = expected == SecurityClass::Owe && class == SecurityClass::Open;
    if class < expected && !owe_transition {
        let source = if b.known.is_empty() { "your saved Wi-Fi profile" } else { "its known access points" };
        let consequence = if class.authenticated() {
            ""
        } else {
            " Anyone can join it, and its operator can watch or alter the traffic of devices that do."
        };
        out.push(Finding::new(
            AlertKind::SecurityDowngrade,
            Severity::Critical,
            if class.authenticated() { 0.45 } else { 0.6 },
            format!(
                "\"{}\" is normally {}, according to {source}, but this access point is {}.{consequence}{clone_note}",
                ap.ssid,
                expected.label(),
                ap.security.label()
            ),
        ));
        return;
    }
    // Same class, weaker key management: e.g. WPA2-PSK offered on a WPA3-only network.
    if class == expected
        && let Some(floor) = b.known.iter().map(|k| k.security.floor_strength()).min()
        && ap.security.floor_strength() < floor
    {
        let known: Vec<String> = b.known.iter().map(|k| k.security.label()).collect();
        out.push(Finding::new(
            AlertKind::SecurityDowngrade,
            Severity::Critical,
            0.45,
            format!(
                "Known access points of \"{}\" use {}; this one also accepts {}, which is weaker (WPA2 \
                 handshakes can be cracked offline).{clone_note}",
                ap.ssid,
                dedup(known).join(" / "),
                ap.security.label()
            ),
        ));
    }
}

/// 7. Management-frame protection missing where the known APs have it.
fn pmf(ap: &ApInfo, b: &NetworkBaseline, out: &mut Vec<Finding>) {
    let Some(min_known) = b.known.iter().map(|k| k.security.pmf).min() else { return };
    if min_known >= Pmf::Capable && ap.security.pmf == Pmf::Disabled && !ap.security.is_open() {
        out.push(Finding::new(
            AlertKind::PmfMissing,
            Severity::Medium,
            0.2,
            format!(
                "Known access points of \"{}\" protect management frames (802.11w); this one doesn't, so \
                 devices can be forcibly disconnected and pushed towards it.",
                ap.ssid
            ),
        ));
    }
}

/// 1, 3, 4. A BSSID the network hasn't been seen with before, and how unlike the known ones it is.
fn unknown_bssid(ap: &ApInfo, b: &NetworkBaseline, cx: &Context, out: &mut Vec<Finding>) {
    if b.known.is_empty() || b.find(ap.bssid).is_some() {
        return;
    }
    let ssid = &ap.ssid;
    let flip = |m: na_model::MacAddr| {
        let mut x = m;
        x.0[0] ^= 0x02;
        x
    };
    let mimic = b.known.iter().find(|k| flip(k.bssid) == ap.bssid);
    let same_vendor = b.known.iter().any(|k| (k.bssid.0[0] | 2) == (ap.bssid.0[0] | 2) && k.bssid.0[1..3] == ap.bssid.0[1..3]);
    // Bands carry different capability elements, so compare within a band only.
    let same_band: Vec<_> = b.known.iter().filter(|k| k.band == ap.band).collect();
    let fp_differs = !same_band.is_empty() && !same_band.iter().any(|k| k.fingerprints.contains(&ap.ie_fingerprint));

    if let Some(k) = mimic {
        out.push(Finding::new(
            AlertKind::EvilTwin,
            Severity::High,
            0.35,
            format!(
                "Its BSSID is {} (a known access point of \"{ssid}\") with the locally-administered bit \
                 flipped, a common way to clone an address without colliding with the original.",
                k.bssid
            ),
        ));
    } else if !same_vendor {
        let known: Vec<String> = dedup(b.known.iter().map(|k| oui_text(k.bssid)).collect());
        out.push(Finding::new(
            AlertKind::EvilTwin,
            Severity::High,
            0.3,
            format!(
                "Its vendor prefix {} matches none of the known access points of \"{ssid}\" ({}).",
                oui_text(ap.bssid),
                known.join(", ")
            ),
        ));
    }
    if fp_differs {
        // On its own (same vendor, related hardware) this is often a different mesh model.
        let severity = if mimic.is_some() || !same_vendor { Severity::High } else { Severity::Medium };
        out.push(Finding::new(
            AlertKind::EvilTwin,
            severity,
            0.25,
            format!(
                "Its beacon capabilities (IE fingerprint) differ from every known {} access point of \
                 \"{ssid}\": different hardware or software is answering for this network.",
                ap.band.label()
            ),
        ));
    }
    if mimic.is_none() && ap.bssid.is_locally_administered() && b.known.iter().all(|k| !k.bssid.is_locally_administered()) {
        out.push(Finding::corroborating(
            AlertKind::RandomizedBssid,
            0.15,
            "Its BSSID is locally administered (not vendor-assigned), unlike the known access points.".into(),
        ));
    }
    let known_uptime = cx
        .peers
        .iter()
        .filter(|p| b.find(p.bssid).is_some())
        .filter_map(|p| p.tsf_uptime_secs)
        .min();
    if let (Some(up), Some(known)) = (ap.tsf_uptime_secs, known_uptime)
        && up < 3_600
        && known > 86_400
    {
        out.push(Finding::corroborating(
            AlertKind::TsfAnomaly,
            0.1,
            format!(
                "Its radio came up {} ago, while the known access points have been up for {}.",
                duration(up),
                duration(known)
            ),
        ));
    }
}

/// No baseline: an unprotected AP sharing a name with protected ones.
fn mixed_security(ap: &ApInfo, cx: &Context, out: &mut Vec<Finding>) {
    let class = SecurityClass::of(&ap.security);
    if class.authenticated() {
        return;
    }
    let Some(protected) = cx.peers.iter().find(|p| SecurityClass::of(&p.security).authenticated()) else {
        return;
    };
    out.push(Finding::new(
        AlertKind::EvilTwin,
        Severity::Medium,
        0.3,
        format!(
            "Other access points named \"{}\" require a password ({}), but this one is {}. Rogue access \
             points often copy a network's name without its password so devices join them.",
            ap.ssid,
            protected.security.label(),
            ap.security.label()
        ),
    ));
}

/// "40s", "12m", "3h 20m", "12 days".
fn duration(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3_600 => format!("{}m", secs / 60),
        3_600..86_400 => format!("{}h {}m", secs / 3_600, secs % 3_600 / 60),
        _ => format!("{} days", secs / 86_400),
    }
}

fn oui_text(m: na_model::MacAddr) -> String {
    let o = m.oui();
    format!("{:02X}:{:02X}:{:02X}", o[0], o[1], o[2])
}

fn dedup(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use na_model::{Akm, Band, Security, TrustSource};

    use super::super::baseline::Baselines;
    use super::super::testutil::{ap, wpa2, wpa3};
    use super::*;

    fn cx<'a>(b: Option<&'a NetworkBaseline>, peers: &'a [&'a ApInfo]) -> Context<'a> {
        Context { baseline: b, peers, karma_decoys: &[], ssids: &[] }
    }

    fn kinds(f: &[Finding]) -> Vec<(AlertKind, Option<Severity>)> {
        f.iter().map(|f| (f.kind, f.severity)).collect()
    }

    /// Home network learned from a connected AP on 5 GHz.
    fn home() -> (Baselines, ApInfo) {
        let mut b = Baselines::in_memory();
        let mut real = ap("Home", "3C:37:86:12:34:56", wpa2(), 0xAAAA);
        real.tsf_uptime_secs = Some(12 * 86_400);
        b.learn(&real, TrustSource::Connected, 0);
        (b, real)
    }

    #[test]
    fn open_twin_with_flipped_bssid() {
        let (b, real) = home();
        let mut twin = ap("Home", "3E:37:86:12:34:56", Security::open(), 0xBBBB);
        twin.tsf_uptime_secs = Some(40);
        let peers = [&real];
        let f = assess(&twin, &cx(b.get("Home"), &peers));
        assert_eq!(
            kinds(&f),
            vec![
                (AlertKind::SecurityDowngrade, Some(Severity::Critical)),
                (AlertKind::EvilTwin, Some(Severity::High)), // mimic
                (AlertKind::EvilTwin, Some(Severity::High)), // fingerprint
                (AlertKind::TsfAnomaly, None),
            ]
        );
        assert_eq!(primary(&f).unwrap().kind, AlertKind::SecurityDowngrade);
        let r = risk(&f);
        assert!(r > 0.8 && r < 0.9, "{r}");
        assert!(f[0].text.contains("Anyone can join it"));
    }

    #[test]
    fn mesh_sibling_is_quiet_but_foreign_vendor_is_not() {
        let (b, real) = home();
        let peers = [&real];
        let satellite = ap("Home", "3C:37:86:99:00:01", wpa2(), 0xAAAA);
        assert!(assess(&satellite, &cx(b.get("Home"), &peers)).is_empty());

        // Same vendor, different hardware on the same band: worth a look, not an alarm.
        let other_model = ap("Home", "3C:37:86:99:00:02", wpa2(), 0xCCCC);
        assert_eq!(kinds(&assess(&other_model, &cx(b.get("Home"), &peers))), vec![(AlertKind::EvilTwin, Some(Severity::Medium))]);

        // 2.4 GHz has no known AP to compare capabilities with.
        let mut radio24 = ap("Home", "3C:37:86:12:34:57", wpa2(), 0xDDDD);
        radio24.band = Band::G2_4;
        assert!(assess(&radio24, &cx(b.get("Home"), &peers)).is_empty());

        let foreign = ap("Home", "00:11:22:33:44:55", wpa2(), 0xAAAA);
        let f = assess(&foreign, &cx(b.get("Home"), &peers));
        assert_eq!(kinds(&f), vec![(AlertKind::EvilTwin, Some(Severity::High))]);
        assert!(f[0].text.contains("00:11:22") && f[0].text.contains("3C:37:86"));
    }

    #[test]
    fn wpa3_network_offered_as_wpa2() {
        let mut b = Baselines::in_memory();
        b.learn(&ap("Lab", "3C:37:86:00:00:01", wpa3(), 1), TrustSource::User, 0);
        let weaker = ap("Lab", "3C:37:86:00:00:01", wpa2(), 1);
        let f = assess(&weaker, &cx(b.get("Lab"), &[]));
        assert_eq!(kinds(&f), vec![(AlertKind::SecurityDowngrade, Some(Severity::Critical))]);
        assert!(f[0].text.contains("used to advertise WPA3-SAE"), "{}", f[0].text);
    }

    #[test]
    fn pmf_dropped() {
        let mut b = Baselines::in_memory();
        b.learn(&ap("Lab", "3C:37:86:00:00:01", wpa2(), 1), TrustSource::User, 0);
        let mut no_pmf = wpa2();
        no_pmf.pmf = Pmf::Disabled;
        let f = assess(&ap("Lab", "3C:37:86:00:00:02", no_pmf, 1), &cx(b.get("Lab"), &[]));
        assert_eq!(kinds(&f), vec![(AlertKind::PmfMissing, Some(Severity::Medium))]);
    }

    #[test]
    fn saved_profile_alone_catches_an_open_copy() {
        let mut b = Baselines::in_memory();
        let saved = na_platform::wifi::SavedNetwork {
            profile: "Home".into(),
            ssid: "Home".into(),
            auth: "WPA2PSK".into(),
            encryption: "AES".into(),
            transition: false,
            auto_connect: true,
            hidden: false,
        };
        b.import_saved(&[saved], 0);
        let f = assess(&ap("Home", "02:00:00:00:00:01", Security::open(), 1), &cx(b.get("Home"), &[]));
        assert_eq!(kinds(&f), vec![(AlertKind::SecurityDowngrade, Some(Severity::Critical))]);
        assert!(f[0].text.contains("according to your saved Wi-Fi profile"), "{}", f[0].text);
        // No known APs yet, so nothing to compare BSSIDs against.
        assert!(assess(&ap("Home", "02:00:00:00:00:02", wpa2(), 1), &cx(b.get("Home"), &[])).is_empty());
    }

    #[test]
    fn without_a_baseline_only_mixed_security_counts() {
        let secured = ap("Cafe", "3C:37:86:00:00:01", wpa2(), 1);
        let open = ap("Cafe", "02:00:00:00:00:01", Security::open(), 2);
        let peers = [&secured];
        let f = assess(&open, &cx(None, &peers));
        assert_eq!(kinds(&f), vec![(AlertKind::EvilTwin, Some(Severity::Medium))]);
        // Open everywhere (a public hotspot) is fine.
        let open2 = ap("Cafe", "02:00:00:00:00:02", Security::open(), 2);
        let open_peers = [&open2];
        assert!(assess(&open, &cx(None, &open_peers)).is_empty());
        // OWE transition: the profile expects OWE, the visible BSS is open.
        let owe = Security { akms: vec![Akm::Owe], ..Default::default() };
        let mut b = Baselines::in_memory();
        b.learn(&ap("Cafe", "3C:37:86:00:00:05", owe, 3), TrustSource::User, 0);
        let near = ap("Cafe", "3C:37:86:00:00:06", Security::open(), 3);
        assert!(assess(&near, &cx(b.get("Cafe"), &[])).is_empty());
    }

    #[test]
    fn karma_and_multi_ssid() {
        let rogue = ap("Free WiFi", "02:13:37:00:00:01", Security::open(), 9);
        let decoys = ["Lounge-3F9A1C".to_string()];
        let ssids = ["Free WiFi".to_string(), "Hotel Guest".to_string(), "Lounge-3F9A1C".to_string()];
        let f = assess(&rogue, &Context { baseline: None, peers: &[], karma_decoys: &decoys, ssids: &ssids });
        assert_eq!(
            kinds(&f),
            vec![(AlertKind::KarmaAp, Some(Severity::Critical)), (AlertKind::MultiSsid, Some(Severity::High))]
        );
        assert!(risk(&f) > 0.95);
        let two = &ssids[..2];
        let f = assess(&rogue, &Context { baseline: None, peers: &[], karma_decoys: &[], ssids: two });
        assert_eq!(kinds(&f), vec![(AlertKind::MultiSsid, Some(Severity::Medium))]);
    }

    #[test]
    fn corroborating_findings_alone_score_zero() {
        let f = vec![Finding::corroborating(AlertKind::TsfAnomaly, 0.1, String::new())];
        assert_eq!(risk(&f), 0.0);
        assert!(primary(&f).is_none());
    }
}
