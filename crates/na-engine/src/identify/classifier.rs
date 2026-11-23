use std::collections::HashMap;

use na_model::{Claim, ClaimKind, Evidence, EvidenceSource, Identity};

/// Combine evidence into an identity.
///
/// For each claim kind, evidence is grouped by (case-insensitive) value and
/// confidences are combined with noisy-OR: `1 - Π(1 - cᵢ)`. Independent weak
/// sources that agree therefore reinforce each other. The highest combined value
/// wins. Ties go to the value with more distinct sources.
pub fn classify(evidence: &[Evidence]) -> Identity {
    let mut identity = Identity::default();
    for kind in ClaimKind::ALL {
        identity.set(kind, best_claim(evidence, kind));
    }
    identity
}

fn best_claim(evidence: &[Evidence], kind: ClaimKind) -> Option<Claim> {
    struct Acc<'a> {
        display: &'a str,
        disbelief: f32,
        sources: Vec<EvidenceSource>,
    }

    let mut groups: HashMap<String, Acc<'_>> = HashMap::new();
    for e in evidence.iter().filter(|e| e.kind == kind && !e.value.trim().is_empty()) {
        let acc = groups.entry(e.value.trim().to_lowercase()).or_insert(Acc {
            display: e.value.trim(),
            disbelief: 1.0,
            sources: Vec::new(),
        });
        acc.disbelief *= 1.0 - e.confidence.clamp(0.0, 1.0);
        if !acc.sources.contains(&e.source) {
            acc.sources.push(e.source);
        }
    }

    groups
        .into_values()
        .map(|a| Claim {
            value: a.display.to_owned(),
            confidence: 1.0 - a.disbelief,
            sources: a.sources,
        })
        .max_by(|a, b| {
            a.confidence
                .total_cmp(&b.confidence)
                .then(a.sources.len().cmp(&b.sources.len()))
                // Deterministic final tie-break.
                .then_with(|| b.value.cmp(&a.value))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(source: EvidenceSource, kind: ClaimKind, value: &str, c: f32) -> Evidence {
        Evidence::new(source, kind, value, c, "")
    }

    #[test]
    fn agreeing_sources_reinforce() {
        let id = classify(&[
            ev(EvidenceSource::Oui, ClaimKind::Vendor, "Synology", 0.5),
            ev(EvidenceSource::Ssdp, ClaimKind::Vendor, "synology", 0.5),
        ]);
        let v = id.vendor.unwrap();
        assert_eq!(v.value, "Synology");
        assert!((v.confidence - 0.75).abs() < 1e-6);
        assert_eq!(v.sources.len(), 2);
    }

    #[test]
    fn strongest_value_wins_conflicts() {
        let id = classify(&[
            ev(EvidenceSource::Oui, ClaimKind::Vendor, "Espressif", 0.5),
            ev(EvidenceSource::Mdns, ClaimKind::Vendor, "Philips", 0.4),
            ev(EvidenceSource::Ssdp, ClaimKind::Vendor, "Philips", 0.4),
        ]);
        // 1 - 0.6*0.6 = 0.64 > 0.5
        assert_eq!(id.vendor.unwrap().value, "Philips");
    }

    #[test]
    fn empty_and_unrelated_kinds_are_none() {
        let id = classify(&[ev(EvidenceSource::Oui, ClaimKind::Vendor, "  ", 0.9)]);
        assert!(id.vendor.is_none());
        assert!(id.model.is_none());
    }
}
