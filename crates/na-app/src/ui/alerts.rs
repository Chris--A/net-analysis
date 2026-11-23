//! Bottom panel: guard status, the alert timeline, the alert list and the event log.

use bevy_egui::egui::{self, Color32, FontId, RichText, Sense, Stroke, vec2};
use na_model::{Alert, EngineCommand, GuardStatus, KarmaOutcome, KarmaStatus, Severity, now_millis};

use super::ago;
use super::theme::{ACCENT, DANGER, OK, WARN, WEAK};
use crate::bridge::{EngineLink, LogKind, Registry};
use crate::picking::Selection;

/// The timeline covers this much history, newest on the right.
const TIMELINE_MS: u64 = 30 * 60_000;

pub fn show(root: &mut egui::Ui, reg: &Registry, sel: &mut Selection, link: Option<&EngineLink>) {
    egui::Panel::bottom("events")
        .resizable(true)
        .default_size(200.0)
        .min_size(110.0)
        .show(root, |ui| {
            guard_bar(ui, reg.guard.as_ref(), link);
            timeline(ui, &reg.alerts, sel);
            ui.columns(2, |cols| {
                alerts(&mut cols[0], reg, sel);
                log(&mut cols[1], reg);
            });
        });
}

pub fn severity_color(s: Severity) -> Color32 {
    match s {
        Severity::Critical => DANGER,
        Severity::High => Color32::from_rgb(255, 130, 50),
        Severity::Medium => WARN,
        Severity::Low | Severity::Info => WEAK,
    }
}

fn guard_bar(ui: &mut egui::Ui, guard: Option<&GuardStatus>, link: Option<&EngineLink>) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Guard").strong().color(ACCENT));
        let Some(g) = guard else {
            ui.label(RichText::new("starting…").color(WEAK));
            return;
        };
        let learned = g.networks.iter().filter(|n| !n.known.is_empty()).count();
        let mut tip = String::from(
            "Trusted networks come from your saved Wi-Fi profiles, networks you connect to with a password, \
             and ones you trust in the inspector.",
        );
        if let Some(msg) = &g.profile_import {
            tip.push_str("\n\n");
            tip.push_str(msg);
        }
        ui.label(format!("{} trusted networks, {learned} with known access points", g.networks.len()))
            .on_hover_text(tip);
        ui.separator();
        karma_label(ui, &g.karma);
        let run = ui
            .add_enabled(!g.karma.running, egui::Button::new("Run Karma test").small())
            .on_hover_text(
                "Sends a probe for a random network name that doesn't exist. Normal access points ignore it; \
                 Karma/MANA rogue access points answer for any name.",
            );
        if run.clicked()
            && let Some(link) = link
        {
            link.send(EngineCommand::RunKarmaTest);
        }
    });
}

fn karma_label(ui: &mut egui::Ui, k: &KarmaStatus) {
    let now = now_millis();
    let (text, color, tip) = match (&k.last, k.running) {
        (_, true) => ("Karma test: listening…".to_owned(), ACCENT, String::new()),
        (Some(r), _) => match &r.outcome {
            KarmaOutcome::NoResponse => (
                format!("Karma test: clean ({})", ago(now, r.at)),
                OK,
                format!("Probed for \"{}\". No access point answered.", r.decoy),
            ),
            KarmaOutcome::Responders(v) => (
                format!("Karma test: {} rogue AP{} answered ({})", v.len(), if v.len() == 1 { "" } else { "s" }, ago(now, r.at)),
                DANGER,
                format!(
                    "Probed for \"{}\", which doesn't exist. Answered by: {}",
                    r.decoy,
                    v.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                ),
            ),
            KarmaOutcome::Failed(why) => ("Karma test: couldn't run".to_owned(), WARN, why.clone()),
        },
        (None, false) => ("Karma test: not run yet".to_owned(), WEAK, String::new()),
    };
    let resp = ui.label(RichText::new(text).color(color));
    if !tip.is_empty() {
        resp.on_hover_text(tip);
    }
}

/// Recent alerts as dots on a time axis; click a dot to select its device. The
/// span grows (5 min → 1 h) to fit the oldest alert, so close alerts stay apart.
fn timeline(ui: &mut egui::Ui, alerts: &[Alert], sel: &mut Selection) {
    let now = now_millis();
    let oldest = alerts.iter().map(|a| now.saturating_sub(a.at)).filter(|&age| age <= TIMELINE_MS).max().unwrap_or(0);
    let span_min = [5u64, 15, 30, 60].into_iter().find(|m| m * 60_000 >= oldest + oldest / 10).unwrap_or(60);
    let span = span_min * 60_000;

    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 24.0), Sense::hover());
    let painter = ui.painter_at(rect);
    let axis_y = rect.top() + 8.0;
    painter.line_segment([egui::pos2(rect.left(), axis_y), egui::pos2(rect.right(), axis_y)], Stroke::new(1.0, WEAK.gamma_multiply(0.5)));
    for i in 0..=5u64 {
        let x = rect.right() - rect.width() * i as f32 / 5.0;
        painter.line_segment([egui::pos2(x, axis_y - 3.0), egui::pos2(x, axis_y + 3.0)], Stroke::new(1.0, WEAK.gamma_multiply(0.6)));
        let secs = span / 1000 * i / 5;
        let label = match secs {
            0 => "now".to_owned(),
            s if s % 60 == 0 => format!("-{}m", s / 60),
            s => format!("-{}m{:02}s", s / 60, s % 60),
        };
        let align = match i {
            0 => egui::Align2::RIGHT_TOP,
            5 => egui::Align2::LEFT_TOP,
            _ => egui::Align2::CENTER_TOP,
        };
        painter.text(egui::pos2(x, axis_y + 4.0), align, label, FontId::proportional(9.5), WEAK);
    }
    for a in alerts {
        let age = now.saturating_sub(a.at);
        if age > span {
            continue;
        }
        let x = rect.right() - rect.width() * age as f32 / span as f32;
        let selected = a.devices.first().is_some_and(|d| sel.selected == Some(*d));
        let center = egui::pos2(x.clamp(rect.left() + 5.0, rect.right() - 5.0), axis_y);
        let dot = egui::Rect::from_center_size(center, vec2(12.0, 12.0));
        let resp = ui.interact(dot, ui.id().with(("alert-dot", a.id)), Sense::click());
        let r = if selected || resp.hovered() { 5.5 } else { 4.0 };
        painter.circle_filled(center, r, severity_color(a.severity));
        if selected {
            painter.circle_stroke(center, r + 2.5, Stroke::new(1.5, Color32::WHITE));
        }
        if resp.clicked() {
            sel.selected = a.devices.first().copied();
        }
        resp.on_hover_text(format!("[{}] {}  ({})", a.severity.label(), a.title, ago(now, a.at)));
    }
}

fn alerts(ui: &mut egui::Ui, reg: &Registry, sel: &mut Selection) {
    ui.label(RichText::new(format!("Alerts ({})", reg.alerts.len())).strong().color(ACCENT));
    egui::ScrollArea::vertical().id_salt("alerts").auto_shrink(false).show(ui, |ui| {
        if reg.alerts.is_empty() {
            ui.label(
                RichText::new(
                    "No alerts. The guard checks every access point against your trusted networks (evil twins, \
                     security downgrades, missing 802.11w) and runs a periodic Karma test.",
                )
                .color(WEAK),
            );
            return;
        }
        let now = now_millis();
        for a in reg.alerts.iter().rev() {
            let selected = a.devices.first().is_some_and(|d| sel.selected == Some(*d));
            let text = format!("{:>7}  [{}] {}", ago(now, a.at), a.severity.label(), a.title);
            let resp = ui.selectable_label(selected, RichText::new(text).color(severity_color(a.severity)));
            if resp.clicked() {
                sel.selected = if selected { None } else { a.devices.first().copied() };
            }
            if selected {
                ui.indent(("alert", a.id), |ui| {
                    ui.label(RichText::new(&a.explanation).size(12.0));
                    for f in &a.findings {
                        ui.label(RichText::new(format!("• {f}")).size(11.5).color(WEAK));
                    }
                });
            } else {
                resp.on_hover_text(&a.explanation);
            }
        }
    });
}

fn log(ui: &mut egui::Ui, reg: &Registry) {
    ui.label(RichText::new("Event log").strong().color(ACCENT));
    egui::ScrollArea::vertical()
        .id_salt("log")
        .auto_shrink(false)
        .stick_to_bottom(true)
        .show(ui, |ui| {
            let now = now_millis();
            for line in &reg.log {
                let color = match line.kind {
                    LogKind::Added => OK,
                    LogKind::Removed => WEAK,
                    LogKind::Source => ACCENT,
                    LogKind::Alert => DANGER,
                };
                let text = format!("{:>8}  {}", ago(now, line.at), line.text);
                ui.label(RichText::new(text).monospace().size(11.0).color(color));
            }
        });
}
