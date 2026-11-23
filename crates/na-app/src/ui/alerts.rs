use bevy_egui::egui::{self, RichText};
use na_model::{Severity, now_millis};

use super::ago;
use super::theme::{ACCENT, DANGER, OK, WARN, WEAK};
use crate::bridge::{LogKind, Registry};
use crate::picking::Selection;

pub fn show(root: &mut egui::Ui, reg: &Registry, sel: &mut Selection) {
    egui::Panel::bottom("events")
        .resizable(true)
        .default_size(150.0)
        .min_size(80.0)
        .show(root, |ui| {
            ui.columns(2, |cols| {
                alerts(&mut cols[0], reg, sel);
                log(&mut cols[1], reg);
            });
        });
}

fn severity_color(s: Severity) -> egui::Color32 {
    match s {
        Severity::Critical => DANGER,
        Severity::High => egui::Color32::from_rgb(255, 130, 50),
        Severity::Medium => WARN,
        Severity::Low | Severity::Info => WEAK,
    }
}

fn alerts(ui: &mut egui::Ui, reg: &Registry, sel: &mut Selection) {
    ui.label(RichText::new(format!("Alerts ({})", reg.alerts.len())).strong().color(ACCENT));
    egui::ScrollArea::vertical().id_salt("alerts").auto_shrink(false).show(ui, |ui| {
        if reg.alerts.is_empty() {
            ui.label(
                RichText::new(
                    "No alerts. Threat detectors (evil twin, Karma, ARP spoofing, rogue DHCP…) arrive in milestone M4.",
                )
                .color(WEAK),
            );
            return;
        }
        for a in reg.alerts.iter().rev() {
            let resp = ui.selectable_label(
                false,
                RichText::new(format!("[{}] {}", a.severity.label(), a.title)).color(severity_color(a.severity)),
            );
            if resp.clicked() {
                sel.selected = a.devices.first().copied();
            }
            resp.on_hover_text(&a.explanation);
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
