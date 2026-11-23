use bevy::prelude::*;
use bevy_egui::egui::{self, RichText};
use na_model::{DeviceKind, EngineCommand, SourceKind, SourceState};

use super::theme::{ACCENT, DANGER, OK, WARN, WEAK};
use super::{UiState, color32};
use crate::bridge::{EngineLink, Registry, describe_state};
use crate::scene::kind_color;
use crate::views::ViewMode;

pub fn show(
    root: &mut egui::Ui,
    view: ViewMode,
    next_view: &mut NextState<ViewMode>,
    ui_state: &mut UiState,
    reg: &Registry,
    link: Option<&EngineLink>,
    fps: Option<f64>,
) {
    egui::Panel::top("topbar").exact_size(40.0).show(root, |ui| {
        ui.horizontal_centered(|ui| {
            ui.label(RichText::new("NET·ANALYSIS").strong().size(17.0).color(ACCENT));
            ui.separator();

            for mode in ViewMode::ALL {
                if ui
                    .selectable_label(view == mode, RichText::new(mode.label()).size(14.0))
                    .clicked()
                {
                    next_view.set(mode);
                }
            }
            ui.separator();

            for kind in SourceKind::ALL {
                let state = reg.sources.get(&kind);
                let (dot, tip) = match state {
                    Some(SourceState::Running) => (OK, "running — click to stop".to_owned()),
                    Some(SourceState::Failed(_)) => (DANGER, describe_state(state.unwrap())),
                    Some(SourceState::Unavailable(_)) => (WARN, describe_state(state.unwrap())),
                    Some(SourceState::Stopped) | None => (WEAK, "stopped — click to start".to_owned()),
                };
                let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                ui.painter().circle_filled(dot_rect.center(), 4.0, dot);
                let text = RichText::new(kind.label()).color(dot);
                let resp = ui.add(egui::Button::new(text).frame(false)).on_hover_text(tip);
                if resp.clicked()
                    && let Some(link) = link
                {
                    let running = matches!(state, Some(SourceState::Running));
                    link.send(EngineCommand::SetSourceEnabled { source: kind, enabled: !running });
                }
            }
            ui.separator();

            let pause = if ui_state.paused { "▶ Resume" } else { "⏸ Pause" };
            if ui.button(pause).clicked() {
                ui_state.paused = !ui_state.paused;
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if reg.sim_running() {
                    ui.label(
                        RichText::new(" SIMULATED DATA ")
                            .strong()
                            .color(egui::Color32::BLACK)
                            .background_color(WARN),
                    )
                    .on_hover_text("The built-in simulator is feeding the engine. Real scanners arrive in M1–M5.");
                }
                if ui_state.paused {
                    ui.label(RichText::new("PAUSED").strong().color(WARN));
                }
                if let Some(fps) = fps {
                    ui.label(RichText::new(format!("{fps:.0} fps")).small().color(WEAK));
                }
                for kind in [DeviceKind::Ble, DeviceKind::LanHost, DeviceKind::AccessPoint] {
                    let n = reg.devices.values().filter(|d| d.kind == kind).count();
                    ui.label(RichText::new(format!("{} {n}", kind.label())).color(color32(kind_color(kind))));
                }
            });
        });
    });
}
