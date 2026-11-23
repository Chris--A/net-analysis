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
    confirm_active(&root.ctx().clone(), ui_state, link);
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
            let (probe_color, probe_tip) = if ui_state.active_probes {
                (WARN, "Active LAN probing is ON: subnet sweep + port/banner checks. Click to turn off.")
            } else {
                (WEAK, "Active LAN probing is off. Discovery is passive: ARP table, mDNS, SSDP, NetBIOS.")
            };
            let probe = ui
                .add(egui::Button::new(RichText::new("Active probes").color(probe_color)).selected(ui_state.active_probes))
                .on_hover_text(probe_tip);
            if probe.clicked() {
                if ui_state.active_probes {
                    ui_state.active_probes = false;
                    if let Some(link) = link {
                        link.send(EngineCommand::SetActiveProbes { enabled: false });
                    }
                } else {
                    ui_state.confirm_active = true;
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
                    .on_hover_text("The built-in simulator is feeding the engine instead of the real scanners.");
                }
                if ui_state.paused {
                    ui.label(RichText::new("PAUSED").strong().color(WARN));
                }
                let flagged = reg.devices.values().filter(|d| d.risk >= 0.3).count();
                if flagged > 0 {
                    ui.label(
                        RichText::new(format!(" ⚠ {flagged} flagged "))
                            .strong()
                            .color(egui::Color32::BLACK)
                            .background_color(DANGER),
                    )
                    .on_hover_text("Devices the guard considers risky. They pulse red and wear a halo in the 3D views.");
                }
                if let Some(fps) = fps {
                    ui.label(RichText::new(format!("{fps:.0} fps")).small().color(WEAK));
                }
                // Right-to-left layout: this reads AP, LAN, BLE, Classic on screen.
                for kind in [DeviceKind::BtClassic, DeviceKind::Ble, DeviceKind::LanHost, DeviceKind::AccessPoint] {
                    let n = reg.devices.values().filter(|d| d.kind == kind).count();
                    if n == 0 && kind == DeviceKind::BtClassic {
                        continue;
                    }
                    ui.label(RichText::new(format!("{} {n}", kind.label())).color(color32(kind_color(kind))));
                }
            });
        });
    });
}

/// Confirmation before any traffic is sent to other people's devices.
fn confirm_active(ctx: &egui::Context, ui_state: &mut UiState, link: Option<&EngineLink>) {
    if !ui_state.confirm_active {
        return;
    }
    let modal = egui::Modal::new(egui::Id::new("confirm_active_probes")).show(ctx, |ui| {
        ui.set_max_width(440.0);
        ui.heading("Enable active LAN probing?");
        ui.add_space(6.0);
        ui.label(
            "This sends a packet to every address on your local subnets, then checks a short list of \
             TCP ports (SSH, HTTP, SMB, printing, casting, RTSP, MQTT…) on each device it finds and \
             reads their service banners.",
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Only enable it on networks you own or are authorized to test. Not on hotel, café, \
                 work or school networks.",
            )
            .color(WARN),
        );
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button(RichText::new("Enable").color(WARN)).clicked() {
                ui_state.active_probes = true;
                ui_state.confirm_active = false;
                if let Some(link) = link {
                    link.send(EngineCommand::SetActiveProbes { enabled: true });
                }
            }
            if ui.button("Cancel").clicked() {
                ui_state.confirm_active = false;
            }
        });
    });
    if modal.should_close() {
        ui_state.confirm_active = false;
    }
}
