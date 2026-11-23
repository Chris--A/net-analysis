use bevy_egui::egui::{self, RichText};
use na_model::{Device, DeviceKind};

use super::theme::{DANGER, WEAK};
use super::{UiState, color32};
use crate::bridge::Registry;
use crate::picking::Selection;
use crate::scene::kind_color;

const FILTER_KINDS: [DeviceKind; 4] = [DeviceKind::AccessPoint, DeviceKind::Ble, DeviceKind::BtClassic, DeviceKind::LanHost];
const LIST_ORDER: [DeviceKind; 5] = [
    DeviceKind::AccessPoint,
    DeviceKind::LanHost,
    DeviceKind::Ble,
    DeviceKind::WifiClient,
    DeviceKind::BtClassic,
];

pub fn show(root: &mut egui::Ui, ui_state: &mut UiState, reg: &Registry, sel: &mut Selection) {
    egui::Panel::left("devices")
        .resizable(true)
        .default_size(280.0)
        .min_size(200.0)
        .show(root, |ui| {
            ui.add_space(4.0);
            ui.heading("Devices");
            ui.add(
                egui::TextEdit::singleline(&mut ui_state.search)
                    .hint_text("Search name, MAC, vendor, SSID…")
                    .desired_width(f32::INFINITY),
            );
            ui.horizontal_wrapped(|ui| {
                for kind in FILTER_KINDS {
                    let mut on = ui_state.shown_kinds.contains(&kind);
                    let text = RichText::new(kind.label()).color(color32(kind_color(kind)));
                    if ui.toggle_value(&mut on, text).changed() {
                        if on {
                            ui_state.shown_kinds.insert(kind);
                        } else {
                            ui_state.shown_kinds.remove(&kind);
                        }
                    }
                }
            });
            ui.separator();

            egui::ScrollArea::vertical()
                .id_salt("device_list")
                .auto_shrink(false)
                .show(ui, |ui| {
                    for kind in LIST_ORDER {
                        let mut list: Vec<&Device> = reg
                            .devices
                            .values()
                            .filter(|d| d.kind == kind && ui_state.shows(d))
                            .collect();
                        if list.is_empty() {
                            continue;
                        }
                        list.sort_by(|a, b| {
                            b.rssi
                                .unwrap_or(i16::MIN)
                                .cmp(&a.rssi.unwrap_or(i16::MIN))
                                .then_with(|| a.display_name().cmp(&b.display_name()))
                        });
                        let title = RichText::new(format!("{} ({})", kind.label(), list.len()))
                            .color(color32(kind_color(kind)))
                            .strong();
                        egui::CollapsingHeader::new(title)
                            .id_salt(kind.label())
                            .default_open(true)
                            .show(ui, |ui| {
                                for d in list {
                                    row(ui, d, sel);
                                }
                            });
                    }
                });
        });
}

fn row(ui: &mut egui::Ui, d: &Device, sel: &mut Selection) {
    let selected = sel.selected == Some(d.id);
    let risky = d.risk > 0.3;
    let mut name = RichText::new(d.display_name());
    if risky {
        name = RichText::new(format!("! {}", d.display_name())).color(DANGER).strong();
    }
    ui.horizontal(|ui| {
        let resp = ui.selectable_label(selected, name);
        if resp.clicked() {
            sel.selected = Some(d.id);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if let Some(r) = d.rssi {
                ui.label(RichText::new(format!("{r} dBm")).small().color(WEAK));
            }
        });
    });
    if let Some(summary) = d.identity.summary() {
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            ui.label(RichText::new(summary).small().color(WEAK));
        });
    }
}
