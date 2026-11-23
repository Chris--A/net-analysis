use bevy_egui::egui::{self, RichText};
use egui_plot::{Line, Plot, PlotPoints};
use na_model::{ApInfo, BleInfo, ClaimKind, Device, LanInfo, now_millis};

use super::theme::{ACCENT, DANGER, WARN, WEAK};
use super::{ago, color32, duration_text};
use crate::bridge::Registry;
use crate::picking::Selection;
use crate::scene::kind_color;

pub fn show(root: &mut egui::Ui, reg: &Registry, sel: &mut Selection) {
    egui::Panel::right("inspector")
        .resizable(true)
        .default_size(340.0)
        .min_size(260.0)
        .show(root, |ui| {
            ui.add_space(4.0);
            let Some(d) = sel.selected.and_then(|id| reg.devices.get(&id)) else {
                ui.heading("Inspector");
                ui.label(RichText::new("Click a device in the 3D view or the list.").color(WEAK));
                ui.label(RichText::new("Esc clears the selection.").small().color(WEAK));
                return;
            };
            egui::ScrollArea::vertical()
                .id_salt("inspector")
                .auto_shrink(false)
                .show(ui, |ui| device(ui, d, reg, sel));
        });
}

fn device(ui: &mut egui::Ui, d: &Device, reg: &Registry, sel: &mut Selection) {
    let now = now_millis();
    ui.horizontal(|ui| {
        ui.heading(RichText::new(d.display_name()).color(color32(kind_color(d.kind))));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("×").on_hover_text("Clear selection (Esc)").clicked() {
                sel.selected = None;
            }
        });
    });
    ui.label(
        RichText::new(format!(
            "{} · {} · first seen {} · last seen {}",
            d.kind.label(),
            d.key,
            ago(now, d.first_seen),
            ago(now, d.last_seen)
        ))
        .small()
        .color(WEAK),
    );
    if d.risk > 0.05 {
        ui.label(RichText::new(format!("⚠ Risk score {:.0}%", d.risk * 100.0)).strong().color(DANGER));
    }

    if !d.rssi_history.is_empty() {
        ui.add_space(4.0);
        let pts: Vec<[f64; 2]> = d
            .rssi_history
            .iter()
            .map(|s| [(s.at as f64 - now as f64) / 1000.0, f64::from(s.dbm)])
            .collect();
        ui.label(RichText::new(format!("Signal  {} dBm", d.rssi.unwrap_or_default())).strong());
        Plot::new(("rssi", d.id.0))
            .height(80.0)
            .allow_drag(false)
            .allow_zoom(false)
            .allow_scroll(false)
            .show_x(false)
            .include_y(-100.0)
            .include_y(-30.0)
            .show(ui, |p| p.line(Line::new("RSSI", PlotPoints::from(pts)).color(color32(kind_color(d.kind)))));
    }

    section(ui, "Identity");
    egui::Grid::new("identity").num_columns(3).spacing([8.0, 4.0]).show(ui, |ui| {
        for kind in ClaimKind::ALL {
            let Some(c) = d.identity.get(kind) else {
                continue;
            };
            ui.label(RichText::new(kind.label()).color(WEAK));
            ui.label(RichText::new(&c.value).strong());
            let sources: Vec<&str> = c.sources.iter().map(|s| s.label()).collect();
            ui.add(
                egui::ProgressBar::new(c.confidence)
                    .desired_width(70.0)
                    .text(format!("{:.0}%", c.confidence * 100.0)),
            )
            .on_hover_text(format!("Sources: {}", sources.join(", ")));
            ui.end_row();
        }
    });
    if d.identity.summary().is_none() {
        ui.label(RichText::new("No identifying evidence yet.").color(WEAK));
    }

    match &d.details {
        na_model::DeviceDetails::Ap(ap) => ap_details(ui, ap),
        na_model::DeviceDetails::Ble(b) => ble_details(ui, b),
        na_model::DeviceDetails::Lan(l) => lan_details(ui, l),
        na_model::DeviceDetails::None => {}
    }

    if !d.evidence.is_empty() {
        section(ui, "Evidence");
        let mut ev: Vec<_> = d.evidence.iter().collect();
        ev.sort_by(|a, b| a.kind.cmp(&b.kind).then(b.confidence.total_cmp(&a.confidence)));
        for e in ev {
            ui.label(
                RichText::new(format!(
                    "[{}] {} = {}  ({:.0}%)",
                    e.source.label(),
                    e.kind.label(),
                    e.value,
                    e.confidence * 100.0
                ))
                .monospace()
                .size(11.5),
            );
            if !e.detail.is_empty() {
                ui.label(RichText::new(format!("    {}", e.detail)).small().color(WEAK));
            }
        }
    }

    let links: Vec<&Device> = d.links.iter().filter_map(|id| reg.devices.get(id)).collect();
    if !links.is_empty() {
        section(ui, "Linked devices");
        for l in links {
            if ui.link(format!("{} — {}", l.kind.label(), l.display_name())).clicked() {
                sel.selected = Some(l.id);
            }
        }
    }
}

fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(8.0);
    ui.label(RichText::new(title).strong().color(ACCENT));
    ui.separator();
}

fn kv(ui: &mut egui::Ui, k: &str, v: impl Into<egui::WidgetText>) {
    ui.label(RichText::new(k).color(WEAK));
    ui.label(v);
    ui.end_row();
}

fn ap_details(ui: &mut egui::Ui, ap: &ApInfo) {
    section(ui, "Wi-Fi access point");
    egui::Grid::new("ap").num_columns(2).spacing([10.0, 3.0]).show(ui, |ui| {
        kv(ui, "SSID", ap.display_ssid());
        let mut bssid = RichText::new(ap.bssid.to_string()).monospace();
        if ap.bssid.is_locally_administered() {
            bssid = bssid.color(WARN);
        }
        kv(ui, "BSSID", bssid);
        if ap.bssid.is_locally_administered() {
            kv(ui, "", RichText::new("locally administered (not vendor-assigned)").small().color(WARN));
        }
        kv(ui, "Band / channel", format!("{} · ch {} · {} MHz", ap.band.label(), ap.channel, ap.width_mhz));
        let mut sec = RichText::new(ap.security.label());
        if ap.security.is_open() {
            sec = sec.color(DANGER);
        }
        kv(ui, "Security", sec);
        kv(ui, "PMF (802.11w)", format!("{:?}", ap.security.pmf));
        if let Some(g) = ap.wifi_gen {
            kv(ui, "Generation", format!("Wi-Fi {g}"));
        }
        if let Some(up) = ap.tsf_uptime_secs {
            kv(ui, "Radio uptime", duration_text(up));
        }
        kv(ui, "Beacon interval", format!("{} TU", ap.beacon_interval_tu));
        kv(ui, "IE fingerprint", RichText::new(format!("{:016x}", ap.ie_fingerprint)).monospace());
        if ap.connected {
            kv(ui, "Connected", RichText::new("yes — this host is associated").color(ACCENT));
        }
        if let Some(w) = &ap.wps {
            for (k, v) in [
                ("WPS manufacturer", &w.manufacturer),
                ("WPS model", &w.model_name),
                ("WPS model no.", &w.model_number),
                ("WPS device name", &w.device_name),
            ] {
                if let Some(v) = v {
                    kv(ui, k, v.as_str());
                }
            }
        }
    });
}

fn ble_details(ui: &mut egui::Ui, b: &BleInfo) {
    section(ui, "Bluetooth LE");
    egui::Grid::new("ble").num_columns(2).spacing([10.0, 3.0]).show(ui, |ui| {
        let kind = if b.random_address { "random (rotates)" } else { "public" };
        kv(ui, "Address", RichText::new(format!("{}  ({kind})", b.address)).monospace());
        if let Some(n) = &b.local_name {
            kv(ui, "Local name", n.as_str());
        }
        if let Some(c) = b.company_id {
            kv(ui, "Company ID", RichText::new(format!("0x{c:04X}")).monospace());
        }
        if !b.manufacturer_data.is_empty() {
            let hex: Vec<String> = b.manufacturer_data.iter().map(|x| format!("{x:02X}")).collect();
            kv(ui, "Mfr data", RichText::new(hex.join(" ")).monospace());
        }
        if !b.service_uuids.is_empty() {
            kv(ui, "Services", b.service_uuids.join(", "));
        }
        if let Some(tx) = b.tx_power {
            kv(ui, "TX power", format!("{tx} dBm"));
        }
        kv(ui, "Connectable", if b.connectable { "yes" } else { "no" });
    });
}

fn lan_details(ui: &mut egui::Ui, l: &LanInfo) {
    section(ui, "LAN host");
    egui::Grid::new("lan").num_columns(2).spacing([10.0, 3.0]).show(ui, |ui| {
        let ips: Vec<String> = l.ips.iter().map(|ip| ip.to_string()).collect();
        kv(ui, "IP", RichText::new(ips.join(", ")).monospace());
        if let Some(mac) = l.mac {
            let mut t = RichText::new(mac.to_string()).monospace();
            if mac.is_locally_administered() {
                t = t.color(WARN);
            }
            kv(ui, "MAC", t);
            if mac.is_locally_administered() {
                kv(ui, "", RichText::new("randomized / private address").small().color(WARN));
            }
        }
        if let Some(h) = &l.hostname {
            kv(ui, "Hostname", h.as_str());
        }
        if !l.open_ports.is_empty() {
            let ports: Vec<String> = l.open_ports.iter().map(|p| p.to_string()).collect();
            kv(ui, "Open ports", RichText::new(ports.join(", ")).monospace());
        }
        if !l.services.is_empty() {
            kv(ui, "Services", l.services.join(", "));
        }
        if l.is_gateway {
            kv(ui, "Role", RichText::new("default gateway").color(ACCENT));
        }
        if l.is_self {
            kv(ui, "Role", RichText::new("this machine").color(ACCENT));
        }
    });
}
