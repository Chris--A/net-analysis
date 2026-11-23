use bevy_egui::egui::{self, RichText};
use egui_plot::{Line, Plot, PlotPoints};
use na_engine::BtDb;
use na_engine::identify::ble::{cod_services, describe_manufacturer, uuid_label};
use na_engine::identify::{VendorIeKind, appearance_label, class_of_device_label, vendor_ie_info};
use na_engine::parse::{ble_ad, ie};
use na_model::{ApInfo, BleInfo, BtClassicInfo, ClaimKind, Device, LanInfo, now_millis};

use super::theme::{ACCENT, DANGER, WARN, WEAK};
use super::{ago, color32, duration_text};
use crate::bridge::Registry;
use crate::picking::Selection;
use crate::scene::kind_color;

pub fn show(root: &mut egui::Ui, reg: &Registry, sel: &mut Selection, bt: &BtDb) {
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
                .show(ui, |ui| device(ui, d, reg, sel, bt));
        });
}

fn device(ui: &mut egui::Ui, d: &Device, reg: &Registry, sel: &mut Selection, bt: &BtDb) {
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
        na_model::DeviceDetails::Ble(b) => ble_details(ui, b, bt),
        na_model::DeviceDetails::BtClassic(c) => classic_details(ui, c),
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
        match ap.tsf_uptime_secs {
            Some(up) => kv(ui, "Radio uptime", duration_text(up)),
            None => kv(ui, "Radio uptime", RichText::new("unknown / randomized TSF").color(WEAK)),
        }
        if let Some(n) = ap.station_count {
            kv(ui, "Clients", n.to_string());
        }
        if let Some(u) = ap.channel_utilization {
            kv(ui, "Channel busy", format!("{:.0}%", f32::from(u) / 255.0 * 100.0));
        }
        if let Some(cc) = &ap.country {
            kv(ui, "Country", cc.as_str());
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
        if !ap.vendor_ies.is_empty() {
            let names: Vec<String> = ap
                .vendor_ies
                .iter()
                .map(|t| match vendor_ie_info(t) {
                    Some((name, VendorIeKind::Chipset)) => format!("{name} (chipset)"),
                    Some((name, _)) => name.to_owned(),
                    None => format!("{:02X}:{:02X}:{:02X}/{}", t[0], t[1], t[2], t[3]),
                })
                .collect();
            kv(ui, "Vendor IEs", names.join(", "));
        }
    });
    raw_ies(ui, &ap.raw_ies);
}

/// Collapsible decoded list of every information element, with a hex preview.
fn raw_ies(ui: &mut egui::Ui, raw: &[u8]) {
    if raw.is_empty() {
        return;
    }
    let elements: Vec<_> = ie::elements(raw).collect();
    egui::CollapsingHeader::new(format!("Information elements ({}, {} bytes)", elements.len(), raw.len()))
        .id_salt("raw_ies")
        .show(ui, |ui| {
            for e in elements {
                let id = match e.ext_id {
                    Some(x) => format!("255/{x}"),
                    None => e.id.to_string(),
                };
                ui.label(
                    RichText::new(format!("{id:>6}  {}  ({} B)", ie::element_name(e.id, e.ext_id), e.data.len()))
                        .monospace()
                        .size(11.5),
                );
                const PREVIEW: usize = 24;
                let mut hex: Vec<String> = e.data.iter().take(PREVIEW).map(|b| format!("{b:02X}")).collect();
                if e.data.len() > PREVIEW {
                    hex.push("…".into());
                }
                if !hex.is_empty() {
                    ui.label(RichText::new(format!("        {}", hex.join(" "))).monospace().small().color(WEAK));
                }
            }
        });
}

fn hex(bytes: &[u8], max: usize) -> String {
    let mut parts: Vec<String> = bytes.iter().take(max).map(|b| format!("{b:02X}")).collect();
    if bytes.len() > max {
        parts.push("…".into());
    }
    parts.join(" ")
}

fn ble_details(ui: &mut egui::Ui, b: &BleInfo, bt: &BtDb) {
    section(ui, "Bluetooth LE");
    egui::Grid::new("ble").num_columns(2).spacing([10.0, 3.0]).show(ui, |ui| {
        kv(ui, "Address", RichText::new(b.address.to_string()).monospace());
        let mut kind = RichText::new(b.address_type.label());
        if b.address_type.is_rotating() {
            kind = kind.color(WEAK);
        }
        kv(ui, "Address type", kind);
        if let Some(n) = &b.local_name {
            kv(ui, "Name", n.as_str());
        }
        if b.connected {
            kv(ui, "Status", RichText::new("connected to this host").color(ACCENT));
        } else if b.paired {
            kv(ui, "Status", "paired");
        }
        if let Some(a) = b.appearance {
            kv(ui, "Appearance", format!("{} (0x{a:04X})", appearance_label(a)));
        }
        if let Some(tx) = b.tx_power {
            kv(ui, "TX power", format!("{tx} dBm"));
        }
        if let Some(f) = b.flags {
            kv(ui, "Flags", ble_ad::flag_labels(f).join(", "));
        }
        kv(ui, "Connectable", if b.connectable { "yes" } else { "no" });
        for m in &b.manufacturer_data {
            let who = bt.company(m.company_id).unwrap_or("unregistered");
            kv(ui, "Manufacturer", format!("{who} (0x{:04X})", m.company_id));
            if let Some(meaning) = describe_manufacturer(m.company_id, &m.data) {
                kv(ui, "", RichText::new(meaning).color(ACCENT));
            }
            if !m.data.is_empty() {
                kv(ui, "", RichText::new(hex(&m.data, 20)).monospace().small().color(WEAK));
            }
        }
        if !b.service_uuids.is_empty() {
            let names: Vec<String> = b.service_uuids.iter().map(|u| uuid_label(*u, bt)).collect();
            kv(ui, "Services", names.join(", "));
        }
        for s in &b.service_data {
            kv(ui, "Service data", uuid_label(s.uuid, bt));
            if !s.data.is_empty() {
                kv(ui, "", RichText::new(hex(&s.data, 20)).monospace().small().color(WEAK));
            }
        }
    });
    raw_ad(ui, &b.raw_ad);
}

/// Collapsible list of every AD structure heard from the device.
fn raw_ad(ui: &mut egui::Ui, raw: &[u8]) {
    if raw.is_empty() {
        return;
    }
    let structures: Vec<_> = ble_ad::structures(raw).collect();
    egui::CollapsingHeader::new(format!("Advertising data ({}, {} bytes)", structures.len(), raw.len()))
        .id_salt("raw_ad")
        .show(ui, |ui| {
            for s in structures {
                ui.label(
                    RichText::new(format!("  0x{:02X}  {}  ({} B)", s.ad_type, ble_ad::ad_type_name(s.ad_type), s.data.len()))
                        .monospace()
                        .size(11.5),
                );
                if !s.data.is_empty() {
                    ui.label(RichText::new(format!("        {}", hex(s.data, 24))).monospace().small().color(WEAK));
                }
            }
        });
}

fn classic_details(ui: &mut egui::Ui, c: &BtClassicInfo) {
    section(ui, "Bluetooth Classic");
    egui::Grid::new("bt_classic").num_columns(2).spacing([10.0, 3.0]).show(ui, |ui| {
        kv(ui, "Address", RichText::new(c.address.to_string()).monospace());
        if let Some(n) = &c.name {
            kv(ui, "Name", n.as_str());
        }
        if c.class_of_device != 0 {
            kv(ui, "Class", format!("{} (0x{:06X})", class_of_device_label(c.class_of_device), c.class_of_device));
            let services = cod_services(c.class_of_device);
            if !services.is_empty() {
                kv(ui, "Service classes", services.join(", "));
            }
        }
        let status = match (c.connected, c.paired) {
            (true, _) => RichText::new("connected to this host").color(ACCENT),
            (false, true) => RichText::new("paired"),
            _ => RichText::new("not paired").color(WEAK),
        };
        kv(ui, "Status", status);
        if c.discoverable {
            kv(ui, "Discoverable", RichText::new("yes — answered the last inquiry").color(WARN));
        }
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
