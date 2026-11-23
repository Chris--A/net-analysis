//! Screen-space overlay on the 3D viewport: view caption, legend, and labels for
//! hovered, selected and risky devices.

use bevy::prelude::*;
use bevy_egui::egui::{self, Align2, Color32, FontId};
use na_model::{Akm, DeviceKind, Pmf, Security};

use super::theme::WEAK;
use super::{UiState, color32};
use crate::bridge::{DeviceNode, Registry};
use crate::picking::Selection;
use crate::scene::{kind_color, security_color};
use crate::views::ViewMode;

#[allow(clippy::too_many_arguments)]
pub fn show(
    ctx: &egui::Context,
    clip: egui::Rect,
    view: ViewMode,
    camera: &Camera,
    cam_tf: &GlobalTransform,
    reg: &Registry,
    sel: &Selection,
    ui_state: &UiState,
    nodes: &Query<(&DeviceNode, &GlobalTransform, &Transform)>,
) {
    let painter = ctx
        .layer_painter(egui::LayerId::new(egui::Order::Middle, egui::Id::new("viewport_overlay")))
        .with_clip_rect(clip);

    painter.text(
        clip.left_top() + egui::vec2(10.0, 8.0),
        Align2::LEFT_TOP,
        view.caption(),
        FontId::proportional(12.5),
        WEAK,
    );
    legend(&painter, clip, view);

    for (node, gtf, tf) in nodes.iter() {
        let Some(d) = reg.devices.get(&node.id) else {
            continue;
        };
        let hovered = sel.hovered == Some(node.id);
        let selected = sel.selected == Some(node.id);
        let risky = d.risk > 0.3;
        if !(hovered || selected || risky) || !ui_state.shows(d) || tf.scale.max_element() < 0.05 {
            continue;
        }
        let top = gtf.translation() + Vec3::Y * (tf.scale.y * 0.6 + 0.2);
        let Ok(p) = camera.world_to_viewport(cam_tf, top) else {
            continue;
        };
        let mut text = d.display_name();
        if let Some(r) = d.rssi {
            text.push_str(&format!("  {r} dBm"));
        }
        if hovered && let Some(s) = d.identity.summary() {
            text.push('\n');
            text.push_str(&s);
        }
        let accent = if risky { Color32::from_rgb(255, 90, 70) } else { color32(kind_color(d.kind)) };
        tag(&painter, egui::pos2(p.x, p.y), &text, accent, selected);
    }
}

fn tag(painter: &egui::Painter, anchor: egui::Pos2, text: &str, accent: Color32, strong: bool) {
    let galley = painter.layout_no_wrap(text.to_owned(), FontId::proportional(13.0), Color32::WHITE);
    let rect = Align2::CENTER_BOTTOM
        .anchor_size(anchor - egui::vec2(0.0, 6.0), galley.size())
        .expand2(egui::vec2(6.0, 3.0));
    painter.rect_filled(rect, 4.0, Color32::from_rgba_unmultiplied(6, 10, 18, 220));
    painter.rect_stroke(
        rect,
        4.0,
        egui::Stroke::new(if strong { 1.5 } else { 1.0 }, accent),
        egui::StrokeKind::Outside,
    );
    painter.galley(rect.min + egui::vec2(6.0, 3.0), galley, Color32::WHITE);
}

fn legend(painter: &egui::Painter, clip: egui::Rect, view: ViewMode) {
    let entries: Vec<(String, Color32)> = match view {
        ViewMode::Spectrum => {
            let s = |akms: &[Akm]| Security { akms: akms.to_vec(), pmf: Pmf::Disabled, ..Default::default() };
            vec![
                ("Open".into(), color32(security_color(&Security::open()))),
                ("OWE".into(), color32(security_color(&s(&[Akm::Owe])))),
                ("WPA2 / transition".into(), color32(security_color(&s(&[Akm::Psk])))),
                ("WPA3".into(), color32(security_color(&s(&[Akm::Sae])))),
                ("Enterprise".into(), color32(security_color(&s(&[Akm::Eap])))),
            ]
        }
        _ => [DeviceKind::AccessPoint, DeviceKind::LanHost, DeviceKind::Ble]
            .into_iter()
            .map(|k| (k.label().to_owned(), color32(kind_color(k))))
            .collect(),
    };
    let mut pos = clip.left_bottom() + egui::vec2(12.0, -14.0);
    for (name, color) in entries {
        painter.circle_filled(pos, 4.5, color);
        let r = painter.text(pos + egui::vec2(9.0, 0.0), Align2::LEFT_CENTER, name, FontId::proportional(12.0), WEAK);
        pos.x = r.right() + 16.0;
    }
}
