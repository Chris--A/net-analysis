use bevy_egui::egui::{self, Color32};

pub const ACCENT: Color32 = Color32::from_rgb(64, 200, 255);
pub const WEAK: Color32 = Color32::from_rgb(120, 140, 165);
pub const WARN: Color32 = Color32::from_rgb(255, 190, 60);
pub const DANGER: Color32 = Color32::from_rgb(255, 80, 60);
pub const OK: Color32 = Color32::from_rgb(80, 230, 140);

/// Dark "instrument panel" look, applied to both light and dark themes.
pub fn apply(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = Color32::from_rgb(8, 12, 20);
    v.window_fill = Color32::from_rgb(11, 16, 26);
    v.extreme_bg_color = Color32::from_rgb(4, 7, 12);
    v.faint_bg_color = Color32::from_rgb(13, 19, 30);
    v.selection.bg_fill = Color32::from_rgb(0, 92, 122);
    v.selection.stroke.color = ACCENT;
    v.hyperlink_color = ACCENT;
    v.widgets.noninteractive.bg_stroke.color = Color32::from_rgb(26, 38, 56);

    ctx.all_styles_mut(|style| {
        style.visuals = v.clone();
        style.spacing.item_spacing = egui::vec2(8.0, 5.0);
    });
}
