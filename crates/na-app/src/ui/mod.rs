//! egui panels around the 3D viewport. The camera viewport is shrunk to the
//! space left between the panels every frame.

mod alerts;
mod device_list;
mod inspector;
mod overlay;
mod theme;
mod topbar;

use std::collections::HashSet;

use bevy::camera::Viewport;
use bevy::diagnostic::{DiagnosticsStore, FrameTimeDiagnosticsPlugin};
use bevy::prelude::*;
use bevy::window::PrimaryWindow;
use bevy_egui::{EguiContexts, EguiPrimaryContextPass, egui};
use na_engine::BtDb;
use na_model::{Device, DeviceKind};

use crate::bridge::{DeviceNode, EngineLink, Registry};
use crate::picking::Selection;
use crate::scene::MainCamera;
use crate::views::ViewMode;

pub struct UiPlugin;

impl Plugin for UiPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<UiState>()
            .insert_resource(BtNames(BtDb::load_default()))
            .add_systems(EguiPrimaryContextPass, ui_system);
    }
}

/// Bluetooth SIG company / UUID names, for labelling raw advert data.
#[derive(Resource)]
pub struct BtNames(pub BtDb);

#[derive(Resource)]
pub struct UiState {
    /// Stop applying engine events (the scene freezes; events queue up).
    pub paused: bool,
    pub search: String,
    pub shown_kinds: HashSet<DeviceKind>,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            paused: false,
            search: String::new(),
            shown_kinds: DeviceKind::ALL.into_iter().collect(),
        }
    }
}

impl UiState {
    /// Filter shared by the device list and the 3D views.
    pub fn shows(&self, d: &Device) -> bool {
        if !self.shown_kinds.contains(&d.kind) {
            return false;
        }
        let q = self.search.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        let mut hay = format!("{} {}", d.display_name(), d.key);
        if let Some(s) = d.identity.summary() {
            hay.push(' ');
            hay.push_str(&s);
        }
        if let Some(ap) = d.ap() {
            hay.push(' ');
            hay.push_str(&ap.ssid);
        }
        hay.to_lowercase().contains(&q)
    }
}

#[allow(clippy::too_many_arguments)]
fn ui_system(
    mut contexts: EguiContexts,
    mut styled: Local<bool>,
    mut ui_state: ResMut<UiState>,
    mut sel: ResMut<Selection>,
    reg: Res<Registry>,
    link: Option<Res<EngineLink>>,
    view: Res<State<ViewMode>>,
    mut next_view: ResMut<NextState<ViewMode>>,
    mut camera: Single<(&mut Camera, &GlobalTransform), With<MainCamera>>,
    window: Single<&Window, With<PrimaryWindow>>,
    nodes: Query<(&DeviceNode, &GlobalTransform, &Transform)>,
    diagnostics: Res<DiagnosticsStore>,
    bt: Res<BtNames>,
) -> Result {
    let fps = diagnostics
        .get(&FrameTimeDiagnosticsPlugin::FPS)
        .and_then(|d| d.smoothed());
    let ctx = contexts.ctx_mut()?.clone();
    if !*styled {
        theme::apply(&ctx);
        *styled = true;
    }

    let mut root = egui::Ui::new(
        ctx.clone(),
        "root".into(),
        egui::UiBuilder::new()
            .layer_id(egui::LayerId::background())
            .max_rect(ctx.viewport_rect()),
    );

    let view = *view.get();
    topbar::show(&mut root, view, &mut next_view, &mut ui_state, &reg, link.as_deref(), fps);
    alerts::show(&mut root, &reg, &mut sel);
    device_list::show(&mut root, &mut ui_state, &reg, &mut sel);
    inspector::show(&mut root, &reg, &mut sel, &bt.0);

    let central = root.available_rect_before_wrap();
    let (ref mut cam, cam_tf) = *camera;
    fit_viewport(cam, &window, central);
    overlay::show(&ctx, central, view, cam, cam_tf, &reg, &sel, &ui_state, &nodes);
    Ok(())
}

/// Restrict the 3D camera to the free area between panels.
fn fit_viewport(camera: &mut Camera, window: &Window, rect: egui::Rect) {
    let sf = window.scale_factor();
    let win = UVec2::new(window.physical_width(), window.physical_height());
    if win.x < 2 || win.y < 2 {
        return;
    }
    let pos = UVec2::new(
        (rect.min.x * sf).max(0.0) as u32,
        (rect.min.y * sf).max(0.0) as u32,
    )
    .min(win - UVec2::ONE);
    let size = UVec2::new((rect.width() * sf) as u32, (rect.height() * sf) as u32).min(win - pos);
    camera.viewport = (size.x >= 32 && size.y >= 32).then(|| Viewport {
        physical_position: pos,
        physical_size: size,
        ..default()
    });
}

// ---------------------------------------------------------------------------
// Shared formatting helpers
// ---------------------------------------------------------------------------

pub fn color32(c: LinearRgba) -> egui::Color32 {
    let s = Color::LinearRgba(LinearRgba::new(
        c.red.min(1.0),
        c.green.min(1.0),
        c.blue.min(1.0),
        1.0,
    ))
    .to_srgba();
    egui::Color32::from_rgb(
        (s.red * 255.0) as u8,
        (s.green * 255.0) as u8,
        (s.blue * 255.0) as u8,
    )
}

pub fn ago(now: u64, then: u64) -> String {
    let s = now.saturating_sub(then) / 1000;
    match s {
        0..=59 => format!("{s}s ago"),
        60..=3599 => format!("{}m ago", s / 60),
        _ => format!("{}h ago", s / 3600),
    }
}

pub fn duration_text(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    match (d, h) {
        (0, 0) => format!("{m}m {}s", secs % 60),
        (0, _) => format!("{h}h {m}m"),
        _ => format!("{d}d {h}h"),
    }
}
