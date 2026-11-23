//! The three projections of the same device registry. Each view only writes
//! [`LayoutTarget`]s and draws its own gizmo scenery. Selection, filters,
//! materials and the UI are shared.

mod constellation;
mod radar;
mod spectrum;

use std::f32::consts::FRAC_PI_2;

use bevy::prelude::*;
use bevy_panorbit_camera::PanOrbitCamera;

use crate::FrameSet;
use crate::bridge::{DeviceNode, Registry};
use crate::picking::Selection;
use crate::scene::MainCamera;
use crate::tween::LayoutTarget;
use crate::ui::UiState;

#[derive(States, Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ViewMode {
    #[default]
    Radar,
    Constellation,
    Spectrum,
}

impl ViewMode {
    pub const ALL: [ViewMode; 3] = [ViewMode::Radar, ViewMode::Constellation, ViewMode::Spectrum];

    pub fn label(self) -> &'static str {
        match self {
            ViewMode::Radar => "Orbital Radar",
            ViewMode::Constellation => "Constellation",
            ViewMode::Spectrum => "Spectrum City",
        }
    }

    pub fn caption(self) -> &'static str {
        match self {
            ViewMode::Radar => {
                "Rings: LAN · Wi-Fi · BLE. Radius ≈ signal strength (approximate; a single antenna gives no bearing)."
            }
            ViewMode::Constellation => {
                "Gateway hub · SSID clusters · open ports orbit their hosts · BLE drifts at the edge."
            }
            ViewMode::Spectrum => {
                "Channels by band. Tower height = signal, colour = security (red = open), ground bar = channel width."
            }
        }
    }
}

pub struct ViewsPlugin;

impl Plugin for ViewsPlugin {
    fn build(&self, app: &mut App) {
        app.init_state::<ViewMode>()
            .init_resource::<constellation::ForceGraph>();

        for mode in ViewMode::ALL {
            app.add_systems(OnEnter(mode), apply_camera_preset);
        }

        app.add_systems(
            Update,
            (
                (radar::layout, radar::scenery)
                    .chain()
                    .run_if(in_state(ViewMode::Radar)),
                (constellation::simulate, constellation::scenery)
                    .chain()
                    .run_if(in_state(ViewMode::Constellation)),
                (spectrum::layout, spectrum::scenery)
                    .chain()
                    .run_if(in_state(ViewMode::Spectrum)),
            )
                .in_set(FrameSet::Layout),
        )
        .add_systems(Update, apply_filters_and_emphasis.in_set(FrameSet::Adjust));
    }
}

fn apply_camera_preset(
    state: Res<State<ViewMode>>,
    reg: Res<Registry>,
    mut cams: Query<&mut PanOrbitCamera, With<MainCamera>>,
) {
    let (focus, radius, yaw, pitch) = match state.get() {
        ViewMode::Radar => (Vec3::ZERO, 48.0, 0.0, 0.75),
        ViewMode::Constellation => (Vec3::ZERO, constellation::framing_radius(&reg), 0.4, 0.5),
        ViewMode::Spectrum => (Vec3::new(spectrum::CENTER_X, 1.5, 3.0), 74.0, 0.0, 0.8),
    };
    for mut cam in &mut cams {
        cam.target_focus = focus;
        cam.target_radius = radius;
        cam.target_yaw = yaw;
        cam.target_pitch = pitch;
    }
}

/// Runs after every layout: hides filtered-out devices and enlarges the selection.
fn apply_filters_and_emphasis(
    reg: Res<Registry>,
    ui: Res<UiState>,
    sel: Res<Selection>,
    mut nodes: Query<(&DeviceNode, &mut LayoutTarget)>,
) {
    for (node, mut target) in &mut nodes {
        let Some(dev) = reg.devices.get(&node.id) else {
            continue;
        };
        if !ui.shows(dev) {
            target.scale = Vec3::splat(LayoutTarget::HIDDEN_SCALE);
        } else if sel.selected == Some(node.id) && !target.is_hidden() {
            target.scale *= 1.35;
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Deterministic value in [0, 1) from an id and a salt.
pub fn unit_hash(id: u64, salt: u64) -> f32 {
    let mut z = id ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    (z >> 40) as f32 / (1u64 << 24) as f32
}

/// Signal strength normalised to [0, 1]: -100 dBm → 0, -30 dBm → 1.
pub fn signal01(rssi: Option<i16>) -> f32 {
    ((f32::from(rssi.unwrap_or(-90)) + 100.0) / 70.0).clamp(0.0, 1.0)
}

/// Rotation that lays a gizmo circle/grid flat on the XZ ground plane.
pub fn ground() -> Quat {
    Quat::from_rotation_x(FRAC_PI_2)
}

pub fn dim(c: LinearRgba, k: f32) -> LinearRgba {
    LinearRgba::new(c.red * k, c.green * k, c.blue * k, 1.0)
}

/// Point on a sphere from azimuth/elevation (radians).
pub fn spherical(radius: f32, azimuth: f32, elevation: f32) -> Vec3 {
    Vec3::new(
        radius * elevation.cos() * azimuth.cos(),
        radius * elevation.sin(),
        radius * elevation.cos() * azimuth.sin(),
    )
}

/// Draw camera-facing text with the gizmo text renderer.
pub fn label(gizmos: &mut Gizmos, cam_rot: Quat, pos: Vec3, text: &str, size: f32, color: LinearRgba) {
    gizmos.text(Isometry3d::new(pos, cam_rot), text, size, Vec2::ZERO, color);
}
