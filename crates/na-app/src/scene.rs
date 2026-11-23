//! Cameras, lighting, shared meshes, the colour language, the per-frame
//! material update that encodes recency, selection and risk, and risk halos.

use bevy::camera::visibility::RenderLayers;
use bevy::camera::CameraOutputMode;
use bevy::core_pipeline::tonemapping::Tonemapping;
use bevy::post_process::bloom::Bloom;
use bevy::prelude::*;
use bevy::render::render_resource::BlendState;
use bevy_egui::{EguiGlobalSettings, PrimaryEguiContext};
use bevy_panorbit_camera::PanOrbitCamera;
use na_model::{DeviceKind, Security, now_millis};

use crate::FrameSet;
use crate::bridge::{DeviceNode, Registry};
use crate::picking::Selection;
use crate::tween::LayoutTarget;
use crate::views::ViewMode;

pub const BACKGROUND: Color = Color::srgb(0.006, 0.010, 0.022);
pub const RISK: LinearRgba = LinearRgba::rgb(1.0, 0.08, 0.04);

pub struct ScenePlugin;

impl Plugin for ScenePlugin {
    fn build(&self, app: &mut App) {
        app.insert_resource(ClearColor(BACKGROUND))
            .add_systems(Startup, setup_scene)
            .add_systems(Update, (update_node_visuals, update_risk_halos).in_set(FrameSet::Visuals));
    }
}

#[derive(Component)]
pub struct MainCamera;

/// "You are here": the scanning host.
#[derive(Component)]
pub struct SelfMarker;

/// Devices at or above this risk wear a halo.
const HALO_RISK: f32 = 0.3;

/// A pulsing ring around a risky device (child of its node, so it follows every view's layout).
#[derive(Component)]
struct RiskHalo;

/// On a node: its halo entity.
#[derive(Component)]
struct HasHalo(Entity);

#[derive(Resource)]
struct HaloAssets {
    mesh: Handle<Mesh>,
    material: Handle<StandardMaterial>,
}

#[derive(Resource)]
pub struct NodeAssets {
    ap: Handle<Mesh>,
    ble: Handle<Mesh>,
    lan: Handle<Mesh>,
    other: Handle<Mesh>,
}

impl NodeAssets {
    pub fn mesh_for(&self, kind: DeviceKind) -> Handle<Mesh> {
        match kind {
            DeviceKind::AccessPoint => self.ap.clone(),
            DeviceKind::Ble => self.ble.clone(),
            DeviceKind::LanHost => self.lan.clone(),
            DeviceKind::WifiClient | DeviceKind::BtClassic => self.other.clone(),
        }
    }
}

/// Class colours shared by every view and the UI.
pub fn kind_color(kind: DeviceKind) -> LinearRgba {
    match kind {
        DeviceKind::AccessPoint => LinearRgba::rgb(0.10, 0.72, 1.00),
        DeviceKind::Ble => LinearRgba::rgb(0.62, 0.34, 1.00),
        DeviceKind::LanHost => LinearRgba::rgb(0.22, 1.00, 0.48),
        DeviceKind::WifiClient => LinearRgba::rgb(1.00, 0.72, 0.18),
        DeviceKind::BtClassic => LinearRgba::rgb(0.90, 0.48, 1.00),
    }
}

/// Security colours used by Spectrum City (red = open).
pub fn security_color(sec: &Security) -> LinearRgba {
    if sec.is_open() {
        return LinearRgba::rgb(1.0, 0.22, 0.10);
    }
    match sec.floor_strength() {
        0 | 1 => LinearRgba::rgb(1.0, 0.78, 0.15), // OWE: encrypted, unauthenticated
        2 => LinearRgba::rgb(0.12, 0.66, 1.0),     // WPA2 (incl. WPA3 transition)
        3 => LinearRgba::rgb(0.18, 1.0, 0.62),     // WPA3
        _ => LinearRgba::rgb(0.50, 0.45, 1.0),     // Enterprise
    }
}

pub fn lerp_rgba(a: LinearRgba, b: LinearRgba, t: f32) -> LinearRgba {
    let t = t.clamp(0.0, 1.0);
    LinearRgba::new(
        a.red + (b.red - a.red) * t,
        a.green + (b.green - a.green) * t,
        a.blue + (b.blue - a.blue) * t,
        a.alpha + (b.alpha - a.alpha) * t,
    )
}

fn setup_scene(
    mut commands: Commands,
    mut egui_settings: ResMut<EguiGlobalSettings>,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
) {
    // The 3D camera gets a viewport between the panels, so egui needs its own
    // full-window overlay camera instead of attaching to the first camera.
    egui_settings.auto_create_primary_context = false;

    commands.spawn((
        MainCamera,
        Camera3d::default(),
        Camera {
            clear_color: ClearColorConfig::Custom(BACKGROUND),
            ..default()
        },
        Tonemapping::TonyMcMapface,
        Bloom::NATURAL,
        Transform::from_xyz(0.0, 30.0, 40.0).looking_at(Vec3::ZERO, Vec3::Y),
        PanOrbitCamera {
            radius: Some(48.0),
            pitch: Some(0.75),
            yaw: Some(0.0),
            zoom_lower_limit: 4.0,
            zoom_upper_limit: Some(180.0),
            ..default()
        },
    ));

    commands.spawn((
        PrimaryEguiContext,
        Camera2d,
        RenderLayers::none(),
        Camera {
            order: 1,
            output_mode: CameraOutputMode::Write {
                blend_state: Some(BlendState::ALPHA_BLENDING),
                clear_color: ClearColorConfig::None,
            },
            clear_color: ClearColorConfig::Custom(Color::NONE),
            ..default()
        },
    ));

    commands.spawn((
        DirectionalLight {
            illuminance: 2_500.0,
            ..default()
        },
        Transform::from_xyz(10.0, 30.0, 15.0).looking_at(Vec3::ZERO, Vec3::Y),
    ));

    commands.insert_resource(HaloAssets {
        mesh: meshes.add(Torus::new(0.92, 1.0)),
        material: materials.add(StandardMaterial {
            base_color: Color::srgba(1.0, 0.15, 0.08, 0.7),
            emissive: LinearRgba::rgb(9.0, 0.6, 0.25),
            unlit: true,
            alpha_mode: AlphaMode::Blend,
            ..default()
        }),
    });

    commands.insert_resource(NodeAssets {
        ap: meshes.add(Cuboid::new(1.0, 1.0, 1.0)),
        ble: meshes.add(Sphere::new(0.5).mesh().ico(3).unwrap()),
        lan: meshes.add(Capsule3d::new(0.32, 0.55)),
        other: meshes.add(Sphere::new(0.5).mesh().ico(1).unwrap()),
    });

    commands.spawn((
        SelfMarker,
        Name::new("This host"),
        Mesh3d(meshes.add(Sphere::new(0.55).mesh().ico(4).unwrap())),
        MeshMaterial3d(materials.add(StandardMaterial {
            base_color: Color::WHITE,
            emissive: LinearRgba::rgb(5.0, 5.0, 6.0),
            ..default()
        })),
        Transform::from_scale(Vec3::splat(LayoutTarget::HIDDEN_SCALE)),
        LayoutTarget::default(),
        Pickable::IGNORE,
    ));
}

/// Encode state into each node's material:
/// - colour: device class, or security in Spectrum City
/// - glow: recency, hover and selection
/// - red pulse: risk from the guard detectors
fn update_node_visuals(
    time: Res<Time>,
    reg: Res<Registry>,
    sel: Res<Selection>,
    view: Res<State<ViewMode>>,
    nodes: Query<(&DeviceNode, &MeshMaterial3d<StandardMaterial>)>,
    mut materials: ResMut<Assets<StandardMaterial>>,
) {
    let now = now_millis();
    let t = time.elapsed_secs();
    for (node, material) in &nodes {
        let Some(dev) = reg.devices.get(&node.id) else {
            continue;
        };
        let mut color = match (view.get(), dev.ap()) {
            (ViewMode::Spectrum, Some(ap)) => security_color(&ap.security),
            _ => kind_color(dev.kind),
        };

        // Fade devices we haven't heard from recently (1.0 → 0.25 over ~20 s).
        let age = now.saturating_sub(dev.last_seen) as f32 / 1000.0;
        let freshness = 1.0 - ((age - 4.0) / 20.0).clamp(0.0, 1.0) * 0.75;

        let mut glow = 1.6 * freshness;
        if sel.hovered == Some(node.id) {
            glow *= 2.0;
        }
        if sel.selected == Some(node.id) {
            glow = glow.max(1.0) * 3.0;
        }
        if dev.risk > 0.05 {
            let pulse = 0.5 + 0.5 * (t * 6.0).sin();
            color = lerp_rgba(color, RISK, dev.risk * (0.6 + 0.4 * pulse));
            glow *= 1.0 + dev.risk * pulse * 2.0;
        }

        let emissive = LinearRgba::new(color.red * glow, color.green * glow, color.blue * glow, 1.0);
        let base = Color::LinearRgba(LinearRgba::new(
            color.red * 0.15,
            color.green * 0.15,
            color.blue * 0.15,
            0.35 + 0.65 * freshness,
        ));

        // Only touch the asset when something visibly changed (avoids GPU re-uploads).
        let unchanged = materials
            .get(&material.0)
            .is_some_and(|m| close(m.emissive, emissive) && m.base_color == base);
        if unchanged {
            continue;
        }
        if let Some(mut m) = materials.get_mut(&material.0) {
            m.emissive = emissive;
            m.base_color = base;
        }
    }
}

/// Add, animate and remove halos as devices cross the risk threshold.
fn update_risk_halos(
    mut commands: Commands,
    time: Res<Time>,
    reg: Res<Registry>,
    assets: Option<Res<HaloAssets>>,
    nodes: Query<(Entity, &DeviceNode, Option<&HasHalo>)>,
    mut halos: Query<&mut Transform, With<RiskHalo>>,
) {
    let Some(assets) = assets else { return };
    let t = time.elapsed_secs();
    for (entity, node, halo) in &nodes {
        let risky = reg.devices.get(&node.id).is_some_and(|d| d.risk >= HALO_RISK);
        match (risky, halo) {
            (true, None) => {
                let h = commands
                    .spawn((
                        RiskHalo,
                        Mesh3d(assets.mesh.clone()),
                        MeshMaterial3d(assets.material.clone()),
                        Transform::from_scale(Vec3::splat(1.6)),
                        Pickable::IGNORE,
                    ))
                    .id();
                commands.entity(entity).add_child(h).insert(HasHalo(h));
            }
            (false, Some(h)) => {
                commands.entity(h.0).despawn();
                commands.entity(entity).remove::<HasHalo>();
            }
            (true, Some(h)) => {
                if let Ok(mut tf) = halos.get_mut(h.0) {
                    let pulse = 0.5 + 0.5 * (t * 3.0).sin();
                    tf.scale = Vec3::splat(1.5 + 0.45 * pulse);
                    tf.rotation = Quat::from_rotation_x(0.35 * (t * 0.7).sin()) * Quat::from_rotation_y(t * 0.9);
                }
            }
            (false, None) => {}
        }
    }
}

fn close(a: LinearRgba, b: LinearRgba) -> bool {
    (a.red - b.red).abs() + (a.green - b.green).abs() + (a.blue - b.blue).abs() < 0.02
}
