//! Engine ↔ ECS bridge. Spawns the engine and mirrors its devices into a
//! [`Registry`] resource. Each device also gets one 3D entity, which every view reuses.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Duration;

use bevy::prelude::*;
use na_engine::{Engine, EngineConfig, EngineHandle, GuardConfig, SimConfig};
use na_model::{
    Alert, Device, DeviceId, EngineCommand, EngineEvent, GuardStatus, Millis, SourceKind, SourceState,
    now_millis,
};

use crate::FrameSet;
use crate::picking::Selection;
use crate::scene::NodeAssets;
use crate::tween::LayoutTarget;
use crate::ui::UiState;

/// Upper bound on events applied per frame, so a burst can't stall rendering.
const MAX_EVENTS_PER_FRAME: usize = 5_000;
const LOG_CAPACITY: usize = 300;

pub struct BridgePlugin;

impl Plugin for BridgePlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<Registry>()
            .add_systems(Startup, start_engine)
            .add_systems(Update, ingest_events.in_set(FrameSet::Ingest));
    }
}

/// Command-line options:
/// - `--sim`: use the built-in simulator instead of the real scanners
/// - `--extra N`: add N load-test devices (simulator)
/// - `--twin-after SECS`: when the simulated evil twin appears (0 disables it)
/// - `--screenshot-dir DIR`: run the screenshot tour
#[derive(Resource, Clone, Debug)]
pub struct LaunchOptions {
    pub sim: bool,
    pub extra_devices: usize,
    pub twin_after_secs: u64,
    pub screenshot_dir: Option<std::path::PathBuf>,
}

impl LaunchOptions {
    pub fn from_args() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut opts = Self {
            sim: args.iter().any(|a| a == "--sim"),
            extra_devices: 0,
            twin_after_secs: 20,
            screenshot_dir: None,
        };
        for pair in args.windows(2) {
            match pair[0].as_str() {
                "--extra" => opts.extra_devices = pair[1].parse().unwrap_or(0),
                "--twin-after" => opts.twin_after_secs = pair[1].parse().unwrap_or(20),
                "--screenshot-dir" => opts.screenshot_dir = Some(pair[1].clone().into()),
                _ => {}
            }
        }
        opts
    }
}

#[derive(Resource)]
pub struct EngineLink(pub EngineHandle);

impl EngineLink {
    pub fn send(&self, cmd: EngineCommand) {
        self.0.send(cmd);
    }
}

/// Marks the 3D entity representing one device.
#[derive(Component, Debug, Clone, Copy)]
pub struct DeviceNode {
    pub id: DeviceId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogKind {
    Added,
    Removed,
    Source,
    Alert,
}

#[derive(Clone, Debug)]
pub struct LogLine {
    pub at: Millis,
    pub kind: LogKind,
    pub text: String,
}

/// The frontend's mirror of engine state.
#[derive(Resource, Default)]
pub struct Registry {
    pub devices: HashMap<DeviceId, Device>,
    pub entities: HashMap<DeviceId, Entity>,
    pub alerts: Vec<Alert>,
    pub log: VecDeque<LogLine>,
    pub sources: BTreeMap<SourceKind, SourceState>,
    /// Trusted networks and the Karma test, as last reported.
    pub guard: Option<GuardStatus>,
}

impl Registry {
    fn push_log(&mut self, kind: LogKind, text: String) {
        self.log.push_back(LogLine {
            at: now_millis(),
            kind,
            text,
        });
        while self.log.len() > LOG_CAPACITY {
            self.log.pop_front();
        }
    }

    pub fn gateway(&self) -> Option<&Device> {
        self.devices
            .values()
            .find(|d| d.lan().is_some_and(|l| l.is_gateway))
    }

    pub fn sim_running(&self) -> bool {
        matches!(self.sources.get(&SourceKind::Sim), Some(SourceState::Running))
    }
}

fn start_engine(mut commands: Commands, opts: Res<LaunchOptions>) {
    let cfg = EngineConfig {
        sources: if opts.sim {
            vec![SourceKind::Sim]
        } else {
            EngineConfig::real_sources()
        },
        sim: SimConfig {
            extra_devices: opts.extra_devices,
            evil_twin_after: (opts.twin_after_secs > 0)
                .then(|| Duration::from_secs(opts.twin_after_secs)),
            ..SimConfig::default()
        },
        // Simulated networks must never land in the real trusted-network file.
        guard: if opts.sim {
            GuardConfig {
                karma_first_after: Duration::from_secs(8),
                karma_interval: Some(Duration::from_secs(300)),
                dhcp_first_after: Duration::from_secs(10),
                dhcp_interval: Some(Duration::from_secs(300)),
                ..GuardConfig::default()
            }
        } else {
            GuardConfig::persistent()
        },
        ..EngineConfig::default()
    };
    match Engine::spawn(cfg) {
        Ok(handle) => commands.insert_resource(EngineLink(handle)),
        Err(e) => error!("failed to start engine: {e:#}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn ingest_events(
    mut commands: Commands,
    link: Option<Res<EngineLink>>,
    ui: Res<UiState>,
    assets: Option<Res<NodeAssets>>,
    mut reg: ResMut<Registry>,
    mut selection: ResMut<Selection>,
    mut materials: ResMut<Assets<StandardMaterial>>,
) {
    let (Some(link), Some(assets)) = (link, assets) else {
        return;
    };
    if ui.paused {
        return;
    }
    for event in link.0.drain().take(MAX_EVENTS_PER_FRAME) {
        match event {
            EngineEvent::DeviceUpserted(device) => {
                let id = device.id;
                if let Entry::Vacant(slot) = reg.entities.entry(id) {
                    slot.insert(spawn_node(&mut commands, &assets, &mut materials, &device));
                    let line = format!("+ {}  {}", device.kind.label(), device.display_name());
                    reg.push_log(LogKind::Added, line);
                }
                reg.devices.insert(id, *device);
            }
            EngineEvent::DeviceRemoved(id) => {
                if let Some(entity) = reg.entities.remove(&id) {
                    commands.entity(entity).despawn();
                }
                if let Some(d) = reg.devices.remove(&id) {
                    let line = format!("− {}  {}", d.kind.label(), d.display_name());
                    reg.push_log(LogKind::Removed, line);
                }
                if selection.selected == Some(id) {
                    selection.selected = None;
                }
                if selection.hovered == Some(id) {
                    selection.hovered = None;
                }
            }
            EngineEvent::Alert(alert) => {
                let line = format!("[{}] {}", alert.severity.label(), alert.title);
                reg.push_log(LogKind::Alert, line);
                reg.alerts.push(alert);
            }
            EngineEvent::Guard(status) => reg.guard = Some(*status),
            EngineEvent::SourceStatus { source, state } => {
                if reg.sources.get(&source) != Some(&state) {
                    let line = format!("source {}: {}", source.label(), describe_state(&state));
                    reg.push_log(LogKind::Source, line);
                }
                reg.sources.insert(source, state);
            }
        }
    }
}

pub fn describe_state(state: &SourceState) -> String {
    match state {
        SourceState::Stopped => "stopped".into(),
        SourceState::Running => "running".into(),
        SourceState::Unavailable(why) => format!("unavailable: {why}"),
        SourceState::Failed(why) => format!("failed: {why}"),
    }
}

fn spawn_node(
    commands: &mut Commands,
    assets: &NodeAssets,
    materials: &mut Assets<StandardMaterial>,
    device: &Device,
) -> Entity {
    let material = materials.add(StandardMaterial {
        base_color: Color::BLACK,
        emissive: LinearRgba::BLACK,
        alpha_mode: AlphaMode::Blend,
        perceptual_roughness: 0.35,
        ..default()
    });
    commands
        .spawn((
            DeviceNode { id: device.id },
            Name::new(device.display_name()),
            Mesh3d(assets.mesh_for(device.kind)),
            MeshMaterial3d(material),
            // Born at the origin, invisible; the active view's layout flies it out.
            Transform::from_scale(Vec3::splat(LayoutTarget::HIDDEN_SCALE)),
            LayoutTarget::default(),
        ))
        .id()
}
