//! 3D frontend. The engine owns all data. This app only drains its events
//! into a [`bridge::Registry`] and projects that registry through one of
//! three interchangeable views (Radar, Constellation, Spectrum).

mod bridge;
mod devtools;
mod picking;
mod scene;
mod tween;
mod ui;
mod views;

use bevy::diagnostic::FrameTimeDiagnosticsPlugin;
use bevy::prelude::*;
use bevy_egui::EguiPlugin;
use bevy_panorbit_camera::PanOrbitCameraPlugin;

/// Per-frame ordering: engine events in → layout targets → filters/emphasis → animation → materials.
#[derive(SystemSet, Debug, Clone, PartialEq, Eq, Hash)]
pub enum FrameSet {
    Ingest,
    Layout,
    Adjust,
    Animate,
    Visuals,
}

fn main() {
    let opts = bridge::LaunchOptions::from_args();
    App::new()
        .add_plugins(DefaultPlugins.set(WindowPlugin {
            primary_window: Some(Window {
                title: "net-analysis".into(),
                resolution: (1600, 960).into(),
                ..default()
            }),
            ..default()
        }))
        .add_plugins((
            EguiPlugin::default(),
            PanOrbitCameraPlugin,
            MeshPickingPlugin,
            FrameTimeDiagnosticsPlugin::default(),
        ))
        .configure_sets(
            Update,
            (
                FrameSet::Ingest,
                FrameSet::Layout,
                FrameSet::Adjust,
                FrameSet::Animate,
                FrameSet::Visuals,
            )
                .chain(),
        )
        .add_plugins(devtools::DevToolsPlugin {
            screenshot_dir: opts.screenshot_dir.clone(),
        })
        .insert_resource(opts)
        .add_plugins((
            scene::ScenePlugin,
            bridge::BridgePlugin,
            views::ViewsPlugin,
            tween::TweenPlugin,
            picking::SelectionPlugin,
            ui::UiPlugin,
        ))
        .run();
}
