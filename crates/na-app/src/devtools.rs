//! `--screenshot-dir DIR`: a scripted tour for visual verification.
//! It captures each view, plus the inspector with the evil twin selected, then exits.
//! Combine with `--twin-after 3` so the twin is present early.

use std::path::{Path, PathBuf};

use bevy::prelude::*;
use bevy::render::view::screenshot::{Screenshot, save_to_disk};
use na_model::DeviceKind;

use crate::bridge::Registry;
use crate::picking::Selection;
use crate::views::ViewMode;

pub struct DevToolsPlugin {
    pub screenshot_dir: Option<PathBuf>,
}

impl Plugin for DevToolsPlugin {
    fn build(&self, app: &mut App) {
        if let Some(dir) = &self.screenshot_dir {
            if let Err(e) = std::fs::create_dir_all(dir) {
                error!("cannot create screenshot dir {}: {e}", dir.display());
                return;
            }
            app.insert_resource(ScreenshotTour {
                dir: dir.clone(),
                step: 0,
                next_at: 8.0,
            })
            .add_systems(Update, run_tour);
        }
    }
}

#[derive(Resource)]
struct ScreenshotTour {
    dir: PathBuf,
    step: usize,
    next_at: f32,
}

fn shot(commands: &mut Commands, dir: &Path, name: &str) {
    let path = dir.join(name);
    info!("screenshot → {}", path.display());
    commands.spawn(Screenshot::primary_window()).observe(save_to_disk(path));
}

fn run_tour(
    mut commands: Commands,
    time: Res<Time>,
    reg: Res<Registry>,
    mut tour: ResMut<ScreenshotTour>,
    mut next_view: ResMut<NextState<ViewMode>>,
    mut sel: ResMut<Selection>,
    mut exit: MessageWriter<AppExit>,
) {
    if time.elapsed_secs() < tour.next_at {
        return;
    }
    let dir = tour.dir.clone();
    let (wait, done) = match tour.step {
        0 => {
            shot(&mut commands, &dir, "1-radar.png");
            next_view.set(ViewMode::Constellation);
            (7.0, false)
        }
        1 => {
            shot(&mut commands, &dir, "2-constellation.png");
            next_view.set(ViewMode::Spectrum);
            (5.0, false)
        }
        2 => {
            shot(&mut commands, &dir, "3-spectrum.png");
            // Prefer the open "HomeNet" twin. Otherwise take the strongest AP.
            let pick = reg
                .devices
                .values()
                .filter(|d| d.kind == DeviceKind::AccessPoint)
                .max_by_key(|d| {
                    let twin = d.ap().is_some_and(|a| a.ssid == "HomeNet" && a.security.is_open());
                    (twin, d.rssi.unwrap_or(i16::MIN))
                })
                .map(|d| d.id);
            sel.selected = pick;
            next_view.set(ViewMode::Radar);
            (5.0, false)
        }
        3 => {
            shot(&mut commands, &dir, "4-radar-selected.png");
            (2.0, false)
        }
        _ => (0.0, true),
    };
    if done {
        exit.write(AppExit::Success);
    }
    tour.step += 1;
    tour.next_at = time.elapsed_secs() + wait;
}
