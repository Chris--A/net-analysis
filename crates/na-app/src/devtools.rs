//! `--screenshot-dir DIR`: a scripted tour for visual verification.
//! It captures each view, then the inspector with the evil twin, a BLE device, a
//! Classic device, a LAN host and the Karma AP selected, then exits.
//! Combine with `--twin-after 3` so the twin is present early.

use std::path::{Path, PathBuf};

use bevy::prelude::*;
use bevy::render::view::screenshot::{Screenshot, save_to_disk};
use na_model::DeviceKind;

use crate::bridge::Registry;
use crate::picking::Selection;
use crate::ui::UiState;
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

#[allow(clippy::too_many_arguments)] // Bevy system parameters
fn run_tour(
    mut commands: Commands,
    time: Res<Time>,
    reg: Res<Registry>,
    mut tour: ResMut<ScreenshotTour>,
    mut next_view: ResMut<NextState<ViewMode>>,
    mut sel: ResMut<Selection>,
    mut ui_state: ResMut<UiState>,
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
            (0.5, false)
        }
        // A capture shows the end-of-frame state, so change the selection a step before each shot.
        4 => {
            // The best-identified BLE device: decoded model first, then signal.
            sel.selected = reg
                .devices
                .values()
                .filter(|d| d.kind == DeviceKind::Ble)
                .max_by_key(|d| (d.identity.model.is_some(), d.rssi.unwrap_or(i16::MIN)))
                .map(|d| d.id);
            (2.0, false)
        }
        5 => {
            shot(&mut commands, &dir, "5-ble-selected.png");
            (0.5, false)
        }
        6 => {
            sel.selected = reg
                .devices
                .values()
                .filter(|d| d.kind == DeviceKind::BtClassic)
                .max_by_key(|d| d.bt_classic().is_some_and(|c| c.connected))
                .map(|d| d.id);
            (2.0, false)
        }
        7 => {
            shot(&mut commands, &dir, "6-classic-selected.png");
            (0.5, false)
        }
        8 => {
            // The best-described LAN host (most evidence), shown in the LAN-centric view.
            sel.selected = reg
                .devices
                .values()
                .filter(|d| d.kind == DeviceKind::LanHost && !d.lan().is_some_and(|l| l.is_self))
                .max_by_key(|d| d.evidence.len())
                .map(|d| d.id);
            next_view.set(ViewMode::Constellation);
            (4.0, false)
        }
        9 => {
            shot(&mut commands, &dir, "7-lan-selected.png");
            (0.5, false)
        }
        10 => {
            // Open (but never confirm) the active-probing dialog.
            ui_state.confirm_active = true;
            (1.0, false)
        }
        11 => {
            shot(&mut commands, &dir, "8-active-confirm.png");
            (0.5, false)
        }
        12 => {
            ui_state.confirm_active = false;
            // The Karma AP: the riskiest device that isn't the evil twin.
            sel.selected = reg
                .devices
                .values()
                .filter(|d| d.ap().is_some_and(|a| a.bssid.is_locally_administered() && a.channel == 11))
                .max_by(|a, b| a.risk.total_cmp(&b.risk))
                .map(|d| d.id);
            next_view.set(ViewMode::Spectrum);
            (4.0, false)
        }
        13 => {
            shot(&mut commands, &dir, "9-karma-selected.png");
            (0.5, false)
        }
        14 => {
            // Trusting a flagged AP asks first.
            ui_state.confirm_trust = reg
                .devices
                .values()
                .find(|d| d.ap().is_some_and(|a| a.ssid == "HomeNet" && a.security.is_open()))
                .and_then(|d| d.ap().map(|a| (a.bssid, a.ssid.clone())));
            (1.0, false)
        }
        15 => {
            shot(&mut commands, &dir, "10-trust-confirm.png");
            (0.5, false)
        }
        16 => {
            ui_state.confirm_trust = None;
            (0.5, false)
        }
        _ => (0.0, true),
    };
    if done {
        exit.write(AppExit::Success);
    }
    tour.step += 1;
    tour.next_at = time.elapsed_secs() + wait;
}
