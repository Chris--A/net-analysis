//! Spectrum City: 2.4 / 5 / 6 GHz "districts" laid out along X, one tower per AP
//! on its primary channel.
//!
//! - Tower height = signal, colour = security (set by the visuals system).
//! - A bar on the ground shows the bonded channel width (e.g. 80 MHz).
//! - Non-AP devices shrink and sink out of the way.

use std::collections::HashMap;

use bevy::prelude::*;
use na_model::{ApInfo, Band, Device, DeviceId};

use super::{dim, ground, label, signal01, unit_hash};
use crate::bridge::{DeviceNode, Registry};
use crate::scene::{MainCamera, SelfMarker, security_color};
use crate::tween::LayoutTarget;

const X24: f32 = -28.0;
const X5: f32 = -14.0;
const X6: f32 = 12.0;
/// Scene units per channel number in each band.
const UNIT24: f32 = 0.8; // channels are 5 MHz apart
const UNIT5: f32 = 0.16; // 0.64 per 20 MHz channel (4 channel numbers)
const UNIT6: f32 = 0.11; // 0.44 per 20 MHz channel
/// Midpoint of the whole layout (2.4 GHz ch 1 … 6 GHz ch 233).
pub const CENTER_X: f32 = 5.0;
const TOWER_W: f32 = 0.45;
const ROW_SPACING: f32 = 1.3;
/// Only the strongest towers get a floating SSID label, to avoid clutter.
const MAX_TOWER_LABELS: usize = 25;

pub fn channel_x(band: Band, channel: u16) -> f32 {
    let ch = f32::from(channel);
    match band {
        Band::G2_4 => X24 + (ch - 1.0) * UNIT24,
        Band::G5 => X5 + (ch - 36.0) * UNIT5,
        Band::G6 => X6 + (ch - 1.0) * UNIT6,
    }
}

fn units_per_channel_number(band: Band) -> f32 {
    match band {
        Band::G2_4 => UNIT24,
        Band::G5 => UNIT5,
        Band::G6 => UNIT6,
    }
}

/// Centre channel number of the bonded block containing `ap.channel`.
fn bonded_center(ap: &ApInfo) -> f32 {
    let n = u16::max(ap.width_mhz / 20, 1);
    if ap.band == Band::G2_4 || n == 1 {
        return f32::from(ap.channel);
    }
    let base = match (ap.band, ap.channel) {
        (Band::G5, c) if c < 100 => 36,
        (Band::G5, c) if c < 149 => 100,
        (Band::G5, _) => 149,
        _ => 1,
    };
    let block = 4 * n;
    let start = base + (ap.channel.saturating_sub(base) / block) * block;
    f32::from(start) + f32::from(2 * (n - 1))
}

/// Row index for each AP. APs sharing a channel stack front-to-back, strongest first.
fn rows(reg: &Registry) -> HashMap<DeviceId, usize> {
    let mut groups: HashMap<(Band, u16), Vec<&Device>> = HashMap::new();
    for d in reg.devices.values() {
        if let Some(ap) = d.ap() {
            groups.entry((ap.band, ap.channel)).or_default().push(d);
        }
    }
    let mut out = HashMap::new();
    for list in groups.values_mut() {
        list.sort_by_key(|d| (std::cmp::Reverse(d.rssi.unwrap_or(i16::MIN)), d.id));
        for (i, d) in list.iter().enumerate() {
            out.insert(d.id, i);
        }
    }
    out
}

fn tower_height(d: &Device) -> f32 {
    0.4 + signal01(d.rssi) * 8.0
}

pub fn layout(
    reg: Res<Registry>,
    mut nodes: Query<(&DeviceNode, &mut LayoutTarget)>,
    mut me: Query<&mut LayoutTarget, (With<SelfMarker>, Without<DeviceNode>)>,
) {
    let rows = rows(&reg);
    for (node, mut target) in &mut nodes {
        let Some(d) = reg.devices.get(&node.id) else {
            continue;
        };
        *target = match d.ap() {
            Some(ap) => {
                let h = tower_height(d);
                let row = rows.get(&d.id).copied().unwrap_or(0);
                let x = channel_x(ap.band, ap.channel);
                let z = 1.5 + row as f32 * ROW_SPACING;
                LayoutTarget::new(Vec3::new(x, h / 2.0, z), Quat::IDENTITY, Vec3::new(TOWER_W, h, TOWER_W))
            }
            None => {
                // Park non-AP devices below the floor.
                let x = (unit_hash(d.id.0, 21) - 0.5) * 70.0 + CENTER_X;
                let z = unit_hash(d.id.0, 22) * 12.0;
                LayoutTarget::hidden_at(Vec3::new(x, -6.0, z))
            }
        };
    }
    if let Ok(mut t) = me.single_mut() {
        *t = LayoutTarget::hidden_at(Vec3::new(CENTER_X, -6.0, 0.0));
    }
}

pub fn scenery(reg: Res<Registry>, mut gizmos: Gizmos, cam: Query<&GlobalTransform, With<MainCamera>>) {
    let cam_rot = cam.single().map(|c| c.rotation()).unwrap_or_default();
    let axis = LinearRgba::new(0.15, 0.3, 0.45, 1.0);
    let tick = LinearRgba::new(0.08, 0.16, 0.25, 1.0);
    let text = LinearRgba::new(0.45, 0.75, 1.1, 1.0);

    gizmos.grid(
        Isometry3d::new(Vec3::new(CENTER_X, -0.01, 3.0), ground()),
        UVec2::new(76, 12),
        Vec2::splat(1.0),
        LinearRgba::new(0.02, 0.035, 0.055, 1.0),
    );

    let districts: [(Band, &str, Vec<u16>, &[u16]); 3] = [
        (Band::G2_4, "2.4 GHz", (1..=13).collect(), &[1, 6, 11]),
        (
            Band::G5,
            "5 GHz",
            (36..=64).step_by(4).chain((100..=144).step_by(4)).chain((149..=177).step_by(4)).collect(),
            &[36, 52, 100, 149, 165],
        ),
        (Band::G6, "6 GHz", (1..=233).step_by(4).collect(), &[1, 37, 69, 101, 133, 165, 197, 229]),
    ];

    for (band, name, channels, labelled) in &districts {
        let (Some(first), Some(last)) = (channels.first(), channels.last()) else {
            continue;
        };
        let x0 = channel_x(*band, *first);
        let x1 = channel_x(*band, *last);
        gizmos.line(Vec3::new(x0 - 0.5, 0.0, 0.0), Vec3::new(x1 + 0.5, 0.0, 0.0), axis);
        for ch in channels {
            let x = channel_x(*band, *ch);
            gizmos.line(Vec3::new(x, 0.0, 0.0), Vec3::new(x, 0.0, 0.35), tick);
        }
        for ch in *labelled {
            let x = channel_x(*band, *ch);
            label(&mut gizmos, cam_rot, Vec3::new(x, 0.0, -1.0), &ch.to_string(), 0.35, dim(text, 0.8));
        }
        label(&mut gizmos, cam_rot, Vec3::new((x0 + x1) / 2.0, 0.0, -3.6), name, 0.9, text);
    }

    let rows = rows(&reg);

    // SSID labels floating above the strongest towers.
    let mut aps: Vec<&Device> = reg.devices.values().filter(|d| d.ap().is_some()).collect();
    aps.sort_by_key(|d| std::cmp::Reverse(d.rssi.unwrap_or(i16::MIN)));
    for d in aps.into_iter().take(MAX_TOWER_LABELS) {
        let Some(ap) = d.ap() else {
            continue;
        };
        let row = rows.get(&d.id).copied().unwrap_or(0);
        let top = Vec3::new(
            channel_x(ap.band, ap.channel),
            tower_height(d) + 0.45,
            1.5 + row as f32 * ROW_SPACING,
        );
        label(&mut gizmos, cam_rot, top, ap.display_ssid(), 0.3, dim(security_color(&ap.security), 1.2));
    }

    // Channel-width bars on the ground in front of each tower.
    for d in reg.devices.values() {
        let Some(ap) = d.ap() else {
            continue;
        };
        let row = rows.get(&d.id).copied().unwrap_or(0);
        let z = 1.5 + row as f32 * ROW_SPACING + TOWER_W;
        let center = channel_x(ap.band, 0) + bonded_center(ap) * units_per_channel_number(ap.band);
        // 20 MHz spans 4 channel numbers in every band.
        let half = f32::from(ap.width_mhz) / 20.0 * 4.0 * units_per_channel_number(ap.band) / 2.0;
        let c = dim(security_color(&ap.security), 0.7);
        let y = 0.02;
        gizmos.line(Vec3::new(center - half, y, z), Vec3::new(center + half, y, z), c);
        gizmos.line(Vec3::new(center - half, y, z - 0.15), Vec3::new(center - half, y, z + 0.15), c);
        gizmos.line(Vec3::new(center + half, y, z - 0.15), Vec3::new(center + half, y, z + 0.15), c);
    }
}

#[cfg(test)]
mod tests {
    use na_model::{MacAddr, Security};

    use super::*;

    fn ap(band: Band, channel: u16, width_mhz: u16) -> ApInfo {
        ApInfo {
            ssid: String::new(),
            bssid: MacAddr::default(),
            channel,
            band,
            width_mhz,
            security: Security::open(),
            wifi_gen: None,
            beacon_interval_tu: 100,
            tsf_uptime_secs: None,
            wps: None,
            ie_fingerprint: 0,
            connected: false,
        }
    }

    #[test]
    fn bonded_centres() {
        // 80 MHz block 36-48 is centred on channel 42; 149-161 on 155.
        assert_eq!(bonded_center(&ap(Band::G5, 44, 80)), 42.0);
        assert_eq!(bonded_center(&ap(Band::G5, 157, 80)), 155.0);
        assert_eq!(bonded_center(&ap(Band::G5, 100, 40)), 102.0);
        // 6 GHz 160 MHz block 33-61 is centred on 47.
        assert_eq!(bonded_center(&ap(Band::G6, 37, 160)), 47.0);
        assert_eq!(bonded_center(&ap(Band::G2_4, 6, 20)), 6.0);
    }

    #[test]
    fn districts_do_not_overlap() {
        assert!(channel_x(Band::G2_4, 14) < channel_x(Band::G5, 36));
        assert!(channel_x(Band::G5, 177) < channel_x(Band::G6, 1));
    }
}
