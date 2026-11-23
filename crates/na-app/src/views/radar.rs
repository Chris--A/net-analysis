//! Orbital Radar: this host at the centre, devices on class rings.
//!
//! - LAN hosts sit on an inner core ring, evenly spaced by IP.
//! - APs sit on the Wi-Fi ring at a radius set by RSSI. Each SSID owns an angular
//!   sector, so an evil twin lands inside the real network's cluster.
//! - Bluetooth devices form an outer spherical shell that slowly drifts.

use std::collections::HashMap;
use std::f32::consts::{FRAC_PI_4, TAU};
use std::net::IpAddr;

use bevy::prelude::*;
use na_model::{Band, Device, DeviceId, DeviceKind, stable_hash};

use super::{dim, ground, label, signal01, spherical, unit_hash};
use crate::bridge::{DeviceNode, Registry};
use crate::scene::{MainCamera, SelfMarker, kind_color};
use crate::tween::LayoutTarget;

const R_LAN: f32 = 4.5;
const R_WIFI_IN: f32 = 8.0;
const R_WIFI_OUT: f32 = 17.0;
const R_BLE_IN: f32 = 20.0;
const R_BLE_OUT: f32 = 28.0;

pub fn layout(
    time: Res<Time>,
    reg: Res<Registry>,
    mut nodes: Query<(&DeviceNode, &mut LayoutTarget)>,
    mut me: Query<&mut LayoutTarget, (With<SelfMarker>, Without<DeviceNode>)>,
) {
    let lan_slots = lan_slots(&reg);
    let drift = time.elapsed_secs() * 0.01;

    for (node, mut target) in &mut nodes {
        let Some(d) = reg.devices.get(&node.id) else {
            continue;
        };
        *target = match d.kind {
            DeviceKind::LanHost => {
                let (i, n) = lan_slots.get(&d.id).copied().unwrap_or((0, 1));
                let a = i as f32 / n.max(1) as f32 * TAU;
                LayoutTarget::new(
                    Vec3::new(a.cos() * R_LAN, 0.0, a.sin() * R_LAN),
                    Quat::IDENTITY,
                    Vec3::splat(0.9),
                )
            }
            DeviceKind::AccessPoint => {
                let ap = d.ap();
                let ssid = ap.map(|a| a.ssid.as_str()).unwrap_or("");
                let sector = unit_hash(stable_hash(ssid.as_bytes()), 7) * TAU;
                let a = sector + (unit_hash(d.id.0, 11) - 0.5) * 0.45;
                let r = R_WIFI_IN + (1.0 - signal01(d.rssi)) * (R_WIFI_OUT - R_WIFI_IN);
                let y = match ap.map(|a| a.band) {
                    Some(Band::G2_4) => -0.7,
                    Some(Band::G6) => 0.7,
                    _ => 0.0,
                };
                // Diamond: a cube balanced on its corner.
                let rot = Quat::from_rotation_z(FRAC_PI_4) * Quat::from_rotation_x(FRAC_PI_4);
                LayoutTarget::new(Vec3::new(a.cos() * r, y, a.sin() * r), rot, Vec3::splat(0.75))
            }
            _ => {
                let az = unit_hash(d.id.0, 1) * TAU + drift;
                let el = (unit_hash(d.id.0, 2) - 0.5) * 1.1;
                let signal = match d.rssi {
                    Some(_) => signal01(d.rssi),
                    // Connected devices stop advertising (no RSSI) but are close by definition.
                    None if connected(d) => 0.85,
                    // No reading at all (Classic inquiry reports none): neither near nor far.
                    None => 0.5,
                };
                let r = R_BLE_IN + (1.0 - signal) * (R_BLE_OUT - R_BLE_IN);
                LayoutTarget::new(spherical(r, az, el), Quat::IDENTITY, Vec3::splat(0.55))
            }
        };
    }

    if let Ok(mut t) = me.single_mut() {
        *t = LayoutTarget::new(Vec3::ZERO, Quat::IDENTITY, Vec3::ONE);
    }
}

fn connected(d: &Device) -> bool {
    d.ble().is_some_and(|b| b.connected) || d.bt_classic().is_some_and(|c| c.connected)
}

/// Stable, evenly spaced slots for LAN hosts, ordered by IP address.
fn lan_slots(reg: &Registry) -> HashMap<DeviceId, (usize, usize)> {
    let mut lan: Vec<&Device> = reg
        .devices
        .values()
        .filter(|d| d.kind == DeviceKind::LanHost)
        .collect();
    let ip_key = |d: &Device| match d.lan().and_then(|l| l.ips.first()) {
        Some(IpAddr::V4(v4)) => u128::from(u32::from(*v4)),
        Some(IpAddr::V6(v6)) => u128::from(*v6),
        None => u128::MAX,
    };
    lan.sort_by_key(|d| (ip_key(d), d.id));
    let n = lan.len();
    lan.iter().enumerate().map(|(i, d)| (d.id, (i, n))).collect()
}

pub fn scenery(mut gizmos: Gizmos, cam: Query<&GlobalTransform, With<MainCamera>>) {
    let flat = Isometry3d::from_rotation(ground());
    let lan = kind_color(DeviceKind::LanHost);
    let wifi = kind_color(DeviceKind::AccessPoint);
    let ble = kind_color(DeviceKind::Ble);

    gizmos.circle(flat, R_LAN, dim(lan, 0.5)).resolution(96);
    gizmos.circle(flat, R_WIFI_IN, dim(wifi, 0.35)).resolution(128);
    gizmos.circle(flat, R_WIFI_OUT, dim(wifi, 0.2)).resolution(128);
    gizmos.circle(flat, R_BLE_IN, dim(ble, 0.25)).resolution(160);
    gizmos.circle(flat, R_BLE_OUT, dim(ble, 0.15)).resolution(160);

    let spoke = LinearRgba::new(0.05, 0.09, 0.14, 1.0);
    for i in 0..12 {
        let a = i as f32 / 12.0 * TAU;
        let dir = Vec3::new(a.cos(), 0.0, a.sin());
        gizmos.line(dir * 1.5, dir * R_BLE_OUT, spoke);
    }

    let Ok(cam) = cam.single() else {
        return;
    };
    let rot = cam.rotation();
    label(&mut gizmos, rot, Vec3::new(0.0, 0.3, -R_LAN - 0.6), "LAN", 0.55, dim(lan, 1.2));
    label(&mut gizmos, rot, Vec3::new(0.0, 0.3, -R_WIFI_IN + 0.6), "Wi-Fi  -30 dBm", 0.5, dim(wifi, 1.2));
    label(&mut gizmos, rot, Vec3::new(0.0, 0.3, -R_WIFI_OUT - 0.6), "-100 dBm", 0.5, dim(wifi, 0.8));
    label(&mut gizmos, rot, Vec3::new(0.0, 0.3, -R_BLE_OUT - 0.8), "Bluetooth", 0.6, dim(ble, 1.2));
    label(&mut gizmos, rot, Vec3::new(0.0, 1.1, 0.0), "you", 0.45, LinearRgba::gray(1.5));
}
