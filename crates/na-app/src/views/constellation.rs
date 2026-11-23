//! Network Constellation: a 3D force-directed graph.
//!
//! - The gateway is pinned at the centre. LAN hosts hang off it.
//! - Every SSID is a virtual hub node linking its BSSIDs.
//! - The gateway links to the APs the engine says belong to it.
//! - Open ports orbit their hosts as small satellites.
//! - BLE devices drift in an outer cloud and take no part in the forces.

use std::collections::{HashMap, HashSet};
use std::f32::consts::TAU;

use bevy::prelude::*;
use na_model::{DeviceId, DeviceKind, stable_hash};

use super::{dim, label, signal01, spherical, unit_hash};
use crate::bridge::{DeviceNode, Registry};
use crate::picking::Selection;
use crate::scene::{MainCamera, SelfMarker, kind_color};
use crate::tween::LayoutTarget;

const REPULSION: f32 = 45.0;
const SPRING: f32 = 4.0;
const CENTERING: f32 = 0.04;
const FLATTEN: f32 = 0.25;
const DAMPING: f32 = 0.88;
const MAX_SPEED: f32 = 25.0;
const SUBSTEPS: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum GraphKey {
    Device(DeviceId),
    Ssid(u64),
    Me,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EdgeKind {
    Ssid,
    Lan,
    Link,
    Me,
}

#[derive(Resource, Default)]
pub struct ForceGraph {
    pos: HashMap<GraphKey, Vec3>,
    vel: HashMap<GraphKey, Vec3>,
    ssid_names: HashMap<u64, String>,
    edges: Vec<(GraphKey, GraphKey, f32, EdgeKind)>,
}

impl ForceGraph {
    fn rebuild(&mut self, reg: &Registry) -> HashSet<GraphKey> {
        self.edges.clear();
        let mut keys: HashSet<GraphKey> = HashSet::from([GraphKey::Me]);
        let gateway = reg.gateway().map(|g| g.id);
        let mut self_host = None;

        for d in reg.devices.values() {
            let k = GraphKey::Device(d.id);
            match d.kind {
                DeviceKind::AccessPoint => {
                    let ssid = d.ap().map(|a| a.display_ssid().to_owned()).unwrap_or_default();
                    let h = stable_hash(ssid.as_bytes());
                    self.ssid_names.entry(h).or_insert(ssid);
                    keys.insert(k);
                    keys.insert(GraphKey::Ssid(h));
                    self.edges.push((k, GraphKey::Ssid(h), 2.2, EdgeKind::Ssid));
                }
                DeviceKind::LanHost => {
                    keys.insert(k);
                    let lan = d.lan();
                    if lan.is_some_and(|l| l.is_self) {
                        self_host = Some(k);
                    }
                    if let Some(gw) = gateway
                        && gw != d.id
                    {
                        self.edges.push((k, GraphKey::Device(gw), 5.0, EdgeKind::Lan));
                    }
                }
                _ => continue,
            }
            for link in &d.links {
                if reg.devices.contains_key(link) {
                    self.edges.push((k, GraphKey::Device(*link), 4.0, EdgeKind::Link));
                }
            }
        }

        match (self_host, gateway) {
            (Some(host), _) => self.edges.push((GraphKey::Me, host, 1.4, EdgeKind::Me)),
            (None, Some(gw)) => self.edges.push((GraphKey::Me, GraphKey::Device(gw), 3.0, EdgeKind::Me)),
            (None, None) => {}
        }

        self.pos.retain(|k, _| keys.contains(k));
        self.vel.retain(|k, _| keys.contains(k));
        keys
    }

    fn seed_position(&self, key: GraphKey) -> Vec3 {
        let id = match key {
            GraphKey::Device(d) => d.0,
            GraphKey::Ssid(h) => h,
            GraphKey::Me => 0,
        };
        // Start near a connected node if one is already placed, so new nodes don't fly in from afar.
        let anchor = self
            .edges
            .iter()
            .find_map(|(a, b, _, _)| match (*a == key, *b == key) {
                (true, _) => self.pos.get(b),
                (_, true) => self.pos.get(a),
                _ => None,
            })
            .copied()
            .unwrap_or(Vec3::ZERO);
        anchor + spherical(3.0 + unit_hash(id, 3) * 5.0, unit_hash(id, 4) * TAU, (unit_hash(id, 5) - 0.5) * 0.8)
    }

    fn step(&mut self, keys: &HashSet<GraphKey>, dt: f32, pinned: Option<GraphKey>) {
        for k in keys {
            if !self.pos.contains_key(k) {
                let p = self.seed_position(*k);
                self.pos.insert(*k, p);
            }
        }
        let nodes: Vec<(GraphKey, Vec3)> = self.pos.iter().map(|(k, p)| (*k, *p)).collect();
        let index: HashMap<GraphKey, usize> = nodes.iter().enumerate().map(|(i, (k, _))| (*k, i)).collect();
        let mut force = vec![Vec3::ZERO; nodes.len()];

        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                let d = nodes[i].1 - nodes[j].1;
                let dist2 = d.length_squared().max(0.25);
                let f = d.normalize_or_zero() * (REPULSION / dist2);
                force[i] += f;
                force[j] -= f;
            }
        }
        for (a, b, rest, _) in &self.edges {
            let (Some(&ia), Some(&ib)) = (index.get(a), index.get(b)) else {
                continue;
            };
            let d = nodes[ib].1 - nodes[ia].1;
            let len = d.length().max(0.01);
            let f = d / len * (len - rest) * SPRING;
            force[ia] += f;
            force[ib] -= f;
        }

        for (i, (k, p)) in nodes.iter().enumerate() {
            if Some(*k) == pinned {
                self.pos.insert(*k, Vec3::ZERO);
                self.vel.insert(*k, Vec3::ZERO);
                continue;
            }
            let f = force[i] - *p * CENTERING - Vec3::Y * p.y * FLATTEN;
            let v = self.vel.entry(*k).or_default();
            *v = ((*v + f * dt) * DAMPING).clamp_length_max(MAX_SPEED);
            let np = *p + *v * dt;
            self.pos.insert(*k, np);
        }
    }
}

/// Camera distance that frames the graph. Its radius grows roughly with √(node count).
pub fn framing_radius(reg: &Registry) -> f32 {
    let mut ssids = HashSet::new();
    let mut n = 1; // this host
    for d in reg.devices.values() {
        match d.kind {
            DeviceKind::AccessPoint => {
                n += 1;
                ssids.insert(d.ap().map(|a| a.ssid.as_str()).unwrap_or(""));
            }
            DeviceKind::LanHost => n += 1,
            _ => {}
        }
    }
    (6.0 * ((n + ssids.len()) as f32).sqrt()).max(30.0)
}

pub fn simulate(
    time: Res<Time>,
    reg: Res<Registry>,
    mut graph: ResMut<ForceGraph>,
    mut nodes: Query<(&DeviceNode, &mut LayoutTarget)>,
    mut me: Query<&mut LayoutTarget, (With<SelfMarker>, Without<DeviceNode>)>,
) {
    let keys = graph.rebuild(&reg);
    let pinned = reg.gateway().map(|g| GraphKey::Device(g.id));
    let dt = time.delta_secs().min(1.0 / 30.0) / SUBSTEPS as f32;
    for _ in 0..SUBSTEPS {
        graph.step(&keys, dt, pinned);
    }

    let drift = time.elapsed_secs() * 0.03;
    for (node, mut target) in &mut nodes {
        let Some(d) = reg.devices.get(&node.id) else {
            continue;
        };
        *target = match graph.pos.get(&GraphKey::Device(node.id)) {
            Some(p) => {
                let s = if d.kind == DeviceKind::AccessPoint { 0.7 } else { 0.9 };
                LayoutTarget::new(*p, Quat::IDENTITY, Vec3::splat(s))
            }
            None => {
                // BLE cloud.
                let az = unit_hash(d.id.0, 1) * TAU + drift;
                let el = (unit_hash(d.id.0, 2) - 0.5) * 1.2;
                let r = 30.0 + (1.0 - signal01(d.rssi)) * 8.0;
                LayoutTarget::new(spherical(r, az, el), Quat::IDENTITY, Vec3::splat(0.45))
            }
        };
    }
    if let (Ok(mut t), Some(p)) = (me.single_mut(), graph.pos.get(&GraphKey::Me)) {
        *t = LayoutTarget::new(*p, Quat::IDENTITY, Vec3::splat(0.8));
    }
}

#[allow(clippy::too_many_arguments)]
pub fn scenery(
    time: Res<Time>,
    reg: Res<Registry>,
    graph: Res<ForceGraph>,
    sel: Res<Selection>,
    mut gizmos: Gizmos,
    nodes: Query<(&DeviceNode, &Transform)>,
    me: Query<&Transform, With<SelfMarker>>,
    cam: Query<&GlobalTransform, With<MainCamera>>,
) {
    // Draw from the animated transforms so lines stay attached while nodes move.
    let mut at: HashMap<GraphKey, Vec3> = nodes
        .iter()
        .map(|(n, tf)| (GraphKey::Device(n.id), tf.translation))
        .collect();
    if let Ok(tf) = me.single() {
        at.insert(GraphKey::Me, tf.translation);
    }
    let pos = |k: &GraphKey| at.get(k).or_else(|| graph.pos.get(k)).copied();

    for (a, b, _, kind) in &graph.edges {
        let (Some(pa), Some(pb)) = (pos(a), pos(b)) else {
            continue;
        };
        let color = match kind {
            EdgeKind::Ssid => dim(kind_color(DeviceKind::AccessPoint), 0.35),
            EdgeKind::Lan => dim(kind_color(DeviceKind::LanHost), 0.3),
            EdgeKind::Link => LinearRgba::gray(0.45),
            EdgeKind::Me => LinearRgba::gray(0.8),
        };
        gizmos.line(pa, pb, color);
    }

    let cam_rot = cam.single().map(|c| c.rotation()).unwrap_or_default();
    let wifi = kind_color(DeviceKind::AccessPoint);
    for (h, name) in &graph.ssid_names {
        if let Some(p) = graph.pos.get(&GraphKey::Ssid(*h)) {
            gizmos.sphere(*p, 0.25, dim(wifi, 0.8));
            label(&mut gizmos, cam_rot, *p + Vec3::Y * 0.7, name, 0.4, dim(wifi, 1.1));
        }
    }

    // Open ports orbit their host.
    let t = time.elapsed_secs();
    let lan = kind_color(DeviceKind::LanHost);
    for (node, tf) in &nodes {
        let Some(l) = reg.devices.get(&node.id).and_then(|d| d.lan()) else {
            continue;
        };
        let n = l.open_ports.len().max(1) as f32;
        let selected = sel.selected == Some(node.id);
        for (i, port) in l.open_ports.iter().enumerate() {
            let a = i as f32 / n * TAU + t * 0.4;
            let p = tf.translation + Vec3::new(a.cos() * 1.3, 0.25 * (t + i as f32).sin(), a.sin() * 1.3);
            gizmos.sphere(p, 0.09, dim(lan, 1.4));
            if selected {
                label(&mut gizmos, cam_rot, p + Vec3::Y * 0.3, &port.to_string(), 0.3, dim(lan, 1.5));
            }
        }
    }
}
