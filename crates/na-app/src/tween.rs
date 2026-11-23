//! Views never move entities directly. They write a [`LayoutTarget`], and this
//! module eases every entity toward its target. As a result, switching views morphs
//! the whole scene instead of cutting.

use bevy::prelude::*;

use crate::FrameSet;

/// Higher = snappier. ~7 gives a ~0.4 s settle.
const EASE_RATE: f32 = 7.0;

pub struct TweenPlugin;

impl Plugin for TweenPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Update, animate.in_set(FrameSet::Animate));
    }
}

#[derive(Component, Clone, Copy, Debug)]
pub struct LayoutTarget {
    pub translation: Vec3,
    pub rotation: Quat,
    pub scale: Vec3,
}

impl LayoutTarget {
    /// Zero scale produces degenerate normal matrices, so "hidden" is just very small.
    pub const HIDDEN_SCALE: f32 = 0.001;

    pub fn new(translation: Vec3, rotation: Quat, scale: Vec3) -> Self {
        Self { translation, rotation, scale }
    }

    pub fn hidden_at(translation: Vec3) -> Self {
        Self::new(translation, Quat::IDENTITY, Vec3::splat(Self::HIDDEN_SCALE))
    }

    pub fn is_hidden(&self) -> bool {
        self.scale.max_element() <= Self::HIDDEN_SCALE * 2.0
    }
}

impl Default for LayoutTarget {
    fn default() -> Self {
        Self::hidden_at(Vec3::ZERO)
    }
}

fn animate(time: Res<Time>, mut q: Query<(&LayoutTarget, &mut Transform, &mut Visibility)>) {
    let k = 1.0 - (-EASE_RATE * time.delta_secs()).exp();
    for (target, mut tf, mut vis) in &mut q {
        tf.translation = tf.translation.lerp(target.translation, k);
        tf.rotation = tf.rotation.slerp(target.rotation, k);
        tf.scale = tf.scale.lerp(target.scale, k);

        // Fully shrunk entities are hidden so they can't be picked.
        let hidden = target.is_hidden() && tf.scale.max_element() < 0.02;
        let want = if hidden { Visibility::Hidden } else { Visibility::Inherited };
        if *vis != want {
            *vis = want;
        }
    }
}
