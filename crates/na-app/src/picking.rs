//! Selection and hover state, fed by Bevy mesh picking and by the UI lists.

use bevy::picking::pointer::PointerButton;
use bevy::prelude::*;
use na_model::DeviceId;

use crate::bridge::DeviceNode;

pub struct SelectionPlugin;

impl Plugin for SelectionPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<Selection>()
            .add_observer(on_click)
            .add_observer(on_over)
            .add_observer(on_out)
            .add_systems(Update, escape_clears_selection);
    }
}

#[derive(Resource, Default, Debug)]
pub struct Selection {
    pub selected: Option<DeviceId>,
    /// Pointer is over this device in the 3D view.
    pub hovered: Option<DeviceId>,
}

// Pointer events bubble from the hit entity up to the window, so these global
// observers see every pick and simply ignore non-device entities.

fn on_click(mut click: On<PointerClick>, nodes: Query<&DeviceNode>, mut sel: ResMut<Selection>) {
    if click.button != PointerButton::Primary {
        return;
    }
    if let Ok(node) = nodes.get(click.entity) {
        sel.selected = Some(node.id);
        click.propagate(false);
    }
}

fn on_over(over: On<PointerOver>, nodes: Query<&DeviceNode>, mut sel: ResMut<Selection>) {
    if let Ok(node) = nodes.get(over.entity) {
        sel.hovered = Some(node.id);
    }
}

fn on_out(out: On<PointerOut>, nodes: Query<&DeviceNode>, mut sel: ResMut<Selection>) {
    if let Ok(node) = nodes.get(out.entity)
        && sel.hovered == Some(node.id)
    {
        sel.hovered = None;
    }
}

fn escape_clears_selection(keys: Res<ButtonInput<KeyCode>>, mut sel: ResMut<Selection>) {
    if keys.just_pressed(KeyCode::Escape) {
        sel.selected = None;
    }
}
