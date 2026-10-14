//! A deployment record's two halves (`docs/design/fleet-shared-state.md` § 1).
//!
//! A deployment's on-disk record is `{spec, state}`. In a fleet, the spec and
//! the state fields every host must agree on go to the fleet store; the rest
//! of the state describes one host's own daemon and stays in that host's file.
//! These functions split and rejoin the JSON, and stamp a placement onto a
//! fleet half that has none.
//!
//! Only `serde_json`, because the `app-lb-fleet-import` binary compiles this
//! file too.

/// The state fields every fleet host must agree on (`docs/design/fleet-shared-state.md`
/// § 1). Everything else in [`DeploymentState`] — suspended sandboxes, create
/// attempts, rollouts, the active prefix, a retirement freeze — describes this
/// host's own daemon and stays in its own file. A field added later is host
/// state until it is listed here.
pub const FLEET_STATE_FIELDS: &[&str] = &["upstream_drains", "discovery_version", "route_handoff"];

/// A whole record's fleet half: the spec and the [`FLEET_STATE_FIELDS`].
pub fn fleet_half(record: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut value: serde_json::Value = serde_json::from_slice(record)?;
    if let Some(state) = value.get_mut("state").and_then(|s| s.as_object_mut()) {
        state.retain(|k, _| FLEET_STATE_FIELDS.contains(&k.as_str()));
    }
    Ok(serde_json::to_vec_pretty(&value)?)
}

/// A whole record from the fleet's half and this host's own record, if any:
/// the fleet's spec and fleet fields, this host's everything else.
pub fn merge_halves(fleet: &[u8], host: Option<&[u8]>) -> std::io::Result<Vec<u8>> {
    let mut merged: serde_json::Value = serde_json::from_slice(fleet)?;
    let mut state = match host {
        Some(bytes) => {
            let host: serde_json::Value = serde_json::from_slice(bytes)?;
            host.get("state")
                .and_then(|s| s.as_object())
                .cloned()
                .unwrap_or_default()
        }
        None => serde_json::Map::new(),
    };
    state.retain(|k, _| !FLEET_STATE_FIELDS.contains(&k.as_str()));
    if let Some(fleet_state) = merged.get("state").and_then(|s| s.as_object()) {
        for (k, v) in fleet_state {
            if FLEET_STATE_FIELDS.contains(&k.as_str()) {
                state.insert(k.clone(), v.clone());
            }
        }
    }
    merged["state"] = serde_json::Value::Object(state);
    Ok(serde_json::to_vec_pretty(&merged)?)
}

/// A fleet half with `spec.placement` pinned to `home`, unless the spec
/// already says where it runs.
#[cfg_attr(not(test), allow(dead_code))] // the importer's
pub fn pin_to(fleet_half: &[u8], home: &str) -> std::io::Result<Vec<u8>> {
    let mut value: serde_json::Value = serde_json::from_slice(fleet_half)?;
    let Some(spec) = value.get_mut("spec").and_then(|s| s.as_object_mut()) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "a deployment record with no spec",
        ));
    };
    spec.entry("placement")
        .or_insert_with(|| serde_json::json!({"mode": "pinned", "home": home}));
    Ok(serde_json::to_vec_pretty(&value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinning_stamps_a_home_and_keeps_an_explicit_placement() {
        let half = br#"{"spec":{"id":"x"},"state":{}}"#;
        let pinned: serde_json::Value =
            serde_json::from_slice(&pin_to(half, "us5").unwrap()).unwrap();
        assert_eq!(
            pinned["spec"]["placement"],
            serde_json::json!({"mode": "pinned", "home": "us5"})
        );
        let explicit = br#"{"spec":{"id":"x","placement":{"mode":"pinned","home":"us4"}}}"#;
        let kept: serde_json::Value =
            serde_json::from_slice(&pin_to(explicit, "us5").unwrap()).unwrap();
        assert_eq!(kept["spec"]["placement"]["home"], "us4");
        assert!(pin_to(b"{}", "us5").is_err());
    }
}
