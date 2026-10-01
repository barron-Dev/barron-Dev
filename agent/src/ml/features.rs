use serde_json::Value;

pub const N_FEATURES: usize = 24;

pub const FEATURE_NAMES: [&str; N_FEATURES] = [
    "entropy", "is_signed", "is_packed", "size_log", "suspicious_imports",
    "network_connections", "child_processes", "file_writes", "registry_writes",
    "mass_file_writes", "encrypts_files", "deletes_shadow_copies",
    "disables_defender", "injects_process", "creates_remote_thread",
    "persistence_registry", "suspicious_parent", "network_beacon",
    "is_process", "is_file", "is_network", "is_registry", "is_sensor", "is_identity",
];

fn num(p: &Value, key: &str) -> f32 {
    match p.get(key) {
        Some(Value::Bool(b)) => if *b { 1.0 } else { 0.0 },
        Some(Value::Number(n)) => n.as_f64()
            .filter(|f| f.is_finite())
            .map(|f| f as f32)
            .unwrap_or(0.0),
        _ => 0.0,
    }
}

fn flag(p: &Value, key: &str) -> f32 {
    match p.get(key).and_then(|v| v.as_bool()) {
        Some(true) => 1.0,
        _ => 0.0,
    }
}

/// Must remain structurally identical to sentinel.ml.features.extract().
pub fn extract(event_type: &str, payload: &Value) -> [f32; N_FEATURES] {
    let size = num(payload, "size").max(0.0);
    let size_log = (size + 1.0).ln();
    let kind = event_type.to_lowercase();
    let signed = match payload.get("signed") {
        Some(Value::Bool(true)) => 1.0,
        _ => 0.0,
    };
    let imports_len = payload
        .get("suspicious_imports")
        .and_then(|v| v.as_array())
        .map(|a| a.len() as f32)
        .unwrap_or(0.0);

    [
        num(payload, "entropy"), signed, flag(payload, "is_packed"), size_log,
        imports_len, num(payload, "network_connections"),
        num(payload, "child_processes"), num(payload, "file_writes"),
        num(payload, "registry_writes"), flag(payload, "mass_file_writes"),
        flag(payload, "encrypts_files"), flag(payload, "deletes_shadow_copies"),
        flag(payload, "disables_defender"), flag(payload, "injects_process"),
        flag(payload, "creates_remote_thread"), flag(payload, "persistence_registry"),
        flag(payload, "suspicious_parent"), flag(payload, "network_beacon"),
        if kind == "process" { 1.0 } else { 0.0 },
        if kind == "file" { 1.0 } else { 0.0 },
        if kind == "network" { 1.0 } else { 0.0 },
        if kind == "registry" { 1.0 } else { 0.0 },
        if kind == "sensor" { 1.0 } else { 0.0 },
        if kind == "identity" { 1.0 } else { 0.0 },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn kind_is_exclusive() {
        for kind in ["process", "file", "network", "registry", "sensor", "identity"] {
            let v = extract(kind, &json!({}));
            assert_eq!(v[18..].iter().sum::<f32>(), 1.0);
        }
    }

    #[test]
    fn missing_fields_are_zero_except_kind() {
        let v = extract("file", &json!({}));
        assert_eq!(v[..18].iter().sum::<f32>(), 0.0);
    }

    #[test]
    fn non_finite_values_are_zero() {
        // JSON cannot represent NaN/Infinity, so exercise the same fallback
        // through non-numeric JSON values.
        let v = extract("file", &json!({"entropy": "NaN", "size": null}));
        assert!(v.iter().all(|x| x.is_finite()));
        assert_eq!(v[0], 0.0);
        assert_eq!(v[3], 0.0);
    }
}
