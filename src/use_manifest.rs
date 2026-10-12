//! `.est/vault.toml` secret-use manifests: the single reader, living
//! beside the vault it names. Every EST tool resolves secret
//! dependencies through this module: `est-health` fleet discovery,
//! `est check` validation, and `est` (`exec`, `inject`, `env`) — one
//! implementation, one profile rule, no divergent copies.
//!
//! Shape:
//! ```toml
//! [use]
//! OPENROUTER_KEY = "OPENROUTER:KEY:ESTIFIE"
//! API_KEY = { address = "X:Y:Z", optional = true }
//! [use.prod]
//! DATABASE_URL = "BACKEND:DATABASEURL:PROD"
//! ```
//! Base keys come from `[use]`; the active profile (`--env`, else
//! `EST_ENV`, else `dev` when present, else the first profile, else
//! `default`) overlays `[use.<profile>]`. A table shaped exactly like
//! `{ address, optional? }` is an inline mapping; any other table is
//! a profile — so a profile may even declare an env var literally
//! named `address`. Malformed entries are errors, never silence.

use std::path::Path;

/// One secret dependency: an env var fed from a vault address.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultUseMapping {
    /// Environment variable to inject (e.g. `OPENROUTER_KEY`).
    pub env_var: String,
    /// Vault address (e.g. `OPENROUTER:KEY:ESTIFIE`).
    pub address: String,
    /// Missing secrets are skipped instead of failing when true.
    pub optional: bool,
}

/// Profile resolution order: explicit flag, `EST_ENV`, `dev` when the
/// file declares it, the first declared profile, else `default`.
fn resolve_profile(explicit: Option<&str>, profiles: &[String]) -> String {
    if let Some(e) = explicit.map(str::trim).filter(|e| !e.is_empty()) {
        return e.to_string();
    }
    if let Ok(e) = std::env::var("EST_ENV")
        && !e.trim().is_empty()
    {
        return e.trim().to_string();
    }
    if profiles.iter().any(|p| p == "dev") {
        return "dev".to_string();
    }
    profiles
        .first()
        .cloned()
        .unwrap_or_else(|| "default".to_string())
}

fn is_inline(t: &toml::map::Map<String, toml::Value>) -> bool {
    // Shape, not a key probe: a profile that happens to declare an env
    // var named `address` must stay a profile.
    matches!(t.get("address"), Some(v) if v.is_str())
        && t.keys().all(|k| k == "address" || k == "optional")
}

fn parse_mapping(k: &str, v: &toml::Value) -> Option<VaultUseMapping> {
    if let Some(s) = v.as_str() {
        Some(VaultUseMapping {
            env_var: k.to_string(),
            address: s.to_string(),
            optional: false,
        })
    } else if let Some(t) = v.as_table() {
        if let Some(addr) = t.get("address").and_then(|a| a.as_str()) {
            let optional = match t.get("optional") {
                None => false,
                Some(o) => o.as_bool()?,
            };
            Some(VaultUseMapping {
                env_var: k.to_string(),
                address: addr.to_string(),
                optional,
            })
        } else {
            None
        }
    } else {
        None
    }
}

fn declared_profiles(use_table: &toml::map::Map<String, toml::Value>) -> Vec<String> {
    let mut out: Vec<String> = use_table
        .iter()
        .filter_map(|(k, v)| {
            if let Some(t) = v.as_table()
                && !is_inline(t)
            {
                return Some(k.clone());
            }
            None
        })
        .collect();
    out.sort();
    out
}

/// Parse one manifest file: `(active_profile, merged_mappings)`.
/// Missing `[use]` reads as empty (a project with no secret needs);
/// malformed TOML is an error, never silence.
pub fn load_vault_use(
    path: &Path,
    explicit_profile: Option<&str>,
) -> Result<(String, Vec<VaultUseMapping>), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let val: toml::Value = toml::from_str(&content)
        .map_err(|e| format!("malformed vault manifest at {}: {e}", path.display()))?;
    let use_table = match val.get("use").and_then(|v| v.as_table()) {
        Some(t) => t,
        None => return Ok(("default".into(), Vec::new())),
    };
    let profiles = declared_profiles(use_table);
    let active = resolve_profile(explicit_profile, &profiles);
    let mut merged: std::collections::BTreeMap<String, VaultUseMapping> =
        std::collections::BTreeMap::new();
    let mut problems = Vec::new();
    for (k, v) in use_table {
        if v.as_table().is_some_and(|t| !is_inline(t)) {
            continue; // profiles merge below
        }
        match parse_mapping(k, v) {
            Some(item) => {
                merged.insert(k.clone(), item);
            }
            None => problems.push(format!(
                "[use] {k}: expected a vault address string or {{ address, optional }} table"
            )),
        }
    }
    if let Some(profile_table) = use_table.get(&active).and_then(|v| v.as_table()) {
        for (k, v) in profile_table {
            match parse_mapping(k, v) {
                Some(item) => {
                    merged.insert(k.clone(), item);
                }
                None => problems.push(format!(
                    "[use.{active}] {k}: expected a vault address string or {{ address, optional }} table"
                )),
            }
        }
    }
    if !problems.is_empty() {
        return Err(format!("{}: {}", path.display(), problems.join("; ")));
    }
    Ok((active, merged.into_values().collect()))
}

/// Declared profile names in one manifest file, sorted.
pub fn available_profiles(path: &Path) -> Result<Vec<String>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let val: toml::Value = toml::from_str(&content)
        .map_err(|e| format!("malformed vault manifest at {}: {e}", path.display()))?;
    Ok(val
        .get("use")
        .and_then(|v| v.as_table())
        .map(declared_profiles)
        .unwrap_or_default())
}

/// Every rule in one place: problems with one vault manifest file.
/// Empty means the file is usable. (Missing file is the caller's
/// concern — vault files are optional per project.)
#[must_use]
pub fn validate_vault_file(path: &Path) -> Vec<String> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return vec![format!("cannot read {}: {e}", path.display())],
    };
    let val: toml::Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return vec![format!(
                "malformed vault manifest at {}: {e}",
                path.display()
            )];
        }
    };
    let mut problems = Vec::new();
    let Some(use_table) = val.get("use").and_then(|v| v.as_table()) else {
        problems.push("no [use] section (declare secret deps or remove the file)".to_string());
        return problems;
    };
    let mut check_mapping = |env_var: &str, v: &toml::Value, at: &str| {
        if let Some(t) = v.as_table()
            && let Some(o) = t.get("optional")
            && !o.is_bool()
        {
            problems.push(format!("{at}: optional is true or false"));
            return;
        }
        match parse_mapping(env_var, v) {
            Some(m) => {
                let addr = m.address.trim();
                if addr.is_empty() {
                    problems.push(format!("{at}: address is empty"));
                } else if addr.chars().any(|c| c.is_whitespace() || c.is_control()) {
                    problems.push(format!("{at}: address has whitespace"));
                } else if let Err(e) = crate::addr::norm(&m.address) {
                    problems.push(format!("{at}: {e}"));
                }
                if env_var.trim().is_empty() || env_var.len() > 128 {
                    problems.push(format!("{at}: env var name is 1-128 chars"));
                }
            }
            None => problems.push(format!(
                "{at}: expected a vault address string or {{ address, optional }} table"
            )),
        }
    };
    for (k, v) in use_table {
        if v.as_table().is_some_and(|t| !is_inline(t)) {
            // A profile section: validate its entries with a prefix.
            if let Some(t) = v.as_table() {
                for (pk, pv) in t {
                    check_mapping(pk, pv, &format!("[use.{k}] {pk}"));
                }
            }
            continue;
        }
        check_mapping(k, v, &format!("[use] {k}"));
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(name: &str, content: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("est-vault-test-{name}"));
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn base_and_profile_merge_with_overlay() {
        let p = write(
            "merge",
            "[use]\nA = \"X:A:P\"\nB = \"X:B:P\"\n[use.prod]\nB = \"X:B:PROD\"\nC = \"X:C:PROD\"\n",
        );
        let (profile, items) = load_vault_use(&p, Some("prod")).unwrap();
        assert_eq!(profile, "prod");
        let get = |k: &str| {
            items
                .iter()
                .find(|m| m.env_var == k)
                .unwrap()
                .address
                .clone()
        };
        assert_eq!(get("A"), "X:A:P");
        assert_eq!(get("B"), "X:B:PROD");
        assert_eq!(get("C"), "X:C:PROD");
    }

    #[test]
    fn inline_tables_carry_optional() {
        let p = write(
            "inline",
            "[use]\nA = { address = \"X:A:P\", optional = true }\n",
        );
        let (_, items) = load_vault_use(&p, None).unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].optional);
    }

    #[test]
    fn malformed_is_an_error_never_silence() {
        let p = write("bad", "[use\nA = ");
        assert!(load_vault_use(&p, None).is_err());
        assert!(!validate_vault_file(&p).is_empty());
    }

    #[test]
    fn missing_use_section_is_empty_ok_for_load_but_flagged_for_validate() {
        let p = write("empty", "# nothing\n");
        let (_, items) = load_vault_use(&p, None).unwrap();
        assert!(items.is_empty());
        assert!(!validate_vault_file(&p).is_empty());
    }

    #[test]
    fn profile_defaults_to_dev_then_first() {
        let p = write(
            "prof",
            "[use]\nA = \"X:A:P\"\n[use.staging]\nB = \"X:B:S\"\n[use.dev]\nC = \"X:C:D\"\n",
        );
        let (profile, _) = load_vault_use(&p, None).unwrap();
        assert_eq!(profile, "dev");
    }

    #[test]
    fn bad_entries_are_errors_never_silence() {
        let p = write("badentry", "[use]\nA = \"X:A:P\"\nB = 5\n");
        let err = load_vault_use(&p, None).unwrap_err();
        assert!(err.contains("[use] B"), "{err}");
        assert!(!validate_vault_file(&p).is_empty());
    }

    #[test]
    fn optional_must_be_bool() {
        let p = write(
            "badopt",
            "[use]\nA = { address = \"X:A:P\", optional = \"yes\" }\n",
        );
        assert!(load_vault_use(&p, None).is_err());
        let problems = validate_vault_file(&p);
        assert!(
            problems
                .iter()
                .any(|s| s.contains("optional is true or false")),
            "{problems:?}"
        );
    }

    #[test]
    fn malformed_addresses_are_flagged() {
        let p = write("badaddr", "[use]\nA = \"NOCOLON\"\n");
        let problems = validate_vault_file(&p);
        assert!(
            problems.iter().any(|s| s.contains("NOCOLON")),
            "{problems:?}"
        );
    }

    #[test]
    fn address_named_var_does_not_mask_a_profile() {
        let p = write(
            "addrvar",
            "[use]\nA = \"X:A:P\"\n[use.prod]\naddress = \"X:D:P\"\nB = \"X:B:P\"\n",
        );
        let (profile, items) = load_vault_use(&p, Some("prod")).unwrap();
        assert_eq!(profile, "prod");
        assert_eq!(items.len(), 3);
        assert!(items.iter().any(|m| m.env_var == "address"));
    }
}
