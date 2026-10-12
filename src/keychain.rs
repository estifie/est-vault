//! The 32-byte key, held base64 in the login Keychain. Reads go through
//! the same `security` argv the Python `sec` toolkit uses (argv carries
//! only service/account names, never secret bytes); writes go through
//! Security.framework so the key never appears in `ps`. Reads fall back
//! through the older services, so a renamed service never orphans the
//! key; writes always go to the explicit service or the EST one. Keys
//! are [`Zeroizing`]: wiped on drop.

#[cfg(target_os = "macos")]
use security_framework::passwords::set_generic_password;
use std::process::Command;

use zeroize::Zeroizing;

use crate::Error;

/// The Keychain service EST Vault writes.
pub const SERVICE: &str = "est-vault";

/// Older services, read newest-first after [`SERVICE`].
pub const FALLBACK_SERVICES: [&str; 1] = ["estifie-sec"];

fn explicit_service() -> Option<String> {
    for var in ["EST_VAULT_KEYCHAIN", "SEC_KEYCHAIN_SERVICE"] {
        if let Ok(name) = std::env::var(var)
            && !name.trim().is_empty()
        {
            return Some(name);
        }
    }
    None
}

/// The headless fallback key file: `EST_VAULT_KEY_FILE` wins when set
/// (hermetic tests), else `~/.estifie/vault/key`.
fn fallback_key_file() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("EST_VAULT_KEY_FILE")
        && !path.trim().is_empty()
    {
        return std::path::PathBuf::from(path);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home)
        .join(".estifie")
        .join("vault")
        .join("key")
}

/// Services to read, in order: the explicit one wins outright, otherwise
/// the EST service, then the older ones.
pub fn service_list(explicit: Option<&str>) -> Vec<String> {
    if let Some(name) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return vec![name.to_string()];
    }
    std::iter::once(SERVICE)
        .chain(FALLBACK_SERVICES)
        .map(str::to_string)
        .collect()
}

/// Where writes go: the explicit service, else the EST one.
pub fn write_service(explicit: Option<&str>) -> String {
    explicit
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(SERVICE)
        .to_string()
}

/// The write target for this process. See [`write_service`].
pub fn service() -> String {
    write_service(explicit_service().as_deref())
}

/// The key from exactly these services, in order, whatever the environment
/// says. For a reader that must not be pointed elsewhere by an exported
/// variable — the waiver key is the one — a caller passes the services it
/// trusts. None when no item opens, or none decodes to 32 bytes.
pub fn get_from(services: &[&str]) -> Result<Option<Zeroizing<[u8; 32]>>, Error> {
    // 1. macOS Keychain via security CLI
    for service in services {
        let out = Command::new("security")
            .args(["find-generic-password", "-a", "master", "-s", service, "-w"])
            .output();
        if let Ok(out) = out
            && out.status.success()
            && let Ok(raw) = crate::base64_decode(&String::from_utf8_lossy(&out.stdout))
            && raw.len() == 32
        {
            let mut key = [0u8; 32];
            key.copy_from_slice(&raw);
            return Ok(Some(Zeroizing::new(key)));
        }
    }

    // 2. Headless / Linux fallback file, or its test override.
    let key_file = fallback_key_file();
    if key_file.is_file()
        && let Ok(content) = std::fs::read_to_string(&key_file)
        && let Ok(raw) = crate::base64_decode(content.trim())
        && raw.len() == 32
    {
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        return Ok(Some(Zeroizing::new(key)));
    }

    Ok(None)
}

/// The key, or None when no item opens — or none decodes to 32 bytes.
/// `EST_VAULT_KEY` wins outright; otherwise the Keychain services,
/// otherwise the headless fallback file (`EST_VAULT_KEY_FILE` wins
/// when set, else `~/.estifie/vault/key`). Never touches the store.
/// See [`get_from`] for the env-proof read.
pub fn get() -> Result<Option<Zeroizing<[u8; 32]>>, Error> {
    if let Some(key) = env_key() {
        return Ok(Some(key));
    }
    let services = service_list(explicit_service().as_deref());
    let names: Vec<&str> = services.iter().map(String::as_str).collect();
    get_from(&names)
}

/// `EST_VAULT_KEY` decoded, when set to 32 base64 bytes.
fn env_key() -> Option<Zeroizing<[u8; 32]>> {
    let raw = crate::base64_decode(std::env::var("EST_VAULT_KEY").ok()?.trim()).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw);
    Some(Zeroizing::new(key))
}

/// Store the key under [`service`], creating or replacing the item.
pub fn put(key: &[u8; 32]) -> Result<(), Error> {
    let service = service();
    let b64 = crate::base64_encode(key);
    let mut saved = false;

    // Keychain first (macOS only): through Security.framework, not the
    // `security` CLI — argv would expose the key to `ps`. Same
    // service/account the CLI used, so old items keep working.
    #[cfg(target_os = "macos")]
    {
        if set_generic_password(&service, "master", b64.as_bytes()).is_ok() {
            saved = true;
        }
    }

    // Also persist the fallback file (0600). `EST_VAULT_KEY_FILE`
    // redirects it for hermetic tests; default is ~/.estifie/vault/key.
    let key_file = fallback_key_file();
    if let Some(key_dir) = key_file.parent() {
        let _ = std::fs::create_dir_all(key_dir);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // `mode` only sets permissions on create: tighten unconditionally
        // so a pre-existing lax file cannot survive a put.
        let wrote = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&key_file)
            .and_then(|f| {
                use std::io::Write;
                let mut f = f;
                f.write_all(b64.as_bytes())?;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))
            });
        if wrote.is_ok() {
            saved = true;
        }
    }

    #[cfg(not(unix))]
    {
        if std::fs::write(&key_file, &b64).is_ok() {
            saved = true;
        }
    }

    if !saved {
        return Err(Error::Keychain(
            "could not save to the Keychain or ~/.estifie/vault/key".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_chain_reads_newest_first() {
        assert_eq!(
            service_list(None),
            vec!["est-vault".to_string(), "estifie-sec".to_string()]
        );
    }

    #[test]
    fn explicit_service_wins_outright() {
        assert_eq!(service_list(Some("custom")), vec!["custom".to_string()]);
        assert_eq!(service_list(Some("  ")).len(), 2);
    }

    #[test]
    fn writes_default_to_est() {
        assert_eq!(write_service(None), "est-vault");
        assert_eq!(write_service(Some("  ")), "est-vault");
        assert_eq!(write_service(Some("custom")), "custom");
    }
}
