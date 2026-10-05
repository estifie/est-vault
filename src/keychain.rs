//! The 32-byte key, held base64 in the login Keychain through the same
//! `security` argv Angel and Python use. Reads fall back through the older
//! services, so a renamed service never orphans the key; writes always go
//! to the explicit service or the EST one. Keys are [`Zeroizing`]: wiped
//! on drop.

use std::process::Command;

use zeroize::Zeroizing;

use crate::Error;

/// The Keychain service EST Vault writes.
pub const SERVICE: &str = "est-vault";

/// Older services, read newest-first after [`SERVICE`].
pub const FALLBACK_SERVICES: [&str; 2] = ["angel-vault", "estifie-sec"];

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

/// The key, or None when no item opens — or none decodes to 32 bytes.
/// Never touches the store, only the Keychain.
pub fn get() -> Result<Option<Zeroizing<[u8; 32]>>, Error> {
    for service in service_list(explicit_service().as_deref()) {
        let out = Command::new("security")
            .args([
                "find-generic-password",
                "-a",
                "master",
                "-s",
                &service,
                "-w",
            ])
            .output()
            .map_err(|e| Error::Keychain(format!("cannot run security: {e}")))?;
        if !out.status.success() {
            continue;
        }
        let raw = crate::base64_decode(&String::from_utf8_lossy(&out.stdout))
            .map_err(|_| Error::Keychain("Keychain key is not base64".to_string()))?;
        if raw.len() != 32 {
            continue;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        return Ok(Some(Zeroizing::new(key)));
    }
    Ok(None)
}

/// Store the key under [`service`], creating or replacing the item.
pub fn put(key: &[u8; 32]) -> Result<(), Error> {
    let service = service();
    let status = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-a",
            "master",
            "-s",
            &service,
            "-w",
            &crate::base64_encode(key),
        ])
        .status()
        .map_err(|e| Error::Keychain(format!("cannot run security: {e}")))?;
    if !status.success() {
        return Err(Error::Keychain(
            "security add-generic-password failed".to_string(),
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
            vec![
                "est-vault".to_string(),
                "angel-vault".to_string(),
                "estifie-sec".to_string()
            ]
        );
    }

    #[test]
    fn explicit_service_wins_outright() {
        assert_eq!(service_list(Some("custom")), vec!["custom".to_string()]);
        assert_eq!(service_list(Some("  ")).len(), 3);
    }

    #[test]
    fn writes_default_to_est() {
        assert_eq!(write_service(None), "est-vault");
        assert_eq!(write_service(Some("  ")), "est-vault");
        assert_eq!(write_service(Some("custom")), "custom");
    }
}
