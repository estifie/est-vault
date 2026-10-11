//! est-vault: the secrets store, natively.
//!
//! Byte-compatible with the legacy vault format and the Python `sec` toolkit: same
//! layout, same files, same outcomes. Crypto is RustCrypto (`aes-gcm`);
//! the Keychain is reached through the `security` CLI. No hand-rolled
//! crypto, ever.

pub mod addr;
pub mod cli;
pub mod crypto;
pub mod keychain;
pub mod schema;
pub mod store;

/// Every way a store operation ends. Display messages never contain a
/// decrypted byte.
#[derive(Debug)]
pub enum Error {
    /// The address is not shaped like an address (rejected before any lookup).
    AddrInvalid(String),
    /// No store: the folder or its `.salt` is missing.
    NoStore(std::path::PathBuf),
    /// Store present, address absent.
    NotFound(String),
    /// Store and address present, but no Keychain key.
    NoKey,
    /// Present, but does not open with the key (wrong key, moved, tampered).
    Decrypt(String),
    /// Not a vault file, or a payload laid out wrongly.
    Format(String),
    /// The schema file is not valid TOML, or a schema rule refuses the address.
    Schema(String),
    /// The `security` CLI failed.
    Keychain(String),
    /// Anything else from the filesystem.
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::AddrInvalid(input) => write!(
                f,
                "bad address {input:?}: 2-5 segments of A-Z 0-9 _ - @ . + joined by ':' \
                 (e.g. REVENUECAT:KEY:COMICSCANNER)"
            ),
            Error::NoStore(dir) => write!(f, "no store at {}", dir.display()),
            Error::NotFound(addr) => {
                write!(f, "no secret {addr}. `est-vault list` shows what there is.")
            }
            Error::NoKey => write!(f, "no key in Keychain; run `est-vault init`"),
            Error::Decrypt(addr) => write!(
                f,
                "{addr} does not decrypt with the Keychain key (wrong key, moved, or tampered)"
            ),
            Error::Format(message) | Error::Schema(message) | Error::Keychain(message) => {
                write!(f, "{message}")
            }
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// The store's result: either the value or one [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Standard-base64 decode; failures are [`Error::Format`].
pub fn base64_decode(text: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|e| Error::Format(format!("not base64: {e}")))
}

/// Standard-base64 encode.
pub fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        assert_eq!(
            base64_decode(&base64_encode(b"key-bytes")).unwrap(),
            b"key-bytes"
        );
        assert!(base64_decode("!!!").is_err());
    }

    #[test]
    fn errors_name_the_fix() {
        assert!(Error::NoKey.to_string().contains("est-vault init"));
        assert!(
            Error::NotFound("X:Y".to_string())
                .to_string()
                .contains("est-vault list")
        );
    }
}
