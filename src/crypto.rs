//! AES-256-GCM through RustCrypto. Random nonces from /dev/urandom.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::Error;

fn cipher(key: &[u8; 32]) -> Result<Aes256Gcm, Error> {
    Aes256Gcm::new_from_slice(key).map_err(|e| Error::Format(format!("bad key length: {e}")))
}

/// Seal one plaintext: a fresh random nonce and the ciphertext with its tag.
/// The address rides as associated data, so a file copied to another address
/// never opens.
pub fn seal_to(key: &[u8; 32], addr: &str, plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>), Error> {
    let nonce = random_nonce()?;
    let blob = cipher(key)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: addr.as_bytes(),
            },
        )
        .map_err(|e| Error::Format(format!("encrypt failed: {e}")))?;
    Ok((nonce, blob))
}

/// Open one ciphertext. A wrong key, address, or byte is [`Error::Decrypt`].
pub fn open(key: &[u8; 32], addr: &str, nonce: &[u8], blob: &[u8]) -> Result<Vec<u8>, Error> {
    if nonce.len() != 12 {
        return Err(Error::Format("not a vault file".to_string()));
    }
    cipher(key)?
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: blob,
                aad: addr.as_bytes(),
            },
        )
        .map_err(|_| Error::Decrypt(addr.to_string()))
}

fn random_nonce() -> Result<[u8; 12], Error> {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|e| Error::Format(format!("no randomness: {e}")))?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    #[test]
    fn roundtrip() {
        let (nonce, blob) = seal_to(&KEY, "A:B", b"value").unwrap();
        assert_eq!(nonce.len(), 12);
        assert_eq!(open(&KEY, "A:B", &nonce, &blob).unwrap(), b"value");
    }

    #[test]
    fn wrong_address_never_opens() {
        let (nonce, blob) = seal_to(&KEY, "A:B", b"value").unwrap();
        assert!(matches!(
            open(&KEY, "A:C", &nonce, &blob),
            Err(Error::Decrypt(_))
        ));
    }

    #[test]
    fn tampered_bytes_never_open() {
        let (nonce, mut blob) = seal_to(&KEY, "A:B", b"value").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(matches!(
            open(&KEY, "A:B", &nonce, &blob),
            Err(Error::Decrypt(_))
        ));
    }

    #[test]
    fn short_nonce_is_a_format_error() {
        assert!(matches!(
            open(&KEY, "A:B", b"short", b"blob"),
            Err(Error::Format(_))
        ));
    }
}
