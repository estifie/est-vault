//! The store: one file per secret, encrypted or plain.
//!
//! Byte-compatible with the legacy vault format and the Python `sec` toolkit — see
//! `docs/format.md`. Resolution order is documented in
//! `docs/resolution.md` and pinned by the tests below.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::{Error, Result, addr, crypto, keychain, schema};

/// Magic bytes opening every encrypted file.
pub const MAGIC: &[u8; 4] = b"SEC2";
/// Suffix for encrypted secret files.
pub const ENC_SUFFIX: &str = ".enc";
/// Suffix for unencrypted secret files.
pub const PLAIN_SUFFIX: &str = ".plain";

/// What an opened secret holds.
#[derive(Debug)]
pub enum Sealed {
    /// Text bytes as stored.
    Text(Vec<u8>),
    /// File bytes with their name.
    File {
        /// The stored file name.
        name: String,
        /// The stored file bytes.
        data: Vec<u8>,
    },
}

/// A secrets store at `dir` with templates at `schema_path`.
pub struct Store {
    dir: PathBuf,
    schema_path: PathBuf,
}

impl Store {
    /// The store for this process: explicit environment first, then the
    /// installation at hand, then shared pointers, then legacy locations.
    pub fn standard() -> Store {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let base = base_dir();
        let dir = resolve_store_dir(
            first_set(&["EST_VAULT_DIR", "SEC_DIR"]).as_deref(),
            &base,
            &home,
        );
        let schema = resolve_schema_path(
            first_set(&["EST_VAULT_SCHEMA", "SEC_SCHEMA"]).as_deref(),
            &base,
            &home,
        );
        Store::at(dir, schema)
    }

    /// Makes a store where [`Store::standard`] points: the folder, its
    /// `.salt` marker, and a Keychain key unless one already opens. Refuses
    /// when a store already lives there, so init never formats over secrets.
    pub fn init(&self) -> Result<()> {
        self.prepare()?;
        if keychain::get()?.is_none() {
            keychain::put(&random_32()?)?;
        }
        Ok(())
    }

    /// A store at an explicit directory with explicit templates. Tests and
    /// tools that manage their own layout.
    pub fn at(dir: PathBuf, schema_path: PathBuf) -> Store {
        Store { dir, schema_path }
    }

    /// Where the secret files live.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where the templates file lives.
    pub fn schema_path(&self) -> &Path {
        &self.schema_path
    }

    /// A store exists when `.salt` does; without it every lookup misses.
    pub fn has_store(&self) -> bool {
        self.dir.join(".salt").is_file()
    }

    /// The file an address maps to under `suffix`.
    pub fn path_of(&self, addr: &str, suffix: &str) -> PathBuf {
        let mut parts = addr.split(':');
        let mut path = self.dir.clone();
        let segments: Vec<&str> = parts.by_ref().collect();
        for dir in &segments[..segments.len() - 1] {
            path.push(dir);
        }
        path.push(format!("{}{suffix}", segments[segments.len() - 1]));
        path
    }

    /// True when either twin exists. Malformed addresses never exist.
    pub fn exists(&self, addr: &str) -> bool {
        let Ok(addr) = addr::norm(addr) else {
            return false;
        };
        self.path_of(&addr, ENC_SUFFIX).is_file() || self.path_of(&addr, PLAIN_SUFFIX).is_file()
    }

    /// Stored unencrypted: an encrypted file at the same address always wins.
    pub fn is_plain(&self, addr: &str) -> bool {
        let Ok(addr) = addr::norm(addr) else {
            return false;
        };
        !self.path_of(&addr, ENC_SUFFIX).is_file() && self.path_of(&addr, PLAIN_SUFFIX).is_file()
    }

    /// Every address in the store, sorted, filtered by uppercase `prefix`.
    pub fn addresses(&self, prefix: &str) -> Vec<String> {
        let mut found = BTreeSet::new();
        if self.dir.is_dir() {
            let mut stack = vec![self.dir.clone()];
            while let Some(dir) = stack.pop() {
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        for suffix in [ENC_SUFFIX, PLAIN_SUFFIX] {
                            if let Some(stem) = name.strip_suffix(suffix)
                                && let Ok(rel) =
                                    path.parent().unwrap_or(&self.dir).strip_prefix(&self.dir)
                            {
                                let mut parts: Vec<String> = rel
                                    .components()
                                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                                    .collect();
                                parts.push(stem.to_string());
                                found.insert(parts.join(":"));
                            }
                        }
                    }
                }
            }
        }
        let upper = prefix.to_uppercase();
        found
            .into_iter()
            .filter(|a| a.starts_with(&upper))
            .collect()
    }

    /// Seal already-framed `plaintext` under an explicit key: the
    /// hermetic write path. Crate-only on purpose: framing is a trap
    /// for outsiders (`unseal` strips the first byte), so tools go
    /// through [`Store::store_text`] / [`Store::set_file_with`].
    pub(crate) fn seal_with(&self, addr: &str, plaintext: &[u8], key: &[u8; 32]) -> Result<()> {
        let addr = addr::norm(addr)?;
        let path = self.path_of(&addr, ENC_SUFFIX);
        if let Some(parent) = path.parent() {
            est_core::store::create_dir_all_mode(parent, 0o700)?;
        }
        let (nonce, blob) = crypto::seal_to(key, &addr, plaintext)?;
        let mut bytes = Vec::with_capacity(4 + 12 + blob.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&blob);
        est_core::store::write_atomic(&path, &bytes, 0o600)?;
        let _ = std::fs::remove_file(self.path_of(&addr, PLAIN_SUFFIX));
        Ok(())
    }

    /// Seal already-framed `plaintext` under the Keychain key.
    /// Crate-only like [`Store::seal_with`]: outsiders frame through
    /// [`Store::store_text`] / [`Store::set_file`].
    pub(crate) fn seal(&self, addr: &str, plaintext: &[u8]) -> Result<()> {
        match keychain::get()? {
            Some(key) => self.seal_with(addr, plaintext, &key),
            None => Err(Error::NoKey),
        }
    }

    /// Stores a text value the way the schema says (or the caller
    /// forces), under an explicit key. True when plain.
    pub fn store_text_with(
        &self,
        addr: &str,
        value: &str,
        plain: Option<bool>,
        key: &[u8; 32],
    ) -> Result<bool> {
        let addr = addr::norm(addr)?;
        let schema = schema::Schema::load(&self.schema_path)?;
        let plain =
            plain.unwrap_or_else(|| schema.kind_rule(&addr).map(|k| k.plain).unwrap_or(false));
        if plain {
            self.put_plain(&addr, value)?;
        } else {
            let mut plaintext = Vec::with_capacity(1 + value.len());
            plaintext.push(b'T');
            plaintext.extend_from_slice(value.as_bytes());
            self.seal_with(&addr, &plaintext, key)?;
        }
        Ok(plain)
    }

    /// Deletes both twins. Missing entirely reads as not found.
    pub fn remove(&self, addr: &str) -> Result<()> {
        let addr = addr::norm(addr)?;
        let mut existed = false;
        for suffix in [ENC_SUFFIX, PLAIN_SUFFIX] {
            match std::fs::remove_file(self.path_of(&addr, suffix)) {
                Ok(()) => existed = true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::Io(e)),
            }
        }
        if existed {
            Ok(())
        } else {
            Err(Error::NotFound(addr))
        }
    }

    /// Store `text` unencrypted. Removes the encrypted twin outright.
    pub fn put_plain(&self, addr: &str, text: &str) -> Result<()> {
        let addr = addr::norm(addr)?;
        let path = self.path_of(&addr, PLAIN_SUFFIX);
        if let Some(parent) = path.parent() {
            est_core::store::create_dir_all_mode(parent, 0o700)?;
        }
        est_core::store::write_atomic(&path, text.as_bytes(), 0o600)?;
        let _ = std::fs::remove_file(self.path_of(&addr, ENC_SUFFIX));
        Ok(())
    }

    /// Stores file bytes under a name, under an explicit key.
    pub fn set_file_with(&self, addr: &str, name: &str, data: &[u8], key: &[u8; 32]) -> Result<()> {
        let addr = addr::norm(addr)?;
        let name_bytes = name.as_bytes();
        if name_bytes.len() > 255 {
            return Err(Error::Format("file name over 255 bytes".to_string()));
        }
        let mut plaintext = Vec::with_capacity(2 + name_bytes.len() + data.len());
        plaintext.push(b'F');
        plaintext.push(name_bytes.len() as u8);
        plaintext.extend_from_slice(name_bytes);
        plaintext.extend_from_slice(data);
        self.seal_with(&addr, &plaintext, key)
    }

    /// Stores file bytes under a name, under the Keychain key.
    pub fn set_file(&self, addr: &str, name: &str, data: &[u8]) -> Result<()> {
        match keychain::get()? {
            Some(key) => self.set_file_with(addr, name, data, &key),
            None => Err(Error::NoKey),
        }
    }

    /// Stores a text value the way the schema says (or the caller forces).
    /// True when plain.
    pub fn store_text(&self, addr: &str, value: &str, plain: Option<bool>) -> Result<bool> {
        let addr = addr::norm(addr)?;
        let schema = schema::Schema::load(&self.schema_path)?;
        let plain =
            plain.unwrap_or_else(|| schema.kind_rule(&addr).map(|k| k.plain).unwrap_or(false));
        if plain {
            self.put_plain(&addr, value)?;
            return Ok(true);
        }
        match keychain::get()? {
            Some(key) => self.store_text_with(&addr, value, Some(false), &key),
            None => Err(Error::NoKey),
        }
    }

    /// Open a secret under an explicit key: the hermetic read path.
    pub fn unseal_with(&self, addr: &str, key: &[u8; 32]) -> Result<Sealed> {
        let addr = addr::norm(addr)?;
        let path = self.path_of(&addr, ENC_SUFFIX);
        if !path.is_file() {
            return self.open_plain(&addr);
        }
        let raw = std::fs::read(&path)?;
        open_bytes(&addr, &raw, key)
    }

    /// Open a secret under the Keychain key.
    pub fn unseal(&self, addr: &str) -> Result<Sealed> {
        let addr = addr::norm(addr)?;
        let path = self.path_of(&addr, ENC_SUFFIX);
        if !path.is_file() {
            return self.open_plain(&addr);
        }
        let raw = std::fs::read(&path)?;
        match keychain::get()? {
            Some(key) => open_bytes(&addr, &raw, &key),
            None => Err(Error::NoKey),
        }
    }

    /// The `.plain` twin, or NotFound. `addr` already normed. Shared by
    /// the two unseal paths so the fallback lives in one place.
    fn open_plain(&self, addr: &str) -> Result<Sealed> {
        let plain = self.path_of(addr, PLAIN_SUFFIX);
        if plain.is_file() {
            return Ok(Sealed::Text(std::fs::read(plain)?));
        }
        Err(Error::NotFound(addr.to_string()))
    }

    /// The filesystem half of [`Store::init`]: refuse when a store already
    /// lives here, else the folder and its `.salt` marker.
    fn prepare(&self) -> Result<()> {
        if self.has_store() {
            return Err(Error::Format(format!(
                "a store already lives at {}",
                self.dir.display()
            )));
        }
        est_core::store::create_dir_all_mode(&self.dir, 0o700)?;
        // `.salt` is only a presence marker (see docs/format.md): its 32
        // random bytes keep the legacy shape, never a KDF input.
        est_core::store::write_atomic(&self.dir.join(".salt"), &random_32()?, 0o600)?;
        Ok(())
    }
}

fn open_bytes(addr: &str, raw: &[u8], key: &[u8; 32]) -> Result<Sealed> {
    if raw.len() < 32 || &raw[..4] != MAGIC {
        return Err(Error::Format(format!("{addr} is not a vault file")));
    }
    let plain = crypto::open(key, addr, &raw[4..16], &raw[16..])?;
    match plain.first() {
        Some(b'F') => {
            if plain.len() < 2 {
                return Err(Error::Format(format!("{addr}: file layout is cut off")));
            }
            let n = plain[1] as usize;
            if plain.len() < 2 + n {
                return Err(Error::Format(format!("{addr}: file layout is cut off")));
            }
            let name = std::str::from_utf8(&plain[2..2 + n])
                .map_err(|_| Error::Format(format!("{addr}: file name is not UTF-8")))?;
            Ok(Sealed::File {
                name: name.to_string(),
                data: plain[2 + n..].to_vec(),
            })
        }
        _ => Ok(Sealed::Text(plain.get(1..).unwrap_or(&[]).to_vec())),
    }
}

/// First non-empty variable wins; the `EST_` name leads each chain.
fn first_set(vars: &[&str]) -> Option<String> {
    vars.iter()
        .filter_map(|v| std::env::var(v).ok())
        .map(|s| s.trim().to_string())
        .find(|s| !s.is_empty())
}

/// Where the product lives: the `EST_DIR` override, a binary in `bin/` one
/// level below it, and anything else running where it stands.
fn base_dir() -> PathBuf {
    let explicit = first_set(&["EST_DIR"]);
    let exe = std::env::current_exe()
        .ok()
        .map(|e| std::fs::canonicalize(&e).unwrap_or(e));
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    est_core::paths::resolve_base(explicit.as_deref(), exe.as_deref(), &cwd)
}

/// Resolve the store directory: explicit env, then the installation at
/// hand, then the installer's pointer, then the historical folder, else the
/// creation target. Pure, so tests pin the order without touching the
/// environment.
pub fn resolve_store_dir(explicit: Option<&str>, base: &Path, home: &str) -> PathBuf {
    if let Some(dir) = explicit.map(str::trim).filter(|d| !d.is_empty()) {
        return PathBuf::from(dir);
    }
    let installed = base.join("vault").join("store");
    if installed.is_dir() {
        return installed;
    }
    if let Some(pointed) = pointer_store(home) {
        return pointed;
    }
    if let Some(legacy) = legacy_store(home) {
        return legacy;
    }
    installed
}

/// Resolve the schema file the same way. Pure; see [`resolve_store_dir`].
pub fn resolve_schema_path(explicit: Option<&str>, base: &Path, home: &str) -> PathBuf {
    if let Some(file) = explicit.map(str::trim).filter(|f| !f.is_empty()) {
        return PathBuf::from(file);
    }
    let fresh = base.join("vault").join("templates.toml");
    if fresh.is_file() {
        return fresh;
    }
    let old = PathBuf::from(home)
        .join(".config")
        .join("sec")
        .join("schema.toml");
    if old.is_file() {
        return old;
    }
    fresh
}

/// The installer's pointer: the first line of the EST `vault-home`, or the
/// historical `sec/home`.
fn pointer_store(home: &str) -> Option<PathBuf> {
    let config = PathBuf::from(home).join(".config");
    for (a, b) in [("est", "vault-home"), ("sec", "home")] {
        if let Some(target) = est_core::paths::pointer_target(&config.join(a).join(b)) {
            return Some(target);
        }
    }
    None
}

/// The pre-vault folder, honored only while it still exists.
fn legacy_store(home: &str) -> Option<PathBuf> {
    let dir = PathBuf::from(home).join("Desktop").join("SECRETS");
    dir.is_dir().then_some(dir)
}

fn random_32() -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    getrandom::fill(&mut out).map_err(|e| Error::Format(format!("no randomness: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const KEY: [u8; 32] = [7; 32];

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("est-vault-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_store(name: &str) -> (PathBuf, Store) {
        let dir = scratch(name);
        let store = Store::at(dir.join("store"), dir.join("schema.toml"));
        (dir, store)
    }

    #[test]
    fn text_roundtrip() {
        let (_dir, store) = test_store("text");
        let mut framed = vec![b'T'];
        framed.extend_from_slice(b"value");
        store.seal_with("t:k:v", &framed, &KEY).unwrap();
        match store.unseal_with("T:K:V", &KEY).unwrap() {
            Sealed::Text(bytes) => assert_eq!(bytes, b"value"),
            Sealed::File { .. } => panic!("text sealed as file"),
        }
        assert!(store.exists("T:K:V"));
        assert!(!store.is_plain("T:K:V"));
        assert!(!store.exists("T:K:NOPE"));
    }

    #[test]
    fn file_roundtrip() {
        let (_dir, store) = test_store("file");
        store
            .set_file_with("A:P8:ME", "AuthKey.p8", b"p8-bytes", &KEY)
            .unwrap();
        match store.unseal_with("A:P8:ME", &KEY).unwrap() {
            Sealed::File { name, data } => {
                assert_eq!(name, "AuthKey.p8");
                assert_eq!(data, b"p8-bytes");
            }
            Sealed::Text(_) => panic!("file sealed as text"),
        }
        assert!(
            store
                .set_file_with("A:P8:ME", &"n".repeat(256), b"x", &KEY)
                .is_err()
        );
    }

    #[test]
    fn encrypted_twin_wins_then_plain_takes_over() {
        let (_dir, store) = test_store("twins");
        store.put_plain("T:K:BOTH", "stale").unwrap();
        assert!(store.is_plain("T:K:BOTH"));
        store.seal_with("T:K:BOTH", b"Tx", &KEY).unwrap();
        assert!(!store.is_plain("T:K:BOTH"));
        match store.unseal_with("T:K:BOTH", &KEY).unwrap() {
            Sealed::Text(bytes) => assert_eq!(bytes, b"x"),
            Sealed::File { .. } => panic!("text sealed as file"),
        }
        store.put_plain("T:K:BOTH", "plain-again").unwrap();
        assert!(store.is_plain("T:K:BOTH"));
        match store.unseal_with("T:K:BOTH", &KEY).unwrap() {
            Sealed::Text(bytes) => assert_eq!(bytes, b"plain-again"),
            Sealed::File { .. } => panic!("plain read as file"),
        }
    }

    #[test]
    fn remove_deletes_both_twins() {
        let (_dir, store) = test_store("remove");
        store.seal_with("T:K:GONE", b"Tx", &KEY).unwrap();
        store.put_plain("T:P:GONE", "x").unwrap();
        store.remove("T:K:GONE").unwrap();
        store.remove("T:P:GONE").unwrap();
        assert!(!store.exists("T:K:GONE"));
        assert!(matches!(store.remove("T:K:GONE"), Err(Error::NotFound(_))));
    }

    #[test]
    fn addresses_list_sorted_with_prefix() {
        let (_dir, store) = test_store("addresses");
        store.seal_with("B:K:2", b"Tx", &KEY).unwrap();
        store.seal_with("A:K:1", b"Tx", &KEY).unwrap();
        store.put_plain("A:P:3", "x").unwrap();
        assert_eq!(store.addresses(""), vec!["A:K:1", "A:P:3", "B:K:2"]);
        assert_eq!(store.addresses("a:"), vec!["A:K:1", "A:P:3"]);
        assert_eq!(store.addresses("B:K"), vec!["B:K:2"]);
    }

    #[test]
    fn sealed_files_carry_mode_and_magic() {
        let (_dir, store) = test_store("modes");
        store.seal_with("T:K:M", b"Tx", &KEY).unwrap();
        let path = store.path_of("T:K:M", ENC_SUFFIX);
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(&raw[..4], MAGIC);
        assert!(raw.len() >= 32);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn tampered_and_truncated_files_fail_right() {
        let (_dir, store) = test_store("tamper");
        store.seal_with("T:K:T", b"Tx", &KEY).unwrap();
        let path = store.path_of("T:K:T", ENC_SUFFIX);
        let mut raw = std::fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        std::fs::write(&path, &raw).unwrap();
        assert!(matches!(
            store.unseal_with("T:K:T", &KEY),
            Err(Error::Decrypt(_))
        ));
        std::fs::write(&path, b"short").unwrap();
        assert!(matches!(
            store.unseal_with("T:K:T", &KEY),
            Err(Error::Format(_))
        ));
    }

    #[test]
    fn prepare_makes_a_store_and_refuses_twice() {
        let (_dir, store) = test_store("prepare");
        assert!(!store.has_store());
        store.prepare().unwrap();
        assert!(store.has_store());
        assert!(store.prepare().is_err());
    }

    #[test]
    fn schema_plain_rule_routes_around_crypto() {
        let (dir, store) = test_store("schemaroute");
        std::fs::write(
            dir.join("schema.toml"),
            "[T.P]\nscope = [\"S\"]\nplain = true\n",
        )
        .unwrap();
        assert!(store.store_text("T:P:X", "hello", None).unwrap());
        assert!(store.is_plain("T:P:X"));
        match store.unseal_with("T:P:X", &KEY).unwrap() {
            Sealed::Text(bytes) => assert_eq!(bytes, b"hello"),
            Sealed::File { .. } => panic!("plain read as file"),
        }
    }

    #[test]
    fn resolution_prefers_explicit_then_installed() {
        let dir = scratch("resolve");
        let base = dir.join("base");
        let home = dir.join("home").to_string_lossy().into_owned();
        assert_eq!(
            resolve_store_dir(Some("/pinned"), &base, &home),
            PathBuf::from("/pinned")
        );
        assert_eq!(
            resolve_store_dir(Some("  "), &base, &home),
            base.join("vault").join("store")
        );
        std::fs::create_dir_all(base.join("vault").join("store")).unwrap();
        assert_eq!(
            resolve_store_dir(None, &base, &home),
            base.join("vault").join("store")
        );
    }

    #[test]
    fn resolution_falls_through_pointer_and_legacy() {
        let dir = scratch("resolve-fallthrough");
        let base = dir.join("base");
        let home = dir.join("home");
        let home_str = home.to_string_lossy().into_owned();
        std::fs::create_dir_all(home.join(".config").join("est")).unwrap();
        std::fs::write(
            home.join(".config").join("est").join("vault-home"),
            "/pointed\n",
        )
        .unwrap();
        assert_eq!(
            resolve_store_dir(None, &base, &home_str),
            PathBuf::from("/pointed")
        );
        std::fs::remove_file(home.join(".config").join("est").join("vault-home")).unwrap();
        std::fs::create_dir_all(home.join("Desktop").join("SECRETS")).unwrap();
        assert_eq!(
            resolve_store_dir(None, &base, &home_str),
            home.join("Desktop").join("SECRETS")
        );
    }

    #[test]
    fn schema_resolution_prefers_explicit_then_files() {
        let dir = scratch("resolve-schema");
        let base = dir.join("base");
        let home = dir.join("home").to_string_lossy().into_owned();
        assert_eq!(
            resolve_schema_path(Some("/pinned.toml"), &base, &home),
            PathBuf::from("/pinned.toml")
        );
        assert_eq!(
            resolve_schema_path(None, &base, &home),
            base.join("vault").join("templates.toml")
        );
        std::fs::create_dir_all(base.join("vault")).unwrap();
        std::fs::write(base.join("vault").join("templates.toml"), "").unwrap();
        assert_eq!(
            resolve_schema_path(None, &base, &home),
            base.join("vault").join("templates.toml")
        );
    }

    #[test]
    fn plain_files_are_owner_only() {
        let (_dir, store) = test_store("plain-perms");
        store.put_plain("ACME:NOTE:ME", "hello").unwrap();
        let mode = std::fs::metadata(store.path_of("ACME:NOTE:ME", PLAIN_SUFFIX))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
