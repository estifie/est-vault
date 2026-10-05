//! Conformance: the Python-generated vectors are the format's one
//! definition, and this crate reads them all.
//!
//! The fixtures are committed under `tests/vectors/` (regenerated only by
//! the vendored `make_vectors.py`), so these tests fail — never skip —
//! when the format drifts. Keychain is never touched: the vectors name
//! their own key.

use std::path::PathBuf;

use est_vault::{Error, base64_decode, store::Store};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn vectors() -> serde_json::Value {
    let text = std::fs::read_to_string(vectors_dir().join("vectors.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn fixture() -> (serde_json::Value, [u8; 32], Store) {
    let v = vectors();
    let dir = vectors_dir();
    let raw = base64_decode(v["key_b64"].as_str().unwrap()).unwrap();
    let key: [u8; 32] = raw.as_slice().try_into().unwrap();
    let store = Store::at(dir.join("store"), dir.join("does-not-exist-schema.toml"));
    (v, key, store)
}

#[test]
fn every_case_opens_to_its_value() {
    let (v, key, store) = fixture();
    for case in v["cases"].as_array().unwrap() {
        let addr = case["address"].as_str().unwrap();
        match store.unseal_with(addr, &key) {
            Ok(est_vault::store::Sealed::Text(bytes)) => {
                assert_eq!(case["kind"].as_str().unwrap(), "text", "{addr}");
                assert_eq!(bytes, case["value"].as_str().unwrap().as_bytes(), "{addr}");
            }
            Ok(est_vault::store::Sealed::File { name, data }) => {
                assert_eq!(case["kind"].as_str().unwrap(), "file", "{addr}");
                assert_eq!(name, case["filename"].as_str().unwrap(), "{addr}");
                let want = base64_decode(case["data_b64"].as_str().unwrap()).unwrap();
                assert_eq!(data, want, "{addr}");
            }
            Err(e) => panic!("{addr} should open: {e}"),
        }
    }
}

#[test]
fn absent_addresses_miss() {
    let (v, key, store) = fixture();
    for addr in v["absent"].as_array().unwrap() {
        let addr = addr.as_str().unwrap();
        assert!(
            matches!(store.unseal_with(addr, &key), Err(Error::NotFound(_))),
            "{addr} should miss"
        );
    }
}

#[test]
fn lowercase_input_finds_the_uppercase_address() {
    let (v, key, store) = fixture();
    let input = v["lowercase_finds"]["input"].as_str().unwrap();
    let want = v["lowercase_finds"]["value"].as_str().unwrap();
    match store.unseal_with(input, &key) {
        Ok(est_vault::store::Sealed::Text(bytes)) => assert_eq!(bytes, want.as_bytes()),
        other => panic!("lowercase should find: {other:?}"),
    }
}

#[test]
fn broken_files_fail_with_the_right_kind() {
    let (v, key, store) = fixture();
    for case in v["errors"].as_array().unwrap() {
        let addr = case["address"].as_str().unwrap();
        let err = match store.unseal_with(addr, &key) {
            Ok(sealed) => panic!("{addr} should fail, opened instead: {sealed:?}"),
            Err(e) => e,
        };
        let kind = match addr.rsplit(':').next().unwrap() {
            "TAMPERED" | "MOVED" => "decrypt",
            _ => "format",
        };
        match (kind, err) {
            ("decrypt", Error::Decrypt(_)) | ("format", Error::Format(_)) => {}
            (_, other) => panic!("{addr} failed wrong: {other}"),
        }
    }
}

#[test]
fn bad_addresses_never_reach_the_disk() {
    let v = vectors();
    for addr in v["bad_addresses"].as_array().unwrap() {
        let addr = addr.as_str().unwrap();
        assert!(
            est_vault::addr::norm(addr).is_err(),
            "{addr:?} should refuse"
        );
    }
}

#[test]
fn addresses_list_in_order() {
    let (v, _, store) = fixture();
    for key in ["addresses_under_telegram", "addresses_under_apple"] {
        let prefix = key.split('_').nth(2).unwrap().to_uppercase() + ":";
        let want: Vec<String> = v[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().to_string())
            .collect();
        assert_eq!(store.addresses(&prefix), want, "{key}");
    }
}
