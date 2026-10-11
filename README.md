# est-vault

Central environment, configuration, and secrets management for the
EST product ecosystem: one encrypted file store every EST product
reads, addressed as `PROVIDER:KIND:SCOPE…`.

Status: pre-release. The crate API is unstable until 1.0; the store
format is stable — byte-compatible with the legacy vault format and
the Python `sec` toolkit, pinned by the conformance suite in
`tests/vectors/`.
Platform: macOS in v1 (the key lives in the Keychain, reached through
the `security` CLI).

## CLI

```sh
cargo install --path .   # or: cargo build --release, then ./../.target/release/est-vault
est-vault where          # store, templates, keychain paths
est-vault init           # make a store where `where` points
echo -n value | est-vault add TELEGRAM:BOT:DEMO
est-vault get TELEGRAM:BOT:DEMO
est-vault run --use TELEGRAM:BOT:DEMO=BOT_TOKEN -- ./bot.sh
est-vault check
```

The full reference is [docs/cli.md](docs/cli.md): every command in
text and `--json` shapes. Store layout and crypto:
[format](docs/format.md). How the store, schema, and key are found:
[resolution](docs/resolution.md).

## Library

```rust
use est_vault::store::Store;

let store = Store::standard();
for addr in store.addresses("TELEGRAM:") {
    println!("{addr}");
}
```

## Modules

| Module | Purpose |
|---|---|
| `addr` | Address validation and normalization |
| `crypto` | AES-256-GCM seal/open with the address as associated data |
| `keychain` | The 32-byte key, held in the Keychain |
| `schema` | Provider templates: what each provider keeps |
| `store` | The file store: seal, unseal, list, remove |

## Develop

```sh
git config core.hooksPath .githooks   # one-time: enable the repo hooks
cargo fmt --all -- --check            # gate 1: formatting
cargo clippy --all-targets -- -D warnings   # gate 2: lints
cargo test                            # gate 3: unit + conformance tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow,
[SECURITY.md](SECURITY.md) for the threat model and reporting, and
[CHANGELOG.md](CHANGELOG.md) for what changed.

## License

Dual-licensed under MIT or Apache-2.0, at your option. See
[LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
