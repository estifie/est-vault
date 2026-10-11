# Changelog

All notable changes, newest first. Format: Keep a Changelog;
versions: SemVer.

''## [Unreleased]

### Added

- `stale [--days N]` + `rotate ADDR [--yes]`: secret ages (file
  mtime) with stale flags, and fresh-nonce re-seals with age reset.
  Rotation refreshes encryption; the checklist reminds to regenerate
  at the provider afterwards.

- `push --verify`: re-read the remote file over ssh after the copy
  and compare SHA-256 digests; mismatched bytes fail loudly instead
  of reporting success.
- `push` runs both hops strict (`StrictHostKeyChecking=yes`,
  `BatchMode=yes`): unknown/changed host keys refuse, nothing ever
  prompts for a password.
- Every push appends to `<store>/.push-log` (0600): when, result,
  target, count, verified, env names — never values.

### Fixed

- `push --json` on real sends (and `--base --json` dry runs) printed
  human lines before the envelope; JSON mode now prints only the
  object, per the CLI contract.

## [0.1.0] - 2026-10-06

### Added

- `addr`, `crypto`, `keychain`, `schema`, `store`: the secrets store
  library, ported from Angel's vault with a byte-identical format.
- `EST_*` environment with full `ANGEL_*`/`SEC_*` fallback, and the
  `est-vault` Keychain service with fallback reads.
- `Zeroizing` key material, wiped on drop.
- Committed conformance vectors proving the Python-generated fixtures
  open untouched.
- `est-vault` binary: `where`, `init`, `list`, `add`, `get`, `remove`,
  `templates`, `template add/delete`, `run`, `push`, and vault-scoped
  `check`, with `--json` envelopes throughout.
