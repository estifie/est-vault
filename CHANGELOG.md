# Changelog

All notable changes, newest first. Format: Keep a Changelog;
versions: SemVer.

## [Unreleased]

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
