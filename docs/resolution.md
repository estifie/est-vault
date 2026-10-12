# Resolution

Nothing is hardcoded: explicit environment first, then the
installation at hand, then shared pointers, then legacy locations.
First hit wins.

## Base directory

1. `EST_DIR` (first non-empty wins)
2. A binary sitting in a `bin/` directory resolves one level up
3. The current directory

## Store directory

1. `EST_VAULT_DIR`, then `SEC_DIR`
2. `<base>/vault/store`, when it is a directory
3. Pointer files (first non-empty line): `~/.config/est/vault-home`,
   then `~/.config/sec/home`
4. `~/Desktop/SECRETS`, while it still exists
5. `<base>/vault/store` (the creation target for `vault init`)

## Schema file

1. `EST_VAULT_SCHEMA`, then `SEC_SCHEMA`
2. `<base>/vault/templates.toml`, when it is a file
3. `~/.config/sec/schema.toml`, when it is a file
4. `<base>/vault/templates.toml`

## Keychain service

Reads try each service in order; writes go to the first.

1. `EST_VAULT_KEYCHAIN`, then `SEC_KEYCHAIN_SERVICE` (explicit)
2. `est-vault`, then `estifie-sec`

## Master key

1. `EST_VAULT_KEY` (explicit, 32 base64 bytes)
2. Keychain services above, newest first
3. `EST_VAULT_KEY_FILE`, else `~/.estifie/vault/key` (headless fallback)

## Migration note

The store bytes and the key never move: migration only repoints
`vault-home` and the environment. Reverting the pointers restores the
previous tool exactly.
