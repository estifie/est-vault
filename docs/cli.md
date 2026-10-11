# est-vault CLI

The whole store from a terminal — and from an agent. `--help` is the
short version of this file.

```sh
est-vault where
est-vault init
est-vault list [PREFIX]
est-vault add ADDR [--plain|--secret] [--file NAME] [--replace] [--value V]
est-vault get ADDR [--out PATH]
est-vault remove ADDR [--yes]
est-vault stale [--days N]
est-vault rotate ADDR [--yes]
est-vault templates
est-vault template add TPL [--plain] [--file] [--hint H] [--about A]
est-vault template delete PROVIDER KIND
est-vault run [--file F] [--use ADDR=ENV]... -- CMD ...
est-vault push [--file F] [--use ADDR=ENV]... [--base F] [--dry-run] [--verify] HOST:PATH
est-vault check
```

## Conventions

- **Exit codes:** `0` ok, `1` failed, `2` wrong usage. `run` exits
  with the child's own status.
- **Errors** go to stderr as `est-vault: ...`; data goes to stdout.
- **Destructive commands ask first** — unless `--yes` is passed or stdin is
  not a terminal, in which case they refuse rather than guess. Agents:
  always pass `--yes` (you already decided).
- **`--json`** rides on any command, anywhere on the line, and prints
  one JSON object instead of text:

```json
{"ok":true,"v":1,...data...}
{"ok":false,"v":1,"error":"no secret X:Y"}
```

- `get` stays raw bytes either way — no envelope belongs around a
  value. `run` prints the child's own output; only its manifest
  errors honor `--json`. Usage errors stay human text on stderr
  with exit 2.

''## Rotation (stale + rotate)

Age is the secret file's mtime: any write (`add --replace`, `rotate`)
resets it. `stale` lists ages and flags rows older than `--days`
(default 90); `rotate` re-seals one address under a fresh nonce and
resets its age. Rotation refreshes the encryption, not the credential:
afterwards regenerate at the provider, then `add --replace`.

```sh
est-vault stale --days 90
est-vault rotate OPENROUTER:KEY:ESTIFIE --yes
```

## where

Where this process resolves the store, the templates, and the key.
Reads nothing secret; the first command to run when anything looks
off. See `resolution.md` for the full order.

```sh
est-vault where
est-vault where --json   # {"ok":true,"v":1,"store":"...","templates":"...","keychain":"..."}
```

## init

Makes a store where `where` points: the folder, its `.salt` marker,
and a Keychain key unless one already opens. Refuses when a store
already lives there.

```sh
est-vault init   # {"ok":true,"v":1,"store":"..."} with --json
```

## list

Addresses, one per line, sorted. JSON adds the storage per address.

```sh
est-vault list
est-vault list TELEGRAM:
est-vault list --json   # {"ok":true,"v":1,"addresses":[{"address":"...","storage":"plain"}]}
```

## add

Stores a value. It rides `--value` or stdin (one trailing newline is
stripped); empty values refuse. `--plain`/`--secret` force the
storage, else the schema decides; `--file NAME` stores file bytes;
`--replace` overwrites an existing address.

```sh
echo -n hunter2 | est-vault add TELEGRAM:BOT:DEMO
est-vault add T:K:P --plain --value hello
est-vault add A:P8:ME --file AuthKey.p8 < key.p8
```

JSON (`--json`): `{"ok":true,"v":1,"address":"..."}` plus a `"note"`
when the address's provider is not in the schema yet.

## get

Prints the value as raw bytes. File secrets need `--out PATH`.

```sh
est-vault get TELEGRAM:BOT:DEMO
est-vault get A:P8:ME --out AuthKey.p8
```

## remove

Deletes both twins after asking. `--yes` skips the question; a
non-terminal stdin refuses.

```sh
est-vault remove TELEGRAM:BOT:DEMO --yes
```

JSON: `{"ok":true,"v":1,"address":"..."}`.

## templates

Every template, `PROVIDER:KIND:<VAR>...` with `plain`/`file` flags.
JSON carries provider, kind, scope array, flags, and hint.

```sh
est-vault templates
est-vault template add 'GITHUB:PAT:<ACCOUNT>' --hint 'classic token'
est-vault template delete GITHUB PAT
```

`delete` refuses while any address still uses the template.

## run

Runs `CMD` with the named secrets as env vars. Every address opens
before the child spawns, so a missing secret fails the run instead of
running naked. File secrets land in a private temp dir the env var
points at; the dir is removed when the child exits.

```sh
est-vault run --use BACKEND:MASTERKEY:PROD=MASTER_KEY -- ./deploy.sh
est-vault run --file .sec.toml -- ./deploy.sh
```

Without `--file`, the manifest is the `.sec.toml` found walking up
from the working directory (stopping at `$HOME`); a missing manifest
is fine when `--use` names secrets. Manifest entries are
`ENV = "ADDR"` or `ENV = { address = "ADDR", optional = true }`, in
the `[use]` table only — optional entries skip silently when
unstored, anything else missing fails before the child spawns.

## push

Builds a `.env` from the store and scps it to `HOST:PATH`. `--base`
prepends a local file (store values come last and win, with a note
naming shadowed names); `--dry-run` names what would go — env names
only, never values — and sends nothing. `--verify` re-reads the
remote file over ssh after the copy and compares SHA-256 digests,
refusing success unless the bytes match. File secrets refuse: a `.env`
holds values.

Both hops run strict: unknown or changed host keys refuse, and nothing
ever prompts for a password — `ssh HOST` once manually to accept a new
host, then push. Every send (and failed send) appends one line to
`<store>/.push-log`: when, result, target, count, verified, env names.
Never values.

```sh
est-vault push --dry-run --use A=B me@vps:/srv/app/.env
est-vault push --verify --file .sec.toml me@vps:/srv/app/.env
```

JSON: `{"ok":true,"v":1,"target":"...","sent":N}` plus
`"dry_run":true` on dry runs and `"verified":true` on verified sends.

## check

Store health: the store exists, the key opens, the schema parses, and
every encrypted file opens with the key. Values are opened but never
printed; only addresses name failures. Exit 0 only when all four hold.

```sh
est-vault check
est-vault check --json
```

JSON: `{"ok":true,"v":1,"store":{"path":"...","present":true,
"secrets":N},"key":{"service":"...","present":true},"schema":{"path":
"...","providers":N},"files":{"encrypted":N,"plain":N,"failed":[]}}`.
Schema and key failures replace their detail object with an
`"error"` field.

## Divergences from the legacy vault

- Envelopes carry `"v":1` per the EST CLI contract; shapes are
  otherwise identical.
- The legacy `teach`/`forget` template aliases were not carried over.
- `check` is vault-scoped (store, key, schema, files); the legacy
  `check` validates its scheduler config instead.
