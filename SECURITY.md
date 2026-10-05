# Security

## Threat model

Single-user local machine. Secrets are encrypted at rest, cross
machines only through an explicit push over SSH, and never leave the
machine otherwise. No hosted service, no telemetry, no accounts.

- At rest: AES-256-GCM with random nonces, the address as associated
  data (a file copied to another address never opens), the 32-byte key
  in OS key storage, `0700`/`0600` file modes, atomic writes. See
  [format](docs/format.md).
- In memory: key material is `Zeroizing` (wiped on drop); error and
  debug output never contain a decrypted byte.
- In motion: values travel store → requester only. This crate never
  logs values; products audit every reveal to screen.
- Network: none. This crate opens no sockets and makes no requests.

Out of scope: a compromised OS keychain, a machine the attacker holds
while unlocked, and exfiltration by a process the user already ran
with the values in its environment.

## Reporting

Do not open a public issue for a suspected vulnerability. Report it
through a [GitHub Security
Advisory](https://github.com/estifie/est-vault/security/advisories/new)
(private), including what you ran and what you observed. Aim: first
response within three days, fix or mitigation plan within two weeks
for anything that leaks secret bytes.

## Supported versions

Pre-1.0: only the latest `main` is supported. After 1.0, the latest
minor of the current major.
