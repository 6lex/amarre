# Amarre

**Fleet-wide restic backup console — monitor, trigger and restore across all your
servers without ever centralizing repository keys.**

Restic encrypts everything, including metadata. A console that can browse your
snapshots is therefore, by construction, a console that holds your keys. Amarre
takes the opposite route: **it never runs restic and never holds a repository
key.** It opens an SSH session whose key is constrained, host-side, by a
`command=` directive. The console *asks*; the host *decides*.

Compromising the console grants the ability to trigger backups and integrity
checks. It grants access to **no data**: no repository password, no storage
credentials, no file contents.

## Why this exists

Existing restic UIs back up the machine they run on. There is no fleet manager
in the restic ecosystem. Amarre fills that gap for people who run backups across
many servers and need one place to answer a single question: *is everything
still being backed up?*

## The alerting model

Amarre watches for the **absence** of a backup, not for failures.

A plan that stops existing emits no error. That is exactly how a backup can stop
running for months without anyone noticing — no alert fires, because nothing
failed. Amarre treats silence as the signal.

## Architecture

```
┌──────────────────────────────────────────┐
│  CONSOLE — no keys, no repository access │
│  inventory · commands · stats · alerts   │
└───────────────────┬──────────────────────┘
                    │ SSH, key restricted by command=
    ┌───────────────┼───────────────┬──────────────┐
┌───┴────┐     ┌────┴───┐     ┌─────┴──┐    ┌──────┴──┐
│  shim  │     │  shim  │     │  shim  │    │  shim   │  ← holds its own key
│ +policy│     │ +policy│     │ +policy│    │ +policy │     enforces its policy
└───┬────┘     └────┬───┘     └─────┬──┘    └──────┬──┘
    └───────────────┴───────────────┴──────────────┘
                         ▼
              object / SFTP storage — one sub-account per host
```

Routine backups are driven by **local systemd timers**, not by the console. If
Amarre is down, backups keep running. The reverse would be unacceptable.

## Security

Three independent barriers guard the console. None is sufficient alone, and the
failure of one does not open the door:

| Layer | Mechanism |
|---|---|
| Network | Source-IP allowlist — enforced in nftables *and* re-checked in the application |
| Password | Argon2id (RFC 9106, 64 MiB / 3 passes), constant-time comparison |
| Second factor | TOTP (RFC 6238), verified against the specification's test vectors |

Additional properties:

- Requests from a non-allowlisted source get **404, not 403** — they do not learn
  a console exists at this address
- An **empty allowlist refuses to start** rather than defaulting to open
- Sessions are bound to the IP that opened them; a stolen cookie replayed
  elsewhere is worthless
- Strict CSP, `frame-ancestors 'none'`, HSTS under TLS, SameSite=Strict cookies
- Login rate limiting, constant-time password comparison, and identical handling
  of unknown users and wrong passwords
- Host key verification is **mandatory** — no trust-on-first-use
- `CGO_ENABLED=0`: a static binary with a pure-Go SQLite, so no native
  dependency in a tool that holds a fleet's SSH access
- Audit trail on both sides — the host keeps its own, so an attacker who takes
  the console cannot erase what the host recorded

## Host-side policy

`/etc/amarre/policy.conf` lives on each host and **cannot be modified from the
console**. Defaults:

| Operation | Default | Rationale |
|---|---|---|
| `status`, `backup`, `check`, `ls` | allowed | metadata only |
| `restore` | **denied** | enable per host, with explicit target paths |
| `dump` (stream to browser) | **denied** | contents would transit the console in clear |
| `forget`, `prune`, `unlock`, `init` | **denied** | a compromised host must not prune its own backups |

## Status

Lot 1: SSH protocol to the shim, collector, fleet view, authentication, audit
log. Restore browsing, performance series and multi-channel alerting follow.

## License

GPL-3.0
