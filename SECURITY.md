# Security

SkyRecon holds the two things an intruder most wants from a security team: the indicators you are
hunting, and the telemetry those indicators came from. This document says exactly what is protected,
what is deliberately not, and what happens when things go wrong.

## Threat model

**Defended against**

| Threat | Control |
|---|---|
| Stolen database file, backup, or disk snapshot | Per-field AES-256-GCM. The master key lives in the environment, never in the database. |
| Ciphertext moved between rows or columns | AAD binds each ciphertext to `table \| column \| row-id`; a relocated blob fails authentication. |
| Offline password cracking | Argon2id, 64 MiB memory cost — GPU-hostile by construction. |
| Stolen refresh token | Rotation with family revocation: replaying a used token kills every descendant of it. |
| Credential stuffing / brute force | Token-bucket rate limiting per identity plus 15-minute lockout after 5 failures. |
| Malicious detection rule | Expressions are parsed by a hand-written recursive-descent parser. No `eval`, no `exec`, no dynamic import. |
| Quiet tampering with history | Hash-chained audit log; any edit or deletion breaks verification. |
| XSS in the dashboard | Strict CSP with no `unsafe-inline` for scripts, no third-party origins, all rendering escaped. |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY`. |
| Poisoned indicator lists | Private, loopback, link-local, CGNAT and documentation ranges are rejected at parse time, along with a known-good domain list. |
| Vulnerable dependency | Every pin exact; `pip-audit` in CI on every push and again weekly. |

**Not defended against — and honestly so**

- **A compromised application host.** If an attacker can read process memory or the environment,
  they have the master key. Encryption at rest protects the data at rest, not a live process.
- **A malicious administrator.** Admins can read decrypted data; that is the role. What they cannot
  do is remove the record of having done so — the audit chain would break.
- **Traffic analysis of the metadata.** See below.
- **Denial of service.** Rate limiting blunts casual abuse. Volumetric DoS is the load balancer's
  job, not the application's.

## What is encrypted, and what is not

Encryption is per-field, so this table is the honest inventory rather than a claim about the
database as a whole.

| Table | Sealed (AES-256-GCM) | Blind index | Left readable, on purpose |
|---|---|---|---|
| `users` | e-mail, display name, TOTP secret | e-mail | role, active flag, MFA flag, lockout counters, timestamps, Argon2id hash |
| `indicators` | the indicator value, analyst notes | value | type, source, confidence, severity, tags, TLP, hit count, timestamps |
| `events` | full payload, source IP, destination IP | source IP, destination IP | source, kind, byte counts, duration, risk score, timestamp |
| `alerts` | title, detail, resolution note | dedupe key | severity, state, score, occurrences, ATT&CK IDs, foreign keys, timestamps |
| `sessions` | user agent, IP | — | user, family, refresh-token digest, expiry, revocation |
| `audit_log` | detail | — | sequence, timestamp, actor, action, target, outcome, hashes |
| `rules` | — | — | everything: detection logic is yours, not a victim's |

Everything in the last column is there because the database has to sort, filter or join on it. That
is a real trade-off with a real consequence: **an attacker with the raw files learns shape, not
content.** They can see that fourteen critical alerts fired on Tuesday and that one indicator was
hit forty times — they cannot learn which indicator, from whom, or what was in the payload.

Two specifics worth naming:

- **`indicators.tags`** is plaintext so it can be filtered on. If your tags are campaign codenames
  you consider sensitive, seal that column too — the pattern to copy is `notes_sealed`.
- **`events.src_ip` / `dst_ip`** are stored both sealed and blind-indexed. The index lets you
  correlate events by address without decrypting; the ciphertext is what an authorised analyst
  actually reads, and what a key rotation uses to rebuild the index.

## How the encryption works

```
master key  (environment only, 32 bytes)
    │
    ├── HKDF-SHA256(salt=per-record) ──► KEK ──► wraps the data key
    │
    └── HKDF-SHA256(salt=domain)     ──► MAC key ──► blind index
```

Each sealed value gets a fresh 256-bit data key and a fresh 96-bit nonce. The data key is wrapped
under a key-encryption key derived from the master key with a per-record salt, so no two records
share a wrapper. Stored form:

```
v1.<salt+wrapped-data-key>.<nonce>.<ciphertext+tag>
```

Additional authenticated data is `v1|table|column|record-id`. The tag therefore covers not just the
plaintext but the field the ciphertext belongs to: an attacker who swaps two encrypted values
between rows gets an authentication failure, not a silent substitution.

**Blind indexes** are `SHA-256(HKDF(master, salt=domain) ‖ normalised-value)`, truncated to 43
characters. They support equality lookup — dedupe, "have we seen this indicator", "find this user by
e-mail" — and deliberately nothing else. No ordering, no prefix matching, no reversal without the
master key. Separate domains ("user-email", "indicator", "alert-dedupe") mean the same value in two
contexts produces two unrelated indexes.

**Rotation** generates a new master key server-side, rewraps every sealed field under it, and
rebuilds every blind index in the same transaction — the indexes are keyed by the master key too, so
skipping them would silently break dedupe and IP correlation.

```bash
curl -X POST "$HOST/api/admin/keys/rotate?dry_run=true" -H "Authorization: Bearer $ADMIN"
# → {"dry_run": true, "fields_to_rewrap": 148, "by_table": {...}}

curl -X POST "$HOST/api/admin/keys/rotate?dry_run=false" -H "Authorization: Bearer $ADMIN"
# → {"fields_rewrapped": 148, "new_master_key": "...", "action_required": "..."}
```

`dry_run` defaults to `true` and writes nothing. The new key is returned exactly once and is never
stored: put it in the environment and restart. If anything fails mid-rotation the whole transaction
rolls back, because a database half under one key and half under another is unrecoverable.

**Completeness is enforced by the build.** The set of columns a rotation must touch is declared in
`app/security/rotation.py`, and `tests/test_rotation.py` cross-checks that declaration against the
table definitions. Add a `*_sealed` column without adding it to the plan and the suite fails —
which matters, because the alternative is a field that becomes permanently unreadable the moment
the old key is retired, with nothing complaining until an analyst opens an old alert.

## Key management

The master key is the whole system. Three rules:

1. **Generate it properly.** `python -m app.cli genkeys`. Not a passphrase, not a UUID, not
   `changeme`.
2. **Store it outside the database and outside the repository.** A secret manager, a platform secret
   (Render generates and stores one for you), or a KMS. Never `.env` in a commit — `.gitignore`
   excludes it, which is a safety net, not a policy.
3. **Back it up before there is data.** There is no recovery path, no escrow and no backdoor. Losing
   the master key means the encrypted rows stay encrypted forever. This is the correct behaviour and
   it will not be softened.

Rotate on a schedule, and immediately if you suspect exposure. Keep the previous key until rotation
has verified — a rewrap you cannot roll back is a worse position than the one you were in.

## Authentication

- **Passwords** — Argon2id, `time_cost=3`, `memory_cost=64 MiB`, `parallelism=2`. Policy rejects
  fewer than 12 characters, fewer than 3 character classes, common passwords, four-character
  repeats, and anything containing the local part of the user's own e-mail. Candidates are NFKC-
  normalised first, so two visually identical passwords typed on different platforms compare equal.
- **Access tokens** — JWT (HS256), 15 minutes by default, carrying user id, role, session id and
  whether MFA was satisfied. `iss`, `exp`, `iat` and `sub` are all required at verification, so a
  token without them is rejected rather than accepted with defaults.
- **Refresh tokens** — opaque 256-bit random values; only the SHA-256 digest is stored. Each refresh
  issues a new token and revokes the old one. A replayed token revokes the entire family, because
  the only way a used token gets presented again is that someone else has it.
- **MFA** — TOTP (RFC 6238), 30-second step, ±1 window of drift for clock skew. Required for admins
  unless `SKYRECON_REQUIRE_ADMIN_MFA=false`. The secret is sealed like any other sensitive field.
  Enrolment also issues ten single-use recovery codes, shown once; only their SHA-256 digests are
  stored.
- **Lockout** — 5 failed logins locks the account for 15 minutes. Failed attempts are audited with
  the reason, never with the attempted password.

## The audit log

Every entry hashes `{seq, timestamp, actor, action, target, outcome, previous-hash}` with SHA-256
and stores the result. Entry *n* commits to entry *n−1*, so silently removing or editing an event
requires rewriting every entry after it.

```bash
python -m app.cli verify-audit          # exits non-zero and names the broken sequence
GET /api/admin/audit/verify             # same check over the API
```

Timestamps are canonicalised to naive UTC at microsecond precision before hashing. That is not
cosmetic: SQLite returns naive datetimes and PostgreSQL returns aware ones, and hashing
`isoformat()` directly meant a chain that verified on write and failed on read.

The chain is tamper-*evident*, not tamper-*proof*. An attacker with write access to the database and
the application's own code could recompute the whole chain. Detecting that requires anchoring the
head hash somewhere the attacker does not control — periodic export to append-only storage is the
normal answer.

## Reporting a vulnerability

Open a [security advisory](https://github.com/Ranchiro/skyrecon/security/advisories/new) on the
repository, or e-mail the maintainer. Please do not open a public issue for anything exploitable.

Useful reports include what you did, what happened, and what you expected. A proof of concept is
welcome; please test against your own instance rather than someone else's.

## Deployment checklist

- [ ] `SKYRECON_ENV=production` — the application refuses to start without real secrets, and hides `/docs`
- [ ] Master key generated with `genkeys`, stored in a secret manager, and **backed up**
- [ ] JWT secret is distinct from the master key and at least 32 characters
- [ ] TLS terminated in front of the app; HSTS is emitted automatically in production
- [ ] `SKYRECON_CORS_ORIGINS` set to your own origin, not left at localhost
- [ ] Bootstrap administrator's password changed after first login, and MFA enrolled
- [ ] Database on a persistent volume with backups — and the backups tested by restoring one
- [ ] `python -m app.cli verify-audit` scheduled, with someone who reads the result
- [ ] `pip-audit` in CI is green, and someone is subscribed to it failing
