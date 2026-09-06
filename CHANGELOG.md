# Changelog

## 2.0.0 — 2026-09-06

A complete rewrite. Version 1 described a Flask + React application with live camera feeds; this
version is a FastAPI service with a buildless dashboard, and the thing it is actually about is
keeping threat-intelligence data unreadable to anyone holding the database.

### Added

- **Encryption at rest** — envelope encryption with per-field AES-256-GCM data keys, wrapped under
  HKDF-derived key-encryption keys, with AAD binding each ciphertext to its table, column and row.
- **Blind indexes** — keyed, equality-only lookups over encrypted columns, so dedupe and correlation
  work without decrypting.
- **Complete key rotation** — rewraps every sealed field and rebuilds every blind index in one
  transaction, with a declared plan the test suite verifies for completeness.
- **Authentication** — Argon2id password hashing with a real policy, JWT access tokens, rotating
  refresh tokens with family revocation on replay, TOTP MFA with single-use recovery codes, account
  lockout and per-identity rate limiting.
- **RBAC** — viewer / analyst / admin mapped to explicit named permissions.
- **Hash-chained audit log** — every entry commits to its predecessor; verification over the API or
  the CLI.
- **IOC pipeline** — refanging, overlap-aware extraction of seven indicator types, rejection of
  private and reserved ranges, confidence decay with source-trust ceilings, DGA and TLD enrichment
  that explains every adjustment.
- **Detection** — a parsed expression language with no `eval`, six built-in rules, rule testing
  before saving, an Isolation Forest anomaly model with a pure-Python fallback, MITRE ATT&CK mapping,
  and alert deduplication.
- **Exports** — STIX 2.1 bundles, MISP events, CSV.
- **Dashboard** — five views, no framework, no build step, strict CSP.
- **Deployment** — hardened Dockerfile, Compose stack with an optional PostgreSQL profile, Render
  blueprint, Fly config, Procfile, and CI running ruff, bandit, pip-audit, the test suite on two
  Python versions, a core-install check on a third, and a container build that must answer
  `/api/health`.

### Fixed during development

- Refresh-token rotation issued a new family per rotation, so replaying a stolen token revoked
  nothing.
- Two built-in rule regexes were double-escaped and could never match.
- A beacon rule matched 47 events and produced 51 alerts; tightened, and alert deduplication added.
- The audit chain verified on write and failed on read, because SQLite returns naive datetimes and
  PostgreSQL returns aware ones.
- Alert titles quoted the indicator that caused them and were stored in the clear, along with the
  dedupe key derived from them — encrypted column, plaintext derivative.
- Key rotation covered indicators and users only, leaving event payloads, alert titles, session
  metadata and audit details sealed under a retired key.
- Anomaly explanations reported millions of sigma when a training feature had no variance.
- Bar charts rendered as empty tracks: an inline `<span>` cannot take a percentage height.
