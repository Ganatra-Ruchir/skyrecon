# Architecture

How SkyRecon is put together, and why it is put together that way. [SECURITY.md](../SECURITY.md)
covers the threat model; this is about the shape of the code.

## The one-paragraph version

A FastAPI application over SQLModel, with a vanilla-JavaScript dashboard served from the same
process. Sensitive columns are encrypted individually before they reach the database, which means
the persistence layer is ordinary SQL and the encryption is not a storage-engine concern. Ingest,
scoring and alerting live in a service layer that the routers call and the tests call directly, so
detection logic is testable without HTTP. There is no build step, no message queue, and no cache —
deliberately, because none of them earn their operational cost at this size.

## Request path

```
                    ┌──────────────────────────────────────────────┐
  browser  ────────►│ SecurityHeaders → CORS → rate limit → auth   │
  or API            └───────────────────────┬──────────────────────┘
                                            │  role + permission check
                                            ▼
                                    ┌───────────────┐
                                    │   routers/    │  auth · intel · admin
                                    └───────┬───────┘
                                            ▼
                                    ┌───────────────┐
                                    │  services.py  │  ingest · score · alert
                                    └───┬───────┬───┘
                        ┌───────────────┘       └──────────────┐
                        ▼                                      ▼
                 ┌─────────────┐                        ┌─────────────┐
                 │    ioc/     │ parse · score          │   detect/   │ rules
                 │             │ enrich · export        │             │ anomaly
                 └──────┬──────┘                        └──────┬──────┘
                        └───────────────┬──────────────────────┘
                                        ▼
                         ┌──────────────────────────────┐
                         │ security/crypto.py — seal    │
                         └──────────────┬───────────────┘
                                        ▼
                                   SQLModel / SQL
                                        │
                                        ▼
                              audit.py — hash chain
```

Every write that matters ends in the audit log, and the audit log is appended in the same
transaction as the change it describes.

## Ingesting an indicator

1. **Extract.** `ioc/parser.py` refangs the text (`hxxp://` → `http://`, `[.]` → `.`,
   `[at]` → `@`), then runs ordered, overlap-aware pattern matching. Order matters: a URL is matched
   before the domain inside it, so `https://evil.com/x` does not also become an indicator for
   `evil.com`.
2. **Reject what would hurt you.** Private, loopback, link-local, CGNAT, multicast, reserved and
   documentation ranges are dropped. So are known-good domains. This is not tidiness — an analyst
   who pastes an incident report containing `10.4.2.19` and gets it added to a blocklist has caused
   an outage.
3. **Normalise.** Lowercase, strip trailing dots, punycode-safe, defang for display only. What is
   stored is the canonical form; what is shown is defanged, so nobody clicks it by accident.
4. **Deduplicate.** The blind index of the normalised value is unique. A second sighting reinforces
   the existing record rather than creating a new one.
5. **Score.** `ioc/scoring.py` combines confidence, severity and source trust into a 0–100 risk
   score. `ioc/enrich.py` adds entropy, DGA likelihood, TLD reputation and URL heuristics — each
   contributing a modifier *and a sentence explaining it*.
6. **Seal and store.** The value and any notes are encrypted; type, source, severity and counters
   stay queryable.

### Why confidence decays

A feed entry from 2023 and one from this morning are not the same evidence, but a static
`confidence: 80` treats them identically. Confidence follows a 30-day half-life and is recomputed on
read, so an indicator that nobody has seen since fades on its own.

Reinforcement is asymmetric: repeated sightings raise confidence, but only towards a ceiling set by
the trust of the source (0.4 for OSINT, 0.9 for manual analyst entry). A noisy feed can assert the
same indicator a thousand times and never reach the confidence of one analyst who checked.

## Detecting on an event

An event arrives, its payload is sealed, and three independent detectors run:

Source and destination addresses are stored twice over: sealed, so an analyst can read them, and
blind-indexed, so events can be correlated by address without decrypting anything. Storing only the
index — the first design — made the address unreadable to the people who needed it *and* made the
index impossible to rebuild during a key rotation.

**1. Indicator match.** The payload is scanned for stored indicators via blind index lookup. A hit
raises an alert, increments the indicator's hit count and reinforces its confidence.

**2. Rule match.** Every enabled rule is evaluated against a fact dictionary built from the event and
its primary matched indicator. Rules are strings like:

```
payload contains "powershell" and payload matches "-e(nc|ncodedcommand)?\s"
```

`detect/rules.py` tokenises and parses these with recursive descent into an expression tree, then
walks the tree. There is no `eval`, no `exec`, no `getattr` on user input, and no way for a rule
string to become code. A rule that raises at match time is skipped — a broken rule must never break
ingestion, because ingestion is how you find out you are being attacked.

**3. Anomaly.** `detect/anomaly.py` featurises the event into six dimensions (log bytes out, log
bytes in, log duration, log out/in ratio, hour of day, payload entropy) and scores it against a
baseline refit every 25 events. With scikit-learn installed that is an Isolation Forest; without it,
a z-score baseline in pure Python. The score maps to 0–1 through a curve anchored so that exactly
6σ lands on 0.85, the alerting threshold — and larger deviations keep ranking above it instead of
flat-lining at 1.0, which is what makes the queue sortable.

Two details that matter more than they look:

- **Deviations are capped at 50σ, and the standard deviation is floored** relative to each feature's
  own scale. A feature that never varied during training otherwise turns any new value into a
  "6,648,089σ from baseline" reading, which is worse than useless in front of an analyst.
- **The anomaly path is a ranking aid, not a verdict.** It says "unlike the baseline". Whether that
  is malicious is a rule's or a human's call — which is why the score is blended into risk rather
  than trusted outright.

### Alert deduplication

One cause, one alert. The dedupe key is a blind index of `(rule, indicator, title)`; an open alert
for the same cause inside 30 minutes increments `occurrences` instead of creating a row.

This started as a bug fix. A beacon rule matched 47 events during testing and produced 51 alerts —
a queue nobody would read. With dedupe the same run produces 6, one of which says "seen 47×". An
alert queue that cannot be read is the same as no alert queue.

## Storage

SQLModel over SQLAlchemy: SQLite by default, PostgreSQL by changing one environment variable. SQLite
runs in WAL mode with foreign keys enforced.

Encryption lives *above* the ORM, in the service layer, rather than in a custom column type. The
trade is explicitness against convenience: every `seal` and `open` call is visible at the point of
use, which makes it obvious when a new field is added and forgotten. The at-rest test is what
catches the case where it is forgotten anyway.

Sealed columns are named `*_sealed` and blind indexes `*_index`, so a schema diff shows immediately
whether a new field was considered.

## The dashboard

No framework, no bundler, no `node_modules`. Roughly 600 lines of HTML, CSS and JavaScript served as
static files from the same process.

That is a deliberate choice, and the reason is the CSP: `script-src 'self'` with no `unsafe-inline`
and no third-party origins. A build pipeline and a CDN would each need a hole in that policy. For a
five-view console, the framework was not buying enough to justify one.

Access tokens are held in a JavaScript closure, never in `localStorage` or a cookie — an XSS is
then a session-length problem rather than a persistent one. Refresh happens transparently on 401.

## What was traded away

| Decision | Cost | Why it was still right |
|---|---|---|
| Per-field encryption instead of full-disk | Cannot `LIKE` over sealed columns; blind indexes are equality-only | Full-disk encryption protects a stolen laptop, not a stolen database dump or a leaked backup |
| In-process rate limiter | Single-writer; needs Redis to scale out | One method behind an interface, and a dependency you do not need at one instance is a dependency you do not have to operate |
| In-process anomaly model | Retrains per process; not shared across replicas | Retraining 500 events is milliseconds, and a shared model service is a lot of machinery for that |
| Hand-written rule parser | ~200 lines to maintain | Every generic alternative is `eval` wearing a hat |
| No frontend framework | More manual DOM code | Keeps the CSP strict and the repository buildless |
| SQLite by default | Single writer | The whole thing runs from `git clone` with no database to install; PostgreSQL is one variable away |

## Testing

60 tests across seven files, all runnable without a network or a database server.

| File | What it pins down |
|---|---|
| `test_crypto.py` | Seal/open round trip, AAD rejection across fields, wrong-key failure, blind-index stability, rewrap, short-key rejection |
| `test_ioc.py` | Refanging, extraction ordering, private-range rejection, normalisation, confidence decay and reinforcement ceilings, entropy and DGA scoring |
| `test_rules.py` | Parser acceptance and rejection, operator semantics, injection attempts, rules that raise |
| `test_api.py` | End-to-end flows through HTTP: auth, ingest, detection, export, health |
| `test_rbac.py` | Every role against every permission, password policy, lockout |
| `test_at_rest.py` | Nothing sensitive is recoverable from the raw database files |
| `test_rotation.py` | The rotation plan covers every encrypted column, and data written before a rotation is still readable after one |

`test_at_rest.py` is the one to keep. It reads the bytes of `test.db`, `test.db-wal` and
`test.db-shm` — what an attacker actually steals — rather than querying through the ORM, and it was
written because an earlier version of this code failed it: the indicator column was encrypted, and
then the alert title quoted the indicator in the clear.

`test_rotation.py` is the other one, and it exists for the same reason in mirror image. Rotation
originally rewrapped indicators and users — the fields that came to mind — and left event payloads,
alert titles, session metadata and audit details sealed under a key that was about to be retired.
Nothing failed at rotation time; the data would simply have become unreadable later. The plan is now
declared in `app/security/rotation.py` and the test fails the build if a `*_sealed` or `*_index`
column is missing from it.

## Where this goes next

- Feed connectors (MISP, OTX, abuse.ch) behind `services.bulk_ingest`
- Redis-backed rate limiting to allow horizontal scaling
- Sigma rule import, translating into the existing expression language
- Webhook and SIEM forwarding on alert creation
- Anchoring the audit head hash in append-only external storage, closing the
  tamper-evident-to-tamper-proof gap
