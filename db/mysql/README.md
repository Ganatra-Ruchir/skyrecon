# MySQL schema — optional, not what the application uses

**The running application does not use these files.** SkyRecon's schema is defined in
`app/models.py` as SQLModel classes, and SQLModel creates the tables itself against SQLite
or PostgreSQL. That is the source of truth.

These files are a separate, more ambitious relational design for MySQL 8, kept here
because the work is done and validated — not because anything reads them today.

| File | Contents |
|---|---|
| `schema.sql` | 33 tables, 43 foreign keys. Validated on MySQL 8.0.46: zero errors, zero warnings, and idempotent on a second run. |
| `seed_demo.sql` | Development data — 120 alerts, 215 alert reasons, 12 indicators, 18 entities, 9 graph edges, 5 incidents. |

## What it adds over the current model

The live model has seven tables. This one keeps all of them and adds the pieces the
current design has no home for:

- **`entities` + `entity_edges`** — hosts, accounts, processes and files as first-class
  rows with typed relationships, so an investigation graph survives the alert that
  revealed it.
- **`alert_reasons`** — one row per piece of evidence instead of a text blob, so
  "every alert where the DGA classifier contributed" is a `WHERE`, not a `LIKE`.
- **`incidents`, `incident_alerts`, `investigation_timeline`** — grouping alerts into a
  case with an owner and a status.
- **`threat_actors`, `watchlists`, `playbooks`, `feed_connectors`, `saved_hunts`**.
- **`login_codes`, `login_attempts`** — passwordless email OTP, with rate limiting and
  lockouts. The reference implementation is `docs/reference/auth_otp.py.example`.

## If you want to adopt it

It is not a drop-in. Adopting MySQL means:

1. Rewriting `app/models.py` so SQLModel matches these tables, or dropping SQLModel for
   raw SQL against this schema.
2. `pip install pymysql` and pointing `SKYRECON_DATABASE_URL` at
   `mysql+pymysql://user:pass@host/skyrecon`.
3. Revisiting `tests/test_at_rest.py` — it reads the raw bytes of `test.db`, which is a
   SQLite file. The equivalent check against MySQL means dumping the tablespace.
4. A migration path for existing encrypted rows: the sealed values carry AAD binding them
   to their table, column and row id, so moving them between schemas means unsealing and
   resealing under the new coordinates. Do it with `app.security.rotation`, not by hand.

Until that work happens, treat this directory as a design document that happens to be
executable.

## Running it anyway, to look around

```bash
mysql -u root -p < db/mysql/schema.sql
mysql -u root -p < db/mysql/seed_demo.sql
mysql -u root -p -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='skyrecon';"
# 33
```
