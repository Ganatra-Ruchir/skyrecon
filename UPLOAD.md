# Uploading this to GitHub

This folder is the **complete repository** — your v2 backend recovered from your machine,
plus everything built in this session. 93 files. Nothing of yours was dropped.

Delete this file after you upload; it is instructions, not part of the project.

---

## What is here

**Yours, untouched** — every Python file, both test suites, all deployment config:

```
app/            41 files: security/ ioc/ detect/ routers/ + main, models, services…
tests/          your 8 pytest files, unchanged
docs/           ARCHITECTURE.md, screenshots/
README.md · SECURITY.md · CHANGELOG.md · LICENSE
Dockerfile · docker-compose.yml · fly.toml · render.yaml · Procfile · pyproject.toml
requirements.txt · requirements-dev.txt · requirements-ml.txt · requirements-postgres.txt
.env.example · .dockerignore · seed.py
```

**Added this session:**

```
console/           standalone analyst workbench — one self-contained HTML file
engine/            its analysis engine (no dependencies, runs in browser and Node)
tests/js/          89 unit tests + 28 browser tests
tools/             generate_er.py — builds the ER diagram from app/models.py
docs/diagrams/     the ER diagram it produces (.drawio, .svg, .png)
docs/reference/    auth_otp.py.example — email OTP reference implementation
brand/             logo: mark, lockup, favicon, monochrome
db/mysql/          optional MySQL schema — read its README before assuming anything
```

**Modified, carefully:**

| File | Change |
|---|---|
| `.github/workflows/ci.yml` | Your four jobs (`test`, `core`, `audit`, `image`) kept exactly. Two added: `console` and `diagrams`. |
| `.gitignore` | Your 16 lines kept. 5 appended for the JS toolchain. |
| `README.md` | Two edits only: fixed the `Ranchiro/skyrecon` badge URL (three occurrences — your CI badge was pointing at a repo that isn't yours), and added a short "Two front ends" section pointing at `console/`. |
| `.gitattributes` | **New.** You had none, which is why touching the repo from WSL showed all 59 files as modified — 6,533 insertions of pure line endings. |

---

## Upload

```powershell
cd ~\skyrecon        # or wherever you extract this

git init
git add -A
git commit -m "SkyRecon: encrypted-at-rest threat intelligence platform"
git branch -M main
git remote add origin https://github.com/Ganatra-Ruchir/skyrecon.git
git push -u origin main --force
```

`--force` is only needed because you cleared the remote. If the repo still has history you
want, drop the flag and merge instead.

**Commit from PowerShell, not from WSL or a Linux shell.** The `.gitattributes` fixes this
going forward, but the first commit still normalises through whatever client makes it.

---

## After the push

**1. CI should go green.** Six jobs. The two new ones are worth knowing about:

- `console` — runs the 89 unit tests, rebuilds `console/index.html` from `engine/engine.js`
  and `console/app.template.html`, and **fails if the committed file does not match**. The
  console can never silently drift from its engine.
- `diagrams` — re-runs `tools/generate_er.py` and **fails if the committed ER diagram no
  longer matches `app/models.py`**. Add a column to a model, and CI tells you the diagram
  is stale.

Both are verified idempotent here, so they pass on a clean checkout.

**2. Fix the About text** — gear icon next to *About*. It still claims React and live
camera feeds:

> Explainable threat intelligence and detection — AES-256-GCM at rest, blind-index search,
> tamper-evident audit log, and detections that show their working. Python · FastAPI · SQLModel.

Remove the `react` topic. Add `detection-engineering`, `stix`, `mitre-attack`.

**3. Optionally host the console.** `console/index.html` needs no build and no server.
Settings → Pages → deploy from `main`, folder `/`. It lands at
`https://ganatra-ruchir.github.io/skyrecon/console/`, which also gives your portfolio
panel a live preview to point at.

---

## Two honest notes

**The console duplicates some of your backend.** `engine/engine.js` re-implements what
`app/ioc/parser.py`, `enrich.py` and `scoring.py` already do — refanging, noise filtering,
entropy, DGA scoring, TLD weighting. It earns its place by running with no backend at all,
but two implementations of the same scoring logic drift apart. `console/README.md` says so
and suggests the fix: have the console call your API when one is reachable, and keep the
local engine as the offline path.

**The MySQL schema is not your schema.** Your application defines its tables in
`app/models.py` as SQLModel classes over SQLite or PostgreSQL — seven tables. The MySQL
files are a larger relational design that nothing currently reads. `db/mysql/README.md`
explains what adopting it would actually cost, including that `tests/test_at_rest.py`
reads raw SQLite bytes and would need rewriting. It is kept because the work is validated,
not because it is wired in.
