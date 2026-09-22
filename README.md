# AI Finance Operations Agent

Two subsystems that share a backend, a database and a React console.

**Accounts payable** - upload an invoice and it runs through OCR extraction, validation, duplicate
detection, fraud checks and approval routing, then posts a journal entry to the ledger.

```
Invoice upload
   -> OCR / field extraction   (Gemini vision)
   -> Validation                (required fields, date/currency/math checks)
   -> Duplicate detection        (vendor + invoice number / amount+date fuzzy match)
   -> Fraud checks               (rule-based flags + Gemini risk assessment)
   -> Approval routing           (auto-approve / pending review / reject)
   -> Accounting entry           (double-entry journal entry, JSON + CSV export)
```

**Transaction fraud investigation** - score every payment against five detectors, then run an
agent pipeline over the ones that matter to build a case file an analyst can act on.

```
Transaction
   -> Point-in-time features + named risk signals
   -> Five detectors    (XGBoost, rule engine, entity graph, behavioural profile, Isolation Forest)
   -> Deterministic score combination + triage
   -> Alert              (low risk -> auto-closed but kept; medium/high -> investigated)
   -> Investigation agents (evidence, behaviour, intel, network, history, hypothesis,
                            recommended actions, narrative)
   -> Case                (analyst decides; the decision becomes the next model's training label)
```

See [Fraud investigation](#fraud-investigation) below.

## Stack

- **Backend**: Python, FastAPI, SQLAlchemy (SQLite by default), [google-genai](https://github.com/googleapis/python-genai) for OCR extraction, invoice fraud-risk assessment and case narratives.
- **Detection**: XGBoost (supervised) and scikit-learn Isolation Forest (unsupervised), networkx for the entity graph, joblib for the model registry artifacts.
- **Frontend**: React 19 + TypeScript + Vite, React Router. Plain CSS, no UI framework.

## Project layout

```
app/
  main.py                 FastAPI app and REST endpoints
  config.py                Settings (env-var driven)
  db.py, models.py         SQLAlchemy engine/session and ORM models
  schemas.py                API request/response schemas
  pipeline/
    extraction.py           OCR / field extraction (Gemini vision + structured output)
    validation.py            Field and math validation rules
    duplicates.py            Duplicate invoice detection
    fraud.py                  Rule-based flags + Gemini fraud-risk assessment
    approval.py               Approval routing decision
    accounting.py              Journal entry construction + CSV export
    orchestrator.py             Runs all stages for one uploaded invoice
    gemini_client.py             Lazily-constructed Gemini client
  fraud_investigation/
    models.py                ORM models (banking data, alerts, cases, audit log, model registry)
    history.py                Point-in-time data access, shared by training and serving
    features.py                Feature + named-signal engine
    intel.py                    Watchlist screening and IP reputation
    geo.py, clock.py             City coordinates; the module's time convention
    synthetic.py                  Synthetic bank generator with injected fraud scenarios
    evaluation.py                  Threshold evaluation for R014 on labelled APP scams + look-alikes
    detection/
      rules.py                     Deterministic rule engine
      ml.py                         XGBoost + Isolation Forest serving, TreeSHAP explanations
      graph.py                       Entity graph, k-hop expansion, communities, taint
      behavior.py                     Behavioural profile and per-dimension deviation
    scoring.py                 Combines detector outputs into one attributable score
    training.py                 Model training, registry, activation, PSI drift
    agents/                      The investigation pipeline (one module per agent)
    pipeline.py                   Transaction -> alert -> case
    cases.py                       Case workflow, decisions, feedback loop
    audit.py                        Hash-chained, append-only audit trail
    overview.py, api.py, schemas.py   Dashboard aggregation and the REST surface
frontend/
  src/
    pages/                   InvoiceListPage, UploadPage, InvoiceDetailPage, DashboardPage,
                             FraudDashboardPage, CaseQueuePage, CaseDetailPage
    components/               Layout, StatusBadge, RiskBadge, NetworkGraph
    api.ts, types.ts           Typed fetch client for the backend
tests/                      Unit tests for both subsystems (see Testing)
storage/
  uploads/                  Uploaded invoice files
  exports/                  (reserved for future export caching)
  models/                   Trained fraud model artifacts (one .joblib per registered version)
```

## Setup

### Backend

```
cd "ai-finance operations agent"
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env      # then edit .env and set GEMINI_API_KEY
uvicorn app.main:app --reload
```

Backend runs at `http://localhost:8000` by default. API docs at `/docs`.

`.env` in the project root is loaded automatically on startup (no `--env-file` flag needed);
variables already set in your shell take precedence over it. Check
`http://localhost:8000/health` - `gemini_configured` must be `true` for uploads to work.

### Frontend

```
cd frontend
npm install
copy .env.example .env      # only needed if the backend isn't on localhost:8000
npm run dev
```

Frontend runs at `http://localhost:5173` (or the next free port if that one's taken).

## Configuration

All settings are environment variables, read in `app/config.py`:

| Variable | Default | Purpose |
|---|---|---|
| `GEMINI_API_KEY` / `GOOGLE_API_KEY` | — | Required. Read automatically by the Gemini SDK. |
| `GEMINI_MODEL` | `gemini-3-flash-preview` | Model used for extraction and fraud assessment. Pro-tier models require a billed Gemini account — see note below. |
| `GEMINI_FALLBACK_MODEL` | `gemini-2.5-flash` | Used when `GEMINI_MODEL` is overloaded or rate-limited (503/429/5xx, after retries). Empty string disables it. |
| `DATABASE_URL` | `sqlite:///./finance_agent.db` | SQLAlchemy connection string. |
| `UPLOAD_DIR` / `EXPORT_DIR` | `storage/uploads` / `storage/exports` | Local file storage. |
| `AUTO_APPROVE_MAX_AMOUNT` | `1000` | Invoices at/under this amount (and low fraud score) auto-approve. |
| `AUTO_APPROVE_MAX_RISK_SCORE` | `20` | Fraud score at/under this auto-approves (combined with amount). |
| `MANDATORY_REVIEW_RISK_SCORE` | `80` | Fraud score at/over this forces manual review regardless of amount. |
| `DUPLICATE_DATE_WINDOW_DAYS` | `3` | Same vendor + amount within this many days flags as a duplicate. |
| `DUPLICATE_NAME_SIMILARITY` | `0.9` | Fuzzy-match threshold (0-1) for vendor name comparison. |
| `FRAUD_LOW_RISK_MAX` | `30` | Combined risk score below this is low risk: alerted, then auto-closed. |
| `FRAUD_HIGH_RISK_MIN` | `70` | Score above this is high risk (high-priority case). |
| `FRAUD_MODEL_DIR` | `storage/models` | Where trained model artifacts are written. |
| `FRAUD_GRAPH_MAX_HOPS` | `3` | How far the network agent expands from the customer. |
| `FRAUD_USE_LLM` | `true` | Whether the narrative agent calls Gemini. With `false` (or no key) cases still open, with a deterministic write-up. |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Exact frontend origins allowed to call the API. |
| `CORS_ORIGIN_REGEX` | `http://(localhost\|127\.0\.0\.1):\d+` | Also allows any localhost port, since Vite picks the next free one. Tighten this for production. |

> **Free-tier note:** on a free (non-billed) Gemini API key, Pro-tier models (e.g.
> `gemini-3.1-pro-preview`) return a quota error (`limit: 0`). Flash-tier models
> (`gemini-3-flash-preview`, `gemini-3.1-flash-lite`, `gemini-2.5-flash`) work on the free tier
> and support both vision input and structured JSON output, which is why one is the default.

## API

### Accounts payable endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness check; reports whether a Gemini API key is configured |
| POST | `/invoices/upload` | Upload an invoice (multipart `file`), runs the full pipeline |
| GET | `/invoices` | List invoices, optional `?status=` filter |
| GET | `/invoices/{id}` | Get one invoice |
| POST | `/invoices/{id}/approve` | Approve a pending invoice (`{"approved_by": "..."}`), posts journal entry |
| POST | `/invoices/{id}/reject` | Reject a pending invoice (`{"reason": "..."}`) |
| GET | `/invoices/{id}/journal-entry` | Get the journal entry for an approved invoice |
| GET | `/invoices/{id}/journal-entry/export` | Download that journal entry as CSV |
| GET | `/journal-entries/export` | Download all posted journal entries as CSV |

### Fraud investigation endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/fraud/dashboard` | Volumes, queue state, model metrics, feedback precision, audit count |
| POST | `/fraud/data/generate` | Generate the synthetic bank (`reset=true` wipes existing fraud data) |
| POST | `/fraud/model/train` | Train both models on the labelled history and activate the version |
| GET | `/fraud/model/versions` | Registered model versions and their metrics |
| POST | `/fraud/model/versions/{version}/activate` | Roll forward or back to a version |
| GET | `/fraud/model/drift` | PSI of recent traffic against the active model's training distribution |
| POST | `/fraud/score` | Score every unscored transaction, investigating what triage escalates |
| POST | `/fraud/transactions/{id}/score` | Score one transaction |
| GET | `/fraud/transactions` | List transactions (`?customer_id=`, `?is_fraud=`) |
| GET | `/fraud/alerts` | List alerts (`?risk_level=`, `?status=`, `?customer_id=`) |
| GET | `/fraud/alerts/{id}` | One alert with its features, signals, rule hits and SHAP explanation |
| GET | `/fraud/cases` | The case queue (`?status=`, `?priority=`, `?assigned_to=`) |
| GET | `/fraud/cases/{id}` | One case with the full case file and notes |
| POST | `/fraud/cases/{id}/assign` | Assign to an analyst |
| POST | `/fraud/cases/{id}/notes` | Add a case note |
| POST | `/fraud/cases/{id}/escalate` | Escalate (`{"analyst": "...", "reason": "..."}`) |
| POST | `/fraud/cases/{id}/decide` | Close with a decision and the confirmed actions |
| GET | `/fraud/feedback/summary` | AI recommendation vs. human decision, over time |
| GET | `/fraud/audit` | The audit trail (`?entity_id=`, `?actor=`) |
| GET | `/fraud/audit/verify` | Recompute the hash chain |

## Fraud investigation

### Getting started

The module ships with a generator rather than a dataset, so there is nothing to download. From the
**Fraud** tab in the console (or via the API):

1. **Generate data** - a synthetic bank: customers with 90 days of everyday traffic, plus injected
   account takeovers, card testing, mule rings and authorised push payment scams, and legitimate
   look-alikes (travel, a new phone, a genuine large purchase, large first payments to a new payee
   or supplier) so the model has to tell them apart.
2. **Train model** - fits XGBoost on the labelled history and an Isolation Forest on the legitimate
   rows only, then registers and activates the version.
3. **Score backlog** - scores every transaction and opens cases for the ones triage escalates.
   Several thousand transactions take a few minutes.
4. **Cases** - work the queue, decide, and the decision becomes the next model's training label.

### How a score is produced

Five detectors run over the same point-in-time features, and `scoring.py` combines them with a
fixed, documented formula - so the same inputs always give the same score, and every point of it
can be attributed to a component:

| Detector | Weight | What it contributes |
|---|---|---|
| Supervised ML (XGBoost) | 0.35 | Learned fraud probability, with exact TreeSHAP per-feature contributions |
| Rule engine | 0.20 | 14 explicit, reviewable conditions; critical rules also floor the score |
| Graph / network | 0.15 | Shared devices, IPs and beneficiaries; links to confirmed fraud |
| Behavioural deviation | 0.15 | Distance from this customer's own 90-day baseline |
| Anomaly (Isolation Forest) | 0.15 | "Unlike anything normal", trained on legitimate traffic only |

A detector that cannot run (no trained model yet) is dropped and the remaining weights are
renormalised, rather than scored as if it had said "no risk". A single very confident detector is
not averaged away, and a critical rule such as a sanctions match puts a floor under the total.

### The investigation agents

Medium and high risk alerts go to an agent pipeline. Each agent is narrow, runs in a fixed order,
and writes its section of the case file plus an audit entry under its own name (`agent:<name>`):

`evidence` → `behavior` → `intel` → `network` → `history` → `hypothesis` → `recommendation` → `narrative`

**Only the narrative agent calls the LLM**, and only to write up conclusions the other agents have
already reached. The score, the hypothesis, the triage decision and the recommended actions are all
computed in code, so a case can be re-derived and defended later. If Gemini is disabled, unkeyed or
failing, the investigation still completes with a deterministic write-up and records why.

One agent failing does not fail the investigation: its section is replaced with an explicit error
placeholder and the rest of the case is still assembled.

### Why a hypothesis, not just a score

A risk score says how worried to be; it does not say what is happening, and the answer changes what
should be done. An **account takeover** means the customer is a victim whose credentials are
compromised - reset them and stop the payment. An **authorised push payment scam** means the
customer sent the money themselves after being deceived - the credentials are fine, and the
intervention is a phone call, not a lockout. The two produce nearly identical risk scores and
opposite responses.

Each typology is a set of weighted indicators plus detractors (evidence against it) and required
core indicators, so the case file shows an analyst "these facts point here, these point away".

### Nothing is done automatically

Detection never blocks, holds or freezes anything. Recommended actions are proposals attached to
the case; only the ones an analyst ticks when deciding are applied, and actions that happen outside
this system (contacting the customer, filing a report) are recorded as instructions rather than
silently marked done. An automated freeze on a false positive locks a customer out of their own
money, so the system is built to recommend and explain.

### The feedback loop

Closing a case writes the analyst's decision back onto the transaction as ground truth and records
an AI-recommendation-vs-human-decision row. The next training run picks those up as label
overrides, and `/fraud/feedback/summary` measures precision from them over time rather than
asserting it once at training. `inconclusive` deliberately stores no label - "we could not tell" is
not evidence the payment was fine.

### Audit trail

Every alert, agent, assignment, note, escalation, action and decision is appended to a hash-chained
log: each entry's hash covers its content and the previous entry's hash, so editing or deleting any
past entry breaks `/fraud/audit/verify` from that point on.

## Testing

```
pytest
```

Covers both subsystems: invoice validation, duplicate detection, approval routing, accounting, the
upload endpoint and the Gemini call helper; and for fraud - score combination, triage, alert and
case creation, case linking, the typology discrimination between a takeover and a scam, the
narrative agent's LLM and fallback paths, the case decision and feedback loop, audit tamper
detection, model training and the registry, PSI drift, and the REST surface.

Gemini is never called: the invoice tests fake the client, and a session-wide fixture turns the
narrative LLM off so a developer's `.env` key cannot leak into a test run.

Two tests deserve mention:

- **Lookup parity** - `history.py` keeps two implementations of the network lookups, an in-memory
  index for bulk work and indexed SQL for serving, so that features are computed identically in
  training and production. A test checks they agree on every transaction; if they drift, a model
  trains on numbers it will never see at serving time.
- **The APP-scam rule and its evidence** - an authorised push payment scam trips none of R001-R013
  (own device, own city, credentials untouched), so R014 fires on a first transfer to a brand-new
  payee at 4x or more the customer's 90-day average. It has no floor and a 0.4 weight, so on its
  own it moves a transaction into review at medium risk and never further. Most such payments are
  genuine, and `tests/test_r014_scam_rule.py` pins both sides: the hand-made cases one fact at a
  time, and a generated bank with labelled APP scams and legitimate look-alikes on which every scam
  is caught by R014 alone, no transaction reaches high risk on R014 alone, and genuine large first
  payments are flagged at every threshold that still catches scams. To see the trade-off across
  thresholds before changing one:

  ```
  python -m app.fraud_investigation.evaluation --customers 600 --thresholds 3 4 5 6
  ```

  It reports recall, precision, false positives by source, overlap with the other rules, and the
  review-queue and case volume each threshold adds. Recall reflects where the injected scams sit
  (4-8x) and precision reflects how many look-alikes are injected per scam, so read the
  false-positive counts and their sources as the part that carries over to real traffic.

## Notes

- The Gemini client is constructed lazily (see `gemini_client.py`) rather than at import time,
  since `google-genai` validates the API key eagerly — a module-level client would break every
  import (including pure-logic tests) whenever no key is configured.
- The database schema is created via `Base.metadata.create_all` on startup — fine for local
  development, but there's no migration tool (Alembic, etc.) wired up yet for schema changes.
- `CORS_ORIGIN_REGEX`'s default is deliberately permissive for local dev (any localhost port).
  Set it to an empty string and rely on `CORS_ORIGINS` alone for a production deployment.
- Backlog scoring, training and data generation are ordinary sync endpoints; FastAPI runs them in a
  worker thread so they do not stall the rest of the API, but a production deployment would move
  them onto a task queue and return a job id.
- The entity graph is an in-memory networkx graph rebuilt from SQL aggregates, which is fine at
  prototype size. A production deployment would keep it in a graph database and run the same
  queries (k-hop expansion, shortest paths, community detection) there.
- The audit chain is serialised with a process-wide lock. A multi-process deployment would need a
  database-level lock or sequence for the same guarantee.
- Backlog scoring computes the graph and external intelligence from the database as it is *now*,
  not as it was at each transaction's timestamp. That is fine for backfilling a demo dataset; a
  live deployment scores each transaction as it arrives, where "now" and "then" are the same
  moment. The features themselves are point-in-time in both paths.
