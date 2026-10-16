# SecOps Coordinator Backend — Implementation Plan

Go/Gin backend for the AI SecOps Coordinator. It uses the same layering as `personal_prod_golang`
(`infrastructure → application → domain`), with that project's known problems fixed (see §8).

**Status: Phases 0–9 implemented and tested (see §7). Phase 10 (frontend auth integration, live
GCP deploy) is not done.** Everything below describes what was built, not just the plan; where
the final implementation differs from the original design, that is noted explicitly.

The API contract is set by the existing frontend at
`../frontend/sec_ops_agent_frontend/app/lib/types.ts` and `app/lib/api/endpoints.ts`.
**The backend matches those JSON shapes and enum strings exactly.** Where the frontend has to
change, §4.2 lists the change.

## 1. Design decisions

| Topic | Decision | Reason |
|---|---|---|
| Database | Postgres on a free external tier (Neon or Supabase) | The Cloud Run filesystem is ephemeral, so SQLite data would be lost. Cloud SQL isn't free. |
| Schema | Embedded SQL migrations (`embed.FS`) run at startup; no GORM AutoMigrate | Triggers, CHECK constraints and partial indexes can't be expressed with AutoMigrate |
| Immutability | Postgres triggers reject UPDATE/DELETE/TRUNCATE on `raw_logs`, `audit_logs`, `incident_comments`, `alert_deliveries`, `batch_logs` | Leaving out a DELETE route doesn't stop direct writes; the database has to enforce it (FR-001, FR-031). Verified against a real Postgres 16 container: direct UPDATE/DELETE/TRUNCATE all raise SQLSTATE 23001. |
| "Unanalyzed" logs | Kept in a separate `batch_logs(log_id PK)` table; `raw_logs` is never updated | Analysis is tracked without mutating the raw rows |
| Caching | Postgres table `threat_intel_cache` with `expires_at`; no Redis | Memorystore isn't free |
| Proactive scan | Runs synchronously inside the `POST /scan/daily` request (timeout `SCAN_TIMEOUT`, default 14 min, under the 900 s Cloud Run cap) | Cloud Run throttles CPU after a response is sent, and in-process tickers die when the service scales to zero |
| Realtime | Frontend polls with TanStack Query; no WebSockets | Open sockets keep instances running and use up the free vCPU-seconds |
| Gemini quota | Logs are pre-aggregated in Go, giving 1–3 calls per scan. A hand-rolled single-slot interval limiter (`internal/infrastructure/httpx.Limiter`, stdlib only — no `golang.org/x/time/rate` dependency was added), backoff on 429/503 that honours the server's `RetryInfo`/`Retry-After` delay, a daily budget in `api_usage`, and `deferred` batches retried on the next scan | Google no longer publishes the free-tier quotas; check AI Studio for the limits on your project. Avoiding `x/time` kept the dependency set unchanged from Phase 0. |
| Gemini output | `responseMimeType: application/json` + `responseSchema`, temperature 0, log data between `<<<LOG_DATA_START/END>>>` delimiters, API key sent via the `x-goog-api-key` header (never a query param) | Forces structured output and limits prompt injection through attacker-controlled fields such as `user_agent` |
| NL query | Gemini returns a **filter JSON** (`actions`, `countries`, `risk_levels`, `hours`, `explanation`), which is validated against fixed enums and clamped before being run as parameterised GORM queries. Gemini never writes SQL and its `explanation` text is only used for display, not for the `interpretation`/`filters_applied` which are built in Go | Prevents SQL injection and data exfiltration |
| Re-alert suppression | `incidents.fingerprint` = sha256 of sorted, lower-cased patterns/IPs/users. New incidents whose fingerprint was resolved within `suppression_days` (default 7) are suppressed; a matching still-open incident is also suppressed (no duplicate) | Each scan creates new incidents, so an ID-only rule would never fire |
| Scan concurrency | **Changed from the original plan.** Instead of `pg_try_advisory_lock`, a partial unique index `scan_runs_one_running_uq ON scan_runs ((true)) WHERE status = 'running'` enforces one running scan; `ScanRunRepository.Start` returns `ErrConflict` (409) on violation. A `FailStale` sweep clears a lock abandoned by a killed instance (after `staleAfter` = 20 min). Cloud Run `--max-instances 1` keeps the in-process Gemini rate limiter valid | Session advisory locks don't survive a connection hand-off on a transaction-mode pooler (Neon/Supabase); a plain unique index does |
| Migration locking | **Changed from the original plan.** Each migration runs in its own transaction holding `pg_advisory_xact_lock` (transaction-scoped, not session-scoped) | Same pooler-safety reason as above |
| Secrets | Secret Manager mounted as env vars. Settings only report `*_set`/`*_configured: bool` | Admins manage thresholds and the schedule in the UI, never raw API keys |
| Deploy | `project.toml` sets `GOOGLE_BUILDABLE=./cmd/api`, so a plain `gcloud run deploy --source .` works | FR-032: no Docker and no extra flags |

## 2. Layout (as built)

```
backend/
  go.mod (module sec_ops, go 1.26.5)   project.toml   PLAN.md   agent.md   .env.example   .gitignore   .gcloudignore
  cmd/api/main.go                       Composition root: config → logger → DB connect → migrate → security →
                                        repositories → external adapters → usecases → router → graceful shutdown
  internal/
    config/                             config.go (FromEnv/Load, fail-fast validation), validators.go (ValidGeminiModel,
                                        webhookHostAllowed, schedulerJobName pattern)
    domain/
      enums/                            RiskLevel, IncidentStatus, LogAction, Role, AuditAction, SystemActor —
                                        string values match the frontend's types.ts exactly
      entities/                         entities.go (User, Principal+SystemPrincipal, RawLog, AnalysisBatch,
                                        Incident, IncidentComment, AuditEntry, ThreatIntel, AlertDelivery, ScanRun,
                                        Settings), rules.go (AuditHash, IncidentFingerprint)
      interfaces/                       errors.go (all sentinels), ports.go (every repository + external-service
                                        interface: UserRepository, LogRepository, BatchRepository, IncidentRepository,
                                        AuditRepository, ThreatIntelCache, AlertDeliveryRepository, ScanRunRepository,
                                        UsageRepository, SettingsRepository, TxManager, LLM, ThreatIntelClient,
                                        AlertNotifier, SchedulerControl, PasswordHasher, TokenService, Clock,
                                        MockLogGenerator)
    application/
      dtos/dtos.go                       JSON shapes mirroring the frontend's types.ts field-for-field
      usecases/{auth,user,audit,ingest,analysis,enrichment,alerting,incident,dashboard,scan,nlquery,settings}/
                                        one package per feature, each takes only interfaces.* in its constructor
    infrastructure/
      logging/                          slog JSON handler with Cloud Logging field names (severity/message)
      database/                         postgres.go (GORM + pgx simple protocol), migrate.go (embedded migrations,
                                        xact-lock, idempotent), migrations/0001_init.sql
      database/dbmodels/                models.go — every model has TableName(); JSONList/JSONMap/JSONRaw
                                        Valuer/Scanner types for jsonb columns (Value() returns string, required
                                        for the simple protocol)
      repository/                       tx.go (TxManager + conn() + translate() + clampLimit), user_repo.go,
                                        log_repo.go, batch_repo.go, incident_repo.go, audit_repo.go, misc_repo.go
                                        (ThreatIntelCache, AlertDeliveryRepository, ScanRunRepository,
                                        UsageRepository, SettingsRepository) — every repo has a
                                        `var _ interfaces.IX = (*x)(nil)` assertion
      security/                        bcrypt.go, jwt.go (hand-rolled HS256 JWT, stdlib only — no golang-jwt
                                        dependency), oidc.go (hand-rolled Google OIDC/JWKS verification, stdlib only)
      httpx/                            shared helpers: NewClient (no redirects), Limiter, Backoff, RetryAfter,
                                        ReadLimited
      ai/gemini/                        REST client for generateContent, no SDK dependency
      threatintel/abuseipdb/            REST client for /api/v2/check
      notify/                           Slack + Discord incoming-webhook clients, with mention/markdown sanitising
      scheduler/                        Cloud Scheduler REST client, authenticated via the GCE metadata server
                                        (no service-account key file, no client library)
      mocklogs/                         deterministic synthetic log generator (seeded math/rand/v2)
      http/{router,middleware,handlers}/
  internal/application/usecases/testfakes/  hand-written fakes for the use-case tests (no mocking library)
```

## 3. Data model (migration `0001_init.sql`, as built)

Enums are stored as text with CHECK constraints, using the exact frontend strings ("Login Failed", "Open", "Critical"…), so the API needs no translation layer. **Differences from the original plan:** `ip_address` columns are `text` (not `inet`) — validated with `net/netip` in Go instead, which avoids pgx/inet mapping edge cases over the simple protocol; the per-batch/incident lists (`suspicious_ips`, `patterns`, `affected_users`) are `jsonb` arrays (not `text[]`) for the same simple-protocol reason; `users` has an added `token_version integer` column (not in the original plan) used to revoke all of a user's sessions on logout/role-change/disable without a token blocklist table.

- `users(id, name, email UNIQUE, password_hash, role CHECK admin|analyst|viewer, token_version, disabled, created_at, updated_at)`
- `raw_logs(id, log_id UNIQUE, ts, user_id, ip_address text, country, city, action, user_agent, flagged, ingested_at)` — **immutable**, `flagged` is CHECK-constrained to agree with `action`
- `scan_runs(id, trigger scheduler|manual, actor, status running|succeeded|failed, started_at, finished_at, logs_fetched, analyzed, new_alerts, error)` + partial unique index enforcing one `running` row at a time
- `analysis_batches(id, scan_run_id, window_start, window_end, status pending|running|done|failed|deferred, attempts, model, risk_score, summary, recommended_action, suspicious_ips jsonb, patterns jsonb, affected_users jsonb, top_ip, raw_response jsonb, error, created_at, analyzed_at)`
- `batch_logs(log_id PK → raw_logs.log_id, batch_id)` — **immutable**; each log is analysed at most once
- `incidents(id, batch_id, fingerprint, ai_risk_score, risk_score, status Open|Acknowledged|Resolved, ai_summary, recommended_action, suspicious_ips jsonb, patterns jsonb, affected_users jsonb, top_ip, country, abuseipdb_confidence, detected_at, acknowledged_at/by, resolved_at/by, updated_at)` + partial UNIQUE(fingerprint) WHERE status <> 'Resolved'
- `incident_comments(id, incident_id, author, role, body, created_at)` — **immutable**
- `threat_intel_cache(ip PK text, abuse_confidence, total_reports, country, raw jsonb, fetched_at, expires_at)`
- `alert_deliveries(id, incident_id, channel, status success|failed, http_status, error, attempted_at)` — **immutable**; `error` never stores the raw error text (which could embed a webhook URL), only a fixed string
- `audit_logs(id bigserial, ts, user_id, action_type, entity_type, entity_id, details, metadata jsonb, prev_hash, hash)` — **immutable**, hash-chained (`entities.AuditHash`), appended under `pg_advisory_xact_lock` so the chain has a strict order
- `api_usage(day, provider, count)` PK(day, provider) — atomic upsert-with-ceiling via `INSERT ... ON CONFLICT ... WHERE count < limit`
- `settings(key PK, value jsonb, updated_by, updated_at)` — single row, key `'runtime'`
- `schema_migrations(version PK, name, applied_at)` — written by the migration runner

All of the above, including every trigger and CHECK constraint, was verified against a real `postgres:16-alpine` container (see §7, Phase 0/7 exit criteria).

## 4. API contract

### 4.1 Endpoints (all under `/api/v1` except health) — as implemented in `router.go`

| Method | Path | Roles | Response (frontend type) | FR |
|---|---|---|---|---|
| GET | `/healthz` | public | `{status}` (liveness, no DB access) | 032 |
| GET | `/readyz` | public | `{status}` / 503 (DB ping) | 032 |
| POST | `/auth/login` | public | `LoginResponse` + refresh cookie | 030 |
| POST | `/auth/refresh` | refresh cookie | `LoginResponse` + rotated cookie | 030 |
| POST | `/auth/logout` | public (reads cookie if present) | `{message}` | 030 |
| GET | `/auth/me` | any | `UserResponse` | 030 |
| GET | `/users` | admin | `UserResponse[]` | 030 |
| POST | `/users` | admin | `UserResponse` | 030 |
| PATCH | `/users/:id/role` | admin | `UserResponse` | 030 |
| GET | `/logs?action&country&search&page&pageSize` | any | `LogPage` | 001 |
| GET | `/logs/countries` | any | `string[]` | 001 |
| POST | `/logs/ingest` `{logs: IngestLog[]}` | admin **or** `X-Ingest-Key` header | `IngestResult` | 001 |
| POST | `/logs/mock` `{scenario, count, attacker_ips?}` | admin | `IngestResult` | 001 |
| GET | `/incidents?status&risk&sort=detected_at\|risk_score&dir=asc\|desc` | any | `Incident[]` | 010 |
| GET | `/incidents/:id` | any | `Incident` | 010 |
| POST | `/incidents/:id/acknowledge` | admin, analyst | `Incident` | 012 |
| POST | `/incidents/:id/resolve` `{comment}` | admin, analyst | `Incident` | 012 |
| GET | `/dashboard/summary` | any | `DashboardSummary` | 010 |
| POST | `/scan/daily` | Cloud Scheduler OIDC **or** admin JWT | `ScanResult` | 003 |
| POST | `/scan/run` | admin | `ScanResult` (manual trigger) | 003 |
| GET | `/scan/runs` | any | `ScanRun[]` | 003 |
| POST | `/query` `{query}` | admin, analyst | `NLQueryResult` | 011 |
| GET | `/audit?action_type&user_id&from&to&limit` | admin, analyst | `AuditEntry[]` | 031 |
| GET | `/audit/verify` | admin | `AuditVerifyResult` | 031 |
| GET | `/settings` | admin | `SchedulerSettings` | 030 |
| PUT | `/settings` `{patch}` | admin | `SchedulerSettings` | 030 |

There is no DELETE or PUT route for logs, audit entries, comments or deliveries. Errors are always `{"error": "..."}` via the shared `handlers.Fail` mapper: 400 validation, 401 unauthenticated, 403 forbidden, 404 not found, 409 conflict/invalid-transition/immutable, 429 upstream quota, 503 upstream unavailable, 500 generic (the original error text is logged server-side with the request id, never returned to the client).

### 4.2 Changes the frontend needs

1. **Auth.** The frontend currently picks a role with a local switcher (`stores/role.ts`) and sends `actor` in request bodies. The backend **ignores `actor`** and takes the identity from the JWT, otherwise anyone could forge the audit trail. The frontend needs a login page, an axios `Authorization: Bearer` interceptor with refresh-on-401, `withCredentials: true`, and the role taken from `/auth/me` instead of the switcher.
2. `PUT /settings` takes `{patch}`; `actor` is ignored.
3. `slack_webhook_set` / `discord_webhook_set` / `gemini_configured` / `abuseipdb_configured` / `scheduler_managed` are all read-only and come from env/Secret Manager/config, not from the patch.
4. `POST /logs/mock` additionally accepts an optional `attacker_ips` array (max 10) so a demo can show AbuseIPDB enrichment against addresses you control.

## 5. Core flows (as implemented)

**Ingest (FR-001, `ingest.Service`).** Each entry's `log_id`, `timestamp` (RFC3339), `user_id`, `ip_address` (`net/netip`), `action` (enum) are validated; `country`/`city`/`user_agent` have control characters stripped and are length-capped. `flagged` is **always** computed server-side from `action.RequiresReview()`; nothing from the client can set it. Invalid rows are rejected individually (reported back per-index) while valid rows in the same batch still insert. Insert uses `ON CONFLICT (log_id) DO NOTHING`. Every call is audited as `LOGS_INGESTED`. The mock generator (`mocklogs.Generator`, seeded `math/rand/v2`, fully deterministic for a fixed seed) produces: `benign`, `brute_force`, `impossible_travel`, `privilege_escalation`, `mixed`; non-attacker IPs always land in the RFC 5737 documentation ranges.

**Scan (FR-003 → 002 → 004 → 005, `scan.Service.Run`).**
1. `POST /scan/daily` is authenticated by `middleware.RequireAdminOrScheduler`: a Google OIDC token (audience + service-account email verified against the JWKS, hand-rolled RS256 verification) **or** an admin JWT.
2. `FailStale` clears any `running` scan abandoned more than 20 minutes ago, then `ScanRunRepository.Start` tries to insert a new `running` row; the partial unique index makes a concurrent second call return `ErrConflict` (409).
3. `logRepo.UnanalyzedFlagged` fetches flagged logs from the last `Config.Window` (default 24h) not yet linked in `batch_logs`, plus any batches eligible for retry (`BatchRepository.Retryable`, status deferred/failed with `attempts < maxAttempts`).
4. Logs are chunked into at most `GEMINI_MAX_BATCHES_PER_SCAN` groups of up to `GEMINI_MAX_LOGS_PER_BATCH`; `analysis.Service.BuildAggregate` groups failures/escalations by IP and flags same-user cross-country logins under 60 minutes apart as possible impossible travel.
5. `analysis.Service.Analyze` consumes one `api_usage` budget unit, calls Gemini with a JSON schema (`risk_score`, `summary`, `recommended_action`, `suspicious_ips[]`, `patterns[]`, `affected_users[]`), and **filters the model's IPs/users down to only those that actually appear in the aggregate** — the model cannot invent targets. A retryable failure (quota/upstream) stores the batch as `deferred` and audits `AI_ANALYSIS_DEFERRED`; otherwise the batch is `done` and audited `AI_ANALYSIS`.
6. For Medium+ risk: compute the fingerprint. A matching still-open incident, or one resolved within `suppression_days`, is suppressed (`ALERT_SUPPRESSED`) instead of creating a duplicate.
7. For High+ with suspicious IPs: `enrichment.Service.CheckIPs` skips private/loopback/documentation addresses, checks the 24h cache first, then AbuseIPDB within budget; confidence over `ABUSE_ESCALATE_THRESHOLD` (default 50) raises the incident to `Critical` (audited `INCIDENT_ESCALATED`).
8. The incident is created (`INCIDENT_CREATED`) and `alerting.Service.Dispatch` sends it to every configured notifier (Slack/Discord); each attempt is recorded in `alert_deliveries` and audited `ALERT_SENT`/`ALERT_FAILED` individually, and a failed webhook never fails the scan.
9. `scan_runs` is closed and audited `SCHEDULED_SCAN` (or `SCAN_FAILED`) with the final counts; the handler returns a `ScanResult`.

**Incident state machine (FR-012, `incident.Service`).** `enums.IncidentStatus.CanTransitionTo` allows `Open → Acknowledged`, `Open → Resolved`, `Acknowledged → Resolved`; anything else is `ErrInvalidTransition` (409). `Resolve` requires a non-empty comment ≤ 2000 chars. The row lock (`GetForUpdate`), status update, comment insert and audit entry all happen inside one `TxManager.WithinTx`.

**NL query (FR-011, `nlquery.Service`).** Gemini maps the prompt (wrapped in `<<<...>>>` delimiters and never treated as instructions) to `{actions[], countries[], risk_levels[], hours, explanation}` against a fixed schema. `buildQueries` clamps `hours` to ≤ 720 and silently drops any value not in the enum whitelist rather than erroring — the model degrading to a broader-but-still-whitelisted search is acceptable, inventing a new filter type is not. The resulting `interfaces.LogQuery`/`IncidentQuery` are always struct values executed through parameterised GORM; **Gemini's output is never concatenated into SQL**. The `interpretation` shown to the user is built in Go from the validated filter, not from the model's raw text. Every query is audited `NL_QUERY`.

**Audit (FR-031, `audit.Service`).** `Record` writes under `pg_advisory_xact_lock`, reading the previous row's hash and computing `hash = AuditHash(prev_hash, entry)` (`sha256` over length-prefixed fields, so entries commit in a strict, verifiable order). `GET /audit/verify` (admin) walks the whole chain in insertion order and recomputes every hash, returning `{valid, checked, first_bad_id, reason, latest_hash}`.

## 6. Deployment

```
# backend/
gcloud run deploy secops-api --source . --region us-central1 \
  --min-instances 0 --max-instances 1 --memory 256Mi --cpu 1 --timeout 900 \
  --set-secrets DATABASE_URL=secops-db-url:latest,JWT_SECRET=secops-jwt:latest,GEMINI_API_KEY=gemini-key:latest,ABUSEIPDB_API_KEY=abuseipdb-key:latest,SLACK_WEBHOOK_URL=slack-webhook:latest \
  --set-env-vars APP_ENV=production,CORS_ALLOWED_ORIGINS=https://<frontend-url>,BOOTSTRAP_ADMIN_EMAIL=...,BOOTSTRAP_ADMIN_PASSWORD=... \
  --allow-unauthenticated

gcloud scheduler jobs create http secops-daily-scan --location us-central1 \
  --schedule "0 2 * * *" --time-zone UTC \
  --uri https://<api-url>/api/v1/scan/daily --http-method POST \
  --oidc-service-account-email secops-scheduler@<project>.iam.gserviceaccount.com \
  --oidc-token-audience https://<api-url> --attempt-deadline 900s
```

`--allow-unauthenticated` is needed because the browser calls the API directly. That makes app-level auth (JWT + RBAC + OIDC on the scan route, both implemented in Phase 1/4) the only protection. **Not yet done:** an actual deploy to GCP, and point 1 of §4.2 (frontend real auth) — do not put real user data behind a public deploy until both are done.

## 7. Phases — status

| # | Scope | Exit criteria | Status |
|---|---|---|---|
| 0 | Module layout, config validation, slog JSON logging, DB connect, embedded migrations with the full schema and immutability triggers, `/healthz` + `/readyz`, CORS allowlist, request ID, recovery, graceful SIGTERM shutdown, `project.toml` | `go build/vet/test` green; migration verified against real Postgres | **Done** |
| 1 | Users, bcrypt, JWT access/refresh, RBAC middleware, admin bootstrap from env, audit recorder with hash chain, `/audit` | Viewer gets 403 on admin routes; UPDATE on audit fails at the DB | **Done** |
| 2 | FR-001 ingest, mock generator, `/logs`, `/logs/countries` | Flagging is correct; duplicate `log_id` is ignored | **Done** |
| 3 | FR-002 Gemini adapter, aggregation, limiter, retries, budget | A fake-429 test server proves backoff and `deferred` | **Done** |
| 4 | FR-003 scan orchestrator, OIDC verifier, one-running lock, `scan_runs`, `/dashboard/summary` | A concurrent scan gets 409; the run is audited | **Done** |
| 5 | FR-004 AbuseIPDB + 24h cache + Critical escalation | A second lookup makes no HTTP call; score > threshold → Critical | **Done** |
| 6 | FR-005 Slack/Discord + delivery log | A failure is recorded and audited, never fails the scan | **Done** |
| 7 | FR-012 incident endpoints + suppression | Resolved fingerprint doesn't alert again | **Done** |
| 8 | FR-011 NL query | Model output never reaches SQL; unknown enums dropped, not erroring | **Done** |
| 9 | Settings + Cloud Scheduler pause/resume/update via REST using the metadata-server token | Admin-only; audited `SETTINGS_UPDATED` | **Done** |
| 10 | Frontend auth integration (§4.2), end-to-end demo on GCP, free-tier review | Full flow works live | **Not started** |

Verification performed for Phases 0–9: `go build ./...`, `go vet ./...`, `gofmt -l .` and `go test -count=1 ./...` all clean across every package (unit tests with hand-written fakes for every usecase, `httptest`-based tests for every external adapter, full RBAC/router tests). The full schema (including every immutability trigger and the CHECK constraints) and a real end-to-end flow — bootstrap admin → login → mock log ingestion → manual scan → dashboard → audit chain verification — were additionally run against a disposable `postgres:16-alpine` Docker container and passed; the container was removed afterward.

## 8. Fixes over `personal_prod_golang`

- Sentinels live only in `domain/interfaces/errors.go`; infrastructure never imports use cases.
- Use cases depend only on ports (interfaces), never on concrete security or HTTP types.
- Every GORM model defines `TableName()`; every repo/adapter has a compile-time `var _ interfaces.IX = (*x)(nil)` assertion.
- Config is validated at startup and fails fast; the GORM logger runs at Warn; there are no `log.Fatal`/`panic` calls in request paths.
- Cookie path, `Secure` and `SameSite` are correct and consistent between set and clear.
- Timestamps are UTC `timestamptz` only, with no timezone hooks.
- There are no soft deletes; the append-only tables are enforced by database triggers, not just by omitting a DELETE route.
- Two additional issues were found and fixed by the test subagents during Phase 6 testing (see git history / agent.md): `scheduler.Client.Configured()` now trims whitespace before checking the job name is non-empty; `mocklogs.Generator` derives `log_id` from its own seeded RNG plus a counter instead of `uuid.NewString()`, making `Generate()` fully deterministic for a given seed.
