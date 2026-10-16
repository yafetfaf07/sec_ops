# agent.md — SecOps Coordinator backend (`AI_TEST/backend`)

Rules for AI agents working on this service. Read `PLAN.md` for scope, phases and status (Phases 0–9 are implemented; Phase 10 — frontend auth integration and the live GCP deploy — is not). This file covers **how** to write the code.

## 1. Context

- Go/Gin API for the AI SecOps Coordinator. Module name **`sec_ops`** (imports look like `sec_ops/internal/...`), `go 1.26.5`.
- Deployed with `gcloud run deploy --source .` through Google Cloud Buildpacks. `project.toml` sets `GOOGLE_BUILDABLE=./cmd/api`. **Never add a Dockerfile**; FR-SEC-032 forbids it.
- Frontend: `../frontend/sec_ops_agent_frontend`. Its `app/lib/types.ts` and `app/lib/api/endpoints.ts` **are the API contract**. Match JSON field names and enum strings exactly (`"Login Failed"`, `"Critical"`, `"Open"`, `"admin"`). If the contract has to change, update `PLAN.md §4.2` and tell the user.
- Postgres on a free external tier (Neon/Supabase). No Redis, no WebSockets, no background goroutines that outlive a request (Cloud Run throttles CPU after the response).
- Architecture is based on `personal_prod_golang`, with its known defects fixed (`PLAN.md §8`). Don't reintroduce them.
- No new third-party dependencies beyond what Phase 0 already had (gin, gorm, pgx driver, uuid, godotenv, golang.org/x/crypto). JWT (HS256), Google OIDC/JWKS verification, Gemini, AbuseIPDB, Slack/Discord webhooks and the Cloud Scheduler client are all hand-rolled REST/stdlib, not SDKs. Keep it that way; ask before adding anything new.

## 2. Commands (run in `backend/`)

| Purpose | Command |
|---|---|
| Build | `go build ./...` |
| Vet | `go vet ./...` |
| Format check | `gofmt -l .` (must print nothing) |
| Tests | `go test -count=1 ./...` |
| DB integration tests | set `TEST_DATABASE_URL` to a **disposable** Postgres (each run creates and drops its own schema). A quick local one: `docker run -d -e POSTGRES_PASSWORD=test -e POSTGRES_DB=secops_test -p 15432:5432 postgres:16-alpine`, then `TEST_DATABASE_URL=postgres://postgres:test@localhost:15432/secops_test?sslmode=disable`. Remove the container (`docker rm -f <id>`) when done. |
| Run locally | copy `.env.example` → `.env`, set `DATABASE_URL`, then `go run ./cmd/api` |

Every change must pass build, vet, gofmt and tests before you call it done. Integration tests skip automatically without `TEST_DATABASE_URL`; say so when they didn't run. The full migration (schema + every trigger + a real login/ingest/scan/audit-verify flow) has already been run once against a real `postgres:16-alpine` container — see `PLAN.md §7` — so the SQL itself is known-good; re-verify only if you change `0001_init.sql` or add a new migration.

## 3. Layout and dependency rule

```
cmd/api/main.go             Composition root only: config → logger → DB → migrate → security → repositories →
                            external adapters → usecases → router → serve/shutdown
internal/config/            FromEnv(getenv) + validation, validators.go. Add new settings here with validation and a test.
internal/domain/            Stdlib only (plus enums). No gin, gorm, http.
  enums/                    RiskLevel, IncidentStatus, LogAction, Role, AuditAction, SystemActor
  entities/                 Plain structs (entities.go) + pure rules (rules.go: AuditHash, IncidentFingerprint)
  interfaces/               Ports (repos + external services, ports.go) and errors.go (ALL sentinels)
internal/application/
  dtos/                     JSON shapes mirroring the frontend types (dtos.go)
  usecases/<feature>/       package name = feature: auth, user, audit, ingest, analysis, enrichment, alerting,
                            incident, dashboard, scan, nlquery, settings
  usecases/testfakes/       hand-written fakes shared by use-case tests
internal/infrastructure/
  database/                 Connect, Migrate, migrations/NNNN_name.sql, dbmodels/
  repository/                GORM implementations of interfaces, one file per aggregate + tx.go + misc_repo.go
  httpx/                    shared outbound-HTTP helpers (client, rate limiter, backoff)
  ai/gemini, threatintel/abuseipdb, notify/{slack,discord}, scheduler, mocklogs, security/{jwt,bcrypt,oidc}
  http/{router,middleware,handlers}
  logging/
```

Imports point inward only: `infrastructure → application → domain`.
- `domain` never imports `application` or `infrastructure`.
- `application` imports `domain` only. Use cases take **interfaces** in their constructors, never `*gorm.DB`, `*http.Client` or concrete adapters.
- `infrastructure` packages never import `application/usecases`. Shared errors come from `domain/interfaces/errors.go`.

## 4. Conventions

### Errors
- Use only the sentinels in `domain/interfaces/errors.go`. Add detail by wrapping: `fmt.Errorf("%w: comment is required", interfaces.ErrValidation)`.
- Repositories translate driver errors via `repository.translate()`: `gorm.ErrRecordNotFound` → `ErrNotFound`, SQLSTATE `23505` → `ErrConflict`, `23001` (immutability trigger) → `ErrImmutable`, `23514`/`22P02`/`23502`/`22001` → `ErrValidation`, `23503` → `ErrNotFound`.
- Handlers map errors with the shared `handlers.Fail(c, log, err)` helper: Validation 400, Unauthorized 401, Forbidden 403, NotFound 404, Conflict/InvalidTransition/Immutable 409, QuotaExceeded 429, UpstreamUnavailable 503, anything else 500 with a **generic** message. The response body is always `{"error": "..."}`. **Never return `err.Error()` for 500s**; `Fail` already logs it with the request id — don't duplicate that in the handler.

### Handlers
- A struct per feature (`IncidentHandler`) holding a use-case service. Each endpoint is a method returning `gin.HandlerFunc`.
- `ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)` for ordinary routes. Exceptions: the scan routes use `cfg.ScanTimeout` (default 14 min, bounded by the 900 s Cloud Run timeout); NL query uses 12 s (Gemini generation can take a few seconds).
- The actor always comes from `middleware.GetPrincipal(c)` (set by `RequireAuth`/`RequireAdminOrScheduler`). **Ignore any `actor` field the frontend sends** — DTOs don't even have one for admin-mutating routes.
- Bind with `c.ShouldBindJSON`/`ShouldBindQuery` into DTOs with `binding`/`form` tags. Parse ids with `uuid.Parse` where relevant (400 on failure), never `MustParse`.
- New routes are added to `router.Deps` and `SetupRouter` under `/api/v1`, with the right `auth`/`admin`/`triage`/`schedulerOrAdmin` middleware chain. Never add a DELETE or UPDATE route for logs, audit entries, comments or deliveries.

### Use cases
- Validate, authorise (role checks happen in middleware *and* again inside the use case for rules middleware can't express, e.g. the last-admin guard), apply domain rules, call ports, write audit entries, return DTOs.
- Writes that touch more than one table go through `interfaces.TxManager.WithinTx`. Example: resolving an incident = row lock + status update + comment insert + audit, all in one transaction.
- Status changes must go through `enums.IncidentStatus.CanTransitionTo`. Risk comparisons must use `RiskLevel.Rank()`/`AtLeast`/`MaxRisk`, never string comparison.
- Flags are computed on the server: `flagged = action.RequiresReview()`. Never trust a client-supplied flag.

### Database
- Schema changes go in a **new** file `internal/infrastructure/database/migrations/NNNN_description.sql` (contiguous numbering starting at 1). Never edit `0001_init.sql` or any applied migration, and never use GORM `AutoMigrate`.
- Enum CHECK constraints must keep the same strings as `domain/enums`. `TestInitMigrationEnumStrings` (in `database`) and `TestEnumStringsMatchFrontendContract` (in `enums`) guard this — keep both passing.
- Append-only tables (`raw_logs`, `batch_logs`, `audit_logs`, `incident_comments`, `alert_deliveries`) keep their `forbid_mutation` triggers (both the row trigger and the `TRUNCATE` statement trigger — `TestInitMigrationProtectsAppendOnlyTables` checks both exist). Don't drop or bypass them, and don't add soft deletes anywhere.
- `ip_address` and `threat_intel_cache.ip` are `text`, not `inet` — the pgx simple protocol (required for pooler compatibility) doesn't map `inet` cleanly. Validate IPs with `net/netip` in Go before they reach the DB.
- List columns (`suspicious_ips`, `patterns`, `affected_users`) are `jsonb`, not `text[]`, for the same simple-protocol reason. Use `dbmodels.JSONList`/`JSONMap`/`JSONRaw` (their `Value()` returns a `string`, not `[]byte` — that distinction matters under the simple protocol, keep it).
- GORM models live in `dbmodels`, define `TableName()`, and have explicit `column` tags. Repos use `db.WithContext(ctx)` (via the shared `conn(ctx, db)` helper, which joins an in-flight transaction from `TxManager`) and parameterised queries only. Never build SQL with `fmt.Sprintf` from request input — see `incident_repo.go`'s `jsonb_exists_any(...)` for how to safely pass a slice into a jsonb operator without GORM misreading a literal `?` as a bind placeholder.
- Every repo/adapter gets a compile-time assertion: `var _ interfaces.ILogRepo = (*logRepository)(nil)`.
- Timestamps are `timestamptz` and set in UTC (`NowFunc` is already UTC). No timezone hooks, no soft deletes.
- Scan concurrency uses a **partial unique index** (`scan_runs_one_running_uq ON scan_runs ((true)) WHERE status = 'running'`), not a session-level advisory lock — session locks don't survive a connection hand-off on a transaction-mode pooler (Neon/Supabase). The migration runner itself uses `pg_advisory_xact_lock` (transaction-scoped) for the same reason. Follow this pattern for any new single-flight requirement; don't introduce `pg_advisory_lock`/`pg_advisory_unlock` (session-scoped).

### Audit (FR-SEC-031)
- Every action in `enums.AuditAction` that happens must be recorded via `audit.Service.Record` with the actor (`entities.SystemPrincipal`/`enums.SystemActor` for automated work), action type, entity and details.
- Audit writes go in the same transaction as the change they describe (pass the same `ctx`), so a change is never committed without its audit entry.
- Never put secrets, tokens, full webhook URLs or raw prompts in audit `details`/`metadata`.
- The hash chain (`entities.AuditHash`) is appended under `pg_advisory_xact_lock`; don't bypass `audit.Service.Record` to insert a row directly. `GET /audit/verify` recomputes the whole chain — if you change what `AuditHash` hashes, every previously-stored row becomes unverifiable; don't do that without a migration plan.

### External APIs (Gemini, AbuseIPDB, Slack/Discord, Cloud Scheduler)
- Each sits behind a port in `domain/interfaces/ports.go`. Adapters take an `*http.Client` (built with `httpx.NewClient`, which disables redirect-following) and a base URL, so tests can point them at `httptest.Server`. Tests never call real APIs.
- Gemini (`ai/gemini`): structured output only (`responseMimeType: "application/json"` + `responseSchema`), temperature 0, log data inside `<<<...>>>` delimiters and treated as untrusted. The API key goes in the `x-goog-api-key` header, never a query parameter. Validate the parsed result (enum, lengths, and — critically — that any IP/user the model names actually appears in the data sent to it) before storing it. Retries honour `RetryInfo`/`Retry-After`; a daily budget lives in `api_usage`; a retryable failure produces a `deferred` batch, picked up by `BatchRepository.Retryable` on the next scan.
- NL query maps text to a **whitelisted** filter struct (`nlquery.llmFilter` → `interfaces.LogQuery`/`IncidentQuery`) that is validated and clamped in Go. **Gemini output is never executed as SQL** and never triggers an action; unknown enum values are silently dropped, not errored.
- AbuseIPDB (`threatintel/abuseipdb`): check `threat_intel_cache` (24h) first via `enrichment.Service`, skip private/loopback/RFC5737-documentation IPs (`net/netip`), respect the daily budget (≤ 1,000, configurable). The API key goes in the `Key` header.
- Webhooks (`notify`): record every attempt in `alert_deliveries` and audit `ALERT_SENT`/`ALERT_FAILED`. A failed delivery must not fail the scan. `alert_deliveries.error` and audit metadata must **never** contain the actual error text (it can embed the webhook URL) — store a fixed string like `"delivery failed"` instead. User-influenced text (AI summaries) going into a webhook payload must be run through `notify.sanitize` first (strips `@everyone`/`@here`/mention syntax).
- Cloud Scheduler (`scheduler`): authenticates via the GCE metadata server (`Metadata-Flavor: Google`), not a key file or client library. `Configured()` must treat a whitespace-only job name as unconfigured (trim before checking) — this was a real bug, caught by tests; don't reintroduce it.

### Security
- Secrets come only from env/Secret Manager. Never log them, return them, or store them in `settings`. Settings expose `*_set`/`*_configured: bool` only.
- Don't log request bodies, query strings, `Authorization` headers, webhook URLs, or `DATABASE_URL`. Config errors must not echo values. Tests check this — keep them passing.
- CORS stays an exact-origin allowlist (no `*`, because credentials are sent). Webhook URLs are host-pinned (`config.webhookHostAllowed`) to `hooks.slack.com` / `discord.com`/`discordapp.com` to block SSRF via a mistyped or malicious URL.
- JWT is hand-rolled HS256 with a fixed header (`jwt.go`) — algorithm-confusion (`alg: none`, foreign-key signing) is explicitly tested against and must stay rejected. `token_version` on the `users` row is how logout/role-change/disable revoke a session; any new auth-affecting mutation on a user must bump it.
- The scan endpoint accepts a Google OIDC token (audience + service-account email + `email_verified` all checked against Google's live JWKS) or an admin JWT — nothing else. `middleware.RequireAdminOrScheduler` is the only place that logic lives; don't duplicate it.
- The service is deployed `--allow-unauthenticated`, so app-level auth is the only protection. Any new route without auth must be justified and flagged to the user.
- Login is timing-safe for account enumeration: an unknown email still calls `BcryptHasher.CompareDummy` before returning the same flat `ErrUnauthorized` as a wrong password.

### Logging
- Use `log/slog` from `infrastructure/logging`. Its JSON output uses Cloud Logging's `severity`/`message` keys. Include `request_id` in request-scoped logs (`middleware.AccessLog` does this automatically; `handlers.Fail` does it for unmapped 500s).
- No `log.Fatal`/`panic` outside `main`'s startup path. `middleware.Recovery` converts any panic in a handler to a generic 500.

### Tests
- Standard `testing`, table-driven where natural, next to the code. Use hand-written fakes of the `interfaces` ports for use-case tests (see `usecases/testfakes`) and `httptest.Server` for handlers and HTTP adapters. **Don't add a mocking or assertion library.**
- Database/migration tests live in `internal/infrastructure/database/migrate_integration_test.go`, gated on `TEST_DATABASE_URL`, each run isolated in its own Postgres schema that is dropped afterward.
- Every bug fix gets a regression test. Two examples already in the suite: `scheduler.TestConfigured` (whitespace job name) and `mocklogs.TestGenerate_Deterministic` (seeded RNG, not `uuid.NewString()`, for `log_id`).

## 5. Recipe: adding a feature endpoint

1. DTOs in `application/dtos/dtos.go`, matching `types.ts` field-for-field.
2. Ports in `domain/interfaces/ports.go` if new data access or an external call is needed.
3. A new migration file if the schema changes (never edit `0001_init.sql`).
4. Repo/adapter in `infrastructure/...` with an interface assertion and error translation via `translate()`.
5. The use case in `application/usecases/<feature>/`, with audit entries and a transaction where needed.
6. Handler + route (right middleware chain), plus `router.Deps` wiring and construction in `cmd/api/main.go`.
7. Tests (use case with fakes, handler/adapter with httptest), then `go build/vet/gofmt/test`.
8. Update `PLAN.md` §4/§7 if scope or the contract changed.

## 6. Don'ts

- Don't add a Dockerfile, Redis, WebSockets, `AutoMigrate`, soft deletes, or goroutines that outlive their request.
- Don't trust client-supplied `actor`, `flagged`, `user_id` or role.
- Don't let LLM output reach SQL, shell commands or outbound actions without validation against a fixed whitelist.
- Don't run anything against production databases or real third-party APIs, and don't deploy, without explicit user approval. Spin up a disposable local/Docker Postgres for integration testing instead (see §2), and tear it down afterward.
- Don't read, print or commit `.env`.
- Don't add or upgrade a dependency without asking. Pin exact versions. Prefer a hand-rolled REST/stdlib adapter over an SDK (see §1) unless there's a concrete reason not to.
