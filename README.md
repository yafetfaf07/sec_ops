# SecOps Coordinator Agent

AI-powered security operations platform for a B2B SaaS environment. The system ingests login and access logs, detects suspicious behavior, enriches suspicious IPs with threat intelligence, creates incidents, dispatches alerts, and provides a responsive security dashboard for human investigation.

> **Current status:** the Go backend, React frontend, authentication integration, Docker/Render deployment path, Cloud Run Buildpacks path, seeded demo data, automated tests, and SRS are implemented. A production deployment still requires platform-specific environment variables, database configuration, and a final deploy/redeploy.

## Project structure

```text
AI_TEST/
├── README.md                         # This document
├── SRS.md                            # Software Requirements Specification
├── backend/                          # Go/Gin API
│   ├── cmd/api/main.go               # Composition root and HTTP server
│   ├── internal/                     # Domain, application, and infrastructure layers
│   ├── Dockerfile                     # Render/Docker deployment
│   ├── docker-compose.yml             # Local API + PostgreSQL stack
│   ├── project.toml                   # Google Cloud Buildpacks configuration
│   ├── .env.example                   # Backend configuration template
│   └── go.mod
├── frontend/
│   └── sec_ops_agent_frontend/        # React Router + TypeScript dashboard
│       ├── app/routes/                # Login and protected application routes
│       ├── app/lib/api/               # Axios client and API endpoint contract
│       ├── app/stores/auth.ts         # In-memory access-token session state
│       ├── .env.example               # VITE_API_BASE_URL template
│       └── package.json
└── seed_data/                         # Safe CSV export of local demo data
    └── README.md
```

## Main capabilities

- **Authentication:** bcrypt passwords, HS256 JWT access tokens, rotating httpOnly refresh cookies, session revocation through token versions.
- **RBAC:** `admin`, `analyst`, and `viewer` roles enforced by the Go API.
- **Log ingestion:** validated JSON logs, deterministic mock scenarios, server-derived flags, duplicate protection, immutable raw evidence.
- **AI analysis:** Gemini structured JSON output for risk classification, summaries, patterns, suspicious IPs, and recommended actions.
- **Threat intelligence:** AbuseIPDB lookups for eligible public IPs with a 24-hour cache and daily request budget.
- **Alerting:** Slack and Discord webhook adapters with safe content sanitization and delivery records.
- **Incident management:** Open → Acknowledged → Resolved state machine, resolution comments, fingerprint-based alert suppression.
- **Natural-language investigation:** Gemini converts analyst questions into a validated filter; the model never writes or executes SQL.
- **Auditability:** append-only audit log with a cryptographic hash chain and administrator verification endpoint.
- **Deployment:** Render/Docker and Google Cloud Run source deployment without requiring local Docker for Cloud Run.

## Technology stack

### Backend

- Go 1.26.5
- Gin HTTP framework
- PostgreSQL
- GORM with pgx
- bcrypt password hashing
- Hand-rolled standard-library HS256 JWT verification
- Hand-rolled Google OIDC/JWKS verification
- Google Gemini REST API
- AbuseIPDB REST API
- Slack and Discord incoming webhooks
- `log/slog` structured logging

### Frontend

- React 19
- TypeScript
- React Router
- TanStack Query
- Axios
- Zustand
- Tailwind CSS and the existing UI component system

## Local development

### Prerequisites

- Go 1.26.5 or a compatible newer Go release.
- Node.js and npm.
- PostgreSQL, or Docker Desktop if using the provided Compose stack.

### Option A: run the backend with local PostgreSQL

1. Copy the backend configuration template:

```bash
cd backend
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

2. Set at least these values in `backend/.env`:

```dotenv
APP_ENV=development
PORT=8080
DATABASE_URL=postgresql://postgres:password@localhost:5432/secops?sslmode=disable
CORS_ALLOWED_ORIGINS=http://localhost:5173
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=change-this-local-password
BOOTSTRAP_ADMIN_NAME=Administrator
GEMINI_MODEL=gemini-3.5-flash-lite
```

Leave `GEMINI_API_KEY` empty if you only want to test authentication, logs, dashboard, and UI behavior. Natural-language queries and AI scans require a valid Gemini key.

3. Start the backend from the **backend root**, not from `backend/cmd/api`:

```bash
go run ./cmd/api
```

The API listens on `http://localhost:8080` by default.

Health checks:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

The backend searches for `.env` from the current working directory. Run `go run ./cmd/api` from `backend/` so it finds `backend/.env`.

### Option B: run API and PostgreSQL with Docker Compose

From `backend/`:

```bash
docker compose up --build
```

The API will be available at:

```text
http://localhost:8080
```

The Compose database is exposed on host port 5432. If another local container already uses port 5432, change the host mapping in `docker-compose.yml`, for example:

```yaml
ports:
  - "5433:5432"
```

The internal API connection remains:

```text
postgres://postgres:postgres@db:5432/secops?sslmode=disable
```

Stop the stack with:

```bash
docker compose down
```

Do not use `docker compose down -v` unless you intentionally want to delete the local database volume.

### Frontend setup

From the frontend directory:

```bash
cd frontend/sec_ops_agent_frontend
npm install
```

Create `.env` from the template:

```bash
cp .env.example .env
```

Set the API URL for real backend mode:

```dotenv
VITE_API_BASE_URL=http://localhost:8080
```

Start the frontend:

```bash
npm run dev
```

Open:

```text
http://localhost:5173/login
```

If `VITE_API_BASE_URL` is empty or missing, the frontend uses its in-memory mock data layer instead of the Go API.

## Local login

The backend creates the first administrator at startup when both bootstrap variables are set:

```dotenv
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=change-this-local-password
```

Use the values configured in your local `.env`. Do not copy local demo credentials into production.

The mock frontend mode accepts any password and uses the email local part to select a demo role:

```text
admin@example.com   → admin
analyst@example.com → analyst
viewer@example.com  → viewer
```

## API overview

All application routes are under `/api/v1`.

### Health

| Method | Endpoint | Authentication |
|---|---|---|
| GET | `/healthz` | Public |
| GET | `/readyz` | Public; checks PostgreSQL |

### Authentication and users

| Method | Endpoint | Authentication |
|---|---|---|
| POST | `/auth/login` | Public |
| POST | `/auth/refresh` | Refresh cookie |
| POST | `/auth/logout` | Public; revokes cookie session when available |
| GET | `/auth/me` | Authenticated |
| GET | `/users` | Admin |
| POST | `/users` | Admin |
| PATCH | `/users/:id/role` | Admin |

### Logs

| Method | Endpoint | Authentication |
|---|---|---|
| GET | `/logs` | Authenticated |
| GET | `/logs/countries` | Authenticated |
| POST | `/logs/ingest` | Admin or `X-Ingest-Key` |
| POST | `/logs/mock` | Admin |

Example mock-log request:

```bash
curl -X POST http://localhost:8080/api/v1/logs/mock \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{"scenario":"mixed","count":100}'
```

Supported scenarios:

```text
benign
brute_force
impossible_travel
privilege_escalation
mixed
```

### Incidents and dashboard

| Method | Endpoint | Authentication |
|---|---|---|
| GET | `/incidents` | Authenticated |
| GET | `/incidents/:id` | Authenticated |
| POST | `/incidents/:id/acknowledge` | Admin or Analyst |
| POST | `/incidents/:id/resolve` | Admin or Analyst; requires a comment |
| GET | `/dashboard/summary` | Authenticated |

### Scans and investigation

| Method | Endpoint | Authentication |
|---|---|---|
| POST | `/scan/run` | Admin |
| POST | `/scan/daily` | Cloud Scheduler OIDC or Admin |
| GET | `/scan/runs` | Authenticated |
| POST | `/query` | Admin or Analyst |

`/query` requires a valid configured Gemini key/model. If Gemini is unavailable, the endpoint returns an upstream-service error rather than executing an unsafe fallback query.

### Audit and settings

| Method | Endpoint | Authentication |
|---|---|---|
| GET | `/audit` | Admin or Analyst |
| GET | `/audit/verify` | Admin |
| GET | `/settings` | Admin |
| PUT | `/settings` | Admin |

The frontend never sends an `actor` field for mutating requests. The backend derives the actor from the authenticated JWT.

## Authentication flow

1. The frontend submits credentials to `/api/v1/auth/login`.
2. The backend returns an access token and sets an httpOnly refresh cookie.
3. The frontend stores the access token in memory only.
4. Axios attaches the access token as `Authorization: Bearer <token>`.
5. On a 401 response, the frontend makes one refresh request and retries the original request once.
6. Logout clears the local session and asks the backend to revoke the refresh session.

## Database and immutability

The backend runs embedded migrations at startup. It does not use GORM `AutoMigrate`.

Important tables include:

```text
users
raw_logs
scan_runs
analysis_batches
batch_logs
incidents
incident_comments
threat_intel_cache
alert_deliveries
audit_logs
api_usage
settings
schema_migrations
```

The following tables are append-only and protected by PostgreSQL triggers:

```text
raw_logs
batch_logs
audit_logs
incident_comments
alert_deliveries
```

Raw logs are never updated to mark them as analyzed. Instead, `batch_logs` records which raw logs belong to an analysis batch.

## Seed data

A safe CSV export of the local seeded database is available under:

```text
seed_data/
```

It includes raw logs, analysis batches, incidents, comments, audit entries, scan runs, and other non-secret data. Password hashes are intentionally excluded from `users.csv`.

The CSV files are for local demonstrations or controlled disposable-database imports. Do not import synthetic seed data into production without review because several tables are append-only.

## Deployment

### Render with Docker

The backend Dockerfile is located at:

```text
backend/Dockerfile
```

Recommended Render configuration:

| Setting | Value |
|---|---|
| Service type | Web Service |
| Runtime | Docker |
| Root Directory | `backend` |
| Dockerfile Path | `Dockerfile` |
| Docker Context Directory | `.` |
| Health Check Path | `/healthz` |

Because Render's Root Directory is `backend`, the Docker build sees:

```text
backend/go.mod       → go.mod
backend/go.sum       → go.sum
backend/Dockerfile   → Dockerfile
```

Required production environment variables include:

```dotenv
APP_ENV=production
PORT=10000
DATABASE_URL=<Supabase pooler or Render PostgreSQL URL>
JWT_SECRET=<at least 32 random characters>
CORS_ALLOWED_ORIGINS=https://<frontend-domain>
COOKIE_SECURE=true
BOOTSTRAP_ADMIN_EMAIL=<admin-email>
BOOTSTRAP_ADMIN_PASSWORD=<strong-password>
GEMINI_API_KEY=<provider-secret>
GEMINI_MODEL=gemini-3.5-flash-lite
ABUSEIPDB_API_KEY=<provider-secret>
```

For Supabase, prefer the Transaction Pooler connection string. It generally uses a host like:

```text
aws-0-<region>.pooler.supabase.com:6543
```

Do not use a direct Supabase host such as `db.<project-ref>.supabase.co:5432` if the deployment environment cannot reach its IPv6 address.

### Google Cloud Run with Buildpacks

From `backend/`:

```bash
gcloud run deploy secops-api --source . --region us-central1
```

The `project.toml` file sets:

```toml
[[build.env]]
name = "GOOGLE_BUILDABLE"
value = "./cmd/api"
```

This path does not use the Dockerfile. The Dockerfile exists for Render and other Docker-based platforms.

### Frontend deployment

The frontend can be deployed as a separate React Router service. Build it with:

```bash
cd frontend/sec_ops_agent_frontend
npm ci
npm run typecheck
npm run build
```

The production frontend must set:

```dotenv
VITE_API_BASE_URL=https://<backend-domain>
```

The backend `CORS_ALLOWED_ORIGINS` must include the deployed frontend origin.

## Security rules

- Never commit `.env` files.
- Never place API keys in the frontend.
- Never expose the refresh token to JavaScript.
- Do not trust client-provided roles or actor names.
- Do not execute SQL generated by Gemini.
- Do not expose raw provider errors or secrets in HTTP responses.
- Rotate any key that has been exposed in terminal output, logs, screenshots, or chat history before production use.
- Keep `COOKIE_SECURE=true` in production.
- Use Supabase/Render secret storage for production secrets.

## Testing

### Backend

```bash
cd backend
go build ./...
go vet ./...
gofmt -l .
go test -count=1 ./...
```

Database integration tests use `TEST_DATABASE_URL` and isolate themselves in a disposable schema.

### Frontend

```bash
cd frontend/sec_ops_agent_frontend
npm run typecheck
npm run build
```

The backend has unit tests for security, repositories/use cases, external adapters, middleware, RBAC, routing, migrations, and mock-log generation. External provider tests use `httptest` and do not make real API calls.

## Troubleshooting

### `DATABASE_URL is required`

Run the backend from the backend root:

```bash
cd backend
go run ./cmd/api
```

Do not run only `go run main.go` from `backend/cmd/api`; the root `.env` may not be found.

### Render says `go.sum` is missing

Set:

```text
Root Directory: backend
Dockerfile Path: Dockerfile
Docker Context Directory: .
```

The Docker build context must contain `go.mod` and `go.sum`.

### Render says `network is unreachable` for Supabase

The service is probably using a direct Supabase IPv6 hostname. Use the Supabase Transaction Pooler URL on port 6543 with `sslmode=require`.

### `/api/v1/query` returns 503 or 500

Check:

1. `GEMINI_API_KEY` is configured in the running deployment.
2. `GEMINI_MODEL` is set to an available model such as `gemini-3.5-flash-lite`.
3. Render was redeployed after changing environment variables.
4. The provider key is valid and has available quota.

### No incidents appear after logs are seeded

`POST /logs/mock` only creates raw logs. Incidents are normally created by:

```text
POST /api/v1/scan/run
```

The scan requires Gemini for AI analysis. Without Gemini, batches are deferred rather than converted into incidents.

## Documentation

- [Software Requirements Specification](SRS.md)
- [Backend implementation plan](backend/PLAN.md)
- [Backend agent/development rules](backend/agent.md)
- [Local seed-data export notes](seed_data/README.md)
