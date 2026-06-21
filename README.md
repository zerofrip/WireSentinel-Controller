# WireSentinel Controller

Central management plane for WireSentinel endpoint enrollment, policy distribution, audit collection, and operational metrics.

## Workspace layout

| Path | Purpose |
|------|---------|
| `controller/` | Domain services (auth, enrollment, devices, policies, audit, metrics) |
| `api/` | Axum HTTP API (`controller-api` binary) |
| `database/` | SQLite migrations and sqlx helpers |
| `agents/` | Rust SDK for endpoint enrollment + heartbeat |
| `web-ui/` | Vite + React admin UI |

## Quick start (dev)

```bash
# API
export DATABASE_URL=sqlite://./data/controller.db?mode=rwc
export WS_CONTROLLER_JWT_SECRET=change-me
cargo run -p controller-api

# UI
cd web-ui && npm install && npm run dev
```

Default admin user is seeded on first run: `admin` / `admin` (change immediately in production).

## API overview

- `POST /api/v1/auth/login` — JWT login
- `GET /api/v1/devices` — list devices (viewer+)
- `POST /api/v1/devices/register` — agent enrollment (public, token required)
- `POST /api/v1/devices/{id}/heartbeat` — agent heartbeat (public)
- `POST /api/v1/enrollment/tokens` — create token (operator+)
- `GET/POST /api/v1/policies` — policy CRUD + push/revoke
- `GET /api/v1/audit`, `POST /api/v1/audit/ingest`
- `GET /api/v1/metrics` — JSON or Prometheus (`Accept: text/plain`)
- `GET /health` — public health probe

## Tests

```bash
cargo test --workspace
cd web-ui && npm run build
```

PowerShell helpers: `scripts/build.ps1`, `scripts/run-tests.ps1`.

## Security notes

- Set `WS_CONTROLLER_JWT_SECRET` to a strong random value.
- `ControllerSecurityPolicy` controls JWT TTL, bcrypt cost, and HTTPS enforcement flag.
- RBAC roles: `admin`, `operator`, `viewer`.
