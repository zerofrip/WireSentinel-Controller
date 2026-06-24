# Phase 9 — WireSentinel Controller

This repository implements the WireSentinel management controller:

- **9-D** — workspace scaffold
- **9-E** — device registry + heartbeat
- **9-F** — policy distribution (global/group/device)
- **9-G** — audit ingest + query
- **9-H** — enrollment tokens (create/revoke/rotate)
- **9-I** — web UI pages
- **9-J** — metrics (JSON + Prometheus stub)
- **9-K** — JWT auth + RBAC
- **9-L** — unit + integration tests

Development uses SQLite. Production deployments should use a managed database and reverse proxy TLS termination.
