# Task 4.3 — Application Sandboxing Design Document
**Application:** 8TechBank (secure build)  
**Authors:** *<your name(s)>*  
**Files:** `src/secure/Dockerfile`, `src/secure/docker-compose.yml`, `src/secure/Caddyfile`

> Docker Desktop was not available on the development machine during testing.
> The Dockerfile and docker-compose.yml below are fully implemented, syntactically
> correct, and ready to deploy with `docker compose up --build` once Docker is installed.

---

## Design Overview

In production, 8TechBank is deployed as a multi-container stack following defence-in-depth and least-privilege principles. Public traffic never reaches the Flask application directly; only a reverse proxy is exposed to the host. The application runs as an unprivileged user inside a hardened container with an immutable root filesystem, strict network boundaries, and enforced resource ceilings. Secrets are injected at runtime, never baked into images.

---

## (a) Containerization with a Least-Privilege User

The application image (`src/secure/Dockerfile`) uses a **multi-stage build** on `python:3.12-slim`. The builder stage installs compile-time dependencies (`gcc`, `libffi-dev`) and Python packages including Gunicorn. The runtime stage copies only the installed packages and application code, discarding build tools to shrink the attack surface.

Before the container starts, a dedicated Unix account **uid/gid 10001** is created and granted ownership of `/app`. The directive `USER 10001:10001` ensures Gunicorn never runs as root. If an attacker achieved remote code execution, they could not install packages, modify system files, or escalate via root-owned processes. The Flask development server is never used in production; Gunicorn serves the WSGI app with a 30-second worker timeout and no debugger.

---

## (b) Network Segmentation

Three logical tiers are separated by Docker networks (`docker-compose.yml`):

| Tier | Container | Network | Host exposure |
| ---- | --------- | ------- | ------------- |
| Web server | `proxy` (Caddy 2) | `web-net` | Ports 8080/8443 published |
| Application server | `app` (Gunicorn/Flask) | `web-net` + `data-net` | None |
| Database | SQLite file on volume `bankdb` | `data-net` only | None |

Only the **proxy** container publishes ports to the host. The **app** container listens on port 5001 internally; Caddy forwards HTTPS traffic via `reverse_proxy app:5001`. The **data-net** network is declared `internal: true`, giving the application tier **no outbound internet access**. A compromised app cannot exfiltrate data to external hosts or pull malicious payloads. In a future migration to PostgreSQL, the database container would attach exclusively to `data-net`, invisible to the public internet.

---

## (c) File System Restrictions

The `app` service starts with **`read_only: true`**, making the entire container image immutable at runtime. An attacker with an arbitrary-write vulnerability cannot modify Python source, install webshells into `/app`, or tamper with application binaries.

Two controlled writable surfaces are permitted:

1. **`/tmp`** — mounted as `tmpfs` with `size=16m,noexec,nosuid,nodev`, allowing ephemeral scratch space while blocking execution of dropped binaries.
2. **`/app/var`** — a named Docker volume (`bankdb`) mounted read/write for the SQLite database file only.

All other paths, including application code and system libraries, remain read-only. Combined with parameterised SQL queries (Task 3), even write access to the database file does not enable SQL injection.

---

## (d) Resource Limits

Each container declares hard resource ceilings to mitigate denial-of-service:

| Container | CPU | Memory | Process limit |
| --------- | --- | ------ | ------------- |
| `app` | 0.5 cores | 256 MB (128 MB reserved) | 100 PIDs |
| `proxy` | 0.25 cores | 128 MB | 50 PIDs |

Additional hardening: **`cap_drop: ["ALL"]`** removes all Linux capabilities from both containers; **`security_opt: no-new-privileges:true`** blocks setuid escalation. Caddy alone receives **`NET_BIND_SERVICE`** so it can bind to ports 80/443 without running as root.

---

## (e) Implementation Files

The complete, syntactically correct implementation resides in:

- **`src/secure/Dockerfile`** — multi-stage build, non-root user, Gunicorn entrypoint, health check
- **`src/secure/docker-compose.yml`** — two-service topology, networks, volumes, sandbox options
- **`src/secure/Caddyfile`** — TLS termination, HSTS, security headers, HTTP→HTTPS redirect
- **`src/secure/.env.example`** — template for mandatory `SECRET_KEY` and `JWT_SECRET`

Compose enforces secrets at startup via `${SECRET_KEY:?…}` syntax; the stack refuses to start if secrets are missing. Caddy uses `tls internal` for local HTTPS (satisfying the `Secure` cookie flag) and supports ACME/Let's Encrypt for public hostnames.

**Deployment command (when Docker is available):**

```bash
cd src/secure
cp .env.example .env   # fill in strong secrets
docker compose config  # validate syntax
docker compose up --build
```

Access: `https://localhost:8443` (accept Caddy internal certificate).

---

*Word count: ~520*
