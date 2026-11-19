# Incident App — Backend API

Rust/Axum backend for the CS 5343 Secure Incident-Reporting Application.
Apache serves the frontend over HTTPS and forwards `/api/*` to this service,
which listens on `127.0.0.1:3000` only and talks to RDS PostgreSQL as the
limited `app_user`.

## Project layout

| File | Purpose |
| --- | --- |
| `src/main.rs` | Startup, logging, router, panic recovery, graceful shutdown |
| `src/config.rs` | Reads DB credentials from Secrets Manager; TLS connection to RDS |
| `src/auth.rs` | Argon2id passwords, session tokens and cookie, `AuthUser` check, roles |
| `src/audit.rs` | Writes audit rows (the DB trigger adds timestamp and hash chain) |
| `src/validate.rs` | Server-side input validation |
| `src/error.rs` | Generic error responses; details go to the log only |
| `src/routes/account.rs` | Login, logout, current user, password change |
| `src/routes/incidents.rs` | Incidents, status changes, comments |
| `src/routes/admin.rs` | User management, audit log, chain verification |
| `deploy/incident-app.service` | systemd unit |
| `deploy/apache-api-proxy.conf` | Apache `/api/` proxy and security headers |

## API

All request and response bodies are JSON. Requests with a body must send
`Content-Type: application/json`. Errors look like `{ "error": "message" }`.

| Method | Path | Who | Body |
| --- | --- | --- | --- |
| GET | `/api/health` | public | — |
| POST | `/api/auth/login` | public | `{ "username", "password" }` |
| POST | `/api/auth/logout` | logged in | — |
| GET | `/api/auth/me` | logged in | — |
| POST | `/api/auth/password` | logged in | `{ "current_password", "new_password" }` |
| GET | `/api/incidents?status=open` | logged in (user: own; reviewer: not closed; admin: all) | — |
| POST | `/api/incidents` | logged in | `{ "title", "description" }` |
| GET | `/api/incidents/{id}` | owner, reviewer (not closed), admin | — |
| PATCH | `/api/incidents/{id}/status` | reviewer | `{ "status": "open" \| "under_review" \| "closed", "version" }` |
| POST | `/api/incidents/{id}/comments` | reviewer, admin | `{ "body" }` |
| GET | `/api/admin/users` | admin | — |
| POST | `/api/admin/users` | admin | `{ "username", "password", "role": "user" \| "reviewer" \| "admin" }` |
| PATCH | `/api/admin/users/{id}` | admin, not on own account | any of `{ "role", "is_active", "password" }` |
| GET | `/api/admin/audit?limit=200` | admin | — |
| GET | `/api/admin/audit/verify` | admin | — |

Status codes: 400 invalid input, 401 not logged in or login failed,
403 role not allowed, 404 not found or outside your scope, 409 conflict
(username taken, or incident changed by someone else), 500 server error.

## Build and deploy (on the EC2 instance)

```bash
# First time only: Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

git clone https://github.com/<you>/<repo>.git ~/incident-app
cd ~/incident-app
cargo build --release            # first build takes several minutes

# First time only: service user and folders
sudo useradd --system --no-create-home --shell /sbin/nologin incidentapp
sudo mkdir -p /opt/incident-app /var/log/incident-app
sudo chown incidentapp:incidentapp /var/log/incident-app

# Install / update the binary and the service
sudo cp target/release/incident-app /opt/incident-app/incident-app
sudo cp deploy/incident-app.service /etc/systemd/system/incident-app.service
sudo systemctl daemon-reload
sudo systemctl enable incident-app
sudo systemctl restart incident-app
sudo systemctl status incident-app
sudo tail -n 20 /var/log/incident-app/app.log   # should end with "incident-app listening"
curl -s http://127.0.0.1:3000/api/health        # ok
```

Then add the contents of `deploy/apache-api-proxy.conf` to
`/etc/httpd/conf.d/incident-app-le-ssl.conf` and reload Apache.
`https://app.cs5343incidents.click/api/health` should return `ok`.

To deploy a change later: `git pull && cargo build --release`, copy the binary,
`sudo systemctl restart incident-app`.

## Create the first admin (once)

Only admins can create users, so the first admin is inserted by hand.

```bash
# Prints an Argon2id hash; the password is not echoed or saved in shell history
read -s -p "Admin password (12+ chars): " PW; echo
printf '%s\n' "$PW" | /opt/incident-app/incident-app hash-password; unset PW
```

Copy the printed hash (starts with `$argon2id$`), then in psql as `postgres`:

```sql
INSERT INTO users (username, password_hash, role_id)
VALUES ('admin', '<paste the hash>', 3)
RETURNING id;

-- Record it in the audit trail too (use the id returned above)
INSERT INTO audit_logs (user_id, action, target_type, target_id)
VALUES (NULL, 'USER_CREATED', 'user', <id>);
```

## Try it with curl (from your laptop)

```bash
API=https://app.cs5343incidents.click/api

# Log in (stores the session cookie in jar.txt)
curl -s -c jar.txt -b jar.txt -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}' $API/auth/login

# Create a reviewer and a normal user
curl -s -b jar.txt -H 'Content-Type: application/json' \
  -d '{"username":"rev1","password":"reviewer-pass-123","role":"reviewer"}' $API/admin/users
curl -s -b jar.txt -H 'Content-Type: application/json' \
  -d '{"username":"user1","password":"user-pass-12345","role":"user"}' $API/admin/users

# Audit log and chain check
curl -s -b jar.txt $API/admin/audit
curl -s -b jar.txt $API/admin/audit/verify
```

Misuse cases for the demo video (each should fail):

| Attempt | Expected |
| --- | --- |
| Any `/api/incidents` call without logging in | 401 |
| `user1` calls `GET /api/admin/users` | 403 |
| `user1` sends `{"role":"admin"}` to `/api/auth/password` | 400 (unknown field) |
| Admin PATCHes their own id with `{"role":"user"}` | 403 (SR-6) |
| `user1` opens another user's incident | 404 |
| `user1` changes an incident's status | 403 |
| 5 wrong passwords for one account | account locked for 15 minutes |
| Old session cookie after logout | 401 |
| `' OR 1=1 --` as username | 401, nothing leaks (bind parameters) |

## Local development (optional)

Without `APP_SECRET_ID`, the app reads `DATABASE_URL` and logs to the console:

```bash
DATABASE_URL=postgres://app_user:<pw>@localhost/incidents cargo run
```

## Requirement mapping

| Requirement | Where |
| --- | --- |
| FR-1–FR-3, SR-6 | `routes/admin.rs` (`create_user`, `update_user`, self-edit blocked) |
| FR-4, FR-5 | `routes/account.rs` (`login`, `logout` deletes the server-side session) |
| FR-6–FR-10 | `routes/incidents.rs` (role-scoped list, `can_view`) |
| FR-11, FR-12, SR-10, SR-11 | `audit.rs` + DB triggers; `/api/admin/audit/verify` |
| SR-1, SR-4, SR-5 | `AuthUser` extractor re-checks session and role on every request |
| SR-2 | Argon2id in `auth.rs` |
| SR-3 | `__Host-session` cookie: Secure, HttpOnly, SameSite=Strict; only its SHA-256 stored |
| SR-7 | `validate.rs` + DB CHECK constraints; `deny_unknown_fields` on every body |
| SR-8 | Every query uses `$n` bind parameters |
| SR-9, SR-12, SR-13 | `error.rs`: generic messages to users, details to `app.log`; no secrets logged |
| SR-14 | `config.rs`: credentials from Secrets Manager via the instance role |
| NFR-3, NFR-4 | Argon2 off the async threads; 10-connection pool |
| NFR-5 | Transactions; optimistic locking on incident status; `FOR UPDATE` on user edits |
| NFR-6 | `CatchPanicLayer`, systemd `Restart=on-failure`, graceful shutdown |
