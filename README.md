# wcloud Agent

Part of **wcloud** (WordOps Multi-Site Manager). The control panel lives in a
separate repo, [`wcloud-portal`](../wcloud-portal); this repo is the agent that
runs on each WordOps server.

A per-server HTTP agent for wcloud. Runs deploy/update/
delete/ssl/purge/reset-password operations so the control panel can trigger them
over an authenticated API instead of SSH. Returns a **job ID** immediately and
streams **live logs** over SSE.

> **Security posture.** The agent runs as **root** (it invokes `wo`, nginx,
> systemctl). Its bearer token is therefore equivalent to root. Bind to a
> private/VPN interface, set an IP allowlist, and keep the token secret.

## Operations

All logic is native JS in `src/operations/*.js`, built on shared helpers in
`src/lib/sys.js` (process, filesystem, wo, nginx, wp-cli wrappers).

| Operation | Params | What it does |
|---|---|---|
| **deploy** | `{ domain, wp_user?, wp_password? }` | `wo site create --wp` + SSL + records DB creds |
| **update** | `{ domain }` | `wp core update` + `wp core update-db` + php-fpm restart |
| **delete** | `{ domain, confirm: true }` | Removes cron, files, WordOps site, nginx config, certs |
| **ssl** | `{ domain }` | `wo site update --le --force` |
| **purge** | `{ domain }` | WP Rocket page cache + object cache flush |
| **resetPassword** | `{ domain, wp_password }` | `wp user update --user_pass` on the admin account |

## Install

```bash
sudo mkdir -p /opt/wcloud
sudo cp -r src package.json /opt/wcloud/
cd /opt/wcloud
sudo npm install --omit=dev
```

Set env vars (inline or in a `.env` file loaded by systemd):

```bash
export AGENT_TOKEN=$(openssl rand -hex 32)
export AGENT_HOST=127.0.0.1
export AGENT_ALLOWED_IPS="10.0.0.5"
```

Run under systemd:

```bash
sudo cp wcloud.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wcloud
sudo journalctl -u wcloud -f
```

## Configuration

| Var | Default | Required |
|---|---|---|
| `AGENT_TOKEN` | *(none)* | yes — ≥32 chars |
| `AGENT_HOST` | `127.0.0.1` | no |
| `AGENT_PORT` | `8787` | no |
| `AGENT_ALLOWED_IPS` | *(any)* | yes if host ≠ 127.0.0.1 |
| `AGENT_WWW_DIR` | `/var/www` | no |
| `AGENT_MAX_CONCURRENT` | `1` | no |
| `AGENT_JOB_RETENTION_MS` | `3600000` (1h) | no |
| `AGENT_JOB_TIMEOUT_MS` | `1200000` (20m) | no |

The agent **refuses to start** if the token is missing or if bound to `0.0.0.0`.

## API

All endpoints except `/healthz` require `Authorization: Bearer <AGENT_TOKEN>` and
must come from an allowed IP.

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness (no auth) |
| GET | `/api/info` | Server name + supported operations |
| GET | `/api/sites` | List websites (`wo site list`) |
| GET | `/api/sites/:domain/credentials` | DB credentials recorded at deploy time |
| POST | `/api/op/:type` | Start an operation → `{ jobId }` |
| GET | `/api/jobs` | List recent jobs |
| GET | `/api/jobs/:id` | Job status |
| GET | `/api/jobs/:id/logs` | Full log buffer (JSON) |
| GET | `/api/jobs/:id/stream` | Live logs (SSE) |
| POST | `/api/jobs/:id/cancel` | Cancel queued/running job |

### Examples

```bash
TOKEN=... ; BASE=http://10.0.0.5:8787

# list sites
curl -s $BASE/api/sites -H "Authorization: Bearer $TOKEN"

# deploy a WordPress site
curl -s -X POST $BASE/api/op/deploy \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}'
# => {"jobId":"...","state":"queued"}

# stream logs
curl -sN $BASE/api/jobs/<jobId>/stream -H "Authorization: Bearer $TOKEN"

# delete (requires confirm:true)
curl -s -X POST $BASE/api/op/delete \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","confirm":true}'
```

SSE events: `hello` (on connect), `line` (`{t,stream,line}`), `state`
(`{state,reason}`). The stream closes at terminal state.

## Notes

- Jobs and logs are **in-memory** (default 1h retention). The portal is the
  durable record; an agent restart forgets history.
- `AGENT_MAX_CONCURRENT` defaults to **1** to serialize operations (avoids
  nginx/php-fpm races).
- Secrets in job params (matching `pass|secret|token|key`) are redacted in
  public job views.