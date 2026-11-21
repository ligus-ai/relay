# Deploying the relay

The relay is one static Go binary, `langstroth-relay`, published as the
container image `ghcr.io/langstroth-ai/langstroth-relay:<version>`
(`linux/amd64`, `linux/arm64`; distroless, runs as UID 65532) and as the Helm
chart `oci://ghcr.io/langstroth-ai/charts/langstroth-relay`. It runs on any
host that can run a container or a Linux binary. This guide is
provider-neutral; every setting is in [reference.md](reference.md).

Three things hold for every deployment:

- **One instance.** Pairing codes, live-push fan-out and rate limits live in
  the process: run exactly one relay per URL, and replace it rather than
  rolling it (stop the old one, then start the new one).
- **HTTPS in front.** Ligus clients require `https://`. The relay serves
  plain HTTP; terminate TLS in a reverse proxy or your platform's edge, and
  tell the relay which proxy to trust (`LANGSTROTH_RELAY_TRUSTED_PROXIES`)
  so rate limits see real client addresses.
- **Health check:** `GET /v1/health` answers `200 ok` when the relay and its
  store are up (`503` when the store doesn't answer).

| Option | Use it for | Files |
|---|---|---|
| [Docker Compose](#docker-compose) | one Linux host, relay + Postgres | `deploy/compose/langstroth-relay/` |
| [systemd](#systemd) | one Linux host, no containers | `deploy/systemd/` |
| [Helm](#helm) | Kubernetes | `deploy/helm/langstroth-relay/` (published as an OCI chart) |
| [A PaaS](#running-on-a-paas) | a container platform that runs an image | none: the image and env vars below |

## Docker Compose

Needs Docker Compose v2.24 or later. Two variants share one `.env`:

- `compose.yaml`: the relay and Postgres 17 (production).
- `compose.standalone.yaml`: the relay alone, with its built-in store
  (memory plus a JSON snapshot on a volume). Fine for a small team or a trial;
  one instance only.

Each publishes the relay on `127.0.0.1:8443` for a reverse proxy on the same
host, and has an optional Caddy service (`--profile tls`) that gets a
certificate for `RELAY_DOMAIN` from Let's Encrypt.

```sh
git clone https://github.com/langstroth-ai/langstroth-relay && cd langstroth-relay/deploy/compose/langstroth-relay
cp .env.example .env && chmod 600 .env
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 24)/" .env
# with your own proxy on this host:
docker compose up -d
# or with Caddy for TLS (set RELAY_DOMAIN in .env, DNS pointing here, ports 80/443 open):
docker compose --profile tls up -d
curl -fsS localhost:8443/v1/health          # ok
```

The standalone variant: `docker compose -f compose.standalone.yaml up -d`
(add `--profile tls` for Caddy). Its one-shot `data-owner` service hands the
fresh volume to the relay's user before the relay starts.

The relay container runs read-only with no capabilities. Its image has no
shell, so Compose can't health-check it from inside; Caddy's health check
probes it over the compose network, or probe `/v1/health` from the host.

## systemd

For a Linux host without containers. The unit runs the binary as a
throwaway user (`DynamicUser`) with no capabilities, a read-only system and a
private state directory (`systemd-analyze security` rates it 1.2, "OK").

Get the binary by building it (Go 1.27, static, no cgo) or by copying it out
of the release image:

```sh
# build:
git clone https://github.com/langstroth-ai/langstroth-relay && cd langstroth-relay
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o langstroth-relay ./cmd/langstroth-relay
# or copy it out of the image:
docker create --name lr ghcr.io/langstroth-ai/langstroth-relay:0.3.1
docker cp lr:/usr/local/bin/langstroth-relay . && docker rm lr
```

Install and start:

```sh
sudo install -m 0755 langstroth-relay /usr/local/bin/langstroth-relay
sudo install -d -m 0750 /etc/langstroth-relay
sudo install -m 0640 deploy/systemd/langstroth-relay.env /etc/langstroth-relay/env
sudo install -m 0644 deploy/systemd/langstroth-relay.service /etc/systemd/system/
sudoedit /etc/langstroth-relay/env               # storage, access, ...
sudo systemctl daemon-reload && sudo systemctl enable --now langstroth-relay
curl -fsS localhost:8443/v1/health               # ok
journalctl -u langstroth-relay -f
```

The env file keeps the relay on `127.0.0.1:8443` and trusts loopback as its
proxy. Put a TLS proxy in front, for example Caddy:
`relay.example.com { reverse_proxy 127.0.0.1:8443 }`. Without
`DATABASE_URL` the state lives in `/var/lib/langstroth-relay` (systemd keeps
it under `/var/lib/private/langstroth-relay`).

## Helm

The chart is published per release; its
[README](../deploy/helm/langstroth-relay/README.md) is the full guide
(topologies, database modes, values, security). One-shot install on an
external Postgres:

```sh
kubectl create namespace langstroth-relay
kubectl label namespace langstroth-relay pod-security.kubernetes.io/enforce=restricted
kubectl -n langstroth-relay create secret generic relay-db \
  --from-literal=DATABASE_URL='postgres://relay:<password>@db.example.internal:5432/relay?sslmode=verify-full'
helm install langstroth-relay oci://ghcr.io/langstroth-ai/charts/langstroth-relay \
  --version 0.3.1 -n langstroth-relay \
  --set database.mode=external --set database.external.existingSecret=relay-db \
  --set 'database.external.cidrs={10.0.0.5/32}'
helm test langstroth-relay -n langstroth-relay
```

`database.mode` can also be `cnpg` (CloudNativePG) or `bundled`. With a coding
agent, [AGENTS.md](../AGENTS.md) and `deploy/agent/` drive the same chart
non-interactively.

## Running on a PaaS

Any platform that runs a container image works (Render, Railway, Fly.io,
Cloud Run, a VM with Docker, ...). There are no provider-specific files in
this repository; configure the platform with:

- **Image:** `ghcr.io/langstroth-ai/langstroth-relay:<version>`, pinned to a
  release. It runs as UID 65532, so a mounted volume must be writable by
  that user.
- **Port:** the relay listens on `$PORT` when the platform sets it, else on
  `LANGSTROTH_RELAY_ADDR`, else on `0.0.0.0:8443`.
- **Storage:** `DATABASE_URL` for the platform's Postgres (and
  `LANGSTROTH_RELAY_REQUIRE_DB=1`), or a volume with
  `LANGSTROTH_RELAY_DATA_DIR` pointing at it.
- **Health check:** HTTP `GET /v1/health`.
- **Scaling:** exactly one instance, always running (no scale-to-zero:
  phone tunnels and event streams are long-lived connections).
- **Client addresses:** set `LANGSTROTH_RELAY_TRUSTED_PROXIES` to the
  platform's proxy range if it documents one. On Fly.io the relay reads
  `Fly-Client-IP` by itself (it detects `FLY_APP_NAME`) when no trusted
  proxies are set.
- **TLS** is the platform's edge.

## Settings

Required: none. With no settings the relay serves on `0.0.0.0:8443`, open to
anyone, in memory only (state lost on restart). What most deployments set:

| Setting | Why |
|---|---|
| `DATABASE_URL` + `LANGSTROTH_RELAY_REQUIRE_DB=1` | Postgres store; refuse to start without it |
| or `LANGSTROTH_RELAY_DATA_DIR` (+ `LANGSTROTH_RELAY_MAX_STORE_BYTES`) | memory store with a snapshot on disk, bounded |
| `LANGSTROTH_RELAY_TRUSTED_PROXIES` | the proxy in front, so rate limits see clients |
| `LANGSTROTH_RELAY_TOKEN_PUBKEY` (+ `LANGSTROTH_RELAY_WORKSPACE_SCOPE`) | admit only clients with tokens you issue (`langstroth-relay keygen`, `issue`; keep the private key off the relay host) |
| `LANGSTROTH_RELAY_METRICS_TOKEN` | require a bearer on `/metrics` |
| `LANGSTROTH_RELAY_TUNNEL` | the phone tunnel (`open` or `allowlist`) |
| `GOMEMLIMIT` | let Go collect garbage before a small host runs out of memory |

Any setting can come from a file instead (`X_FILE`, or
`$LANGSTROTH_RELAY_SECRETS_DIR/X`). The relay refuses to start on a
configuration error, and while a variable under a pre-rename name
(`HIVE_RELAY_*`, `LIGUS_RELAY_*`) is set.

### A relay for the public

Every quota and rate limit for strangers is off by default. For a relay
anyone may use, turn on the community limits ([reference.md](reference.md#community-limits));
`deploy/compose/langstroth-relay/.env.example` lists a commented profile
sized for one machine with 1 GB of memory and a 10 GB Postgres disk. Quotas
refuse with `507` and never evict; rates answer `429` with `Retry-After`.

## Storage

- **Postgres** (`DATABASE_URL`): durable; use it for anything a team depends
  on. Migrations run at startup under an advisory lock, are additive, and are
  safe behind a transaction-pooling PgBouncer. Use `sslmode=verify-full` when
  the database is on another host.
- **Memory + snapshot** (`LANGSTROTH_RELAY_DATA_DIR`): everything in memory,
  written to `relay-state.json` (and attachments to `blobs/`) in that
  directory every few seconds and on shutdown. Bound it with
  `LANGSTROTH_RELAY_MAX_STORE_BYTES`.
- **Memory only** (neither set): for tests. Lost on restart.

Clients keep full copies of their workspaces and push again, so a reset relay
costs a resync, not data; a backup saves that resync and keeps pairing,
membership and contact state.

## Backups

- **Postgres:** your database's own backups (point-in-time recovery where
  available), or a dump:
  `docker compose exec -T db pg_dump -U relay -Fc relay > relay-$(date +%F).dump`.
  Restore into an empty database with `pg_restore` before starting the relay.
- **Snapshot store:** copy the data directory (`relay-state.json` and
  `blobs/`). The relay writes both atomically (temp file and rename), so a
  copy taken while it runs is consistent per file; stop it first for a copy
  of both at one instant.
- The database holds push tokens and pairing state: keep its backups apart
  from an APNs key.

## Upgrades

1. Read [CHANGELOG.md](../CHANGELOG.md) for the release: settings that
   changed and any step to take first.
2. Change the pinned version: the image tag in `compose.yaml`, the binary
   under systemd, `--version` for Helm, the image on a PaaS.
3. Restart: `docker compose pull && docker compose up -d`;
   `sudo systemctl restart langstroth-relay`; `helm upgrade ... --version <new>`.
   Expect a few seconds without sync; clients reconnect by themselves.
4. Check `GET /v1/health`.

Migrations are additive, so you can roll back one release by pinning the
previous version again.
