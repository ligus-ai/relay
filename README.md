# Langstroth Relay

The sync relay for [Ligus](https://github.com/langstroth-ai/ligus), part of
the [Langstroth](https://langstroth.ai) platform. Ligus is short for
*ligustica*; the Ligus apps (desktop, CLI, phone, terminal) are the clients,
and this relay is the small server they sync through.

- **End-to-end encrypted, content-blind.** Clients post sealed event
  envelopes per workspace and fetch everything after a cursor. The relay never
  holds a workspace key and never sees plaintext, file contents or names, nor
  a forge (GitHub, GitLab, ...) token.
- **What it does:** stores and forwards envelopes, key rotations, presence
  and connection candidates; brokers short single-use pairing codes; stores
  encrypted attachments (blobs); holds opaque client-signed contact records;
  and, when turned on, runs the phone tunnel between the Ligus iPhone app and
  a `ligus serve` host.
- **What its operator can see:** ciphertext and its sizes, timing, random
  room ids and client addresses. Never the content.

One Go binary (`langstroth-relay`), plus an optional sign-in service
(`langstroth-auth`) in the same repo. MIT licensed.

## Community relay or your own

`https://relay.langstroth.ai` is a community relay the Langstroth project runs
for anyone to try Ligus with: free, best-effort, no uptime guarantee, and it
may be reset (devices keep full copies and push again). For a team that
depends on sync, run your own: it is a single static binary in a small
container. See [The community relay](https://docs.langstroth.ai/operate/networking/community-relay/)
and [Self-host a relay](https://docs.langstroth.ai/operate/networking/self-host/).

The relay URL travels inside every Ligus invite, so only the person who
creates a workspace picks a relay.

## Quick start

```sh
go run ./cmd/langstroth-relay        # serves http on 0.0.0.0:8443, in memory
curl localhost:8443/v1/health        # ok
```

Keep data across restarts with `LANGSTROTH_RELAY_DATA_DIR=/some/dir`
(memory plus a JSON snapshot), or point several processes' storage at
Postgres with `DATABASE_URL`. `deploy/agent/local.sh start` runs a built
binary on loopback with a data dir and prints JSON with `--json`.

Clients require `https://`: terminate TLS at your platform's edge or a reverse
proxy (for example Caddy: `relay.example.com { reverse_proxy localhost:8443 }`).

## Deploy

Full guide: [docs/deploy.md](docs/deploy.md).

**Docker.** The root `Dockerfile` builds a small Alpine image;
`deploy/container/Dockerfile` is a non-root distroless variant for Kubernetes.

```sh
docker build -t langstroth-relay .
docker run -d -p 8443:8443 -v langstroth-data:/data \
  -e LANGSTROTH_RELAY_DATA_DIR=/data langstroth-relay
```

Release images: `ghcr.io/langstroth-ai/langstroth-relay:<version>` and
`ghcr.io/langstroth-ai/langstroth-auth:<version>` (linux/amd64, linux/arm64).

**Helm.** Charts are in `deploy/helm/` (`langstroth-relay`, `langstroth-auth`,
and the `langstroth-postgres` library) and are published per release at
`oci://ghcr.io/langstroth-ai/charts/<name>`. `database.mode` picks
`external`, `cnpg` (CloudNativePG) or `bundled` Postgres. Start with
[deploy/helm/langstroth-relay/README.md](deploy/helm/langstroth-relay/README.md)
and [Kubernetes](https://docs.langstroth.ai/operate/deploy/kubernetes/).

**Compose, systemd or a PaaS.** [docs/deploy.md](docs/deploy.md) has
one-shot sequences for Docker Compose (relay + Postgres, or the relay alone;
optional Caddy for TLS) in `deploy/compose/langstroth-relay/`, a hardened
systemd unit in `deploy/systemd/`, Helm, and any platform that runs a
container image (the binary honours `$PORT`, else `LANGSTROTH_RELAY_ADDR`,
else `0.0.0.0:8443`), plus settings, storage, TLS, backups and upgrades.

**With a coding agent.** [AGENTS.md](AGENTS.md) has the decision table
(local binary, `eval-memory`, `team-bundled`, `team-external`, `team-cnpg`,
`langstroth-auth`), the non-interactive scripts in `deploy/agent/`, and the
steps only a human can do.

The relay is single-replica by design: pairing codes, live-push fan-out and
rate limits live in the process.

## Configuration

Every setting is an environment variable named `LANGSTROTH_RELAY_*` (plus
`PORT` and `DATABASE_URL`). Any of them can also come from a file, `X_FILE`
or `$LANGSTROTH_RELAY_SECRETS_DIR/X`, so secrets can be mounted. The older
`HIVE_RELAY_*` and `LIGUS_RELAY_*` names are not read: the relay refuses to
start while one is set and names the variable to use instead (the Ligus
client's `LIGUS_RELAY_URL` is exempt).

The ones most deployments touch:

| Variable | Default | Meaning |
|---|---|---|
| `PORT` / `LANGSTROTH_RELAY_ADDR` | `0.0.0.0:8443` | bind address |
| `DATABASE_URL` | empty | shared Postgres store |
| `LANGSTROTH_RELAY_DATA_DIR` | empty | memory store with a JSON snapshot here |
| `LANGSTROTH_RELAY_REQUIRE_DB` | off | `1`: refuse to start without `DATABASE_URL` |
| `LANGSTROTH_RELAY_TOKEN_PUBKEY` | empty | require signed `hrt1` access tokens from this Ed25519 issuer |
| `LANGSTROTH_RELAY_ACCESS_TOKENS` | empty | static bearer-token allowlist |
| `LANGSTROTH_RELAY_WORKSPACE_SCOPE` | `off` | `claims` or `strict`: confine signed tokens to their workspaces |
| `LANGSTROTH_RELAY_TRUSTED_PROXIES` | empty | proxies whose forwarding header names the client |
| `LANGSTROTH_RELAY_TUNNEL` | `off` | phone tunnel: `off`, `open` or `allowlist` |
| `LANGSTROTH_RELAY_BLOBS` | `on` | encrypted attachments |
| `LANGSTROTH_RELAY_METRICS_TOKEN` | empty | bearer required on `/metrics` |

The relay is open by default (the URL is not a secret). Mint signed tokens
with `langstroth-relay keygen` and `langstroth-relay issue --key <priv-hex>
--sub <id> ...`, keeping the issuer key off the relay host; the relay only
verifies. The full list, with every limit and its default, is in
[docs/reference.md](docs/reference.md#configuration-env) and
[Environment variables](https://docs.langstroth.ai/operate/reference/env-vars/).

## Routes

All under `/v1`, JSON unless noted. Details: [docs/reference.md](docs/reference.md).

| Area | Routes |
|---|---|
| Sync | `POST`/`GET /v1/workspaces/{id}/envelopes` (paged with `?after=`), `GET .../events` (Server-Sent Events nudges), `.../keyring`, `.../presence`, `.../candidates` |
| Attachments | `POST /v1/workspaces/{id}/blobs`, `GET`/`DELETE .../blobs/{blob}`: opaque ciphertext, 25 MiB per blob by default, 30-day retention ([docs/blobs.md](docs/blobs.md)) |
| Membership | `.../members`, `.../members/claim`, `.../invites`, `.../join` (with `LANGSTROTH_RELAY_MEMBERSHIP=1`) |
| Pairing | `POST /v1/pair`, `GET /v1/pair/{code}`: single-use short codes |
| Contacts | `PUT`/`GET`/`DELETE /v1/contacts/{cid}`, `.../drop` |
| Phone tunnel | `/v1/tunnel/info`, `host`, `accept`, `connect` (WebSocket, Noise end to end), `revoke` |
| Tenancy | `GET /v1/tenant`, `GET /v1/tenant/rooms`, `DELETE /v1/tenant/rooms/{id}` |
| Operations | `GET /` (status page), `GET /v1/health`, `GET /metrics` |

The GitHub-keyed directory, account and friends routes are deprecated, off
by default since v0.3 (`LANGSTROTH_RELAY_GITHUB_ROUTES=on` for older
clients), and removed in v0.4.

## Refusals: 429 and 507

Every limit refuses rather than evicts. A rate limit answers `429`, a full
quota answers `507`; both carry `Retry-After` and a stable JSON code:

```json
{"error": "room_bytes", "message": "room storage quota reached", "retryAfter": 3600}
```

Clients switch on `error` (for example `ip_rate`, `room_rate`, `client_rooms`,
`room_bytes`, `tenant_bytes`, `blob_room_bytes`). A refused write stored
nothing, so retrying later is safe. Community limits (room bytes and envelope
counts, rooms per client, per-client and per-room rates, idle-room retention)
are all off by default. Table of codes:
[Refusals](docs/reference.md#refusals-429-and-507).

## Tenancy

Off by default. `LANGSTROTH_RELAY_TENANCY` (normally from
`LANGSTROTH_RELAY_TENANCY_FILE`) lets one relay serve several organisations
that don't trust each other. The tenant comes only from a verified signed
token; rooms, contacts, pairing codes and tunnel hosts are isolated per
tenant; each tenant gets its own quotas and rates (`507`/`429`) and its own
admin routes. It is logical isolation in one process, not HA, and the
operator still sees every tenant's metadata. See [docs/tenancy.md](docs/tenancy.md)
and [Multi-tenant](https://docs.langstroth.ai/operate/deploy/multi-tenant/).

## Sign-in with your identity provider

`langstroth-auth` (`cmd/langstroth-auth`, chart `deploy/helm/langstroth-auth`)
is an optional separate service: people sign in with an OIDC provider (Pocket
ID, Dex, Keycloak, ...) and get short-lived relay tokens; it supports SCIM for
provisioning. A token says which workspaces a person may reach; it never
grants workspace membership or holds a workspace key. Guides:
[langstroth-auth](https://docs.langstroth.ai/operate/deploy/ligus-auth/).
Examples: `deploy/compose/langstroth-auth-pocket-id`, `deploy/compose/langstroth-auth-dex`.

## Develop and test

```sh
go test -race ./...                           # unit, HTTP, snapshot, chart render tests (with helm)
TEST_DATABASE_URL=postgres://... go test ./... # also the Postgres integration tests
helm lint --strict deploy/helm/langstroth-relay
```

The relay package (`internal/relay`) exposes extension seams (`Store`,
`EntitlementVerifier`, `AdminAuthorizer`, `WriteGuard`, `Hooks`,
`TunnelPolicy`, `PushSender`) through `New(Options{...})` for another binary
under `cmd/` in this module; see `internal/relay/seams.go`. Repository layout:
[CONTRIBUTING.md](CONTRIBUTING.md#repository-layout). Release notes
and upgrade steps: [CHANGELOG.md](CHANGELOG.md).

## Documentation

- [Operating Langstroth](https://docs.langstroth.ai/operate/): deploy, networking, security
- [Self-host a relay](https://docs.langstroth.ai/operate/networking/self-host/)
- [Wire protocols](https://docs.langstroth.ai/operate/reference/wire-protocols/)
- [Threat model](https://docs.langstroth.ai/operate/security/threat-model/)
- [Using Ligus](https://docs.langstroth.ai/ligus/)
- This repo: [docs/deploy.md](docs/deploy.md), [docs/reference.md](docs/reference.md), [docs/blobs.md](docs/blobs.md), [docs/tenancy.md](docs/tenancy.md)

## Contributing

Questions, bugs and ideas: open an
[issue](https://github.com/langstroth-ai/langstroth-relay/issues) or a
[discussion](https://github.com/langstroth-ai/langstroth-relay/discussions).
See [CONTRIBUTING.md](CONTRIBUTING.md). The `/v1` API, `hrt1` tokens, header
names, the tunnel subprotocol and metric names are fixed wire identifiers:
keep them byte-compatible.

## Security

Please don't report vulnerabilities in public issues. See [SECURITY.md](SECURITY.md).

## Licence

MIT, see [LICENSE](LICENSE).
