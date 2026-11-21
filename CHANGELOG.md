# Changelog

## v0.3.2 (unreleased)

`/v1` and `hrt1` request and response formats are unchanged (byte-identical
to v0.3.1); only who roster mode authorizes changed.

### Fixed

- **Roster mode no longer refuses a Viewer's writes.** With
  `LANGSTROTH_RELAY_MEMBERSHIP=1`, a claimed room required Contributor to post
  envelopes, presence, candidates and blobs. Ligus Viewers legitimately write
  envelopes (their key-agreement key, read state, attachments), so on a
  claimed room a Viewer could never publish its key-agreement key and never
  received a key rotation. Any member, Viewer included, may now make those
  writes. Unchanged: key rotations (`POST .../keyring`) still need
  Contributor, roster and invite management still needs Admin, a blob delete
  still needs its uploader or an Admin, and a non-member is refused as before.

### Deploying

- **Provider-neutral deploy options.** `docs/deploy.md` is the deploy guide:
  one-shot sequences for Docker Compose, systemd, Helm and any platform that
  runs a container image, plus settings, storage, TLS, backups and upgrades.
  New `deploy/compose/langstroth-relay/` (relay + Postgres, or the relay
  alone with its snapshot store; optional Caddy for TLS; pinned to the
  release image, with an `.env.example`) and `deploy/systemd/` (a hardened
  unit and env file for the static binary). The Helm chart README now starts
  with an install from the OCI registry.

### Repository layout

- **The repository root holds only docs, `go.mod` and the `Dockerfile`.**
  The relay package moved to `internal/relay` (with its tests and
  `testdata`), `apns` and `langstrothauth` to `internal/`, the relay's
  subcommands to `cmd/langstroth-relay`, and `entrypoint.sh` to
  `deploy/container/`. Tests of the charts, agent scripts and workflows are
  the `deploy` package. No behaviour, route, response or token format
  changed (the golden `/v1` and contact tests are unchanged). The relay
  package can no longer be imported from outside this module.
- Removed `deploy/fly-rename-secrets.sh` and its test: a one-off script that
  renamed one Fly app's secrets for v0.3.0. Rename old `HIVE_RELAY_*` /
  `LIGUS_RELAY_*` settings by hand (the relay names each one at startup).

## v0.3.1

A fix release. `/v1` and `hrt1` are unchanged (byte-identical to v0.3.0).

### Fixed

- **A phone's failed pairing attempts no longer lock out its box.** The relay
  limits failed tunnel attempts per network (10 a minute, then a 5-minute
  block; IPv6 counts per /64). Box (host) connections and phone connections
  were counted together, so a phone retrying a used-up pairing link on the
  same home network could block the box's own control connection, and the
  box couldn't reconnect until the block lifted. Host endpoints
  (`/v1/tunnel/host` and `/v1/tunnel/accept`) now count their failures
  separately from phone endpoints, with the same limits.

### Changed

- Helm charts: `langstroth-relay` 0.3.1 and `langstroth-auth` 0.1.1 (app version 0.3.1).
- Package comments name the relay Langstroth and point at the ligus
  repository for the tunnel spec.

## v0.3.0

Additive for every existing `/v1` route and for `hrt1`: their requests and
responses are byte-identical to v0.2.0 (checked by golden responses recorded
against v0.2.0), and no crypto domain-separation string changed. The
behavior changes are that the deprecated GitHub social routes are off by
default, and that settings are read only under `LANGSTROTH_RELAY_*` names:
the relay refuses to start while a `HIVE_RELAY_*` or `LIGUS_RELAY_*`
variable is set, so rename them first ("Fly secrets" below for Fly).

### Renamed to Langstroth

The server side is now **Langstroth** (after the Langstroth frame hive); the
client apps stay **Ligus**. No wire format, token, crypto string, header,
route or database table changes.

- Go module `github.com/langstroth-ai/langstroth-relay` (was
  `github.com/ligus-ai/relay`); `cmd/langstroth-relay`, `cmd/langstroth-auth`;
  package `langstrothauth` (was `ligusauth`).
- Images `ghcr.io/langstroth-ai/langstroth-relay` and
  `ghcr.io/langstroth-ai/langstroth-auth`. The binaries are only
  `langstroth-relay` and `langstroth-auth`: `cmd/hive-relay` and the
  `ligus-relay`, `hive-relay` and `ligus-auth` aliases are gone. The root
  image's unprivileged user is `langstroth` (was `hive`) with the same UID/GID
  1000, so an existing snapshot volume keeps its owner.
- Charts `langstroth-relay`, `langstroth-auth` and the `langstroth-postgres`
  library, published from each release tag at
  `oci://ghcr.io/langstroth-ai/charts/<name>`. The auth chart's appVersion
  follows the repository (0.3.0). *Upgrade:* a release installed from the
  `ligus-relay` or `ligus-auth` chart upgrades with `--set
  nameOverride=ligus-relay` (or `ligus-auth`) to keep its resource names and
  selector labels; the charts now mount under `/etc/langstroth-relay` and
  `/etc/langstroth-auth`.
- Settings are `LANGSTROTH_RELAY_*` and `LANGSTROTH_AUTH_*` only. The
  `HIVE_RELAY_*`, `LIGUS_RELAY_*` and `LIGUS_AUTH_*` names are no longer
  read, and the relay (or `langstroth-auth`) **refuses to start** while a
  variable under one of them is set, or a file under one of them is in
  `LANGSTROTH_RELAY_SECRETS_DIR`; the error names each variable with its new
  name (never its value), so a forgotten secret can't silently turn push, the
  tunnel or the access gate off. The Ligus client's `LIGUS_RELAY_URL` is
  exempt (the relay never read it). The chart refuses `config.env` keys under
  the old names. *Upgrade:* rename every setting before deploying v0.3.0; on
  Fly see "Fly secrets" below.
- `langstroth-auth` reads `/etc/langstroth-auth/config.json`, or
  `/etc/ligus-auth/config.json` when only that exists (the image no longer
  passes `--config`), and the systemd credential
  `langstroth-auth-signing-key`, or `ligus-auth-signing-key`.
- The agent scripts read `LANGSTROTH_NAMESPACE`, `LANGSTROTH_RELEASE`,
  `LANGSTROTH_SCENARIO`, ... and still accept the `LIGUS_NAMESPACE`-style
  names (two different values are a usage error); `LIGUS_RELAY_*` and
  `LIGUS_AUTH_BIN` are a usage error. `local.sh` keeps using a
  `~/.local/state/ligus-relay` data directory and pid file from before the
  rename and renames its `secrets/LIGUS_RELAY_METRICS_TOKEN`;
  `bootstrap-secrets.sh` moves an existing Secret's
  `LIGUS_RELAY_METRICS_TOKEN` key to `LANGSTROTH_RELAY_METRICS_TOKEN`.
- The generic APNs alert (shown when the app's extension can't decrypt a
  push) is titled "Ligus" (was "Hive"). The payload's `hive` member keeps its
  name: it is a wire identifier the app reads.
- `langstroth-relay bootstrap-agent` prints `brew install langstroth-ai/ligus/ligus`.
- The Fly deploy runs only for a release tag `v*`, after `ci` passes on it,
  not on every push to main. Fly concurrency counts open connections
  (1500/2000), and the health check uses the current `http_service.checks`
  schema.
- The project's public relay is deployed with the community profile on
  (`.github/workflows/deploy.yml`): room quotas, 4 GiB of rooms, 2 GiB of
  attachments and 1 GiB of contacts in total, memory caps on requests and
  blob transfers in flight, 50 rooms per client and 100 000 in all, 180-day
  idle-room expiry, per-client and per-room request rates, and at most
  1200 event streams (below Fly's 2000-connection hard limit). Before, every
  one of these was off on it.

### Added

- **Blob channel** for end-to-end encrypted file attachments (additive; the
  existing routes are unchanged): `POST /v1/workspaces/{id}/blobs` (raw
  ciphertext body; the relay mints a random 43-character id and answers
  `201 {"id","size","sha256","expiresAt"}`), `GET …/blobs/{blob}` and
  `DELETE …/blobs/{blob}` (`204`; a blob uploaded with an identified token
  can be deleted only by that subject or, with relay membership, a
  workspace Admin: `403 blob_not_yours` otherwise). No listing route; ids can't be chosen or
  enumerated; an unknown, expired or other workspace's blob is `404`. Blobs
  never create a room. Limits: one blob `LANGSTROTH_RELAY_BLOB_MAX_BYTES`
  (25 MiB, `413`), per workspace `_BLOB_ROOM_MAX_BYTES` (512 MiB) and
  `_BLOB_ROOM_MAX_COUNT` (2000), per uploader per workspace
  `_BLOB_WRITER_MAX_BYTES` / `_COUNT`, relay-wide `_BLOB_TOTAL_MAX_BYTES`,
  per-tenant `blob_max_bytes` / `blob_max_count` and per-workspace overrides
  in the tenancy config (`507 blob_*`), upload rate `_BLOB_RATE` / `_BURST`
  (1/s, burst 20, `429 blob_rate`), uploads in flight `_BLOB_MAX_INFLIGHT`
  (16) and `_BLOB_WRITER_INFLIGHT` (4 per uploader, `429 blob_inflight`),
  download rates per blob `_BLOB_DOWNLOAD_RATE` / `_BURST` (0.5/s, burst
  100) and per downloader `_BLOB_CLIENT_DOWNLOAD_RATE` / `_BURST` (2/s,
  burst 60, `429 blob_download_rate`),
  retention `_BLOB_RETENTION_DAYS` (30). An upload idle for 15 s, or
  averaging under 8 KiB/s after 15 s, is cut off (`408 blob_too_slow`).
  Quotas are checked atomically with the insert on both stores. Room purges,
  idle-room retention and (with relay membership) a member's removal delete
  the blobs with them. Postgres gets `relay_blobs` and `relay_blob_usage`
  (migrated under the advisory lock); the memory store counts blobs toward
  `LANGSTROTH_RELAY_MAX_STORE_BYTES` and keeps their bytes in files under
  `<data dir>/blobs/` (the JSON snapshot holds only their metadata).
  `LANGSTROTH_RELAY_BLOBS=off` turns the routes off. Chart: `blobs.*`, and
  the ingress-nginx body limit follows `blobs.maxBytes`. Operator guide:
  [docs/blobs.md](docs/blobs.md).
- **Community limits** (all off by default): per-room byte and envelope
  quotas (`LANGSTROTH_RELAY_ROOM_MAX_BYTES`, `_ROOM_MAX_ENVELOPES`), a total
  room-byte cap on both stores (`_MAX_TOTAL_ROOM_BYTES`), rooms per client
  (`_MAX_ROOMS_PER_CLIENT`), rooms across the relay (`_MAX_ROOMS`, the bound
  that holds when clients rotate addresses), per-client and per-room request rates
  (`_IP_RATE`/`_BURST`, `_ROOM_RATE`/`_BURST`) and configurable tunnel push
  limits (`_TUNNEL_PUSH_RATE`/`_BURST`/`_PER_DAY`, defaults unchanged).
  Storage quotas answer `507` and never evict; rates answer `429`. Every
  `429` and `507` (all routes) carries `Retry-After` and a JSON body
  `{"error","message","retryAfter"}` with a stable code (README, "Refusals:
  429 and 507"); before, most were free text with no `Retry-After`. New
  metrics `hive_relay_limit_rejections_total{limit}`,
  `hive_relay_rooms`, `hive_relay_room_bytes`. `deploy/fly.toml` documents a
  community profile (commented out). Helm: `limits.*`.
- **Idle-room retention**, `LANGSTROTH_RELAY_ROOM_RETENTION_DAYS` (off by
  default): deletes a whole room nobody has appended to for N days, keeping
  its sequence counter and roster. A room in use keeps its whole log: Ligus
  clients rebuild a workspace from its first envelope.
- **Tenancy** (`LANGSTROTH_RELAY_TENANCY`, normally `_TENANCY_FILE`; off by
  default): several organisations on one relay process. The tenant comes
  only from a verified token (`tid` plus that tenant's issuer key or the
  shared key); rooms and contacts are stored per tenant, pairing codes are
  per tenant, tunnel hosts are bound to their registration tenant;
  per-tenant quotas, rates, pairing, host and push limits; `/v1/tenant`
  admin routes (new, only with tenancy); tenant metrics with a label cap
  (`LANGSTROTH_RELAY_METRICS_MAX_TENANTS`); tenancy requires
  `LANGSTROTH_RELAY_METRICS_TOKEN`. See `docs/tenancy.md`. Helm:
  `tenancy.existingSecret` (mounted as a file). Without tenancy every `/v1`
  route is byte-identical.
- Postgres: `relay_rooms` and `relay_tenant_usage` (with a one-time backfill
  from existing envelopes and key rotations, recorded in
  `relay_migrations`) and `relay_tunnel_hosts.tenant`, added in place by the
  advisory-locked migration.

- **Phone revocation over HTTPS.** `POST /v1/tunnel/revoke` (new, additive):
  a host revokes one of its phones with a request signed by its registered
  host key, without needing its control connection, and learns what was done
  (`sessionsClosed`, `pushTokenRemoved`). Timestamped within ±300 s and
  single-use per nonce (a replay answers `409`; each host may hold an eighth
  of the nonce cache); a forged or cross-host request answers `401`; a
  validly signed request with a skewed `ts` answers `401
  {"error":"clock_skew","now"}` and isn't counted as a failed
  authentication. A revocation that races a phone's session admission
  leaves neither the session nor its push token. It adds one signing label, `hive-tunnel/1
  host-revoke`; no existing label changes. The control connection's `revoke`
  is unchanged.
- **langstroth-auth: end one device's session.** `POST
  /admin/v1/tenants/{t}/devices/{device}/revoke` (admin listener) revokes
  every refresh token bound to that device id and leaves the person's other
  devices signed in. Idempotent. Access tokens already minted stay valid
  until they expire (at most an hour). A tenant may set `device_revoke_token_file` (0600)
  or `device_revoke_token_sha256`: that token opens this route for that
  tenant only (no other admin route, no other tenant), so a serve box never
  holds the operator token. No env var form.
- **Push to more than one app build.** `LANGSTROTH_RELAY_APNS_TOPICS` (comma
  list) allow-lists more bundle ids next to `LANGSTROTH_RELAY_APNS_TOPIC` (which
  keeps working alone). The phone may report its bundle id with its token
  (`apns.topic`, optional); the relay pushes with it when allowed and refuses
  otherwise, keeping the token. A phone that reports none gets the default
  topic, and `DeviceTokenNotForTopic` for it no longer drops its token.
  Postgres gains `relay_tunnel_push_tokens.topic` (added in place).
- **Push results are logged.** Every host push is logged at info as `tunnel
  push` with its result and, for APNs, env, topic, status, reason and apns-id
  (never the device token). A host push may set `"diag": true` to get the same
  as `"detail"` in its ack; acks without it are byte-identical.

- **Contacts, `/v1/contacts/*`.** An opaque, client-signed contact record per
  random contact id (16 bytes, base64url), owned by a 32-byte write-key
  capability whose SHA-256 the relay stores, plus a sealed, append-only drop
  box per contact that only the key holder reads or empties. The relay does no
  cryptography on either. Size caps (64 KiB record and drop), a 30-day record
  TTL refreshed on every write, per-box row (5000) and byte (4 MiB) caps
  (eviction takes drops already served to the owner first, then the heaviest
  sender's unread drops, so a flood evicts itself and not a pending invite),
  30-day drop retention, and rate limits per sender and
  box, per box, per record and per client. Stored in the memory store, its
  snapshot and Postgres (`relay_contacts`, `relay_contact_drop`). Requests that
  carry a forge token are refused. Settings: `LANGSTROTH_RELAY_CONTACTS`,
  `LANGSTROTH_RELAY_CONTACT_*`, `LANGSTROTH_RELAY_MAX_CONTACTS`; see README "Contacts".
  - An expired cid stays reserved for its old write key for 180 days
    (`LANGSTROTH_RELAY_CONTACT_RECLAIM_HOLD_DAYS`), so nobody who learned the cid
    can claim it while its owner is offline.
  - Drop-box seqs never restart for a cid: a box created again starts after
    its creation second times 2^20, so every device's cursor and ack stay
    correct.
  - Records and drops must be valid UTF-8 (`400` otherwise), so they come back
    byte for byte from every store, across restarts.
  - New records are also limited per IPv6 /48 (16x the per-client limit).
- `ContactStore`, an optional store interface (like `TunnelStore`): a
  downstream `Store` without it keeps compiling and serves `404` on contacts.
- `/v1/contacts/` joins the reserved extension prefixes.
- Helm chart: `contacts.*` and `githubRoutes` values.
- **Helm charts: one database choice, `database.mode`** (ligus-relay and
  ligus-auth, from a shared `deploy/helm/ligus-postgres` library chart):
  `external` (a Postgres you run; DSN Secret, egress `cidrs`), `cnpg` (a
  CloudNativePG `Cluster` in the release namespace: TLS `verify-full` against
  the operator's CA, 1 or 3+ instances, WAL archiving and scheduled backups
  to object storage, optional PodMonitor; needs the operator) and `bundled`
  (one hardened Postgres 16 pod: digest-pinned, Pod Security `restricted`,
  `ReadWriteOncePod`, TLS required from a Secret or cert-manager, a
  non-superuser role with `scram-sha-256`, a `pg_dump` CronJob with
  retention and a values-driven restore). For `cnpg` and `bundled` the DSN
  carries no password: pgx reads a mounted `pgpass` file and CA. Backups can
  only be turned off with `acknowledgeNoBackups`. The egress NetworkPolicy
  allows only the chosen database. See the chart README, "Database".

### Deprecated, and off by default

- **GitHub social routes** (`/v1/directory/*`, `/v1/account/*`,
  `/v1/friends/*`). They need the relay to see users' GitHub tokens, and
  Ligus 2.0 replaces them with contacts, invite links and QR codes. They are
  now registered only with `LANGSTROTH_RELAY_GITHUB_ROUTES=on` (or
  `LANGSTROTH_RELAY_GITHUB_SOCIAL=1`); otherwise they
  answer `404`. When on, responses carry `Deprecation` and `Link:
  rel="deprecation"` headers. **They are removed in v0.4**, together with the
  `relay_directory*`, `relay_account*`, `relay_login_index`, `relay_inbox` and
  `relay_friend*` tables and the GitHub verifier.
  *Upgrade:* a relay serving older clients that use
  invite-by-handle, friends or the account inbox must set
  `LANGSTROTH_RELAY_GITHUB_ROUTES=on` until those clients are gone.

- **Helm: `postgres.enabled`, `externalDatabase.*` (ligus-relay) and
  `store.databaseUrl` (ligus-auth)** are deprecated aliases for
  `database.mode` (`bundled` in its old development form, `external`). They
  render exactly as before when `database.mode` is empty, with a note at
  install; the README has the move from `postgres.enabled` to a real mode.

### Removed

- **Per-envelope eviction**: `LANGSTROTH_RELAY_MAX_ENVELOPES` (a rolling
  window per room, on by default at 50 000) and
  `LANGSTROTH_RELAY_RETENTION_DAYS`. Both dropped a room's oldest envelopes,
  including the founder's seed, which permanently broke every device that
  joined the room afterwards (clients fold from seq 1 and never backfill).
  The memory store no longer trims on write and Postgres no longer prunes
  hourly; a relay that relied on the default stops evicting when it runs
  this release. The relay refuses to start while either is set to anything
  but `0`. Use the room quotas and `LANGSTROTH_RELAY_ROOM_RETENTION_DAYS`.
- **The downstream build hooks** `MainWith`, `Extension`, `Addon` and
  `Assemble`, and the `Options.TunnelBilling` override. The relay binary is
  `Main()`; a custom build still composes `New(Options{...})` with the seams
  (`TunnelPolicy`, `PushSender`, `EntitlementVerifier`, `WriteGuard`, `Hooks`).
  `GET /v1/tunnel/info` keeps its `billing` field, now always `"none"`, so
  clients that read it see the same bytes as before.

### Also in this release

- **ligus-auth** (`cmd/ligus-auth`): optional OIDC sign-in service that mints
  short-lived `hrt1` relay tokens, with SCIM 2.0 deprovisioning, per-tenant
  IdPs and workspace grants, device-bound rotating refresh tokens, a distroless
  image (`deploy/container/Dockerfile.ligus-auth`), a Helm chart
  (`deploy/helm/ligus-auth`) and compose examples for Pocket ID and Dex. It
  gates relay access only; workspace membership stays in the signed roster.
- **Token claims `tid`, `uid`, `did`** (all optional and omitted when empty):
  tokens minted without them are byte-identical to before.
- **`LANGSTROTH_RELAY_TENANTS`** (off by default): confine signed tokens to the
  listed `tid` values.
- **`LANGSTROTH_RELAY_TOKEN_PUBKEY_NEXT`** (off by default): accept a second issuer
  key during a key rotation.
- **`LANGSTROTH_RELAY_MAX_CONTACT_BYTES`** (Postgres; off by default, the
  community profile sets 1 GiB): contact records plus drops across the
  relay, `507` `contacts_full` past it. On Postgres nothing bounded them but
  the disk, and at the per-client create rate one IPv4 address could add a
  few GB of drop boxes a day.
- **`LANGSTROTH_RELAY_MAX_INFLIGHT_PER_CLIENT`** (off by default; the
  community profile sets 32): ordinary requests one client may hold open at
  once, `429` `client_inflight` past it, so one address can't pin hundreds
  of multi-MiB bodies or response pages in memory.
- **Blob downloads in flight** (`LANGSTROTH_RELAY_BLOB_DOWNLOAD_INFLIGHT`,
  default 8, and `_CLIENT_DOWNLOAD_INFLIGHT`, default 2; `429
  blob_inflight`), and downloads are paced like uploads (a reader that
  stalls for 15 s or averages under 8 KiB/s is cut off). A download holds
  its whole blob (up to 25 MiB) in memory, and nothing bounded how many ran
  at once or how long a client that stopped reading kept one.
- **Pairing codes per client** (`LANGSTROTH_RELAY_MAX_PAIRINGS_PER_CLIENT`,
  default 20; each IPv6 /48 gets 16x in total) and **live pairing bytes**
  (`LANGSTROTH_RELAY_MAX_PAIRING_BYTES`, default 32 MiB): one address could
  hold every one of the 50 000 live codes, answering `503` to everyone
  else's pairing, and 50 000 payloads of 8 KiB would hold 400 MB of memory.
  Past the per-client cap: `429` `pair_codes` with `Retry-After`.
- `langstroth-relay issue --tenant <id>` sets `tid`.
- Exported `IssueToken`, `VerifyToken`, `ParsePubkey` and `ParseSigningKey`.

### Fly secrets (do this before deploying v0.3.0)

v0.3.0 refuses to start while any `HIVE_RELAY_*` or `LIGUS_RELAY_*` secret is
set, and the deploy workflow refuses to deploy while the app holds one. Rename
them first, staged, so the running v0.2 relay is not restarted and the
renamed secrets go live with the v0.3.0 deploy itself. No step prints a value.

1. See what will change (names only; changes nothing):

   ```sh
   fly secrets list --app <app>                    # names and digests
   deploy/fly-rename-secrets.sh <app>              # the plan
   ```

   Each `HIVE_RELAY_<X>` / `LIGUS_RELAY_<X>` becomes `LANGSTROTH_RELAY_<X>`.
   When both old names are set, the `LIGUS_RELAY_` value (the one the v0.2
   relay uses) is kept. `HIVE_RELAY_ADMIN_LOGINS` is dropped: the open relay
   never read it (only the old Rust relay and the enterprise build did).
   `HIVE_RELAY_MAX_ENVELOPES` and `HIVE_RELAY_RETENTION_DAYS` are dropped
   too: per-envelope eviction is removed, and v0.3.0 refuses to start while
   either is set to anything but `0`. `DATABASE_URL` is unchanged.

2. Stage the renames:

   ```sh
   fly ssh issue --agent                           # once, if fly ssh isn't set up
   deploy/fly-rename-secrets.sh <app> --apply
   ```

   The script reads each value from the running machine with
   `fly ssh console -C 'printenv NAME'` into a mode-0600 temp file, stages it
   with `fly secrets import --stage` from that file, checks that the new
   name's digest in `fly secrets list` equals the old one's, and only then
   stages `fly secrets unset` of the old names. If a digest differs it stops
   with the old names in place.

   By hand instead (when you hold the values, e.g. the `.p8` file), stage
   each one from a file, never echoing it:

   ```sh
   fly secrets import --app <app> --stage < renamed.env   # NAME=value lines; a PEM as NAME="""…"""
   fly secrets list --app <app>                           # digests: new == old
   fly secrets unset --app <app> --stage HIVE_RELAY_… LIGUS_RELAY_…
   ```

3. Check `fly secrets list --app <app>` shows no `HIVE_RELAY_*` or
   `LIGUS_RELAY_*` name, then deploy v0.3.0 (push the tag; the workflow sets
   `LANGSTROTH_RELAY_REQUIRE_DB=1`, was `HIVE_RELAY_REQUIRE_DB=1`; by hand:
   `fly deploy --app <app> --config deploy/fly.toml --env
   LANGSTROTH_RELAY_REQUIRE_DB=1`).

4. After the deploy: `/v1/health` answers 200, `fly logs` shows the tunnel
   and `tunnel push via APNs` lines, and `fly config show --app <app>` lists
   no `HIVE_RELAY_*` env. A refused start logs
   `HIVE_RELAY_* and LIGUS_RELAY_* names are no longer read: rename ...`
   naming each leftover.

## v0.2.0

The relay is now Ligus Relay. Ligus (LEE-gus) is short for *ligustica*, the
Italian honeybee. The `/v1` API, `hrt1` tokens, `X-Hive-*`
headers, the `hive-tunnel.1` subprotocol and the `hive_relay_*` metric names are
unchanged: existing clients keep working against this relay, except where the
security changes below say otherwise.

### Renamed

- **Module path** is `github.com/ligus-ai/relay`. `github.com/honeyhive-ai/relay`
  (v0.1.x) is deprecated; update imports and `go.mod`.
- **Binary** is `ligus-relay` (`cmd/ligus-relay`). `cmd/hive-relay` still
  builds, and the repository-root (Alpine) image keeps a `hive-relay` symlink,
  until Ligus v3.0. The distroless image (`deploy/container/Dockerfile`) ships
  only `ligus-relay`.
- **Settings** are named `LIGUS_RELAY_*`. Every `HIVE_RELAY_*` name still
  works: if both are set the new name wins, and the relay logs a one-time
  warning per legacy name in use.

### Security changes that affect clients

- **GitHub-backed routes no longer read the `Authorization` bearer.** The
  directory, account and friends routes used to fall back to the bearer when
  no GitHub token header was sent, and verified it against `api.github.com`,
  so a relay access token could reach GitHub. Only `X-Hive-Github-Token` (or
  the new `X-Ligus-Github-Token`) is used now; a request with only a bearer
  gets `401`. Ligus 2.0 clients already send `X-Hive-Github-Token`.
  *Residual:* the relay operator can still see the GitHub tokens sent to these
  routes; a client change to stop sending the raw token is pending.
- **Pairing payloads are restricted.** `POST /v1/pair` takes only a peer
  friend code (`hive_` + base64url of 32 bytes, or `hivepeer1:` + 64 hex) or a
  sealed payload (`sealed1:` + base64url, at least 32 bytes). `hivews1:` and
  `ligusws1:` workspace invites, which carry the workspace key in cleartext,
  and anything else get `422`. Ligus 2.0 clients publish only friend codes
  here and already refuse to broker workspace invites; older clients that
  published `hivews1:` codes through the relay can no longer do so.
- **Pairing codes are single-use.** The first successful resolve consumes the
  code; a second resolve gets `404`. The TTL (default 600 s, 30–3600 s) is
  unchanged.
- **Keyring rotations past the caps are refused, not evicted.** Both stores
  used to keep only the newest rotations past the per-workspace cap (and
  Postgres pruned the same way hourly), so junk rotations could push a
  workspace's real rotations out. Past `LIGUS_RELAY_MAX_KEYRING_PER_WS`
  (2000) rotations or `LIGUS_RELAY_MAX_KEYRING_BYTES_PER_WS` (16 MiB) a new
  rotation gets `507` and the keyring is unchanged. A single rotation over
  `LIGUS_RELAY_MAX_ROTATION_BYTES` (256 KiB) gets `413`. The wire format is
  unchanged.
- **Workspace reads are rate limited per client** (`LIGUS_RELAY_READ_RATE`
  100/s, `LIGUS_RELAY_READ_BURST` 400; `429` past it), and **SSE streams are
  capped per client** (`LIGUS_RELAY_MAX_SSE_PER_CLIENT`, 100; `429`).
- **Idempotency keys are scoped to the writer.** A client-chosen
  `Idempotency-Key` or `X-Hive-Event-Id` is stored as a hash of (writer, key),
  so one writer can't claim another's key and turn that writer's push into a
  silent duplicate. Body-hash dedup (no header) is unchanged. Ligus 2.0 clients
  send neither header.

### Other security fixes

- Admin request bodies are capped at 16 KiB, and admin and friend handlers log
  store errors instead of returning them. The membership claim body is bounded.
- Rate limits and abuse blocks key IPv6 clients on their /64. A client-supplied
  `Fly-Client-IP` is ignored off Fly.io; `LIGUS_RELAY_TRUSTED_PROXIES` and
  `LIGUS_RELAY_CLIENT_IP_HEADER` name the proxies whose forwarding header is
  trusted.
- Membership roles can't be raised above the caller's own or used against
  higher ranks, and a claimed workspace's roster is readable by its members
  only.
- Opt-in per-workspace token scope from a signed `workspaces` claim
  (`LIGUS_RELAY_WORKSPACE_SCOPE`).
- Optional heap budget for the memory store (`LIGUS_RELAY_MAX_STORE_BYTES`),
  charged with each workspace's overhead.
- Bounded workspace and device id lengths, stored idempotency keys, and
  keyring, candidate and presence list responses (`LIGUS_RELAY_MAX_LIST_BYTES`).
- The memory-store snapshot is written owner-only.
- A malformed `LIGUS_RELAY_TOKEN_PUBKEY` fails closed (denies every token).
- Pairing-code sweeps run at most once a second, and the per-client resolve
  block is checked first.

### Added since v0.1.0

- Relay tunnel (`hive-tunnel/1`) for phone ↔ home host remote access, off by
  default, with an optional built-in APNs push sender.
- `MainWith` / `Assemble` extension point, so a downstream binary is a strict
  superset of the open relay; `Server.RefreshTunnelStatus`.
- Relay-managed team membership (roster, claim, invites, join) behind
  `LIGUS_RELAY_MEMBERSHIP`, with a membership identity key
  (`LIGUS_RELAY_MEMBERSHIP_PUBKEY`) independent of the access gate.
- `ligus-relay bootstrap-agent` to stand up a remote agent with one line.
- Durable users and tokens with an admin API (disabled unless a downstream
  build supplies an `AdminAuthorizer`), and a public status page at `/`.
- Bounded envelope pages (`X-Hive-Next-After` / `X-Hive-More`).
- SSE push (`GET /v1/workspaces/{id}/events`), idempotent envelope push,
  structured request logs and `/metrics`.
- Workspace reads require the same access token as writes.
- Postgres: retention, pooler-safe statements, primary pinning, text-bound
  blobs.
- Helm chart (`deploy/helm/ligus-relay`, chart version 0.2.0) and a non-root
  distroless image. Defaults: tunnel off; liveness doesn't depend on the
  database; the APNs key reaches only the tunnel pod, from a Secret of its own
  (the chart refuses `config.existingSecret` for it and `*_RELAY_APNS_*` keys
  in `config.env`); DNS egress only to the cluster resolver
  (`networkPolicy.dns.*`, default `kube-system` pods labeled
  `k8s-app: kube-dns`).

### New settings

All are also read under their `HIVE_RELAY_*` names. See the README's
configuration tables for every setting.

| Setting | Default |
|---|---|
| `LIGUS_RELAY_READ_RATE` / `LIGUS_RELAY_READ_BURST` | `100` / `400` |
| `LIGUS_RELAY_MAX_SSE_PER_CLIENT` | `100` |
| `LIGUS_RELAY_MAX_KEYRING_BYTES_PER_WS` | `16777216` |
| `LIGUS_RELAY_MAX_ROTATION_BYTES` | `262144` |
| `LIGUS_RELAY_MAX_KEYRING_PER_WS` | `2000` (now refuses instead of evicting) |
| `LIGUS_RELAY_MAX_LIST_BYTES` | `16777216` |
| `LIGUS_RELAY_MAX_STORE_BYTES` | `0` (unbounded) |
| `LIGUS_RELAY_MAX_BODY_BYTES` | `4194304` |
| `LIGUS_RELAY_MAX_ENVELOPES` / `LIGUS_RELAY_RETENTION_DAYS` | `50000` / `0` |
| `LIGUS_RELAY_MAX_DEVICE_BLOBS_PER_WS` | `1000` |
| `LIGUS_RELAY_MAX_PAIRINGS` | `50000` |
| `LIGUS_RELAY_MAX_SSE` | `2000` |
| `LIGUS_RELAY_PUSH_RATE` / `_BURST` | `100` / `300` |
| `LIGUS_RELAY_WS_WRITER_RATE` / `_BURST` | `20` / `200` |
| `LIGUS_RELAY_GITHUB_RATE` / `_BURST` | `30` / `120` |
| `LIGUS_RELAY_INVITE_RATE` / `_BURST` | `0.05` / `10` |
| `LIGUS_RELAY_INVITE_REQUIRE_FRIEND` | off |
| `LIGUS_RELAY_INBOX_MAX_ROWS` | `5000` |
| `LIGUS_RELAY_INBOX_RETENTION_DAYS` / `LIGUS_RELAY_FRIEND_REQ_RETENTION_DAYS` | `30` / `30` |
| `LIGUS_RELAY_TRUSTED_PROXIES` / `LIGUS_RELAY_CLIENT_IP_HEADER` | empty / `X-Forwarded-For` |
| `LIGUS_RELAY_WORKSPACE_SCOPE` | `off` |
| `LIGUS_RELAY_MEMBERSHIP` / `LIGUS_RELAY_MEMBERSHIP_PUBKEY` | off / empty |
| `LIGUS_RELAY_METRICS_TOKEN` | empty (open) |
| `LIGUS_RELAY_REQUIRE_DB` | off |
| `LIGUS_RELAY_TUNNEL` / `LIGUS_RELAY_TUNNEL_HOSTS` | `off` / empty |
| `LIGUS_RELAY_APNS_KEY_FILE`, `_KEY`, `_KEY_ID`, `_TEAM_ID`, `_TOPIC`, `_ENV` | empty, `ENV` = `auto` |

### Upgrade notes for self-hosters

1. **Names.** Nothing breaks if you keep `HIVE_RELAY_*`, the `hive-relay`
   binary name or the old module path for now, but rename them: the relay logs
   a warning per legacy setting, and the aliases go away in Ligus v3.0. If you
   build from source, change imports to `github.com/ligus-ai/relay`.
2. **Behind a reverse proxy or ingress, set `LIGUS_RELAY_TRUSTED_PROXIES`.**
   Without it every client shares the proxy's address, and so shares one
   bucket for the new read limit (100/s) and one SSE allowance (100 streams),
   as well as the existing write limits. Raise `LIGUS_RELAY_READ_RATE` and
   `LIGUS_RELAY_MAX_SSE_PER_CLIENT` if you can't.
3. **Pairing.** Codes created before the upgrade live in memory and are gone
   after the restart anyway. Clients that shared workspaces through
   short codes must share the `hivews1:` invite directly (Ligus 2.0 already
   does).
4. **Keyring.** A workspace already over 2000 rotations or 16 MiB keeps what it
   has, but new rotations get `507` until you raise
   `LIGUS_RELAY_MAX_KEYRING_PER_WS` / `LIGUS_RELAY_MAX_KEYRING_BYTES_PER_WS`.
   Postgres no longer prunes the keyring hourly. If you raise the byte cap,
   raise `LIGUS_RELAY_MAX_LIST_BYTES` to match.
5. **Idempotency keys.** Stored keys change form, so a re-push with a header
   of an envelope pushed before the upgrade is appended once more. Clients
   dedupe events by id, so this is harmless.
6. **GitHub routes.** A client that sent its GitHub token only as the
   `Authorization` bearer must send `X-Hive-Github-Token` instead.
7. **Helm.** If your APNs key was in `config.existingSecret` or in
   `config.env`, move it to a Secret of its own and set
   `tunnel.apns.existingSecret`. If your cluster's resolver pods aren't
   labeled `k8s-app: kube-dns` in `kube-system`, set
   `networkPolicy.dns.namespaceSelector` / `podSelector`, or DNS stops
   resolving with `networkPolicy.restrictEgress` on.

## v0.1.0

First release of the Go relay at `github.com/honeyhive-ai/relay`, at parity
with the Rust reference relay's `/v1` API and `hrt1` tokens.
