# Relay reference

Configuration, storage, limits and every route of `langstroth-relay`, in detail.
Start with the [README](../README.md) for what the relay is and how to deploy it.

## Configuration (env)

Settings are read only under their `LANGSTROTH_RELAY_*` names. The relay
refuses to start while any `HIVE_RELAY_*` or `LIGUS_RELAY_*` variable is set
(except the Ligus client's `LIGUS_RELAY_URL`, which the relay never read): the
error names each one with its `LANGSTROTH_RELAY_*` name, never its value.
Rates are tokens per
second per client; a client is the TCP peer, or the address a trusted proxy
names (`LANGSTROTH_RELAY_TRUSTED_PROXIES`), with IPv6 keyed on its /64.

**Core and access**

| Var | Default | Meaning |
|---|---|---|
| `PORT` / `LANGSTROTH_RELAY_ADDR` | `0.0.0.0:8443` | bind address (`$PORT` wins) |
| `DATABASE_URL` | empty | shared **Postgres** store → horizontal scaling / HA (no data migration) |
| `LANGSTROTH_RELAY_DATA_DIR` | empty | in-memory store + JSON snapshot here (single instance). Ignored if `DATABASE_URL` is set |
| `LANGSTROTH_RELAY_REQUIRE_DB` | off | `1`: refuse to start without `DATABASE_URL` instead of falling back to memory |
| `LANGSTROTH_RELAY_TOKEN_PUBKEY` | empty | Ed25519 public key → require **signed** access tokens. A key that doesn't parse denies every token |
| `LANGSTROTH_RELAY_ACCESS_TOKENS` | empty | comma-separated static allowlist (coarse gate) |
| `LANGSTROTH_RELAY_WORKSPACE_SCOPE` | `off` | `off`, `claims` or `strict`: confine signed tokens to the workspace ids in their `workspaces` claim. See [Optional access gating](#optional-access-gating) |
| `LANGSTROTH_RELAY_TOKEN_PUBKEY_NEXT` | empty | A second issuer public key accepted next to `LANGSTROTH_RELAY_TOKEN_PUBKEY` while the issuer rotates its key. Needs `LANGSTROTH_RELAY_TOKEN_PUBKEY`; a key that doesn't parse denies every token |
| `LANGSTROTH_RELAY_TENANTS` | unset | Comma-separated tenant ids. When set, a signed token must carry a `tid` claim in this list (tokens without one get `401`). Needs `LANGSTROTH_RELAY_TOKEN_PUBKEY` and `LANGSTROTH_RELAY_WORKSPACE_SCOPE=strict` (the relay refuses to start otherwise, because `tid` alone does not keep one tenant out of another's workspaces). See [Sign-in with your identity provider](#sign-in-with-your-identity-provider-langstroth-auth) |
| `LANGSTROTH_RELAY_MEMBERSHIP` | off | `1`: relay-managed team membership (roster, claim, invites, join) |
| `LANGSTROTH_RELAY_MEMBERSHIP_PUBKEY` | empty | Ed25519 key whose signed tokens identify callers for membership on an otherwise open relay |
| `LANGSTROTH_RELAY_METRICS_TOKEN` | empty | bearer required on `/metrics` (empty = open) |
| `LANGSTROTH_RELAY_CONTACTS` | on | `off`: unregister `/v1/contacts/*` (404, as on a v0.2 relay). See [Contacts](#contacts-v1contacts) |
| `LANGSTROTH_RELAY_GITHUB_ROUTES` | off | **Deprecated, removed in v0.4.** `on`: register the GitHub social routes (directory, account, friends) for older clients; every response then carries a `Deprecation` header. `LANGSTROTH_RELAY_GITHUB_SOCIAL=1` is accepted too. See [GitHub social routes](#github-social-routes-deprecated-off-by-default) |
| `LANGSTROTH_RELAY_FRIEND_CAP` | none | max accepted friends per account (GitHub routes only) |
| `LANGSTROTH_RELAY_INVITE_REQUIRE_FRIEND` | off | `1`: `POST /v1/account/invites` only reaches existing friends (GitHub routes only) |
| `LANGSTROTH_RELAY_TRUSTED_PROXIES` | empty | comma-separated CIDRs/IPs of reverse proxies whose forwarding header names the client (empty = use the TCP peer, ignore every forwarding header). Set it behind an ingress or load balancer, or every client shares one rate-limit bucket. Some platforms' edges are recognized when it is unset; see [Running on a PaaS](deploy.md#running-on-a-paas) |
| `LANGSTROTH_RELAY_CLIENT_IP_HEADER` | `X-Forwarded-For` | header read from a trusted proxy (walked right to left past trusted hops), or a single-address header such as `X-Real-IP` |

**Storage, retention and size bounds**

| Var | Default | Meaning |
|---|---|---|
| `LANGSTROTH_RELAY_MAX_ENVELOPES` | removed | **Removed.** Evicting a room's oldest envelopes dropped its seed and broke every device that joined later. The relay refuses to start while it is set to anything but `0`; use `LANGSTROTH_RELAY_ROOM_MAX_ENVELOPES` (refuses with `507`) |
| `LANGSTROTH_RELAY_RETENTION_DAYS` | removed | **Removed**, for the same reason; refused unless `0`. Use `LANGSTROTH_RELAY_ROOM_RETENTION_DAYS` (whole idle rooms) |
| `LANGSTROTH_RELAY_MAX_STORE_BYTES` | `0` (unbounded) | memory store: cap on workspace bytes held across all workspaces (envelope bodies, keyring rows, candidate and presence blobs, per-workspace overhead). Writes past it answer `507`. Set it below your memory limit on any relay reachable by untrusted clients |
| `LANGSTROTH_RELAY_MAX_BODY_BYTES` | `4194304` (4 MiB) | max JSON request-body size |
| `LANGSTROTH_RELAY_MAX_LIST_BYTES` | `16777216` (16 MiB) | bound on one `GET …/keyring`, `…/candidates` or `…/presence` response, by stored blob bytes (`0` = unbounded). At least one row is always returned |
| `LANGSTROTH_RELAY_MAX_KEYRING_PER_WS` | `2000` | key rotations stored per workspace. Past it a new rotation gets `507`; stored rotations are never evicted |
| `LANGSTROTH_RELAY_MAX_KEYRING_BYTES_PER_WS` | `16777216` (16 MiB) | stored keyring bytes per workspace; `507` past it. Keep it at or below `LANGSTROTH_RELAY_MAX_LIST_BYTES` so `GET …/keyring` always returns the whole keyring |
| `LANGSTROTH_RELAY_MAX_ROTATION_BYTES` | `262144` (256 KiB) | one key rotation's size; `413` past it (`0` = only the body cap) |
| `LANGSTROTH_RELAY_MAX_DEVICE_BLOBS_PER_WS` | `1000` | candidate and presence device entries per workspace |
| `LANGSTROTH_RELAY_MAX_PAIRINGS` | `50000` | live pairing codes per instance (`503` past it) |
| `LANGSTROTH_RELAY_MAX_PAIRINGS_PER_CLIENT` | `20` | live pairing codes one client may hold (address; IPv6 by /64, and each IPv6 /48 gets 16x in total); `429` `pair_codes` past it (`0` = off) |
| `LANGSTROTH_RELAY_MAX_PAIRING_BYTES` | `33554432` (32 MiB) | payload bytes all live pairing codes hold in memory (`503` past it; `0` = off) |
| `LANGSTROTH_RELAY_INBOX_MAX_ROWS` | `5000` | account-inbox rows per recipient (oldest evicted) |
| `LANGSTROTH_RELAY_INBOX_RETENTION_DAYS` | `30` | Postgres: prune inbox rows older than N days (`0` = off) |
| `LANGSTROTH_RELAY_FRIEND_REQ_RETENTION_DAYS` | `30` | Postgres: prune answered friend requests older than N days (`0` = off) |
| `LANGSTROTH_RELAY_CONTACT_MAX_RECORD_BYTES` | `65536` (64 KiB) | one contact record's size; `413` past it |
| `LANGSTROTH_RELAY_CONTACT_MAX_DROP_BYTES` | `65536` (64 KiB) | one sealed drop's size; `413` past it |
| `LANGSTROTH_RELAY_CONTACT_TTL_DAYS` | `30` | a record expires N days after its last write (clients re-publish on heartbeat); an expired record and its drop box are deleted |
| `LANGSTROTH_RELAY_CONTACT_RECLAIM_HOLD_DAYS` | `180` | after a record expires, only its old write key may create the cid again for N days (`403` for any other key); then the cid is free. `0` = free at once |
| `LANGSTROTH_RELAY_CONTACT_DROP_MAX_ROWS` | `5000` | drops per box (same as the inbox cap); see eviction under Contacts |
| `LANGSTROTH_RELAY_CONTACT_DROP_MAX_BOX_BYTES` | `4194304` (4 MiB) | drop bytes per box; see eviction under Contacts |
| `LANGSTROTH_RELAY_CONTACT_DROP_RETENTION_DAYS` | `30` | delete drops older than N days, hourly (`0` = off) |
| `LANGSTROTH_RELAY_MAX_CONTACTS` | `100000` | memory store: live contact records (`507` past it; `0` = unbounded). Records and drops also count toward `LANGSTROTH_RELAY_MAX_STORE_BYTES` |
| `LANGSTROTH_RELAY_MAX_CONTACT_BYTES` | `0` (off) | Postgres: record plus drop bytes across the relay (re-read every 10 s). New records and drops past it get `507` `contacts_full`; an existing record can still be refreshed. Without it, Postgres is bounded only by its disk and the rate limits |

**Blobs** (encrypted attachments; see [blobs.md](blobs.md))

| Var | Default | Meaning |
|---|---|---|
| `LANGSTROTH_RELAY_BLOBS` | `on` | `off` → the blob routes answer `404` |
| `LANGSTROTH_RELAY_BLOB_MAX_BYTES` | `26214400` (25 MiB) | one blob; `413 blob_too_large` past it (`0` keeps the default) |
| `LANGSTROTH_RELAY_BLOB_ROOM_MAX_BYTES` / `_ROOM_MAX_COUNT` | `536870912` / `2000` | blob bytes and blobs per workspace (`0` = off); `507 blob_room_bytes` / `blob_room_count` |
| `LANGSTROTH_RELAY_BLOB_WRITER_MAX_BYTES` / `_WRITER_MAX_COUNT` | 128 MiB / `500` (`0` = off) | per uploader (token subject, else address) per workspace; `507 blob_writer_*` |
| `LANGSTROTH_RELAY_BLOB_TOTAL_MAX_BYTES` | `0` (off) | blob bytes across the relay; `507 blob_total_bytes` |
| `LANGSTROTH_RELAY_BLOB_RETENTION_DAYS` | `30` | a blob expires N days after upload (`0` = keep until deleted) |
| `LANGSTROTH_RELAY_BLOB_RATE` / `_BURST` | `1` / `20` | uploads per second per uploader per workspace; `429 blob_rate` |
| `LANGSTROTH_RELAY_BLOB_MAX_INFLIGHT` / `_WRITER_INFLIGHT` | `16` / `4` | uploads being received at once, relay-wide and per uploader (`0` = off); `429 blob_inflight` |
| `LANGSTROTH_RELAY_BLOB_DOWNLOAD_RATE` / `_BURST` | `0.5` / `100` | downloads per second of one blob (`0` = off); `429 blob_download_rate` |
| `LANGSTROTH_RELAY_BLOB_CLIENT_DOWNLOAD_RATE` / `_BURST` | `2` / `60` | blob downloads per second per downloader (token subject, else address; `0` = off); `429 blob_download_rate` |
| `LANGSTROTH_RELAY_BLOB_DOWNLOAD_INFLIGHT` / `_CLIENT_DOWNLOAD_INFLIGHT` | `8` / `2` | downloads being written at once, relay-wide and per downloader (`0` = off); `429 blob_inflight`. A download holds its whole blob in memory, and one that stalls is cut off |

**Community limits** (all off by default; see [Community limits](#community-limits))

| Var | Default | Meaning |
|---|---|---|
| `LANGSTROTH_RELAY_ROOM_MAX_BYTES` | `0` (off) | stored bytes per room (envelope bodies + key rotations); `507` past it |
| `LANGSTROTH_RELAY_ROOM_MAX_ENVELOPES` | `0` (off) | stored envelopes per room; `507` past it |
| `LANGSTROTH_RELAY_MAX_TOTAL_ROOM_BYTES` | `0` (off) | room bytes across the relay, both stores (Postgres re-reads the sum every 10 s); `507` |
| `LANGSTROTH_RELAY_MAX_ROOMS_PER_CLIENT` | `0` (off) | rooms a client may create (token subject, else address; IPv6 /64); `429` past it. A room is created by its first write of any kind. A client that rotates addresses gets a fresh count per address, so pair it with `LANGSTROTH_RELAY_MAX_ROOMS` |
| `LANGSTROTH_RELAY_MAX_ROOMS` | `0` (off) | rooms across the relay, both stores (Postgres re-reads the count every 10 s); `507` `total_rooms` past it. The bound that holds when clients rotate addresses, and the only one on rooms that hold no envelopes |
| `LANGSTROTH_RELAY_ROOM_RETENTION_DAYS` | `0` (off) | delete a room's envelopes, key rotations and device blobs once nothing has been appended to it for N days; its sequence and roster stay |
| `LANGSTROTH_RELAY_IP_RATE` / `_BURST` | off / 2x rate | every request per client (except `/`, `/v1/health`, `/metrics`); `429` with `Retry-After` |
| `LANGSTROTH_RELAY_ROOM_RATE` / `_BURST` | off / 2x rate | every request to one room, all clients together; `429` with `Retry-After` |
| `LANGSTROTH_RELAY_MAX_INFLIGHT_PER_CLIENT` | `0` (off) | ordinary requests one client (address; IPv6 by /64, and each /48 gets 16x in total) may hold open at once; `429` `client_inflight` past it. Event streams, tunnel WebSockets and blob transfers have their own caps and don't count. Each request in progress can hold a few MiB (a 4 MiB body, a page of envelopes), so this bounds what one address can pin in memory |
| `LANGSTROTH_RELAY_TUNNEL_PUSH_RATE` / `_BURST` / `_PER_DAY` | `1` / `5` / `2000` | pushes per tunnel host (`0` = no limit) |
| `LANGSTROTH_RELAY_TENANCY` | unset | tenancy config JSON, normally from `LANGSTROTH_RELAY_TENANCY_FILE`; see [Tenancy](#tenancy-several-organisations-on-one-relay) |
| `LANGSTROTH_RELAY_METRICS_MAX_TENANTS` | `50` | tenants reported under their own metrics label; the rest are `tenant="_other"` |

**Rate and concurrency limits** (a rate of `0` disables that limit)

| Var | Default | Meaning |
|---|---|---|
| `LANGSTROTH_RELAY_PUSH_RATE` / `_BURST` | `100` / `300` | every unauthenticated write (envelopes, keyring, presence, candidates, pairing) per client |
| `LANGSTROTH_RELAY_WS_WRITER_RATE` / `_BURST` | `20` / `200` | envelope appends per (workspace, writer) |
| `LANGSTROTH_RELAY_READ_RATE` / `_BURST` | `100` / `400` | workspace reads (envelopes, keyring, presence, candidates, members, SSE connects) per client; `429` past it |
| `LANGSTROTH_RELAY_MAX_SSE` | `2000` | concurrent SSE streams per instance (`503` past it; `0` = unlimited) |
| `LANGSTROTH_RELAY_MAX_SSE_PER_CLIENT` | `100` | concurrent SSE streams per client (token subject, else address; `429` past it; `0` = unlimited) |
| `LANGSTROTH_RELAY_GITHUB_RATE` / `_BURST` | `30` / `120` | GitHub-backed routes (directory, account, friends) per client |
| `LANGSTROTH_RELAY_INVITE_RATE` / `_BURST` | `0.05` / `10` | account invites per (sender, recipient) |
| `LANGSTROTH_RELAY_CONTACT_DROP_RATE` / `_BURST` | `0.05` / `10` | contact drops per (sender, cid); the account-invite defaults |
| `LANGSTROTH_RELAY_CONTACT_DROP_CID_RATE` / `_BURST` | `1` / `60` | contact drops per cid, all senders together |
| `LANGSTROTH_RELAY_CONTACT_WRITE_RATE` / `_BURST` | `0.2` / `10` | contact record updates per cid (counted only after the key matches) |
| `LANGSTROTH_RELAY_CONTACT_CREATE_RATE` / `_BURST` | `0.01` / `20` | new contact records per client (token subject, else address; IPv6 by /64, and each IPv6 /48 also gets 16x this rate and burst in total) |

**Relay tunnel and push**

| Var | Default | Meaning |
|---|---|---|
| `LANGSTROTH_RELAY_TUNNEL` | `off` | relay tunnel (phone ↔ home host): `off` (`/v1/tunnel/*` → 404), `open` (any host may register), `allowlist` (only `LANGSTROTH_RELAY_TUNNEL_HOSTS`). See [Relay tunnel](#relay-tunnel-hive-tunnel1) |
| `LANGSTROTH_RELAY_TUNNEL_HOSTS` | empty | comma-separated `host_id`s admitted when `LANGSTROTH_RELAY_TUNNEL=allowlist` |
| `LANGSTROTH_RELAY_APNS_KEY_FILE` | empty | APNs auth key (`AuthKey_<KEYID>.p8`) for the built-in push sender; or `LANGSTROTH_RELAY_APNS_KEY` with the PEM inline (`\n` escapes allowed). Push is **off** unless the key and the three vars below are all set. See [Push from your own relay](#push-from-your-own-relay) |
| `LANGSTROTH_RELAY_APNS_KEY_ID` / `LANGSTROTH_RELAY_APNS_TEAM_ID` | empty | the key's Key ID and your Apple developer Team ID |
| `LANGSTROTH_RELAY_APNS_TOPIC` | empty | bundle id of the iPhone app build you publish (the default APNs topic) |
| `LANGSTROTH_RELAY_APNS_TOPICS` | empty | more bundle ids this relay may push to, comma-separated (for example the App Store build and a dev build). Either this or `LANGSTROTH_RELAY_APNS_TOPIC` is enough; without `LANGSTROTH_RELAY_APNS_TOPIC` the first one is the default |
| `LANGSTROTH_RELAY_APNS_ENV` | `auto` | `auto` (the environment each phone reports with its token: `development` → sandbox, `production` → production), `sandbox` or `production` |

Storage selection: `DATABASE_URL` → Postgres; else `LANGSTROTH_RELAY_DATA_DIR` →
memory+snapshot; else in-memory only.

**Pod roles.** `LANGSTROTH_RELAY_ROUTES=tunnel` serves only `/v1/tunnel/*`,
`/v1/health` and `/metrics` (the Helm chart sets it on the tunnel pod, so
pairing has one store, on relay-sync). APNs settings on a process whose tunnel
is off are refused at startup: push only goes out through the tunnel, so keep
the APNs key on the tunnel pod alone.

**Settings from files.** Any setting `X` above (and `DATABASE_URL`) that is
unset in the environment is read from the file named by `X_FILE` (for example
`DATABASE_URL_FILE`, `LANGSTROTH_RELAY_ACCESS_TOKENS_FILE`), else from the file
`$LANGSTROTH_RELAY_SECRETS_DIR/X` (a file under a `HIVE_RELAY_*` or
`LIGUS_RELAY_*` name there stops the relay at startup), so secrets can be mounted
files instead of environment variables. The environment wins over
`X_FILE`, which wins over the directory; one trailing newline is trimmed.
`LANGSTROTH_RELAY_APNS_KEY_FILE` keeps its own meaning (the path of the key). The
relay refuses to start when any `LANGSTROTH_RELAY_*_FILE` or `DATABASE_URL_FILE`
it is given, or any file in `LANGSTROTH_RELAY_SECRETS_DIR`, can't be read or is
empty: an unreadable file would otherwise read as unset, and an unset
`LANGSTROTH_RELAY_TOKEN_PUBKEY` means an open relay.

## Persistence & scaling

- **Single instance:** mount a volume at `/data` and set `LANGSTROTH_RELAY_DATA_DIR=/data`
  (JSON snapshot store; survives restarts). Nothing to back up but that volume.
- **Multiple instances:** set `DATABASE_URL` to a shared Postgres — it takes
  precedence over the snapshot dir, so every instance shares stored state (no
  migration). Short pairing codes, SSE fan-out and rate limits stay per
  process, so the Helm chart runs exactly one sync instance; more than
  one is unsupported.
- **On Kubernetes** the chart's `database.mode` picks the Postgres: `external`
  (managed), `cnpg` (a CloudNativePG cluster in the release namespace, HA and
  PITR) or `bundled` (one hardened pod with TLS and nightly dumps, no HA).
  See `deploy/helm/langstroth-relay/README.md`, "Database".

### Envelope retention

The relay never removes envelopes from a room it still holds. A Ligus client
rebuilds a workspace by folding its whole envelope log from the founder's
signed seed (seq 1) and does not backfill from peers, so trimming the front of
a room's log permanently breaks every device that joins afterwards. The
per-envelope bounds `LANGSTROTH_RELAY_MAX_ENVELOPES` (once on by default at
50 000) and `LANGSTROTH_RELAY_RETENTION_DAYS` are removed; the relay refuses to
start while either is set to anything but `0`.

Bound storage instead with the room quotas (`507` refusals, never eviction),
`LANGSTROTH_RELAY_MAX_STORE_BYTES` on the memory store, and whole-room expiry
(`LANGSTROTH_RELAY_ROOM_RETENTION_DAYS`); see [Community limits](#community-limits).

## Community limits

For a relay anyone may use (a public relay on one machine). Every limit is
off by default; `deploy/compose/langstroth-relay/.env.example` has a
commented community profile with values for one small machine (see
[deploy.md](deploy.md#a-relay-for-the-public)), and the Helm chart sets them
under `limits.*`. The project's community relay runs that profile on
Postgres.

- **Quotas refuse, they don't evict.** A Ligus client rebuilds a workspace by
  folding its whole envelope log from the founder's seed, and the relay
  can't tell a seed or a roster change from a chat message (all are
  ciphertext). So a full room answers `507` to new writes and stays
  readable; nothing is pushed out. A re-push of an envelope already stored
  still gets its seq.
- **Retention is per room.** `LANGSTROTH_RELAY_ROOM_RETENTION_DAYS` expires a
  whole room that nobody has appended to for N days. A room in use keeps
  every envelope however old. An expired room keeps its sequence counter
  (returning devices' cursors stay valid) and, with membership, its roster.
- Quotas are checked atomically with the write (the memory store's lock;
  the Postgres append transaction, with per-room usage in `relay_rooms`).
- Every refusal is counted in `hive_relay_limit_rejections_total{limit}`;
  `hive_relay_rooms` and `hive_relay_room_bytes` report usage.

### Refusals: 429 and 507

Every `429` and `507` the relay sends (any route, any limit) carries a
`Retry-After` header in whole seconds (at least 1) and a JSON body with a
stable code:

```json
{"error": "room_bytes", "message": "room storage quota reached", "retryAfter": 3600}
```

`error` is the contract; `message` is for people and may change. Clients
should switch on `error`, and treat an unknown code by its status.

| Status | `error` | Meaning | What a client should do |
|---|---|---|---|
| 429 | `ip_rate`, `room_rate`, `tenant_rate`, `write_rate`, `read_rate`, `room_writer_rate`, `contact_create_rate`, `contact_write_rate`, `contact_drop_rate`, `rate_limited` | a request rate | wait `Retry-After` (the time until a token is free), then retry the same request; keep the outbox |
| 429 | `client_inflight` | too many requests in progress from this client | wait `Retry-After` (a second), then retry |
| 429 | `sse_streams` | too many open event streams from this client | close a stream; retry after `Retry-After` |
| 429 | `pair_lockout` | too many failed pairing-code guesses | stop guessing until `Retry-After` |
| 429 | `pair_codes` | this client holds its quota of live pairing codes | wait `Retry-After` (a minute) or until one of its codes is used or expires |
| 429 | `client_rooms` | this client created its quota of rooms | don't retry automatically: tell the user; it clears when one of its rooms expires or is deleted |
| 429 | `too_many_pending` | GitHub routes: too many pending friend requests | as `client_rooms` |
| 507 | `room_bytes`, `room_envelopes` | this room is full | stop writing to this room and tell the user; the room stays readable; `Retry-After` is an hour |
| 507 | `keyring` | the room's key-rotation log is full | as `room_bytes` |
| 507 | `tenant_bytes`, `tenant_rooms` | the tenant's quota (tenancy) | tell the user to contact their admin; `Retry-After` is an hour |
| 507 | `store_bytes`, `total_bytes`, `contacts_full` | the relay itself is full | back off and retry after `Retry-After` (ten minutes) |
| 429 | `blob_rate` | attachment uploads per uploader per workspace | wait `Retry-After`, then retry the upload |
| 429 | `blob_inflight` | too many attachment uploads or downloads in progress (relay-wide or this client's) | as `blob_rate` |
| 429 | `blob_download_rate` | this attachment, or this client, is downloading too often | wait `Retry-After`, then retry the download |
| 507 | `blob_room_bytes`, `blob_room_count`, `blob_writer_bytes`, `blob_writer_count` | the workspace's (or this uploader's) attachment quota | don't retry automatically: tell the user; it clears as attachments expire or are deleted. Messages are unaffected |
| 507 | `blob_tenant_bytes`, `blob_tenant_count` | the tenant's attachment quota | as `tenant_bytes` |
| 507 | `blob_total_bytes` | the relay's attachment storage is full | as `total_bytes` |

A refused write stored nothing, so retrying it later is always safe; an
envelope re-push keeps its idempotency key and gets its original seq.

## Tenancy: several organisations on one relay

Off by default. With `LANGSTROTH_RELAY_TENANCY` (JSON, normally read from a
file through `LANGSTROTH_RELAY_TENANCY_FILE`) one process serves several
tenants that don't trust each other. Design and rules: [tenancy.md](tenancy.md).

```json
{"defaults": {"max_bytes": 10737418240, "rate": 200, "burst": 400},
 "tenants": [
   {"id": "acme", "issuer_pubkeys": ["<acme's langstroth-auth public key>"], "shared_issuer": false,
    "admin_token_sha256": "<sha256 hex of acme's admin token>", "limits": {"max_rooms": 500}},
   {"id": "home"}]}
```

- **The tenant comes only from a verified token**: a signed `hrt1` token
  whose `tid` names a configured tenant, signed by that tenant's
  `issuer_pubkeys` or (when `shared_issuer` is on, the default) by
  `LANGSTROTH_RELAY_TOKEN_PUBKEY`. A token from tenant A's issuer that names
  tenant B gets `401`; headers and query parameters never name a tenant.
  The open policy and `LANGSTROTH_RELAY_ACCESS_TOKENS` can't be used.
- **Isolation:** rooms and contacts are stored under `<tenant>/<id>`, so two
  tenants using the same workspace id get unrelated rooms; pairing codes are
  drawn and resolved per tenant; a tunnel host is bound to the tenant of its
  registration token, for good.
- **Per-tenant limits:** `max_bytes` and `max_rooms` (`507`),
  `room_max_bytes`, `room_max_envelopes`, `rate`/`burst` (`429`),
  `max_pairings`, `max_hosts`, `push_per_day`, and for attachments
  `blob_max_bytes`, `blob_max_count`, `blob_room_max_bytes`,
  `blob_room_max_count` ([blobs.md](blobs.md)).
- **Tenant admin** (only with tenancy): `GET /v1/tenant` (usage and limits),
  `GET /v1/tenant/rooms?after=&limit=` (the tenant's rooms), `DELETE
  /v1/tenant/rooms/{id}` (purge one), admitted by a tenant token with the
  `tenant_admin` cap or the tenant's static admin token.
- **Metrics** per tenant (`hive_relay_tenant_requests_total`,
  `hive_relay_tenant_limit_rejections_total`, `hive_relay_tenant_bytes`,
  `hive_relay_tenant_rooms`), labelled by configured tenant id only and
  capped by `LANGSTROTH_RELAY_METRICS_MAX_TENANTS`.
- Still one process (single replica): this is logical isolation, not HA.
  The operator still sees every tenant's metadata. Turning tenancy on for a
  relay that already holds rooms hides them (they aren't under a tenant).

## Envelope paging

`GET /v1/workspaces/{id}/envelopes?after=<seq>[&limit=<n>]` returns one bounded
page, oldest first: at most `limit` envelopes (default and maximum 1000) and, past
the first envelope, at most 4 MiB of stored body bytes. The body is the same bare
JSON array as always; two response headers describe the page:

- `X-Hive-Next-After: <seq>` — the cursor for the next request (the last seq in
  the page, or `after` when the page is empty);
- `X-Hive-More: true` — present only when envelopes past this page exist.

A client loops `after = X-Hive-Next-After` until `X-Hive-More` is absent. A client
that ignores the headers still converges: it sets its cursor to the highest seq it
received and its next poll continues from there.

## Idempotent push

`POST /v1/workspaces/{id}/envelopes` drops a re-push instead of appending it
twice and answers with the original `seq`. A re-push is recognized by the
client's `Idempotency-Key` (or `X-Hive-Event-Id`) header, scoped to the writer
(the token subject, else the client address), so one writer can't claim a key
another writer will use; without a header, by the SHA-256 of the sealed body.

## Live push (Server-Sent Events)

`GET /v1/workspaces/{id}/events` (`Content-Type: text/event-stream`) lets a
client wake instantly on new traffic instead of polling on a timer. It is a
content-blind **nudge** channel — never envelope bodies:

- on connect: `: connected` (a comment), then optionally `data: {"seq":<head>}`;
- on every new envelope appended to the workspace: `data: {"seq":<newSeq>}` —
  the client pulls with its own `?after=` cursor over `GET /envelopes`;
- every ~25s idle: a `: keep-alive` comment to survive proxy idle timeouts.

Read-authorized exactly like the other workspace reads (`enforceRead`), and
counted against the read rate. Each client may hold at most
`LANGSTROTH_RELAY_MAX_SSE_PER_CLIENT` streams (`429` past it), and the instance at
most `LANGSTROTH_RELAY_MAX_SSE` (`503`). Fan-out
is **single-instance / in-process** today; cross-instance push (Postgres
`LISTEN/NOTIFY`) is tracked as a follow-up, and multi-instance deployments keep
the `?after=` poll as the backstop.

## Pairing codes

`POST /v1/pair` `{payload, ttl_secs?}` stores a payload behind a short code
(`ttl_secs` 30–3600, default 600) and `GET /v1/pair/{code}` returns it. The
broker keeps payloads in cleartext in the relay's memory, so it takes only
payloads that are safe for the relay operator to read:

- a public peer friend code: `hive_` + base64url of a 32-byte public key, or
  the legacy `hivepeer1:` + 64 hex characters;
- a sealed payload: `sealed1:` + base64url of at least 32 bytes of ciphertext.
  The relay can't check that it is really encrypted; the prefix is the
  client's statement that it is.

Anything else gets `422`, including `hivews1:` / `ligusws1:` workspace
invites, which carry the workspace's end-to-end key: share those over a
channel you trust. A code is **single-use**: the first successful resolve
consumes it, and a second resolve gets `404`. Unresolved codes still expire at
their TTL. Failed resolves are capped per client (10 per minute, then `429`),
so the code space can't be enumerated.

## Blobs (`/v1/workspaces/{id}/blobs`)

End-to-end encrypted file attachments: the relay stores and returns opaque
ciphertext and never sees a file's contents, name or type; clients check
each download against the signed event that refers to it. On by default
(`LANGSTROTH_RELAY_BLOBS=off` → `404`).

| Method | Path | Request | Response |
|---|---|---|---|
| `POST` | `/v1/workspaces/{id}/blobs` | raw ciphertext body (≤ `LANGSTROTH_RELAY_BLOB_MAX_BYTES`, 25 MiB) | `201 {"id":"<43 chars>","size":n,"sha256":"<hex>","expiresAt":<unix s, 0 = never>}` |
| `GET` | `/v1/workspaces/{id}/blobs/{blob}` | | `200 application/octet-stream` (`Content-Disposition: attachment`, `nosniff`, `no-store`) |
| `DELETE` | `/v1/workspaces/{id}/blobs/{blob}` | | `204` (also when absent); `403 blob_not_yours` when it was uploaded by another token subject and the caller isn't a workspace Admin on the relay roster |

Ids are 32 random bytes minted by the relay (base64url, no padding); there
is no listing route. An unknown, expired or other workspace's blob is `404
blob_not_found`; an upload to a workspace that holds nothing is `404
no_workspace` (blobs never create rooms). Per-blob, per-workspace,
per-uploader, per-tenant and relay-wide quotas, an upload rate, 30-day
retention and deletion: [blobs.md](blobs.md).

## Contacts (`/v1/contacts/*`)

A contact is an opaque, client-signed record stored under a random contact id
(`cid`), plus a sealed drop box for that `cid`, so people can reach each other
without a provider-keyed directory. The relay does **no cryptography** on
contacts: it can't verify a record and doesn't try. Clients verify the record's
signature chain against the account fingerprint they got out of band (invite
link or QR code), and seal drops to the recipient's key-agreement keys.

Ownership is a capability: on the first write the client sends a `writeKey`
(32 random bytes, base64url without padding); the relay stores only its
SHA-256 and compares hashes. Whoever holds the key may update or delete the
record and read or empty the drop box. Anyone who knows the `cid` may read the
record and drop into the box. Every route goes through the access gate.

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| `PUT` | `/v1/contacts/{cid}` | first write: `writeKey` in the body (or the header); later: `X-Ligus-Contact-Key` (or the same `writeKey` in the body) | `{"record": <JSON ≤ 64 KiB>, "writeKey": "<b64url 32 bytes>"}` | `200 {"created":bool,"updatedAt":<unix s>,"expiresAt":<unix s>}` |
| `GET` | `/v1/contacts/{cid}` | gate only | | `200 {"record": <as published>, "updatedAt": <unix s>}` |
| `DELETE` | `/v1/contacts/{cid}` | `X-Ligus-Contact-Key` | | `200 {"ok":true}`; the drop box goes too |
| `POST` | `/v1/contacts/{cid}/drop` | gate only (rate-limited) | `{"blob": <JSON ≤ 64 KiB, sealed client-side>}` | `200 {"ok":true}` (no sequence, so senders can't measure the box) |
| `GET` | `/v1/contacts/{cid}/drop?after=<seq>&limit=<n>` | `X-Ligus-Contact-Key` | | `200 {"items":[{"seq":n,"blob":<as sent>,"createdAt":<unix s>}],"more":bool}` |
| `DELETE` | `/v1/contacts/{cid}/drop?through=<seq>` | `X-Ligus-Contact-Key` | | `200 {"ok":true,"deleted":n}` |

- `cid` must be base64url (no padding) of exactly 16 bytes, and a write key of
  exactly 32 bytes; anything else gets `400`.
- Errors: `400` malformed (or header and body keys differ), `401` key missing,
  `403` key doesn't match, `404` no live record (also for a drop to an unknown
  `cid`), `413` too large, `429` rate-limited, `507` capacity.
- Records and blobs are stored and returned byte for byte (any JSON value but
  `null`), on every store, across snapshot restarts.
- Reading the drop box doesn't delete anything, so each device of an account
  can keep its own `after` cursor; the owner deletes what all its devices have
  processed with `DELETE …/drop?through=<seq>`. Past the row or byte cap the
  relay evicts drops it has already served to the owner first (oldest first),
  then the unread drops of the heaviest sender in the box (most bytes, then
  most rows; an unverified sender before one with a relay-token subject on a
  tie), oldest first. A sender is the relay-token subject, else the client
  address (IPv6 /64); it is stored only as a salted hash. So a flood from a few
  addresses that know the cid evicts its own drops, not an unread invite from
  someone else. `limit` defaults to 100 (max 1000) and a page is
  also bounded by `LANGSTROTH_RELAY_MAX_LIST_BYTES`.
- A request on these routes that carries a forge token (any
  `X-*-Github-Token`, `X-*-Gitlab-Token`, `X-*-Forge-Token`, ... header, or a
  `ghp_` / `github_pat_` / `glpat-` style bearer) is refused with `400`; the
  token is never verified, logged or forwarded.
- A relay without contacts (v0.2, or `LANGSTROTH_RELAY_CONTACTS=off`) answers
  `404`, and clients fall back to links and QR codes.

**What the relay still sees:** which `cid`s exist, when records change, drop
timing and sizes, and client addresses. It can withhold or replay an old
record; clients reject a record older than the newest they've seen for that
`cid`.

## GitHub social routes (deprecated, off by default)

The identity directory, account and friends routes (`/v1/directory/*`,
`/v1/account/*`, `/v1/friends/*`, keyed by `github:<id>`) need the relay to
see each caller's GitHub token. Current Ligus clients don't use them. Since v0.3 they are
**not registered** (404) unless `LANGSTROTH_RELAY_GITHUB_ROUTES=on`, which exists
only for older clients; when on, every response carries
`Deprecation: @1794614400` and `Link: <…CHANGELOG.md>; rel="deprecation"`.
**v0.4 removes them**, together with their tables and the GitHub verifier.

When enabled, they identify the caller by a GitHub token sent in
`X-Hive-Github-Token` (or `X-Ligus-Github-Token`), verified against
`api.github.com/user` and cached briefly by the token's hash. Only that header
is used: the `Authorization` bearer carries the relay access token and is never
sent to GitHub, so a request with only a bearer gets `401`. The relay operator
can see the GitHub tokens sent to these routes; enable them only on a relay
you trust.

## Optional access gating

Open by default (self-host — the URL isn't a secret). To gate:

- **Allowlist:** `LANGSTROTH_RELAY_ACCESS_TOKENS=tokA,tokB` (opaque bearer tokens).
- **Signed tokens:** set `LANGSTROTH_RELAY_TOKEN_PUBKEY=<hex>` and mint per-subject
  tokens with `langstroth-relay keygen` / `langstroth-relay issue` — keep the issuer private
  key off the relay host (the relay only ever verifies).
- **Durable users + tokens:** manage per-person access over the admin API
  (below) instead of an env list — no redeploy, survives restarts, instant
  revocation. Pair it with `StoreEntitlementVerifier` to make the store the
  access gate.

Workspace keyrings are bounded by refusal, not eviction: past
`LANGSTROTH_RELAY_MAX_KEYRING_PER_WS` rotations or `LANGSTROTH_RELAY_MAX_KEYRING_BYTES_PER_WS`
bytes, a new rotation gets `507` and the stored ones stay, so a flood of junk
rotations can't push a workspace's real rotations out. One rotation is capped at
`LANGSTROTH_RELAY_MAX_ROTATION_BYTES`.

Gating applies symmetrically to **reads and writes**: both `GET`
(envelopes / keyring / presence / candidates) and `POST` on a workspace require
the same access token (`enforceRead` mirrors `enforceWrite`). Under a token-gated
policy an unauthenticated read is `401`; under the open policy reads stay open,
just like writes. This is a coarse, content-blind token gate — it checks the
presented token, never the body — so workspace ciphertext + keyring are no
longer readable by anyone who merely learns a workspace id. Clients already send
their access token on every request, so no client change is needed.

**Per-workspace token scope (opt-in, `LANGSTROTH_RELAY_WORKSPACE_SCOPE`).** The
token gate is coarse: any admitted caller may read and write any workspace.
Signed tokens can carry an optional `workspaces` claim (`langstroth-relay issue …
--workspace <id> [--workspace <id>]`, `*` = any). With
`LANGSTROTH_RELAY_WORKSPACE_SCOPE=claims` a token that carries the claim is confined
to those ids on every `/v1/workspaces/{id}/…` route (envelopes, events,
keyring, presence, candidates, and the membership routes); tokens without it
keep coarse access. `strict` requires the claim on every workspace route (so
it needs signed tokens; the open policy and static allowlist get `403`). `off`
(default) ignores the claim. The claim lives inside the signed claims JSON, so
the `hrt1` format is unchanged, but a relay that doesn't enforce it (older, or
`off`) ignores it: a scoped token is only confined where the operator turns
this on. Relay-managed membership (`LANGSTROTH_RELAY_MEMBERSHIP=1`) is the
alternative when the roster, not the issuer, should decide.

**Deferred (known, needs a design decision — not implemented here):**
- *High-entropy workspace ids.* Clients today derive a workspace id from a
  possibly-guessable room *name*. Making ids high-entropy (so an id can't be
  guessed at all) is a client-side + invite-model change, not a relay change.

## Sign-in with your identity provider (langstroth-auth)

`langstroth-auth` (`cmd/langstroth-auth`, image `deploy/container/Dockerfile.langstroth-auth`,
chart `deploy/helm/langstroth-auth`) is an optional, separate service that lets
people sign in with any OIDC provider (Pocket ID, Dex, Keycloak, Authentik,
Okta, Entra ID, ...) and receive short-lived relay tokens. It never runs
inside the relay; the relay only needs its public key.

- **Flows:** authorization code + PKCE for apps with a browser (loopback
  redirect on the desktop, the system browser on iOS) and the device
  authorization grant (RFC 8628) for `ligus serve`, workers and the CLI.
- **Tokens:** ordinary `hrt1` tokens, signed with the langstroth-auth issuer key.
  `sub` is `<tenant>:<user>`, `exp` is at most an hour away (15 minutes by
  default), and three claims are added, each omitted when empty: `tid`
  (tenant), `uid` (a hash of the IdP subject) and `did` (the device id whose
  Ed25519 key signed the token request). `workspaces` comes from group grants
  and is never empty, so set `LANGSTROTH_RELAY_WORKSPACE_SCOPE=strict`.
  Refresh tokens are opaque, rotate on every use (reuse revokes the session)
  and only work from the device key they were issued to.
- **SCIM 2.0** at `/t/<tenant>/scim/v2` (Users, Groups) for provisioning and
  deprovisioning: deactivating a user revokes their refresh tokens at once;
  access tokens lapse within the access TTL.
- **Membership is not granted.** A token only says which workspaces a person
  may reach on the relay. It carries no workspace key and writes no roster
  entry: joining a workspace still takes an invite (the end-to-end key) and an
  Admin's signed `MemberAdded`, and governance events from outside the signed
  roster are refused by every client, whatever the relay forwards.
- **Tenants** each have their own IdP, SCIM token and workspaces. A workspace
  belongs to one tenant; grants can name only the tenant's own workspaces, and
  `LANGSTROTH_RELAY_TENANTS` makes the relay refuse other tenants' tokens.

```sh
langstroth-auth keygen --out /etc/langstroth-auth/signing-key   # prints only the public key
LANGSTROTH_RELAY_TOKEN_PUBKEY=<that key> LANGSTROTH_RELAY_WORKSPACE_SCOPE=strict \
  LANGSTROTH_RELAY_TENANTS=home langstroth-relay
langstroth-auth serve --config /etc/langstroth-auth/config.json
```

Examples: `deploy/compose/langstroth-auth-pocket-id` (home lab, passkeys) and
`deploy/compose/langstroth-auth-dex` (federation; Kubeflow shops can reuse their
Dex). Full setup guides: [langstroth-auth](https://docs.langstroth.ai/operate/deploy/ligus-auth/),
[with Pocket ID](https://docs.langstroth.ai/operate/deploy/ligus-auth-pocket-id/) and
[with Dex](https://docs.langstroth.ai/operate/deploy/ligus-auth-dex/).

## User/token admin API (`/v1/admin/*`)

The relay has a durable user + token store (both backends implement it) and a
management API, gated by the `AdminAuthorizer` seam. It's **disabled by
default** (no authorizer → `404`); supply one via `Options{AdminAuth: …}` to
enable it. The open `langstroth-relay` binary has no environment switch for it
(there is no `LANGSTROTH_RELAY_ADMIN_LOGINS`): it needs a downstream build. Tokens are stored only as SHA-256 hashes; the raw value is returned
once at creation.

- `POST /v1/admin/users` `{name, login?}` → create user + first token (raw once)
- `GET /v1/admin/users` → users + their tokens (no hashes)
- `POST /v1/admin/users/{id}/tokens` `{label?}` → another token (raw once)
- `POST /v1/admin/users/{id}/disabled` `{disabled}` → enable/disable a user
- `DELETE /v1/admin/tokens/{id}` → revoke a token

Admin request bodies are capped at 16 KiB (`413`). Store errors are logged, not
returned: a failing store answers `500 internal error`.

## Status page

`GET /` serves a small public HTML status page ("Langstroth relay · online") so a
human who opens the URL sees an intentional page rather than a `401`. `GET
/v1/health` round-trips the store and returns `200 ok`, or `503` if the backend
is unreachable — wire it to your orchestrator's liveness/readiness probe.
Everything else is token-gated.

## Relay tunnel (`hive-tunnel/1`)

Lets the Ligus iPhone app reach a `ligus serve` home host through the relay —
no VPN, no inbound port on the host. The relay checks **who may connect** and
then forwards opaque bytes: phone and host run a Noise IK session end to end
through it, so the relay can't read, alter or forge traffic, and can't
impersonate either side. The protocol is open; the spec lives in the
[Ligus repo](https://github.com/langstroth-ai/ligus) (`docs/relay-tunnel.md`, with golden vectors in `docs/relay-tunnel/`).

**Off by default.** A relay upgraded to this version does not become a public
tunnel provider. Enable it with `LANGSTROTH_RELAY_TUNNEL=open` (any host may
register) or `LANGSTROTH_RELAY_TUNNEL=allowlist` + `LANGSTROTH_RELAY_TUNNEL_HOSTS=<host_id>,…`.
When the relay's access gate is configured (`LANGSTROTH_RELAY_TOKEN_PUBKEY` /
`LANGSTROTH_RELAY_ACCESS_TOKENS`), a host's first registration must also present a
token that passes it (`ligus remote enable --reg-token …`).

Endpoints (WebSockets require the subprotocol `hive-tunnel.1`, else `426`;
they authenticate themselves, so they bypass the bearer-token gate):

| Route | Who | What |
|---|---|---|
| `GET /v1/tunnel/info` | anyone | `{"versions":[1],"push":bool,"billing":"none"}` (`404` when off) |
| `GET /v1/tunnel/host` | host | control socket: Ed25519-signed challenge; `host_id = H(host key)`, registered implicitly on first connect |
| `GET /v1/tunnel/accept?sid=…` | host | one data socket per phone session (`sid` is single-use, valid 10 s) |
| `GET /v1/tunnel/connect?host=…` | phone | host-signed `hpc1` credential + proof-of-possession signature (or a pairing-window tag to enroll), then a 1:1 splice to the host |
| `POST /v1/tunnel/revoke` | host | revoke one phone without the control socket: `{"v":1,hostId,pid,exp,ts,nonce,sig}`, `sig` = Ed25519 by the registered host key over `ctx("host-revoke", hostId, pid, u64be(exp), u64be(ts), nonce)`; `ts` within ±300 s (else `401 {"error":"clock_skew","now"}`), each nonce once (`409 replayed`). Records the revocation, drops the push token, closes live sessions with `4003`, and answers `{"ok":true,"pid","revokedUntil","sessionsClosed","pushTokenRemoved"}`. Idempotent; a host can only name its own `hostId` |

What the relay stores (both backends; part of the snapshot / database):
registered hosts `(host_id, pub, created_at, last_seen)`, revoked phones
`(host_id, pid, exp)` until their credentials would have expired, and APNs push
tokens. It never holds a key that opens session traffic.

Limits (spec defaults): 8 KiB text / 65 535 B binary messages; 8 concurrent
sessions per host and 3 per phone; 60 sessions opened per host per minute; 30
connects per IP per minute, and 10 failed auths per minute blocks the IP for
5 minutes (counted apart for phones, on connect and revoke, and for hosts, on
host and accept, so a phone failing from a box's network doesn't lock the box
out); 2 enrollment windows per host (≤ 15 min, 5 attempts each);
enrollment sessions capped at 5 min / 4 MiB; 20 control messages per second.
Every tunnel socket is pinged every 20 s and closed after 60 s of silence; the
`http.Server` read/write timeouts are cleared on upgrade. On shutdown every
tunnel socket is closed with `4011 shutting_down` (wired via
`http.Server.RegisterOnShutdown(srv.ShutdownTunnels)`).

**One instance per host.** Live control connections are kept in process: run a
single relay instance for the tunnel, or route `/v1/tunnel/connect?host=H` and
`/v1/tunnel/accept` to the instance holding H's control connection.

**Self-hosting the tunnel.** `LANGSTROTH_RELAY_TUNNEL=open` turns on remote access
on your own relay: every registered host is `active`. `GET /v1/tunnel/info`
then reports `"billing":"none"`, and the Ligus app shows "ask the relay
operator" when a session is refused with `4006`. The `billing` field is a
protocol value kept for wire compatibility; this relay always reports
`"none"`.

**Push on a self-hosted relay.** Without a `PushSender` host pushes are acked
`push_unavailable`, and `ligus serve` falls back to ntfy when it's configured.
APNs only accepts a push signed with a key from the Apple developer team that
publishes the app, so a relay can push only to builds of the Ligus app its
operator publishes (see below). It can't push to someone else's App Store
build. Proposed (not built): an optional push gateway run by the app's
publisher that accepts the same end-to-end encrypted `ct` from a self-hosted
relay and forwards it to APNs, so the gateway sees only ciphertext plus the
device token. It would need its own abuse controls (a per-relay key and rate
limits).

## Push from your own relay

If you build and sign the iPhone app under your own Apple developer account,
your relay can push to it with the built-in APNs sender:

1. In the Apple developer portal (Certificates, Identifiers & Profiles → Keys)
   create a key with **Apple Push Notifications service (APNs)** enabled.
   Download the `.p8` once and keep it secret; note its Key ID and your Team ID.
2. Run the relay with the tunnel on and the key configured:

   ```sh
   LANGSTROTH_RELAY_TUNNEL=open \
   LANGSTROTH_RELAY_APNS_KEY_FILE=/secrets/AuthKey_ABC123DEFG.p8 \
   LANGSTROTH_RELAY_APNS_KEY_ID=ABC123DEFG \
   LANGSTROTH_RELAY_APNS_TEAM_ID=<your team id> \
   LANGSTROTH_RELAY_APNS_TOPIC=<your app's bundle id> \
   LANGSTROTH_RELAY_APNS_TOPICS=<your dev build's bundle id> \
   langstroth-relay
   ```

   The relay logs `tunnel push via APNs (topics …; default …; env auto)`, and
   `GET /v1/tunnel/info` and the host's `welcome` report `"push": true`. An
   incomplete configuration or a key that doesn't parse is logged and leaves
   push off; the relay still starts.
3. Build the app with push enabled (see the Ligus iPhone app's build instructions), pair the phone with a
   host that uses this relay, and allow notifications.

The relay forwards the host's ciphertext untouched in the spec §14 payload
(`{"aps":{"alert":{"title":"Ligus","body":"New activity on your host"},"mutable-content":1},"hive":{…,"ct":…}}`)
with `apns-push-type: alert`, priority 10 (`high`) or 5 (`normal`),
`apns-expiration` now + 1 h and the host's opaque collapse id. When APNs says
a device token is dead (`410 Unregistered`, `BadDeviceToken`,
`DeviceTokenNotForTopic` for the topic the phone reported) the relay forgets
it; the phone sends a fresh one on its next connect.

A dev build and an App Store build have different bundle ids. The app reports
its bundle id with its token (`apns.topic` in the phone's `auth`), and the
relay pushes with that topic when it is `LANGSTROTH_RELAY_APNS_TOPIC` or listed in
`LANGSTROTH_RELAY_APNS_TOPICS`; any other topic is refused (the token is kept, so
adding the topic and restarting is enough). A phone that doesn't report one
(an older app) gets the default topic, and `DeviceTokenNotForTopic` for it
leaves its token alone: the relay's default was wrong, not the token. With
`LANGSTROTH_RELAY_APNS_ENV=auto` a debug build from Xcode (sandbox token) and a
TestFlight/App Store build (production token) both work.

Every push the relay handles is logged at info as `tunnel push` with
`result` (`sent`, `no_push_token`, `push_failed`, `rate_limited`, `revoked`,
`push_unavailable`), and for APNs the `env`, `topic`, HTTP `status`, `reason`
and `apns_id`. Never the device token or the ciphertext. A host can ask for
that same detail in the ack (`"diag": true` on its `push`; `ligus remote
push-test` does): the ack then carries `"detail"`. Without `diag` acks are
unchanged.

A downstream build can inject its own `TunnelPolicy` (host admission: hosts
can be `pending` — enrollment works, sessions get `4006`; pending hosts unseen
for 30 days are forgotten) and an APNs `PushSender` through
`New(Options{...})` (below).

## Extending (seams)

The relay package (`internal/relay`) is a complete relay on its own. It also
exposes extension points (see `internal/relay/seams.go`) so another binary
under `cmd/` in this module can add custom behavior via `New(Options{...})`.
The package is internal: code outside this module can't import it.

Seams:

- **`Store`** — durable backend (in-memory/snapshot or Postgres built in);
  includes the user/token store behind the admin API.
- **`EntitlementVerifier`** — admission policy (open / allowlist / signed from
  env, `StoreEntitlementVerifier` for tokens managed over the admin API, or
  your own).
- **`AdminAuthorizer`** — gates `/v1/admin/*` user management (`nil` = disabled).
- **`WriteGuard`** — optional pre-write authorization hook (`nil` = content-blind).
- **`Hooks`** — optional lifecycle observers (e.g. audit / metrics; no-op by
  default).
- **`TunnelPolicy`** / **`PushSender`** — relay-tunnel host admission and
  access (`nil` = `LANGSTROTH_RELAY_TUNNEL` env policy), and end-to-end
  encrypted push delivery (`nil` = the built-in APNs sender when
  `LANGSTROTH_RELAY_APNS_*` is set, else unavailable). The sender itself is the
  importable `github.com/langstroth-ai/langstroth-relay/apns` package; a sender that wraps
  `relay.ErrPushTokenGone` makes the relay forget that phone's token. A `Store` that also implements
  `TunnelStore` keeps tunnel state durable (both built-in backends do).

