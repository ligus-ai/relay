# langstroth-relay Helm chart (preview)

> **Preview.** From relay v0.3.0 each release tag publishes this chart to
> `oci://ghcr.io/langstroth-ai/charts/langstroth-relay` and the image to
> `ghcr.io/langstroth-ai/langstroth-relay` (`.github/workflows/release.yml`).
> The chart's version matches the relay release. Values may change while the
> chart is in preview.
>
> **Renamed from `ligus-relay`.** Releases installed from the `ligus-relay`
> chart named their resources and selector labels after it. Selectors can't
> change in place, so upgrade such a release with `--set
> nameOverride=ligus-relay` (keeps every name and label, and the PVCs with
> them); a fresh install needs nothing. Settings are `LANGSTROTH_RELAY_*`
> only: the relay no longer reads `LIGUS_RELAY_*` or `HIVE_RELAY_*` and
> refuses to start while a variable (or a Secret key in the settings
> directory) under one of those names is set, and the chart refuses such a
> `config.env` key. Rename them before upgrading.

The Langstroth relay on Kubernetes: content-blind, end-to-end encrypted sync, plus
the phone tunnel. The relay never holds a workspace key, a device key or
plaintext; its namespace holds only the database password, its token-issuer
public key and (on the tunnel pod) the APNs key.

## Topologies

The relay keeps some state in process (live tunnel control connections, SSE
fan-out, short pairing codes, rate limiters), so the chart runs the same image
in two shapes:

| `topology` | Renders | Store |
|---|---|---|
| `split` | `<release>-sync` Deployment (every route except `/v1/tunnel/*`, `LANGSTROTH_RELAY_TUNNEL=off`, exactly one replica in 2.0, `Recreate`) and `<release>-tunnel` Deployment (`/v1/tunnel/*`, exactly one replica, `strategy: Recreate`) | Postgres (required) |
| `single` | one Deployment, every route, one replica, `Recreate` | Postgres, or memory with an optional snapshot PVC |
| `auto` (default) | `split` when a database is configured, else `single` | |

`Recreate` matters for the tunnel: with a rolling update the old pod keeps a
host's control socket while a phone's connect lands on the new pod. On
shutdown the relay closes tunnel sockets with `4011 shutting_down` and hosts
reconnect within seconds.

With an Ingress or HTTPRoute enabled, `/v1/tunnel` routes to the tunnel
Service and everything else to the sync Service. In-cluster clients use the
two Services directly (`LIGUS_RELAY_URL` and `LIGUS_REMOTE_RELAY`); the
install notes print both URLs.

## Install from the registry

No checkout needed. Pin the chart version (it matches the relay release; see
the [releases](https://github.com/langstroth-ai/langstroth-relay/releases)
and CHANGELOG.md before upgrading).

```sh
kubectl create namespace langstroth-relay
kubectl label namespace langstroth-relay pod-security.kubernetes.io/enforce=restricted
# Production: an external Postgres (or database.mode=cnpg / bundled, below).
kubectl -n langstroth-relay create secret generic relay-db \
  --from-literal=DATABASE_URL='postgres://relay:<password>@db.example.internal:5432/relay?sslmode=verify-full'
helm install langstroth-relay oci://ghcr.io/langstroth-ai/charts/langstroth-relay \
  --version 0.3.1 -n langstroth-relay \
  --set database.mode=external --set database.external.existingSecret=relay-db \
  --set 'database.external.cidrs={10.0.0.5/32}'   # the database's address, for the egress policy
kubectl -n langstroth-relay rollout status deploy/langstroth-relay-sync
helm test langstroth-relay -n langstroth-relay
```

To try it without a database, leave out the `database.*` and secret lines:
the chart runs one pod (`deploy/langstroth-relay`) on the in-memory store. Expose it with
`ingress.enabled` or `httpRoute.enabled` (TLS at the ingress; clients require
`https://`), and set `clientIP.trustedProxies` to the ingress's addresses.
Upgrade with `helm upgrade ... --version <new>`; roll back with
`helm rollback`. Every value is listed under [Values](#values).

## Quick start from a checkout (kind or k3d)

```sh
docker build -f deploy/container/Dockerfile -t langstroth-relay:dev .
kind load docker-image langstroth-relay:dev

kubectl create namespace langstroth-relay
kubectl label namespace langstroth-relay pod-security.kubernetes.io/enforce=restricted
# The bundled Postgres's password and pgpass line (the chart generates none).
PW=$(openssl rand -hex 24)
kubectl -n langstroth-relay create secret generic relay-postgres-auth \
  --from-literal=password=$PW --from-literal=pgpass="*:*:*:relay:$PW"
helm install langstroth-relay deploy/helm/langstroth-relay -n langstroth-relay \
  --set image.repository=langstroth-relay --set image.tag=dev \
  --set database.mode=bundled \
  --set database.bundled.auth.existingSecret=relay-postgres-auth \
  --set database.bundled.allowPlaintextInNamespace=true
helm test langstroth-relay -n langstroth-relay
```

`allowPlaintextInNamespace` keeps this quick start free of certificates; drop
it and give the bundled Postgres a certificate (below) for anything you keep.

Use the release name `langstroth-relay` to get Service names `langstroth-relay-sync` and
`langstroth-relay-tunnel`; other release names are prefixed.

With a database configured the chart sets `LANGSTROTH_RELAY_REQUIRE_DB=1`, so a pod
with a missing or broken URL fails instead of silently serving from memory.

## Database

The relay's PostgreSQL is one choice, `database.mode`:

| `database.mode` | What runs | Connection | HA | Backups | Use it for |
|---|---|---|---|---|---|
| `external` | nothing: you point at a Postgres you run (RDS, Cloud SQL, Crunchy Bridge, a VM) | your DSN from a Secret; use `sslmode=verify-full` | the provider's | the provider's PITR | production, when you have a managed Postgres |
| `cnpg` | a [CloudNativePG](https://cloudnative-pg.io) `Cluster` in the release namespace | TLS `verify-full` against the operator's CA; non-TLS refused | `instances: 3` (or more): streaming replicas, automatic failover | WAL archiving + `ScheduledBackup` to object storage (PITR) | production in-cluster |
| `bundled` | one hardened Postgres pod (StatefulSet) | TLS `verify-full` (your certificate or cert-manager), `scram-sha-256` | none: one pod, one volume | `pg_dump` CronJob to a PVC, with retention and a restore switch | small self-hosts |
| `none` | nothing (memory store) | | | | kind/k3d, `topology=single` only |

Every mode keeps secrets out of the environment. For `cnpg` and `bundled` the
DSN (a ConfigMap) carries no password: it names a `pgpass` file and the server
CA, both projected `0400` from Secrets into `/etc/langstroth-relay/db` next to it,
and the relay (pgx) reads them itself:

```
postgres://relay@<host>:5432/relay?sslmode=verify-full&sslrootcert=/etc/langstroth-relay/db/ca.crt&passfile=/etc/langstroth-relay/db/pgpass
```

Only the keys the relay needs are projected: `pgpass` and `ca.crt`, never the
CA's private key or the server's key.

The relay's egress NetworkPolicy allows only the chosen database: the
cluster's or the bundled pod's labels for `cnpg` and `bundled`, and
`database.external.cidrs` (an `ipBlock`) for `external`. The chart refuses
external CIDRs broader than `/8` (IPv4) or `/48` (IPv6), containing a cloud
metadata address (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`), or
written as IPv4-mapped, IPv4-compatible or NAT64 IPv6; the DNS rule and the metadata
exclusions are unchanged.

Migrations run in one transaction under a transaction-scoped advisory lock,
in every mode (see Backups and upgrades). This was verified against a
CloudNativePG cluster and through its PgBouncer `Pooler` in transaction mode
(`TestPG_MigrationLeavesNoLockBehindAPooler`). The chart does not render a
`Pooler`: one replica of relay-sync needs none.

### `external`

```yaml
database:
  mode: external
  external:
    existingSecret: relay-database      # key DATABASE_URL (existingSecretKey)
    cidrs: [10.20.0.15/32]              # the database's address, for egress
```

The Secret holds the full DSN, e.g.
`postgres://relay:<pw>@db.example.internal:5432/relay?sslmode=verify-full&sslrootcert=system`
(`system` for a publicly trusted certificate) or `sslrootcert=` pointing at a
CA file you mount (put it in `config.existingSecret`, mounted at
`/etc/langstroth-relay/secrets`). Leave `cidrs` empty only if you add the rule to
`networkPolicy.extraEgress` yourself; the install notes remind you.

### `cnpg` (CloudNativePG)

Prerequisite: the operator, installed once per cluster in its own namespace,
for example

```sh
kubectl apply --server-side -f \
  https://github.com/cloudnative-pg/cloudnative-pg/releases/download/v1.30.1/cnpg-1.30.1.yaml
```

The chart refuses to render `cnpg` when the cluster does not serve
`postgresql.cnpg.io/v1`. `helm template`, Argo CD and Flux render without
asking the cluster: pass `--api-versions postgresql.cnpg.io/v1` or set
`database.skipCapabilityCheck=true`.

```yaml
database:
  mode: cnpg
  cnpg:
    instances: 3                     # 1 = single instance; 3 = HA with failover
    storage: {size: 20Gi, storageClass: fast}
    backups:
      barmanObjectStore:             # passed to spec.backup.barmanObjectStore
        destinationPath: s3://relay-backups/prod
        s3Credentials:
          accessKeyId: {name: relay-backup-s3, key: ACCESS_KEY_ID}
          secretAccessKey: {name: relay-backup-s3, key: ACCESS_SECRET_KEY}
        wal: {compression: gzip}
      retentionPolicy: 30d
      schedule: "0 0 3 * * *"        # six fields, seconds first
    podMonitor: {enabled: true}      # Prometheus Operator
```

- The chart renders the `Cluster` (`<release>-langstroth-relay-db`; `initdb` of
  `database.name` owned by `database.user`), a `ScheduledBackup`, an optional
  `PodMonitor` and a NetworkPolicy that admits 5432 only from the relay pods,
  the cluster's own instances and the operator's namespace
  (`cnpg.networkPolicy.operatorNamespaceSelector`, default `cnpg-system`;
  change it if you installed the operator elsewhere, or the operator loses
  its instances).
- The operator makes the application user's Secret (`<cluster>-app`) and the
  CA (`<cluster>-ca`); the relay mounts `pgpass` and `ca.crt` from them and
  connects to `<cluster>-rw` (the primary) with `verify-full`. `pg_hba`
  rejects every non-TLS connection.
- Backups are required unless you say otherwise:
  `backups.enabled=false` renders only with
  `backups.acknowledgeNoBackups=true`. `method: plugin` uses the Barman Cloud
  plugin instead (CloudNativePG 1.26+; `plugin.parameters.barmanObjectName`
  names an `ObjectStore` you create).
- Restore is CloudNativePG's: a new cluster bootstrapped from the backup
  (`database.cnpg.bootstrap: {recovery: {source: origin}}` with
  `database.cnpg.externalClusters`), or point-in-time with
  `recoveryTarget`. See the CloudNativePG docs, "Recovery".
- Pods are Pod Security `restricted` compatible (the operator's defaults).
- Single instance (`instances: 1`): the operator's default PodDisruptionBudget
  blocks node drains; set `cnpg.enablePDB=false` if you accept the downtime.

### `bundled`

One Postgres 16 pod for a small self-host. No HA: if the node or the volume
is lost, you restore from the last dump. Pinned by digest (the chart refuses
an image tag without one), Pod Security `restricted` (UID 70, read-only root
filesystem, no capabilities), a `ReadWriteOncePod` volume.

```sh
PW=$(openssl rand -hex 24)
kubectl -n <ns> create secret generic relay-postgres-auth \
  --from-literal=password=$PW --from-literal=pgpass="*:*:*:relay:$PW"
```

```yaml
database:
  mode: bundled
  bundled:
    auth: {existingSecret: relay-postgres-auth}
    tls:
      certManager:
        issuerRef: {name: ligus-ca, kind: Issuer}   # a CA issuer: the Secret gets ca.crt
      # or: existingSecret: relay-postgres-tls      # tls.crt, tls.key, ca.crt
    backups:
      schedule: "17 3 * * *"
      keep: 7
```

- **TLS is required.** The server certificate comes from a
  `kubernetes.io/tls` Secret with the issuing CA under `ca.crt`, or from a
  cert-manager `Certificate` the chart renders when `tls.certManager.issuerRef`
  is set (DNS names `<release>-langstroth-relay-postgres[.<ns>[.svc[.cluster.local]]]`;
  cert-manager must serve `cert-manager.io/v1`). Without either the chart
  refuses to render, unless `allowPlaintextInNamespace: true` (development:
  `sslmode=disable`, still `scram-sha-256`). A small sidecar reloads
  Postgres's configuration when the mounted certificate changes, so renewals
  need no restart.
- **Roles.** The relay's role (`database.user`) is not a superuser; it owns
  `database.name` and nothing else. `pg_hba` admits it only to that database,
  only over TLS, with `scram-sha-256`; the `postgres` superuser only over the
  pod's local socket (`peer`); everything else is rejected.
- **NetworkPolicy.** Only the relay pods and the backup job reach 5432;
  Postgres itself has no egress.
- **Backups.** A CronJob runs `pg_dump --format=custom` over TLS to the
  backup volume, checks each dump with `pg_restore --list`, and keeps the
  newest `backups.keep`. `backups.enabled=false` renders only with
  `backups.acknowledgeNoBackups=true`. The volume
  (`backups-<release>-langstroth-relay-postgres-0`) is a claim of the StatefulSet,
  so it binds with the Postgres pod (`helm --wait` and Argo CD health don't
  wait for the first backup), the jobs run on that pod's node, and it is kept
  when the StatefulSet or the release is deleted. Postgres does not mount it.
  It lives on the same cluster: copy dumps off it too (Velero, or
  `kubectl cp` from a backup job's pod).
- Turning backups on or off later, or resizing a volume, changes the
  StatefulSet's claims, which Kubernetes does not allow in place:
  `kubectl delete statefulset <release>-langstroth-relay-postgres --cascade=orphan`
  then upgrade (the pod and its volumes stay).

#### Restoring the bundled Postgres

1. Pick a dump (`<db>-<UTC time>.dump`) from the backup job's logs
   (`kubectl -n <ns> logs job/<name>`) or by listing the backup volume.
2. `helm upgrade ... --reuse-values --set database.bundled.backups.restore.file=relay-20261117T031700Z.dump`.
   While it is set the relay runs **no replicas** (nothing writes during the
   restore), the backup CronJob is suspended, and a Job runs
   `pg_restore --clean --if-exists --no-owner --single-transaction`: one
   transaction, so a failed restore leaves the database as it was.
3. Wait for the Job: `kubectl -n <ns> wait --for=condition=Complete job/<release>-langstroth-relay-postgres-restore-<hash>`.
4. `helm upgrade ... --reuse-values --set database.bundled.backups.restore.file=`
   brings the relay back.

To restore a dump you have elsewhere, stream it into the pod:
`kubectl -n <ns> exec -i <release>-langstroth-relay-postgres-0 -- pg_restore -U postgres -d relay --clean --if-exists --no-owner --role=relay --single-transaction < relay.dump`
(with the relay scaled to zero).

Major Postgres upgrades are not automated: dump, install a new release (or
switch to `cnpg`) and restore.

### Deprecated keys

When `database.mode` is empty the old keys still work, unchanged, and the
install notes print a deprecation note. Setting both is refused.

| Old | Maps to |
|---|---|
| `externalDatabase.existingSecret` / `existingSecretKey` | `database.mode=external`, `database.external.existingSecret` / `existingSecretKey` |
| `externalDatabase.url` | `external`, with the URL rendered into a chart Secret as before (prefer a Secret of your own) |
| `postgres.enabled` + `postgres.*` | `bundled` in its old development form: same StatefulSet and volume, no TLS, no backups, the role is a superuser |

Moving off `postgres.enabled` (the old pod has no TLS and its role is a
superuser, so switch to a fresh database rather than in place):

```sh
ns=<ns>; rel=<release>; pg=$rel-langstroth-relay-postgres
# 1. Dump the old pod, and check the dump.
kubectl -n $ns exec $pg-0 -- pg_dump --format=custom -U relay -d relay > relay.dump
pg_restore --list relay.dump > /dev/null
# 2. Remove the old pod and its volume (the new StatefulSet has the same name).
kubectl -n $ns delete statefulset $pg && kubectl -n $ns delete pvc data-$pg-0
# 3. Switch modes (create the bundled Secrets first, see above).
helm upgrade $rel deploy/helm/langstroth-relay -n $ns --reuse-values \
  --set postgres.enabled=false --set database.mode=bundled \
  --set database.bundled.auth.existingSecret=relay-postgres-auth \
  --set database.bundled.tls.existingSecret=relay-postgres-tls --wait
# 4. Stop the relay, load the dump as the superuser over the pod's socket,
#    owned by the relay's role, and start the relay again.
kubectl -n $ns scale deploy -l app.kubernetes.io/instance=$rel,app.kubernetes.io/name=langstroth-relay --replicas=0
kubectl -n $ns exec -i $pg-0 -- pg_restore -U postgres -d relay --clean --if-exists \
  --no-owner --role=relay --single-transaction < relay.dump
kubectl -n $ns scale deploy -l app.kubernetes.io/instance=$rel,app.kubernetes.io/name=langstroth-relay --replicas=1
```

For `cnpg` step 2 is optional (Helm removes the old StatefulSet; delete its
PVC once you no longer need it), and the restore goes into the primary:
`kubectl -n $ns exec -i $rel-langstroth-relay-db-1 -c postgres -- pg_restore -U postgres -d relay ...`.

### langstroth-auth

The `langstroth-auth` chart has the same `database.*` block and the same three
modes, from the same templates (the `deploy/helm/langstroth-postgres` library
chart, linked into each chart's `charts/`). langstroth-auth gets its own cluster or
pod (`<release>-langstroth-auth-db`, `<release>-langstroth-auth-postgres`), database and
role `ligus_auth`, and its DSN at `/etc/langstroth-auth/db/database-url`
(`LANGSTROTH_AUTH_DATABASE_URL_FILE`). Any mode but `none` selects its Postgres
store; the old `store.driver=postgres` with `store.databaseUrl.existingSecret`
maps to `external`.

## Values

| Key | Default | Notes |
|---|---|---|
| `image.repository` / `tag` / `digest` | `ghcr.io/langstroth-ai/langstroth-relay`, appVersion | Pin by digest in production |
| `image.command` | `[/usr/local/bin/langstroth-relay]` | Runs the binary directly as UID 65532; also skips the Alpine image's root-only entrypoint |
| `topology` | `auto` | `split`, `single`, `auto` |
| `tunnel.mode` | `off` | `off`, `open`, `allowlist` (`tunnel.allowedHosts`). `open` admits any host; pair it with a token gate |
| `tunnel.apns.*` | off | Built-in push sender on the tunnel pod; key file from `existingSecret`, a Secret of its own (the chart refuses `config.existingSecret` or `LANGSTROTH_RELAY_APNS_*` in `config.env`, which reach relay-sync too) |
| `sync.replicas`, `sync.autoscaling`, `sync.pdb` | 1, off, off | Fixed in 2.0: anything else fails to render (see Scaling) |
| `database.mode` | empty | `external`, `cnpg`, `bundled` or `none`; empty derives it from the deprecated keys, else `none` (see Database) |
| `database.name` / `user` | `relay` | Database and role (`cnpg` and `bundled`) |
| `database.skipCapabilityCheck` | `false` | Render `cnpg`, cert-manager or PodMonitor objects without asking the cluster for their API (GitOps) |
| `database.external.existingSecret` / `existingSecretKey` / `cidrs` / `port` | empty, `DATABASE_URL`, `[]`, 5432 | DSN Secret mounted as a file; the database's addresses for egress |
| `database.cnpg.*` | 1 instance, 10Gi, backups required | `instances`, `imageName`, `storage`, `walStorage`, `resources`, `affinity`, `enablePDB`, `parameters`, `bootstrap`, `externalClusters`, `backups.*`, `podMonitor.*`, `networkPolicy.*` |
| `database.bundled.*` | Postgres 16 by digest, TLS required, backups on | `auth.existingSecret`, `tls.existingSecret` or `tls.certManager.issuerRef`, `allowPlaintextInNamespace`, `persistence.*`, `parameters`, `resources`, `backups.*` (`schedule`, `keep`, `persistence`, `restore.file`) |
| `postgres.*`, `externalDatabase.*` | | Deprecated aliases (see Database) |
| `memoryStore.maxBytes` | `100000000` | Memory store only: heap budget for workspace data (`LANGSTROTH_RELAY_MAX_STORE_BYTES`); writes past it get 507 |
| `contacts.enabled` | `true` | `/v1/contacts/*` (contact records + sealed drop boxes); `false` renders `LANGSTROTH_RELAY_CONTACTS=off` (404) |
| `contacts.*` (`maxRecordBytes`, `maxDropBytes`, `ttlDays`, `dropMaxRows`, `dropMaxBoxBytes`, `dropRetentionDays`, `reclaimHoldDays`, `maxContacts`, `dropRate`/`dropBurst`, `dropCidRate`/`dropCidBurst`, `writeRate`/`writeBurst`, `createRate`/`createBurst`) | `null` (binary defaults) | Contact size caps, TTL, drop-box bounds and rate limits; each maps to a `LANGSTROTH_RELAY_CONTACT*` variable (see the relay docs/reference.md). Rate limiters are per pod |
| `blobs.enabled` | `true` | Blob channel for encrypted attachments (`/v1/workspaces/{id}/blobs`); `false` renders `LANGSTROTH_RELAY_BLOBS=off` (404) |
| `blobs.*` (`maxBytes`, `roomMaxBytes`, `roomMaxCount`, `writerMaxBytes`, `writerMaxCount`, `totalMaxBytes`, `retentionDays`, `rate`/`burst`, `maxInflight`, `writerInflight`, `downloadRate`/`downloadBurst`, `clientDownloadRate`/`clientDownloadBurst`) | `null` (binary defaults: 25 MiB, 512 MiB, 2000, 128 MiB, 500, off, 30 days, 1/s burst 20, 16, 4, 0.5/s burst 100, 2/s burst 60) | Blob size, quotas (507), upload rate (429) and retention; each maps to a `LANGSTROTH_RELAY_BLOB*` variable (relay `docs/blobs.md`). With `ingress.streamingDefaults` the ingress-nginx `proxy-body-size` follows `maxBytes`. On the memory store blobs count toward `memoryStore.maxBytes` |
| `limits.*` (`roomMaxBytes`, `roomMaxEnvelopes`, `totalRoomBytes`, `maxRoomsPerClient`, `roomRetentionDays`, `ipRate`/`ipBurst`, `roomRate`/`roomBurst`, `tunnelPushRate`/`tunnelPushBurst`/`tunnelPushPerDay`, `metricsMaxTenants`) | `null` (off) | Room quotas (507), request rates (429 with `Retry-After`), idle-room retention and tunnel push limits; each maps to a `LANGSTROTH_RELAY_*` variable (relay docs/reference.md, "Community limits"). Rate limiters are per pod |
| `tenancy.existingSecret` / `tenancy.key` | `""` / `tenancy.json` | Tenancy on: a Secret holding the tenancy JSON (`docs/tenancy.md`), mounted as a file into every relay pod and read through `LANGSTROTH_RELAY_TENANCY_FILE`. `config.env` keys `LANGSTROTH_RELAY_TENANCY*` are refused |
| `githubRoutes` | `false` | Deprecated GitHub social routes for older clients (`LANGSTROTH_RELAY_GITHUB_ROUTES=on`); removed in relay v0.4 |
| `persistence.enabled` | `false` | Memory-store snapshot PVC (`single` only) |
| `config.env` | `{}` | Plain `LANGSTROTH_RELAY_*` settings (membership mode, retention, ...) |
| `config.existingSecret` | empty | Secret-valued settings, one key per setting name (`LANGSTROTH_RELAY_ACCESS_TOKENS`, `LANGSTROTH_RELAY_METRICS_TOKEN`, `LANGSTROTH_RELAY_TOKEN_PUBKEY`, ...), mounted 0400 as a directory the relay reads (`LANGSTROTH_RELAY_SECRETS_DIR`); never env |
| `clientIP.trustedProxies` / `clientIP.header` / `allowSharedBucket` | empty, `X-Forwarded-For`, off | Exact addresses of the ingress or LB whose forwarding header names the client (never the whole pod CIDR; see Scaling) |
| `ingress.*`, `httpRoute.*` | off | TLS required (`ingress.tls.secretName`, or `tls.terminatedUpstream` behind a TLS load balancer). `ingress.streamingDefaults` (on) sets 3600 s nginx/ALB timeouts and `proxy-buffering: off`; `httpRoute.timeouts` 3600 s. Requires `clientIP.trustedProxies` (or `allowSharedBucket`) and `metrics.token` (or `metrics.allowPublicUnauthenticated`) |
| `metrics.token.existingSecret` / `key` | empty, `token` | `LANGSTROTH_RELAY_METRICS_TOKEN` as a file; the ServiceMonitor uses it too |
| `metrics.serviceMonitor.*` | off | Prometheus Operator; set `bearerTokenSecret` when a metrics token is configured |
| `networkPolicy.enabled` | `true` | Ingress to 8443 from `ingressFrom` (empty = anywhere) |
| `networkPolicy.restrictEgress` | `true` | Egress only to DNS, the chosen database and `extraEgress` (for APNs, 443) |
| `networkPolicy.dns.namespaceSelector` / `podSelector` | `kube-system`, `k8s-app: kube-dns` | Where DNS egress may go. Change them if your resolver pods are labeled differently, or DNS stops resolving |

The chart refuses combinations that cannot work: more than one relay-sync
replica, autoscaling or a PDB, `split` without a database, the database
settings above (no operator API, no TLS, no backups without acknowledgment,
an unpinned bundled image, an external CIDR that is too broad or contains a
metadata address),
a snapshot PVC with a database or with `split`, `allowlist` without hosts. It
also refuses APNs settings outside `tunnel.apns.*`.

## Security

- Distroless static image, UID 65532, read-only root filesystem, all
  capabilities dropped, `RuntimeDefault` seccomp: passes Pod Security
  `restricted`.
- No Kubernetes API access: the service account has no token mounted.
- No secret in the environment: the database URL (or, for `cnpg` and
  `bundled`, the `pgpass` file and CA next to a password-free DSN),
  `config.existingSecret` and the APNs key are files mounted `0400` (with `fsGroup` the kubelet adds group
  read: `0440`, group 65532). The relay reads any setting `X` from `X_FILE` or
  from `$LANGSTROTH_RELAY_SECRETS_DIR/X` when `X` itself is unset, and refuses to
  start when one of those files can't be read or is empty (a wrong
  `fsGroup` or `runAsUser` then fails the rollout instead of opening the
  access gate).
- `checksum/secrets` rolls the pods when a Secret they read changes. It uses
  `lookup`, a constant under `helm template`; with Argo CD or Flux use
  [Reloader](https://github.com/stakater/Reloader) or bump `podAnnotations`.
- The chart generates no Secrets, so every render is the same.
- Clients require `https://` outside the cluster: terminate TLS at the Ingress
  or Gateway (cert-manager); the chart refuses an Ingress without TLS.
- `/metrics` is open unless a metrics token is set, so a public relay must
  have one.

## Scaling

`relay-sync` runs exactly one replica in 2.0, with `Recreate` (a rolling
update's surge pod would be a second store for a moment); the chart refuses
more replicas, an HPA or a PDB. With more than one:

- short pairing codes (`/v1/pair`) live in one process, so a code created on
  one replica is unknown to another;
- SSE nudges fire only on the replica that stored the envelope (clients still
  poll, so this costs latency, not correctness);
- rate limits are per process.

Rate limits key on the connection's remote address. Behind a Kubernetes
ingress every client shares the proxy's address (and one bucket: ten bad
pairing-code guesses from anyone block pairing for everyone for a minute), so
set `clientIP.trustedProxies` to the CIDRs your ingress controller or load
balancer connects from. The relay then reads `X-Forwarded-For` (or
`clientIP.header`) from those peers only, walking right to left past trusted
hops; a header from any other peer is ignored.

## Backups and upgrades

- **Back up Postgres, not pods.** Use point-in-time recovery where you can (a
  managed database's PITR, or `database.mode=cnpg` with WAL archiving); the
  bundled Postgres has nightly dumps (see Database). Connect with
  `sslmode=verify-full` and the server's CA. The relay holds ciphertext only,
  but the database also holds push tokens and pairing state: keep its dumps
  apart from the APNs key (together they are a push channel to every phone).
- **Migrations** run at startup in one transaction under a transaction-scoped
  Postgres advisory lock, so pods starting together can't race; it is safe
  behind a transaction-pooling PgBouncer (a session lock would leak there).
  A pod waits at most two minutes for the lock, then exits and is restarted.
  They are additive (expand/contract): a release
  never drops or renames what the previous release still reads, so an old and
  a new pod can overlap during an upgrade and you can roll back one release.
- **Upgrade order:** the relay first, then langstroth-auth, then the workspaces
  (`ligus` chart), with each serve image pinned to the desktop release your
  members run. relay-sync and the tunnel use `Recreate`: expect a few seconds
  without sync, and hosts reconnecting their tunnels.
- **Turning on `LANGSTROTH_RELAY_WORKSPACE_SCOPE=strict`:** issue
  workspace-scoped tokens first, roll them out to every client, then flip to
  `strict`; the reverse order locks out clients with unscoped tokens.
- The workspaces' serve and worker volumes hold identities and keys: the
  `ligus` chart's docs say not to back them up (revoke and re-enrol instead).

## Explicitly unsupported in 2.0

- More than one relay-sync replica, autoscaling, or tunnel/langstroth-auth HA.
- Mutually distrusting tenants on one relay, langstroth-auth or cluster.
- The deprecated in-chart Postgres (`postgres.enabled`) for anything but
  development; HA for the bundled Postgres (use `cnpg` with `instances: 3`).

## Image

Release images are `ghcr.io/langstroth-ai/langstroth-relay:<version>`
(`linux/amd64`, `linux/arm64`); the binary is
`/usr/local/bin/langstroth-relay` (the former `ligus-relay` and `hive-relay`
names are gone, so a custom `image.command` must use it).
`deploy/container/Dockerfile` builds the non-root distroless image used here,
cross-compiled for `linux/amd64` and `linux/arm64` with buildx:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  -f deploy/container/Dockerfile -t <registry>/langstroth-relay:<version> --push .
```

The repository-root `Dockerfile` (Alpine, root entrypoint that chowns a data
volume) is unchanged for hosts that mount root-owned volumes.

## CI

`.github/workflows/kind-e2e.yml` lints every `ci/*-values.yaml` (one per
database mode), renders every documented combination and the refusals,
builds the image, installs the chart on kind (split on the deprecated dev
Postgres, single on memory, split on the bundled Postgres with TLS, a backup
and a restore) under Pod Security `restricted` and runs `helm test`.
`deploy/helm_chart_test.go` and `deploy/helm_chart_db_test.go` (`go test`, needs helm)
check the rendered security properties of every mode and the refusals.
