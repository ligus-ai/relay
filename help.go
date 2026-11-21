package relay

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// The binary's built-in documentation: `langstroth-relay help [topic]`.
// Everything an operator or a coding agent needs to run the relay is here,
// so nobody needs the docs site to deploy it. settings_test.go checks that
// the config topic lists every variable the code reads.

// Exit codes of every subcommand.
const (
	exitOK      = 0
	exitFailed  = 1 // a check failed, or the server could not start
	exitUsage   = 2 // unknown command, flag or topic
	usageFooter = "Run `langstroth-relay help <topic>` for more. Topics: "
)

// errUsage marks a command-line mistake (exit 2, not 1).
var errUsage = errors.New("usage")

func usageErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errUsage}, args...)...)
}

const usageText = `langstroth-relay: the Langstroth sync relay for Ligus (Ligus is short for
ligustica). It stores and forwards end-to-end encrypted envelopes; it never
holds a workspace key or sees plaintext.

Usage:
  langstroth-relay                    run the server (configured by environment)
  langstroth-relay check [--json] [--url URL]
                                      check this environment's settings without
                                      serving; with --url also probe a running relay
  langstroth-relay keygen             print a new Ed25519 token-issuer keypair
  langstroth-relay issue --key HEX --sub ID [flags]
                                      mint a signed hrt1 access token
  langstroth-relay bootstrap-agent --key HEX --relay URL --room ID --sub ID [flags]
                                      print one command that enrolls a headless agent
  langstroth-relay help [topic]       this text, or a topic below
  langstroth-relay <command> --help   help for one command

Configuration is environment variables only, named LANGSTROTH_RELAY_* (plus
PORT and DATABASE_URL). Any of them can come from a file instead: <NAME>_FILE,
or $LANGSTROTH_RELAY_SECRETS_DIR/<NAME>. ` + "`langstroth-relay help config`" + ` lists
every variable with its default.

Quick start:
  langstroth-relay                         # http on 0.0.0.0:8443, memory only
  curl -fsS http://localhost:8443/v1/health # prints ok
  LANGSTROTH_RELAY_DATA_DIR=./data langstroth-relay   # keep state across restarts

The relay refuses to start (exit 1, the reason on stderr) when:
  - a HIVE_RELAY_* or LIGUS_RELAY_* variable is set, or a file with such a name
    is in LANGSTROTH_RELAY_SECRETS_DIR. These names from before the Langstroth
    rename are not read; the error names the LANGSTROTH_RELAY_* replacement,
    never the value. LIGUS_RELAY_URL (a Ligus client setting) is exempt.
  - a <NAME>_FILE or a file in LANGSTROTH_RELAY_SECRETS_DIR can't be read or
    is empty (an unreadable secret would otherwise read as unset: an open
    gate, or the memory store);
  - LANGSTROTH_RELAY_TOKEN_PUBKEY or _TOKEN_PUBKEY_NEXT is not an Ed25519 key,
    _NEXT is set without the first key, or LANGSTROTH_RELAY_TENANTS is empty,
    lacks LANGSTROTH_RELAY_TOKEN_PUBKEY or lacks WORKSPACE_SCOPE=strict;
  - LANGSTROTH_RELAY_TENANCY doesn't parse or conflicts with another setting;
  - the removed LANGSTROTH_RELAY_MAX_ENVELOPES or _RETENTION_DAYS is set to
    anything but 0;
  - LANGSTROTH_RELAY_ROUTES is not all or tunnel, or is tunnel with the
    tunnel off;
  - an APNs key, key id or team id is set while LANGSTROTH_RELAY_TUNNEL is off;
  - LANGSTROTH_RELAY_REQUIRE_DB is on without DATABASE_URL, or Postgres can't
    be reached or migrated.
` + "`langstroth-relay check`" + ` runs the same checks without serving (it doesn't
contact Postgres).

Exit codes: 0 ok; 1 failed (a check failed, the server could not start);
2 usage error (unknown command, flag or topic).

Endpoints: GET / (status page), GET /v1/health ("ok", or 503 when the store is
unreachable), GET /metrics (Prometheus; set LANGSTROTH_RELAY_METRICS_TOKEN).
`

// helpTopic is one `langstroth-relay help <name>` page.
type helpTopic struct {
	summary string
	write   func(w io.Writer)
}

func textTopic(s string) func(io.Writer) { return func(w io.Writer) { fmt.Fprint(w, s) } }

var helpTopics = map[string]helpTopic{
	"config":          {"every environment variable, its default and meaning", writeConfigHelp},
	"deploy":          {"one-shot deploys: Docker, Helm (OCI chart), Fly.io, systemd", textTopic(deployHelp)},
	"membership":      {"roster mode (LANGSTROTH_RELAY_MEMBERSHIP)", textTopic(membershipHelp)},
	"tunnel":          {"the phone tunnel between the Ligus iPhone app and ligus serve", textTopic(tunnelHelp)},
	"push":            {"push notifications to your own iPhone app build (APNs)", textTopic(pushHelp)},
	"backup":          {"what to back up and how to restore", textTopic(backupHelp)},
	"troubleshooting": {"common failures and their fixes", textTopic(troubleshootingHelp)},
	"check":           {"the check command", textTopic(checkHelp)},
	"keygen":          {"the keygen command", textTopic(keygenHelp)},
	"issue":           {"the issue command", textTopic(issueHelp)},
	"bootstrap-agent": {"the bootstrap-agent command", textTopic(bootstrapAgentHelp)},
}

func topicNames() []string {
	names := make([]string, 0, len(helpTopics))
	for n := range helpTopics {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// writeUsage prints the top-level help.
func writeUsage(w io.Writer) {
	fmt.Fprint(w, usageText)
	fmt.Fprintln(w, "\nHelp topics (langstroth-relay help <topic>):")
	for _, n := range topicNames() {
		fmt.Fprintf(w, "  %-16s %s\n", n, helpTopics[n].summary)
	}
}

// cmdHelp prints the top-level help or one topic. An unknown topic is a
// usage error.
func cmdHelp(args []string, w io.Writer) error {
	if len(args) == 0 {
		writeUsage(w)
		return nil
	}
	if len(args) > 1 {
		return usageErrorf("help takes one topic, got %d", len(args))
	}
	t, ok := helpTopics[strings.TrimPrefix(args[0], "--")]
	if !ok {
		return usageErrorf("no help topic %q. %s%s", args[0], usageFooter, strings.Join(topicNames(), ", "))
	}
	t.write(w)
	return nil
}

// wantsHelp reports whether a subcommand's arguments ask for its help.
func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "help" {
			return true
		}
	}
	return false
}

func writeConfigHelp(w io.Writer) {
	fmt.Fprint(w, `Configuration: environment variables

Every setting is an environment variable; set them before the relay starts.

Settings from files (for secrets): a setting X that is unset in the
environment is read from the file named by X_FILE, else from the file
$LANGSTROTH_RELAY_SECRETS_DIR/X. The environment wins over X_FILE, which wins
over the directory; one trailing newline is trimmed. Examples:
DATABASE_URL_FILE, LANGSTROTH_RELAY_METRICS_TOKEN_FILE,
LANGSTROTH_RELAY_TENANCY_FILE. LANGSTROTH_RELAY_APNS_KEY_FILE keeps its own
meaning (the path of the APNs key). An unreadable or empty file stops the
relay at startup.

Old names: HIVE_RELAY_* and LIGUS_RELAY_* are not read, and the relay refuses
to start while one is set (LIGUS_RELAY_URL, a Ligus client setting, is
exempt). Rename each to LANGSTROTH_RELAY_<same suffix>.

Storage: DATABASE_URL set -> Postgres; else LANGSTROTH_RELAY_DATA_DIR set ->
memory plus a JSON snapshot; else memory only (lost on restart).

Rates are tokens per second per client. A client is the TCP peer, or the
address a trusted proxy names (LANGSTROTH_RELAY_TRUSTED_PROXIES); IPv6 is
keyed on its /64. A 429 or 507 answer carries Retry-After and a JSON error
code; a refused write stored nothing.
`)
	writeSettings(w)
	fmt.Fprint(w, `
Not read by the relay itself but useful next to it: GOMEMLIMIT (Go runtime;
for example 800MiB on a 1 GB machine).
`)
}

const deployHelp = `Deploy: one-shot sequences

Each sequence ends with a health check that prints "ok". Replace <version>
with a release, for example 0.3.2 (images and charts are tagged without the
leading v). Clients need https: Fly terminates TLS for you; elsewhere put a
reverse proxy or an ingress with TLS in front, for example Caddy:
  relay.example.com { reverse_proxy localhost:8443 }
and set LANGSTROTH_RELAY_TRUSTED_PROXIES to the proxy's address so rate limits
see real clients. After deploying, give the relay's https URL to whoever
creates a Ligus workspace; it travels inside every invite.

Docker
  The published image is distroless: no shell, runs as UID 65532. Make the
  data volume writable by that user once, then run:

    docker volume create langstroth-relay-data
    docker run --rm -v langstroth-relay-data:/data alpine:3 chown 65532:65532 /data
    docker run -d --name langstroth-relay --restart unless-stopped \
      -p 8443:8443 -v langstroth-relay-data:/data \
      -e LANGSTROTH_RELAY_DATA_DIR=/data \
      ghcr.io/langstroth-ai/langstroth-relay:<version>
    curl -fsS http://localhost:8443/v1/health
    docker exec langstroth-relay /usr/local/bin/langstroth-relay check

  Postgres instead of the volume: -e DATABASE_URL=postgres://... (or mount the
  URL as a file and set DATABASE_URL_FILE). From a checkout, "docker build -t
  langstroth-relay ." builds an Alpine image that defaults to /data itself.

Helm (Kubernetes, the published OCI chart)
    helm install langstroth-relay \
      oci://ghcr.io/langstroth-ai/charts/langstroth-relay --version <version> \
      -n langstroth-relay --create-namespace --wait
    helm test langstroth-relay -n langstroth-relay
    kubectl -n langstroth-relay port-forward svc/langstroth-relay 8443:8443 &
    curl -fsS http://localhost:8443/v1/health

  That is one pod on the memory store (state is lost when the pod restarts).
  For a team: --set database.mode=bundled, cnpg or external (Postgres; the
  chart then splits sync and tunnel pods and sets
  LANGSTROTH_RELAY_REQUIRE_DB=1), and ingress.* with TLS. Settings go in
  config.env, secrets in a Secret named by config.existingSecret (mounted
  as LANGSTROTH_RELAY_SECRETS_DIR). Values: "helm show values
  oci://ghcr.io/langstroth-ai/charts/langstroth-relay --version <version>".
  For coding agents, the checkout's deploy/agent/*.sh scripts (see AGENTS.md)
  run preflight, secrets, install and verify non-interactively with --json.

Fly.io (one machine with a volume; Fly terminates TLS)
    git clone https://github.com/langstroth-ai/langstroth-relay
    cd langstroth-relay
    fly apps create <app>
    fly volumes create hive_data --size 1 --region <region> -a <app> --yes
    fly deploy . --config deploy/fly.toml -a <app> --primary-region <region> --ha=false
    curl -fsS https://<app>.fly.dev/v1/health

  --ha=false keeps one machine: the relay is single-replica by design. The
  volume name hive_data is what deploy/fly.toml mounts. Secrets: "fly secrets
  set -a <app> LANGSTROTH_RELAY_METRICS_TOKEN=...". For Postgres set
  DATABASE_URL as a secret and LANGSTROTH_RELAY_REQUIRE_DB=1.

systemd (a plain binary on a Linux host; Go 1.27 or newer to build it)
    go install github.com/langstroth-ai/langstroth-relay/cmd/langstroth-relay@v<version>
    sudo install -m 0755 "$(go env GOPATH)/bin/langstroth-relay" /usr/local/bin/
    sudo tee /etc/systemd/system/langstroth-relay.service >/dev/null <<'EOF'
    [Unit]
    Description=Langstroth relay
    Wants=network-online.target
    After=network-online.target

    [Service]
    ExecStart=/usr/local/bin/langstroth-relay
    DynamicUser=yes
    StateDirectory=langstroth-relay
    Environment=LANGSTROTH_RELAY_DATA_DIR=/var/lib/langstroth-relay
    Environment=LANGSTROTH_RELAY_ADDR=127.0.0.1:8443
    # Secrets as files, one per setting (file name = setting name):
    # LoadCredential=LANGSTROTH_RELAY_METRICS_TOKEN:/etc/langstroth-relay/metrics-token
    # Environment=LANGSTROTH_RELAY_SECRETS_DIR=%d
    Restart=on-failure
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    PrivateTmp=yes

    [Install]
    WantedBy=multi-user.target
    EOF
    sudo systemctl daemon-reload
    sudo systemctl enable --now langstroth-relay
    curl -fsS http://127.0.0.1:8443/v1/health

  It listens on loopback; put a TLS reverse proxy in front. Logs:
  "journalctl -u langstroth-relay". A checkout's deploy/agent/local.sh runs
  the same binary on loopback without systemd.

After any deploy
  langstroth-relay check --url https://relay.example.com   # health and tunnel
  Gate access before sharing a public URL: see "langstroth-relay help issue"
  and LANGSTROTH_RELAY_TOKEN_PUBKEY in "langstroth-relay help config".
`

const membershipHelp = `Membership: roster mode

Off by default: any client that passes the access gate may read and write
any workspace whose id it knows. Turn on relay-managed membership with

  LANGSTROTH_RELAY_MEMBERSHIP=1        (1 or true; anything else is off)

The relay then keeps a roster of {account, role} per workspace and enforces
it. It still never holds a workspace key or sees plaintext: the roster is
account ids, logins and coarse roles. Roles, highest first: owner, admin,
contributor, viewer.

  - A workspace is unclaimed until an identified caller sends
    POST /v1/workspaces/{id}/members/claim and becomes its owner. An
    unclaimed workspace behaves as if membership were off.
  - On a claimed workspace the caller's token subject (sub) must be on the
    roster: reads and writes (envelopes, presence, candidates, blob uploads)
    need any role, viewer included; key rotations need contributor or above;
    roster changes and invites need admin or above; a blob delete needs its
    uploader or an admin. Nobody can grant a role above their own
    or change a member who outranks them, and the last owner can't be
    removed or demoted.
  - Routes: GET/POST .../members, DELETE .../members/{account},
    POST .../members/claim, POST/GET .../invites,
    DELETE .../invites/{inviteId}, POST .../join (redeem an invite code).

Who the caller is comes from a signed hrt1 token's sub:
  - LANGSTROTH_RELAY_TOKEN_PUBKEY: every request needs a token (gate and
    identity), or
  - LANGSTROTH_RELAY_MEMBERSHIP_PUBKEY: the relay stays open for unclaimed
    workspaces and uses a signed token, when one is sent, as identity.
Mint tokens with "langstroth-relay issue"; "langstroth-relay
bootstrap-agent --admin-sub ..." adds a headless agent to a roster.

Attested mode (LANGSTROTH_RELAY_MEMBERSHIP=attested, where the workspace's
own admin devices publish a signed member list and every request carries a
member proof) is in design and not built. Setting the value today leaves
membership off.
`

const tunnelHelp = `Tunnel: the Ligus iPhone app to a ligus serve host

The tunnel lets the phone app reach a "ligus serve" host through the relay,
with no VPN and no inbound port on the host. Phone and host run a Noise
session end to end; the relay checks who may connect, then forwards bytes it
can't read.

Turn it on (off by default; /v1/tunnel/* answers 404 when off):
  LANGSTROTH_RELAY_TUNNEL=open                      any host may register
  LANGSTROTH_RELAY_TUNNEL=allowlist
  LANGSTROTH_RELAY_TUNNEL_HOSTS=<host_id>,<host_id>  only these hosts

With an access gate configured (LANGSTROTH_RELAY_TOKEN_PUBKEY or
LANGSTROTH_RELAY_ACCESS_TOKENS), a host's first registration must present a
token that passes it ("ligus remote enable --reg-token ...").

Routes (WebSockets need the subprotocol hive-tunnel.1):
  GET  /v1/tunnel/info      {"versions":[1],"push":bool,"billing":"none"}
  GET  /v1/tunnel/host      host control socket
  GET  /v1/tunnel/accept    host data socket per phone session
  GET  /v1/tunnel/connect   phone
  POST /v1/tunnel/revoke    host revokes one phone

Run one process for the tunnel: hosts' control connections live in memory.
The Helm chart's split topology runs a separate tunnel pod
(LANGSTROTH_RELAY_ROUTES=tunnel). Behind a proxy, allow WebSocket upgrades
and long idle timeouts (sockets are pinged every 20 s). Push limits per
host: LANGSTROTH_RELAY_TUNNEL_PUSH_RATE, _BURST, _PER_DAY. Push itself:
"langstroth-relay help push". Check it: "langstroth-relay check --url URL"
reports the tunnel and push state.
`

const pushHelp = `Push: notifications from your own relay (APNs)

Push goes out only through the tunnel, and APNs accepts a push only when it
is signed with a key from the Apple developer team that publishes the app. So
your relay can push to iPhone app builds you sign under your own Apple
developer account, not to someone else's build. Without push, "ligus serve"
falls back to ntfy when it is configured.

1. In the Apple developer portal (Certificates, Identifiers & Profiles,
   Keys) create a key with Apple Push Notifications service enabled.
   Download the .p8 once; note its Key ID and your Team ID.
2. Run the relay with the tunnel on and the key:

     LANGSTROTH_RELAY_TUNNEL=open \
     LANGSTROTH_RELAY_APNS_KEY_FILE=/secrets/AuthKey_ABC123DEFG.p8 \
     LANGSTROTH_RELAY_APNS_KEY_ID=ABC123DEFG \
     LANGSTROTH_RELAY_APNS_TEAM_ID=<team id> \
     LANGSTROTH_RELAY_APNS_TOPIC=<your app's bundle id> \
     langstroth-relay

   LANGSTROTH_RELAY_APNS_KEY holds the PEM inline instead of a file.
   LANGSTROTH_RELAY_APNS_TOPICS lists more bundle ids (a dev build next to
   the App Store build). LANGSTROTH_RELAY_APNS_ENV: auto (default; follows
   what each phone reports), sandbox or production.
3. Check: the log says "tunnel push via APNs", and GET /v1/tunnel/info
   reports "push": true ("langstroth-relay check --url URL" shows it).

An incomplete APNs configuration or a key that doesn't parse is logged and
leaves push off; the relay still starts. APNs settings on a process whose
tunnel is off stop it from starting (keep the key on the tunnel pod only).
Every push is logged as "tunnel push" with a result (sent, no_push_token,
push_failed, rate_limited, revoked, push_unavailable), never the device
token or the payload.
`

const backupHelp = `Backup and restore

The relay holds ciphertext, key rotations (encrypted), rosters, pairing
state, tunnel host registrations and push tokens. Devices keep full copies
of their workspaces and push again to an empty relay, but rosters, tunnel
registrations and push tokens live only here.

Memory store with LANGSTROTH_RELAY_DATA_DIR
  The state is one file, $LANGSTROTH_RELAY_DATA_DIR/relay-state.json,
  rewritten atomically (temp file plus rename) every 5 s and on shutdown.
  Back up: copy that file (safe while running), for example
    cp /data/relay-state.json /backup/relay-state-$(date -u +%Y%m%dT%H%M%SZ).json
  Restore: stop the relay, put the file back as relay-state.json, start it.
  An unreadable snapshot is logged and the relay starts empty, so keep the
  copies.

Postgres (DATABASE_URL)
  Back up the database, not the pods: a managed database's point-in-time
  recovery, CloudNativePG with WAL archiving (Helm database.mode=cnpg), or
    pg_dump --format=custom --file=relay.dump "$DATABASE_URL"
  Restore: stop the relay, pg_restore --clean --no-owner --dbname=... the
  dump, start the relay. The Helm chart's bundled Postgres takes nightly
  dumps and restores with database.bundled.backups.restore.file (see the
  chart README). Migrations at startup are additive, so you can roll the
  relay back one release.

Memory only (no DATABASE_URL, no LANGSTROTH_RELAY_DATA_DIR): nothing to back
up; everything is lost on restart.

Keep backups apart from the APNs key: together they are a push channel to
every registered phone. The token issuer's private key (from keygen) is not
on the relay; back it up wherever you issue tokens.
`

const troubleshootingHelp = `Troubleshooting

Start here:
  langstroth-relay check            # the startup checks, without serving
  langstroth-relay check --json --url https://relay.example.com

The relay exits at startup with "... names are no longer read: rename ..."
  A HIVE_RELAY_* or LIGUS_RELAY_* variable (or such a file in
  LANGSTROTH_RELAY_SECRETS_DIR) is set. Rename it as the message says. On Fly:
  "fly secrets list", then set the new name and unset the old one.

"cannot read" or "is empty" for a _FILE or LANGSTROTH_RELAY_SECRETS_DIR
  The file is missing, unreadable by the relay's user (UID 65532 in the
  published image) or empty. Fix the path, mode or fsGroup.

"LANGSTROTH_RELAY_REQUIRE_DB is set but DATABASE_URL is empty"
  Set DATABASE_URL (or DATABASE_URL_FILE), or unset REQUIRE_DB to allow the
  memory store.

"... is removed" (MAX_ENVELOPES, RETENTION_DAYS)
  Unset it or set it to 0; use LANGSTROTH_RELAY_ROOM_MAX_ENVELOPES or
  LANGSTROTH_RELAY_ROOM_RETENTION_DAYS.

Every client gets 401
  The access gate is on (LANGSTROTH_RELAY_TOKEN_PUBKEY or _ACCESS_TOKENS)
  and clients send no token or a token from another issuer or expired.
  Issue tokens with "langstroth-relay issue" against the matching key.

403 on one workspace
  WORKSPACE_SCOPE confines the token to other workspaces, or membership is
  on and the token's sub is not on the claimed workspace's roster (or its
  role is too low). See "langstroth-relay help membership".

429 for everyone at once
  The relay sits behind a proxy without LANGSTROTH_RELAY_TRUSTED_PROXIES, so
  every client shares the proxy's address and one rate-limit bucket. Set the
  proxy's CIDR.

507 refusals
  A quota is full (the JSON error says which: room_bytes, total_rooms,
  blob_room_bytes, ...). Raise the limit or let retention free space; the
  relay never evicts envelopes.

GET /v1/health answers 503
  The store is unreachable (Postgres down, wrong URL or credentials).

State is gone after a restart
  Neither DATABASE_URL nor LANGSTROTH_RELAY_DATA_DIR is set (memory only), or
  the data directory isn't on a persistent volume.

The phone can't connect through the tunnel
  /v1/tunnel/info answers 404: LANGSTROTH_RELAY_TUNNEL is off. With
  allowlist, the host's host_id must be in LANGSTROTH_RELAY_TUNNEL_HOSTS.
  A proxy must pass WebSocket upgrades and keep idle sockets for 60 s or
  more. More than one relay process: route the tunnel to one of them.

No push notifications
  /v1/tunnel/info shows "push": false: the APNs settings are incomplete or
  the key doesn't parse (the startup log says which). See
  "langstroth-relay help push".

Clients refuse the URL
  Clients require https. Terminate TLS in front of the relay.
`

const checkHelp = `langstroth-relay check [--json] [--url URL]

Runs the startup checks against this process's environment without serving:
old HIVE_RELAY_*/LIGUS_RELAY_* names, secret files, the access gate,
tenancy, removed settings, routes and the tunnel, push, storage, the metrics
token and the listen address. It does not connect to Postgres.

With --url, also probes a running relay: GET URL/v1/health must answer 200,
and GET URL/v1/tunnel/info reports whether the tunnel and push are on.

Flags:
  --json      print one JSON object on stdout:
              {"tool":"langstroth-relay check","ok":bool,
               "checks":[{"name","status","detail","fix"}]}
              status is pass, warn, fail or skip; a failed check says what to
              do in fix.
  --url URL   base URL of a running relay, for example https://relay.example.com
  -h, --help  this text

Exit codes: 0 no check failed (warnings allowed); 1 a check failed; 2 usage
error.

Examples:
  langstroth-relay check
  LANGSTROTH_RELAY_DATA_DIR=/data langstroth-relay check --json
  langstroth-relay check --url https://relay.example.com
`

const keygenHelp = `langstroth-relay keygen

Prints a fresh Ed25519 token-issuer keypair as hex:
  private_key=...   keep it where you issue tokens, never on the relay
  public_key=...    set it as LANGSTROTH_RELAY_TOKEN_PUBKEY on the relay

The relay only verifies tokens. With the public key set, every /v1 request
needs a token minted with "langstroth-relay issue --key <private_key>".
During an issuer key change, put the new public key in
LANGSTROTH_RELAY_TOKEN_PUBKEY_NEXT until every client has a new token.

Example:
  langstroth-relay keygen > issuer.txt && chmod 600 issuer.txt
`

const issueHelp = `langstroth-relay issue --key HEX --sub ID [flags]

Mints a signed hrt1 access token and prints it on stdout. Run it where the
issuer private key lives, not on the relay.

Flags:
  --key HEX            issuer private key (64 hex chars, from keygen); required
  --sub ID             subject: the account or device id; required. Membership
                       rosters key on it.
  --exp-days N         expire after N days (default: never)
  --workspace ID       confine the token to this workspace id (repeat; * = any).
                       Enforced with LANGSTROTH_RELAY_WORKSPACE_SCOPE=claims or strict.
  --tenant ID          tenant id (tid claim), checked against
                       LANGSTROTH_RELAY_TENANTS or the tenancy config
  --plan NAME          plan claim (free text, for example team)
  --max-members N      max-members claim
  --retention-days N   retention-days claim
  --turn               turn claim
  --cap NAME           capability claim (repeat), for example remove_member
  -h, --help           this text

Examples:
  langstroth-relay issue --key "$ISSUER_KEY" --sub alice --exp-days 365
  langstroth-relay issue --key "$ISSUER_KEY" --sub ci-bot \
    --workspace 0f3c... --exp-days 30
`

const bootstrapAgentHelp = `langstroth-relay bootstrap-agent --key HEX --relay URL --room ID --sub ID [flags]

Prints one command to run on a remote box so a headless Ligus agent joins a
workspace: it installs ligus, enrolls with a minted token and a connection
invite, and starts "ligus worker". The issuer key stays here; only the
agent's token leaves.

Flags:
  --key HEX          issuer private key (from keygen); required
  --relay URL        the relay's base URL; required
  --room ID          the workspace (room) id; required
  --sub ID           the agent's subject, for example github:<agent-id>; required
  --ws-key PASS      workspace passphrase to put in the invite
  --admin-sub ID     an owner or admin of the workspace: with it the agent is
                     added to the roster (membership on) using a one-hour
                     token for that admin
  --role ROLE        roster role (default contributor)
  --label NAME       worker label (default: the sub with : and / as -)
  --exp-days N       agent token lifetime in days (default 365)
  -h, --help         this text

The command goes to stdout, notes to stderr. Example:
  langstroth-relay bootstrap-agent --key "$ISSUER_KEY" \
    --relay https://relay.example.com --room 0f3c... \
    --sub github:my-agent --admin-sub github:me
`
