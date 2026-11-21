package relay

import (
	"fmt"
	"io"
	"strings"
)

// relaySetting documents one environment variable the relay reads. The list
// below is what `langstroth-relay help config` prints. settings_test.go
// keeps it honest: every variable name the code reads must be listed here,
// every name listed here must be read by the code, and every numeric default
// must match the default the code passes when the variable is unset.
type relaySetting struct {
	Name    string // the variable, e.g. LANGSTROTH_RELAY_PUSH_RATE
	Default string // as printed; a numeric default starts with the number
	Meaning string
}

type settingGroup struct {
	Title    string
	Settings []relaySetting
}

// relaySettingGroups is every setting, in the order help prints them.
var relaySettingGroups = []settingGroup{
	{"Listen address and storage", []relaySetting{
		{"PORT", "unset", "Listen on 0.0.0.0:$PORT (set by Fly, Cloud Run, Heroku and similar). Wins over LANGSTROTH_RELAY_ADDR."},
		{"LANGSTROTH_RELAY_ADDR", "0.0.0.0:8443", "Listen address (host:port) when PORT is unset."},
		{"DATABASE_URL", "unset", "Postgres connection URL. Set: the shared Postgres store (survives restarts and machine moves). Wins over LANGSTROTH_RELAY_DATA_DIR."},
		{"LANGSTROTH_RELAY_DATA_DIR", "unset", "Memory store plus a JSON snapshot (relay-state.json) in this directory, written every 5 s and on shutdown. Unset with no DATABASE_URL: memory only, lost on restart. The Alpine image sets /data."},
		{"LANGSTROTH_RELAY_REQUIRE_DB", "off", "1/true/yes/on: refuse to start without DATABASE_URL instead of falling back to the memory store."},
		{"LANGSTROTH_RELAY_SECRETS_DIR", "unset", "Directory of one file per setting (file name = variable name). A setting unset in the environment is read from <NAME>_FILE, else from this directory."},
	}},
	{"Access", []relaySetting{
		{"LANGSTROTH_RELAY_TOKEN_PUBKEY", "unset (open relay)", "Ed25519 issuer public key (64 hex chars or base64, from `langstroth-relay keygen`). Set: every /v1 request needs a signed hrt1 token. A key that does not parse stops the relay."},
		{"LANGSTROTH_RELAY_TOKEN_PUBKEY_NEXT", "unset", "A second issuer key accepted while the issuer rotates its key. Needs LANGSTROTH_RELAY_TOKEN_PUBKEY."},
		{"LANGSTROTH_RELAY_ACCESS_TOKENS", "unset", "Comma-separated static bearer tokens (a coarse gate). Used when LANGSTROTH_RELAY_TOKEN_PUBKEY is unset."},
		{"LANGSTROTH_RELAY_WORKSPACE_SCOPE", "off", "off, claims or strict: confine signed tokens to the workspace ids in their workspaces claim (issue --workspace). claims: only tokens that carry the claim; strict: every token must carry it. Any other value means strict."},
		{"LANGSTROTH_RELAY_TENANTS", "unset", "Comma-separated tenant ids; a signed token must carry a tid in the list. Needs LANGSTROTH_RELAY_TOKEN_PUBKEY and LANGSTROTH_RELAY_WORKSPACE_SCOPE=strict."},
		{"LANGSTROTH_RELAY_MEMBERSHIP", "off", "1 or true: relay-managed membership (roster mode). See `langstroth-relay help membership`."},
		{"LANGSTROTH_RELAY_MEMBERSHIP_PUBKEY", "unset", "Ed25519 key whose signed tokens identify callers for membership on an otherwise open relay."},
		{"LANGSTROTH_RELAY_METRICS_TOKEN", "unset (open /metrics)", "Bearer token required on GET /metrics."},
		{"LANGSTROTH_RELAY_TRUSTED_PROXIES", "unset", "Comma-separated CIDRs or IPs of reverse proxies whose forwarding header names the client. Unset: the TCP peer is the client and forwarding headers are ignored (behind a proxy every client then shares one rate-limit bucket)."},
		{"LANGSTROTH_RELAY_CLIENT_IP_HEADER", "X-Forwarded-For", "Header read from a trusted proxy, walked right to left past trusted hops, or a single-address header such as X-Real-IP."},
		{"FLY_APP_NAME", "unset", "Set by Fly.io. With it set and LANGSTROTH_RELAY_TRUSTED_PROXIES unset, the client address comes from Fly-Client-IP."},
		{"LANGSTROTH_RELAY_ROUTES", "all", "all, or tunnel: serve only /v1/tunnel/*, /v1/health and /metrics (the Helm chart's tunnel pod). tunnel needs LANGSTROTH_RELAY_TUNNEL on."},
		{"LANGSTROTH_RELAY_CONTACTS", "on", "off/0/false/no: unregister /v1/contacts/* (404)."},
		{"LANGSTROTH_RELAY_GITHUB_ROUTES", "off", "Deprecated, removed in v0.4. on: register the GitHub social routes (directory, account, friends) for older clients."},
		{"LANGSTROTH_RELAY_GITHUB_SOCIAL", "off", "Older name for LANGSTROTH_RELAY_GITHUB_ROUTES; either one turns the routes on."},
		{"LANGSTROTH_RELAY_FRIEND_CAP", "unset (no cap)", "Accepted friends per account (GitHub routes only)."},
		{"LANGSTROTH_RELAY_INVITE_REQUIRE_FRIEND", "off", "1: account invites reach only existing friends (GitHub routes only)."},
	}},
	{"Storage bounds", []relaySetting{
		{"LANGSTROTH_RELAY_MAX_STORE_BYTES", "0 (unbounded)", "Memory store: workspace bytes held across all workspaces; writes past it get 507. Set it below the memory limit on a relay untrusted clients can reach."},
		{"LANGSTROTH_RELAY_MAX_BODY_BYTES", "4194304 (4 MiB)", "Largest JSON request body."},
		{"LANGSTROTH_RELAY_MAX_LIST_BYTES", "16777216 (16 MiB)", "Bound on one keyring, candidates or presence listing, by stored bytes (0 = unbounded)."},
		{"LANGSTROTH_RELAY_MAX_KEYRING_PER_WS", "2000", "Key rotations stored per workspace; a new one past it gets 507."},
		{"LANGSTROTH_RELAY_MAX_KEYRING_BYTES_PER_WS", "16777216 (16 MiB)", "Stored keyring bytes per workspace; 507 past it."},
		{"LANGSTROTH_RELAY_MAX_ROTATION_BYTES", "262144 (256 KiB)", "One key rotation's size; 413 past it (0 = only the body cap)."},
		{"LANGSTROTH_RELAY_MAX_DEVICE_BLOBS_PER_WS", "1000", "Candidate and presence device entries per workspace."},
		{"LANGSTROTH_RELAY_MAX_PAIRINGS", "50000", "Live pairing codes per process (503 past it)."},
		{"LANGSTROTH_RELAY_MAX_PAIRINGS_PER_CLIENT", "20", "Live pairing codes one client may hold (429 past it; 0 = off)."},
		{"LANGSTROTH_RELAY_MAX_PAIRING_BYTES", "33554432 (32 MiB)", "Payload bytes all live pairing codes hold (503 past it; 0 = off)."},
		{"LANGSTROTH_RELAY_INBOX_MAX_ROWS", "5000", "Account-inbox rows per recipient on the memory store (oldest evicted)."},
		{"LANGSTROTH_RELAY_INBOX_RETENTION_DAYS", "30", "Postgres: prune inbox rows older than N days (0 = off)."},
		{"LANGSTROTH_RELAY_FRIEND_REQ_RETENTION_DAYS", "30", "Postgres: prune answered friend requests older than N days (0 = off)."},
		{"LANGSTROTH_RELAY_CONTACT_MAX_RECORD_BYTES", "65536 (64 KiB)", "One contact record's size; 413 past it."},
		{"LANGSTROTH_RELAY_CONTACT_MAX_DROP_BYTES", "65536 (64 KiB)", "One sealed drop's size; 413 past it."},
		{"LANGSTROTH_RELAY_CONTACT_TTL_DAYS", "30", "A contact record expires N days after its last write."},
		{"LANGSTROTH_RELAY_CONTACT_RECLAIM_HOLD_DAYS", "180", "After a record expires, only its old write key may recreate the cid for N days (0 = free at once)."},
		{"LANGSTROTH_RELAY_CONTACT_DROP_MAX_ROWS", "5000", "Drops per contact drop box."},
		{"LANGSTROTH_RELAY_CONTACT_DROP_MAX_BOX_BYTES", "4194304 (4 MiB)", "Drop bytes per contact drop box."},
		{"LANGSTROTH_RELAY_CONTACT_DROP_RETENTION_DAYS", "30", "Delete drops older than N days, hourly (0 = off)."},
		{"LANGSTROTH_RELAY_MAX_CONTACTS", "100000", "Memory store: live contact records (507 past it; 0 = unbounded)."},
		{"LANGSTROTH_RELAY_MAX_CONTACT_BYTES", "0 (off)", "Postgres: contact record plus drop bytes across the relay; new ones past it get 507."},
	}},
	{"Blobs (encrypted attachments)", []relaySetting{
		{"LANGSTROTH_RELAY_BLOBS", "on", "off/0/false/no: the blob routes answer 404."},
		{"LANGSTROTH_RELAY_BLOB_MAX_BYTES", "26214400 (25 MiB)", "One blob; 413 past it (0 keeps the default)."},
		{"LANGSTROTH_RELAY_BLOB_ROOM_MAX_BYTES", "536870912 (512 MiB)", "Blob bytes per workspace (0 = off); 507."},
		{"LANGSTROTH_RELAY_BLOB_ROOM_MAX_COUNT", "2000", "Blobs per workspace (0 = off); 507."},
		{"LANGSTROTH_RELAY_BLOB_WRITER_MAX_BYTES", "134217728 (128 MiB)", "Blob bytes per uploader per workspace (0 = off); 507."},
		{"LANGSTROTH_RELAY_BLOB_WRITER_MAX_COUNT", "500", "Blobs per uploader per workspace (0 = off); 507."},
		{"LANGSTROTH_RELAY_BLOB_TOTAL_MAX_BYTES", "0 (off)", "Blob bytes across the relay; 507."},
		{"LANGSTROTH_RELAY_BLOB_RETENTION_DAYS", "30", "A blob expires N days after upload (0 = keep until deleted)."},
		{"LANGSTROTH_RELAY_BLOB_RATE", "1", "Uploads per second per uploader per workspace (0 = off); 429."},
		{"LANGSTROTH_RELAY_BLOB_BURST", "20", "Burst for LANGSTROTH_RELAY_BLOB_RATE."},
		{"LANGSTROTH_RELAY_BLOB_MAX_INFLIGHT", "16", "Uploads being received at once, relay-wide (0 = off); 429."},
		{"LANGSTROTH_RELAY_BLOB_WRITER_INFLIGHT", "4", "Uploads being received at once per uploader (0 = off); 429."},
		{"LANGSTROTH_RELAY_BLOB_DOWNLOAD_RATE", "0.5", "Downloads per second of one blob (0 = off); 429."},
		{"LANGSTROTH_RELAY_BLOB_DOWNLOAD_BURST", "100", "Burst for LANGSTROTH_RELAY_BLOB_DOWNLOAD_RATE."},
		{"LANGSTROTH_RELAY_BLOB_CLIENT_DOWNLOAD_RATE", "2", "Blob downloads per second per downloader (0 = off); 429."},
		{"LANGSTROTH_RELAY_BLOB_CLIENT_DOWNLOAD_BURST", "60", "Burst for LANGSTROTH_RELAY_BLOB_CLIENT_DOWNLOAD_RATE."},
		{"LANGSTROTH_RELAY_BLOB_DOWNLOAD_INFLIGHT", "8", "Downloads being written at once, relay-wide (0 = off); 429."},
		{"LANGSTROTH_RELAY_BLOB_CLIENT_DOWNLOAD_INFLIGHT", "2", "Downloads being written at once per downloader (0 = off); 429."},
	}},
	{"Community limits (all off by default; quotas refuse with 507, never evict)", []relaySetting{
		{"LANGSTROTH_RELAY_ROOM_MAX_BYTES", "0 (off)", "Stored bytes per room (envelopes plus key rotations)."},
		{"LANGSTROTH_RELAY_ROOM_MAX_ENVELOPES", "0 (off)", "Stored envelopes per room."},
		{"LANGSTROTH_RELAY_MAX_TOTAL_ROOM_BYTES", "0 (off)", "Room bytes across the relay."},
		{"LANGSTROTH_RELAY_MAX_ROOMS_PER_CLIENT", "0 (off)", "Rooms one client may create; 429."},
		{"LANGSTROTH_RELAY_MAX_ROOMS", "0 (off)", "Rooms across the relay."},
		{"LANGSTROTH_RELAY_ROOM_RETENTION_DAYS", "0 (off)", "Delete a room's envelopes, key rotations and device blobs once nothing was appended for N days."},
		{"LANGSTROTH_RELAY_IP_RATE", "0 (off)", "Every request per client, per second (except /, /v1/health, /metrics); 429."},
		{"LANGSTROTH_RELAY_IP_BURST", "2x the rate", "Burst for LANGSTROTH_RELAY_IP_RATE."},
		{"LANGSTROTH_RELAY_ROOM_RATE", "0 (off)", "Every request to one room, all clients together, per second; 429."},
		{"LANGSTROTH_RELAY_ROOM_BURST", "2x the rate", "Burst for LANGSTROTH_RELAY_ROOM_RATE."},
		{"LANGSTROTH_RELAY_MAX_INFLIGHT_PER_CLIENT", "0 (off)", "Ordinary requests one client may hold open at once; 429."},
		{"LANGSTROTH_RELAY_METRICS_MAX_TENANTS", "50", "Tenants reported under their own metrics label; the rest are tenant=\"_other\"."},
	}},
	{"Rates and concurrency (a rate of 0 turns that limit off)", []relaySetting{
		{"LANGSTROTH_RELAY_PUSH_RATE", "100", "Unauthenticated writes per client per second."},
		{"LANGSTROTH_RELAY_PUSH_BURST", "300", "Burst for LANGSTROTH_RELAY_PUSH_RATE."},
		{"LANGSTROTH_RELAY_WS_WRITER_RATE", "20", "Envelope appends per (workspace, writer) per second."},
		{"LANGSTROTH_RELAY_WS_WRITER_BURST", "200", "Burst for LANGSTROTH_RELAY_WS_WRITER_RATE."},
		{"LANGSTROTH_RELAY_READ_RATE", "100", "Workspace reads per client per second; 429."},
		{"LANGSTROTH_RELAY_READ_BURST", "400", "Burst for LANGSTROTH_RELAY_READ_RATE."},
		{"LANGSTROTH_RELAY_MAX_SSE", "2000", "Concurrent event streams per process (503 past it; 0 = unlimited)."},
		{"LANGSTROTH_RELAY_MAX_SSE_PER_CLIENT", "100", "Concurrent event streams per client (429 past it; 0 = unlimited)."},
		{"LANGSTROTH_RELAY_GITHUB_RATE", "30", "GitHub social routes per client per second."},
		{"LANGSTROTH_RELAY_GITHUB_BURST", "120", "Burst for LANGSTROTH_RELAY_GITHUB_RATE."},
		{"LANGSTROTH_RELAY_INVITE_RATE", "0.05", "Account invites per (sender, recipient) per second."},
		{"LANGSTROTH_RELAY_INVITE_BURST", "10", "Burst for LANGSTROTH_RELAY_INVITE_RATE."},
		{"LANGSTROTH_RELAY_CONTACT_DROP_RATE", "0.05", "Contact drops per (sender, cid) per second."},
		{"LANGSTROTH_RELAY_CONTACT_DROP_BURST", "10", "Burst for LANGSTROTH_RELAY_CONTACT_DROP_RATE."},
		{"LANGSTROTH_RELAY_CONTACT_DROP_CID_RATE", "1", "Contact drops per cid, all senders together, per second."},
		{"LANGSTROTH_RELAY_CONTACT_DROP_CID_BURST", "60", "Burst for LANGSTROTH_RELAY_CONTACT_DROP_CID_RATE."},
		{"LANGSTROTH_RELAY_CONTACT_WRITE_RATE", "0.2", "Contact record updates per cid per second."},
		{"LANGSTROTH_RELAY_CONTACT_WRITE_BURST", "10", "Burst for LANGSTROTH_RELAY_CONTACT_WRITE_RATE."},
		{"LANGSTROTH_RELAY_CONTACT_CREATE_RATE", "0.01", "New contact records per client per second."},
		{"LANGSTROTH_RELAY_CONTACT_CREATE_BURST", "20", "Burst for LANGSTROTH_RELAY_CONTACT_CREATE_RATE."},
	}},
	{"Phone tunnel and push", []relaySetting{
		{"LANGSTROTH_RELAY_TUNNEL", "off", "off (/v1/tunnel/* answers 404), open (any host may register) or allowlist (only LANGSTROTH_RELAY_TUNNEL_HOSTS)."},
		{"LANGSTROTH_RELAY_TUNNEL_HOSTS", "unset", "Comma-separated host_ids admitted when LANGSTROTH_RELAY_TUNNEL=allowlist."},
		{"LANGSTROTH_RELAY_TUNNEL_PUSH_RATE", "1", "Pushes per tunnel host per second (0 = no limit)."},
		{"LANGSTROTH_RELAY_TUNNEL_PUSH_BURST", "5", "Burst for LANGSTROTH_RELAY_TUNNEL_PUSH_RATE."},
		{"LANGSTROTH_RELAY_TUNNEL_PUSH_PER_DAY", "2000", "Pushes per tunnel host per day (0 = no limit)."},
		{"LANGSTROTH_RELAY_APNS_KEY_FILE", "unset", "Path of the APNs auth key (AuthKey_<KEYID>.p8). Push is off unless a key, the key id, the team id and a topic are all set."},
		{"LANGSTROTH_RELAY_APNS_KEY", "unset", "The APNs key PEM inline (\\n escapes allowed), instead of LANGSTROTH_RELAY_APNS_KEY_FILE."},
		{"LANGSTROTH_RELAY_APNS_KEY_ID", "unset", "The APNs key's Key ID."},
		{"LANGSTROTH_RELAY_APNS_TEAM_ID", "unset", "Your Apple developer Team ID."},
		{"LANGSTROTH_RELAY_APNS_TOPIC", "unset", "Bundle id of the iPhone app build you publish (the default topic)."},
		{"LANGSTROTH_RELAY_APNS_TOPICS", "unset", "More bundle ids this relay may push to, comma-separated."},
		{"LANGSTROTH_RELAY_APNS_ENV", "auto", "auto (the environment each phone reports), sandbox or production."},
	}},
	{"Tenancy", []relaySetting{
		{"LANGSTROTH_RELAY_TENANCY", "unset (off)", "Tenancy config JSON, normally from LANGSTROTH_RELAY_TENANCY_FILE: several organisations on one relay (docs/tenancy.md). Needs LANGSTROTH_RELAY_METRICS_TOKEN; refused with LANGSTROTH_RELAY_TENANTS, LANGSTROTH_RELAY_ACCESS_TOKENS or the GitHub routes."},
	}},
	{"Removed (the relay refuses to start while set to anything but 0)", []relaySetting{
		{"LANGSTROTH_RELAY_MAX_ENVELOPES", "removed", "Use LANGSTROTH_RELAY_ROOM_MAX_ENVELOPES (refuses with 507, never evicts)."},
		{"LANGSTROTH_RELAY_RETENTION_DAYS", "removed", "Use LANGSTROTH_RELAY_ROOM_RETENTION_DAYS (expires whole idle rooms)."},
	}},
}

// settingsByName indexes relaySettingGroups.
func settingsByName() map[string]relaySetting {
	m := map[string]relaySetting{}
	for _, g := range relaySettingGroups {
		for _, s := range g.Settings {
			m[s.Name] = s
		}
	}
	return m
}

// writeSettings prints every setting with its default and meaning.
func writeSettings(w io.Writer) {
	for _, g := range relaySettingGroups {
		fmt.Fprintf(w, "\n%s\n", g.Title)
		for _, s := range g.Settings {
			fmt.Fprintf(w, "  %s  (default: %s)\n", s.Name, s.Default)
			for _, line := range wrapText(s.Meaning, 72) {
				fmt.Fprintf(w, "      %s\n", line)
			}
		}
	}
}

// wrapText breaks s into lines of at most width runes, on spaces.
func wrapText(s string, width int) []string {
	var lines []string
	var cur strings.Builder
	for _, word := range strings.Fields(s) {
		if cur.Len() > 0 && cur.Len()+1+len(word) > width {
			lines = append(lines, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(word)
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}
