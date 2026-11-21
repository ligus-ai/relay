package relay

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// `langstroth-relay check`: the startup checks Main runs, plus a few
// warnings, without serving. With --url it also probes a running relay.
// The JSON shape matches the deploy/agent scripts' contract.

type checkResult struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | warn | fail | skip
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

type checkReport struct {
	Tool   string        `json:"tool"`
	OK     bool          `json:"ok"`
	Checks []checkResult `json:"checks"`
}

// checkHTTPClient is the client --url probes use (replaced in tests).
var checkHTTPClient = &http.Client{Timeout: 10 * time.Second}

func cmdCheck(args []string, w io.Writer) error {
	var asJSON bool
	var url string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--json":
			asJSON = true
		case a == "--url":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return usageErrorf("--url needs a value")
			}
			i++
			url = args[i]
		case strings.HasPrefix(a, "--url="):
			url = strings.TrimPrefix(a, "--url=")
		default:
			return usageErrorf("check: unknown flag %s (try `langstroth-relay check --help`)", a)
		}
	}
	rep := runChecks(os.Environ(), url)
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		for _, c := range rep.Checks {
			fmt.Fprintf(w, "%-4s  %-14s %s\n", c.Status, c.Name, c.Detail)
			if c.Fix != "" {
				fmt.Fprintf(w, "      %-14s fix: %s\n", "", c.Fix)
			}
		}
		if rep.OK {
			fmt.Fprintln(w, "ok")
		} else {
			fmt.Fprintln(w, "FAILED")
		}
	}
	if !rep.OK {
		return errChecksFailed
	}
	return nil
}

var errChecksFailed = fmt.Errorf("one or more checks failed")

func runChecks(environ []string, url string) checkReport {
	rep := checkReport{Tool: "langstroth-relay check", OK: true}
	add := func(name, status, detail, fix string) {
		if status == "fail" {
			rep.OK = false
		}
		rep.Checks = append(rep.Checks, checkResult{name, status, detail, fix})
	}
	fromErr := func(name string, err error, okDetail, fix string) {
		if err != nil {
			add(name, "fail", err.Error(), fix)
		} else {
			add(name, "pass", okDetail, "")
		}
	}

	fromErr("old-names", removedEnvError(environ), "no HIVE_RELAY_* or LIGUS_RELAY_* variables",
		"rename each variable as the message says, then unset the old name")
	fromErr("secret-files", secretFilesConfigError(os.Getenv), "every _FILE and secrets-dir file is readable",
		"fix the file's path, owner or mode, or unset the _FILE variable")

	// Access gate.
	if err := entitlementConfigError(); err != nil {
		add("access", "fail", err.Error(), "see `langstroth-relay help config` (Access)")
	} else {
		switch entitlementFromEnv().kind {
		case entSigned:
			add("access", "pass", "signed tokens required (LANGSTROTH_RELAY_TOKEN_PUBKEY), workspace scope "+workspaceScopeFromEnv(), "")
		case entTokens:
			add("access", "pass", "static token allowlist (LANGSTROTH_RELAY_ACCESS_TOKENS)", "")
		default:
			add("access", "warn", "open: any client may use the relay",
				"before sharing a public URL, set LANGSTROTH_RELAY_TOKEN_PUBKEY (see `langstroth-relay help keygen`)")
		}
	}

	fromErr("tenancy", tenancyConfigError(), tenancyDetail(), "see docs/tenancy.md")
	fromErr("removed", evictionConfigError(), "no removed settings set",
		"unset LANGSTROTH_RELAY_MAX_ENVELOPES and LANGSTROTH_RELAY_RETENTION_DAYS (or set them to 0)")

	// Routes, tunnel and push.
	tunnel := strings.ToLower(strings.TrimSpace(getenv("LANGSTROTH_RELAY_TUNNEL")))
	if tunnel == "" {
		tunnel = TunnelOff
	}
	if err := routesConfigError(getenv); err != nil {
		add("routes", "fail", err.Error(), "set LANGSTROTH_RELAY_ROUTES to all, or turn the tunnel on")
	} else {
		r := strings.ToLower(strings.TrimSpace(getenv("LANGSTROTH_RELAY_ROUTES")))
		if r == "" {
			r = "all"
		}
		add("routes", "pass", "routes "+r+", tunnel "+tunnel, "")
	}
	if err := apnsWithoutTunnelError(getenv); err != nil {
		add("push", "fail", err.Error(), "remove the APNs settings here, or turn the tunnel on")
	} else if tunnelOff(getenv) {
		add("push", "skip", "tunnel off, so no push", "")
	} else if s, err := APNsPushSenderFromEnv(); err != nil {
		add("push", "warn", err.Error()+"; the relay starts with push off", "see `langstroth-relay help push`")
	} else if s == nil {
		add("push", "skip", "APNs not configured; hosts fall back to ntfy if they have it", "")
	} else {
		add("push", "pass", "APNs push to "+strings.Join(s.Topics, ", ")+" ("+s.Env+")", "")
	}

	// Storage (no connection is made).
	dsn := getenv("DATABASE_URL")
	dir := getenv("LANGSTROTH_RELAY_DATA_DIR")
	switch {
	case envBool("LANGSTROTH_RELAY_REQUIRE_DB") && dsn == "":
		add("store", "fail", "LANGSTROTH_RELAY_REQUIRE_DB is set but DATABASE_URL is empty",
			"set DATABASE_URL (or DATABASE_URL_FILE), or unset LANGSTROTH_RELAY_REQUIRE_DB")
	case dsn != "":
		add("store", "pass", "Postgres (DATABASE_URL set; not contacted by check)", "")
	case dir != "":
		if err := dirWritable(dir); err != nil {
			add("store", "fail", "memory plus snapshot in "+dir+": "+err.Error(),
				"create the directory and make it writable by the relay's user")
		} else {
			add("store", "pass", "memory plus snapshot in "+filepath.Join(dir, snapshotFile), "")
		}
	default:
		add("store", "warn", "memory only: everything is lost on restart",
			"set LANGSTROTH_RELAY_DATA_DIR or DATABASE_URL to keep state")
	}

	if strings.TrimSpace(getenv("LANGSTROTH_RELAY_METRICS_TOKEN")) == "" {
		add("metrics", "warn", "/metrics is public", "set LANGSTROTH_RELAY_METRICS_TOKEN on a relay others can reach")
	} else {
		add("metrics", "pass", "/metrics needs the bearer token", "")
	}
	add("listen", "pass", resolveAddr(), "")

	if url != "" {
		probeRelay(strings.TrimRight(url, "/"), add)
	}
	return rep
}

func tenancyDetail() string {
	if strings.TrimSpace(getenv("LANGSTROTH_RELAY_TENANCY")) == "" {
		return "tenancy off"
	}
	return "tenancy config parses"
}

// dirWritable reports whether the relay could write its snapshot in dir.
// A missing directory is fine: the relay creates it on its first snapshot.
func dirWritable(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".check-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// probeRelay checks a running relay's health and tunnel endpoints.
func probeRelay(base string, add func(name, status, detail, fix string)) {
	resp, err := checkHTTPClient.Get(base + "/v1/health")
	if err != nil {
		add("health", "fail", err.Error(), "is the relay running and the URL right?")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		add("health", "fail", fmt.Sprintf("GET /v1/health: %d %s", resp.StatusCode, strings.TrimSpace(string(body))),
			"503 means the store is unreachable: check DATABASE_URL and the database")
	} else {
		add("health", "pass", "GET /v1/health: 200 "+strings.TrimSpace(string(body)), "")
	}

	resp, err = checkHTTPClient.Get(base + "/v1/tunnel/info")
	if err != nil {
		add("tunnel-info", "fail", err.Error(), "")
		return
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound:
		add("tunnel-info", "skip", "tunnel off on this relay", "")
	case http.StatusOK:
		var info struct {
			Versions []int `json:"versions"`
			Push     bool  `json:"push"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<12)).Decode(&info); err != nil {
			add("tunnel-info", "warn", "GET /v1/tunnel/info: unreadable answer: "+err.Error(), "")
			return
		}
		add("tunnel-info", "pass", fmt.Sprintf("tunnel on, versions %v, push %t", info.Versions, info.Push), "")
	default:
		add("tunnel-info", "warn", fmt.Sprintf("GET /v1/tunnel/info: %d", resp.StatusCode), "")
	}
}
