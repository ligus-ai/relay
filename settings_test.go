package relay

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// envReaders are the functions whose first argument is a variable name.
var envReaders = map[string]bool{
	"getenv": true, "Getenv": true, "LookupEnv": true, "lookupRelayEnv": true,
	"envBool": true, "envFloat": true, "envInt64": true, "daysEnv": true,
	"pos": true, "nonNeg": true, "get": true,
}

var relayVarRe = regexp.MustCompile(`^LANGSTROTH_RELAY_[A-Z0-9_]+$`)

// envNamesInCode parses the relay package's non-test Go files and returns
// every environment variable name the code can read: each LANGSTROTH_RELAY_*
// string literal, each envPrefix + "X" expression, and each literal passed
// to an env-reading function (PORT, DATABASE_URL, FLY_APP_NAME, ...).
func envNamesInCode(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{} // name -> file:line
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		lit := func(e ast.Expr) (string, bool) {
			b, ok := e.(*ast.BasicLit)
			if !ok || b.Kind != token.STRING {
				return "", false
			}
			s, err := strconv.Unquote(b.Value)
			return s, err == nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				if s, ok := lit(x); ok && relayVarRe.MatchString(s) {
					found[s] = fset.Position(x.Pos()).String()
				}
			case *ast.BinaryExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "envPrefix" && x.Op == token.ADD {
					if s, ok := lit(x.Y); ok {
						found[envPrefix+s] = fset.Position(x.Pos()).String()
					}
				}
			case *ast.CallExpr:
				name := ""
				switch fn := x.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				}
				if envReaders[name] && len(x.Args) > 0 {
					if s, ok := lit(x.Args[0]); ok && regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`).MatchString(s) {
						found[s] = fset.Position(x.Pos()).String()
					}
				}
			}
			return true
		})
	}
	return found
}

// clearSettings unsets every documented setting for the test (and puts
// them back after it).
func clearSettings(t *testing.T) {
	t.Helper()
	for name := range settingsByName() {
		t.Setenv(name, "")
		os.Unsetenv(name)
		t.Setenv(name+"_FILE", "")
		os.Unsetenv(name + "_FILE")
	}
}

func helpText(t *testing.T, topic string) string {
	t.Helper()
	var b bytes.Buffer
	if err := cmdHelp([]string{topic}, &b); err != nil {
		t.Fatalf("help %s: %v", topic, err)
	}
	return b.String()
}

// Every environment variable the code reads is documented in `help config`.
func TestHelpConfigListsEveryEnvVarReadInCode(t *testing.T) {
	code := envNamesInCode(t)
	if len(code) < 100 {
		t.Fatalf("scan found only %d variable names; the scanner is broken", len(code))
	}
	help := helpText(t, "config")
	var missing []string
	for name, where := range code {
		if !regexp.MustCompile(`(^|[^A-Z0-9_])` + name + `([^A-Z0-9_]|$)`).MatchString(help) {
			missing = append(missing, name+" (read at "+where+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("`langstroth-relay help config` doesn't document:\n  %s\nadd them to relaySettingGroups in settings.go", strings.Join(missing, "\n  "))
	}
	// And the registry names a variable once each.
	seen := map[string]bool{}
	for _, g := range relaySettingGroups {
		for _, s := range g.Settings {
			if seen[s.Name] {
				t.Errorf("%s is listed twice", s.Name)
			}
			seen[s.Name] = true
		}
	}
}

// Every documented variable is still read by the code (no stale entries).
func TestHelpConfigListsNoVariableTheCodeDoesNotRead(t *testing.T) {
	code := envNamesInCode(t)
	for name := range settingsByName() {
		if _, ok := code[name]; !ok {
			t.Errorf("settings.go documents %s, but no code reads it", name)
		}
	}
}

// Numeric defaults in the help match what the code falls back to.
func TestHelpConfigDefaultsMatchCode(t *testing.T) {
	clearSettings(t)
	seen := map[string]float64{}
	var mu sync.Mutex
	f := func(name string, def float64) {
		mu.Lock()
		defer mu.Unlock()
		seen[name] = def
	}
	noteDefault.Store(&f)
	defer noteDefault.Store(nil)

	// Everything that reads a numeric setting with a default.
	New(Options{Store: newMemoryStore()})
	communityLimitsFromEnv()
	blobConfigFromEnv()
	contactConfigFromEnv()
	contactLimitersFromEnv()
	listCapFromEnv()
	daysEnv("LANGSTROTH_RELAY_INBOX_RETENTION_DAYS", defaultInboxMaxAgeDays)
	daysEnv("LANGSTROTH_RELAY_FRIEND_REQ_RETENTION_DAYS", defaultFriendReqMaxAgeDays)
	lim := defaultTunnelLimits()
	seen["LANGSTROTH_RELAY_TUNNEL_PUSH_RATE"] = lim.PushRate
	seen["LANGSTROTH_RELAY_TUNNEL_PUSH_BURST"] = lim.PushBurst
	seen["LANGSTROTH_RELAY_TUNNEL_PUSH_PER_DAY"] = float64(lim.PushPerDay)
	seen["LANGSTROTH_RELAY_MAX_BODY_BYTES"] = float64(bodyCapFromEnv())
	noteDefault.Store(nil)

	// The pruning loop and the tunnel hub read these with the same
	// defaults; keep the calls above in step with main.go and tunnel.go.
	settings := settingsByName()
	if len(seen) < 70 {
		t.Fatalf("observed only %d defaults; the hook is not reached", len(seen))
	}
	for name, def := range seen {
		s, ok := settings[name]
		if !ok {
			t.Errorf("%s has a default (%v) in code but is not in settings.go", name, def)
			continue
		}
		first := strings.Fields(s.Default)[0]
		got, err := strconv.ParseFloat(first, 64)
		if err != nil {
			t.Errorf("%s: help default %q is not a number, code default is %v", name, s.Default, def)
			continue
		}
		if got != def {
			t.Errorf("%s: help says default %v, code uses %v", name, got, def)
		}
	}
}

// help, help <topic> and every command's --help work; unknown topics are
// usage errors.
func TestHelpTopics(t *testing.T) {
	var b bytes.Buffer
	if err := cmdHelp(nil, &b); err != nil {
		t.Fatal(err)
	}
	top := b.String()
	for _, want := range []string{"HIVE_RELAY_*", "LIGUS_RELAY_*", "LIGUS_RELAY_URL", "Exit codes", "check", "keygen", "issue", "bootstrap-agent"} {
		if !strings.Contains(top, want) {
			t.Errorf("top-level help lacks %q", want)
		}
	}
	for _, name := range []string{"config", "deploy", "membership", "tunnel", "push", "backup", "troubleshooting", "check", "keygen", "issue", "bootstrap-agent"} {
		if !strings.Contains(top, "  "+name+" ") {
			t.Errorf("top-level help doesn't list topic %s", name)
		}
		if out := helpText(t, name); len(out) < 200 {
			t.Errorf("help %s is too short", name)
		}
	}
	deploy := helpText(t, "deploy")
	for _, want := range []string{"docker run", "oci://ghcr.io/langstroth-ai/charts/langstroth-relay", "fly deploy", "--ha=false", "systemctl enable --now", "/v1/health"} {
		if !strings.Contains(deploy, want) {
			t.Errorf("help deploy lacks %q", want)
		}
	}
	if !strings.Contains(helpText(t, "membership"), "attested") {
		t.Error("help membership doesn't mention attested mode")
	}
	if err := cmdHelp([]string{"nope"}, &b); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("unknown topic: got %v, want a usage error", err)
	}
}

// Every flag the issue and bootstrap-agent parsers accept is in their help.
func TestCommandHelpListsEveryFlag(t *testing.T) {
	src, err := os.ReadFile("cli.go")
	if err != nil {
		t.Fatal(err)
	}
	flags := regexp.MustCompile(`case "(--[a-z-]+)":`).FindAllStringSubmatch(string(src), -1)
	if len(flags) < 15 {
		t.Fatalf("found only %d flags in cli.go", len(flags))
	}
	both := helpText(t, "issue") + helpText(t, "bootstrap-agent")
	for _, f := range flags {
		if !strings.Contains(both, f[1]+" ") {
			t.Errorf("flag %s is parsed in cli.go but not in the command help", f[1])
		}
	}
}

func TestCheckJSON(t *testing.T) {
	clearSettings(t)
	srv := httptest.NewServer(New(Options{Store: newMemoryStore()}).Handler())
	defer srv.Close()

	dir := t.TempDir()
	t.Setenv("LANGSTROTH_RELAY_DATA_DIR", dir)
	var b bytes.Buffer
	if err := cmdCheck([]string{"--json", "--url", srv.URL}, &b); err != nil {
		t.Fatalf("check: %v\n%s", err, b.String())
	}
	var rep checkReport
	if err := json.Unmarshal(b.Bytes(), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b.String())
	}
	if !rep.OK || rep.Tool != "langstroth-relay check" {
		t.Fatalf("report: %+v", rep)
	}
	byName := map[string]checkResult{}
	for _, c := range rep.Checks {
		byName[c.Name] = c
	}
	if c := byName["health"]; c.Status != "pass" {
		t.Errorf("health: %+v", c)
	}
	if c := byName["tunnel-info"]; c.Status != "skip" {
		t.Errorf("tunnel-info with the tunnel off: %+v", c)
	}
	if c := byName["access"]; c.Status != "warn" {
		t.Errorf("access on an open relay: %+v", c)
	}
	if c := byName["store"]; c.Status != "pass" || !strings.Contains(c.Detail, dir) {
		t.Errorf("store: %+v", c)
	}
}

func TestCheckFailsOnOldNamesAndRequireDB(t *testing.T) {
	clearSettings(t)
	t.Setenv("LIGUS_RELAY_METRICS_TOKEN", "x")
	t.Setenv("LANGSTROTH_RELAY_REQUIRE_DB", "1")
	var b bytes.Buffer
	err := cmdCheck([]string{"--json"}, &b)
	if err != errChecksFailed {
		t.Fatalf("got %v, want errChecksFailed", err)
	}
	var rep checkReport
	if err := json.Unmarshal(b.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	fails := map[string]string{}
	for _, c := range rep.Checks {
		if c.Status == "fail" {
			fails[c.Name] = c.Detail
			if c.Fix == "" {
				t.Errorf("failed check %s has no fix", c.Name)
			}
		}
	}
	if !strings.Contains(fails["old-names"], "LIGUS_RELAY_METRICS_TOKEN -> LANGSTROTH_RELAY_METRICS_TOKEN") {
		t.Errorf("old-names: %q", fails["old-names"])
	}
	if _, ok := fails["store"]; !ok {
		t.Errorf("store should fail with REQUIRE_DB and no DATABASE_URL: %v", fails)
	}
	if strings.Contains(b.String(), "\"x\"") {
		t.Error("check echoed a setting's value")
	}
}

func TestCheckUsageErrors(t *testing.T) {
	var b bytes.Buffer
	for _, args := range [][]string{{"--nope"}, {"--url"}} {
		if err := cmdCheck(args, &b); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("check %v: got %v, want a usage error", args, err)
		}
	}
}

func TestCheckProbeReportsUnhealthy(t *testing.T) {
	clearSettings(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	rep := runChecks(nil, srv.URL)
	if rep.OK {
		t.Fatalf("a 503 health answer should fail the check: %+v", rep)
	}
}
