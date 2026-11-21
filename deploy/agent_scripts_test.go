package deploy

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Tests for the agent deployment tooling in deploy/agent (AGENTS.md): exit
// codes, the --json contract agents parse, and that every scenario values
// file renders and holds no secret. None of them needs a cluster.

func agentScript(t *testing.T, env []string, script string, args ...string) (int, string, string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	cmd := exec.Command("bash", append([]string{filepath.Join("deploy/agent", script)}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("%s: %v", script, err)
	}
	return code, stdout.String(), stderr.String()
}

type agentCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
}

type agentReport struct {
	Tool   string         `json:"tool"`
	OK     *bool          `json:"ok"`
	Checks []agentCheck   `json:"checks"`
	Extra  map[string]any `json:"-"`
}

// parseOne asserts stdout is exactly one JSON object with tool, ok and
// well-formed checks.
func parseOne(t *testing.T, tool, stdout string) agentReport {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 1 {
		t.Fatalf("%s --json must print exactly one line, got %d:\n%s", tool, len(lines), stdout)
	}
	var r agentReport
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatalf("%s --json is not JSON: %v\n%s", tool, err, stdout)
	}
	if r.Tool != tool || r.OK == nil {
		t.Fatalf("%s --json lacks tool/ok: %s", tool, stdout)
	}
	for _, c := range r.Checks {
		switch c.Status {
		case "pass", "warn", "fail", "skip":
		default:
			t.Fatalf("%s: check %q has status %q", tool, c.Name, c.Status)
		}
		if c.Name == "" || c.Detail == "" {
			t.Fatalf("%s: check without name or detail: %+v", tool, c)
		}
		if c.Status == "fail" && c.Fix == "" {
			t.Fatalf("%s: failed check %q gives no fix", tool, c.Name)
		}
	}
	return r
}

func TestAgentScriptsShellcheck(t *testing.T) {
	sc, err := exec.LookPath("shellcheck")
	if err != nil {
		t.Skip("shellcheck not installed")
	}
	files, _ := filepath.Glob("deploy/agent/*.sh")
	for i, f := range files {
		files[i] = filepath.Base(f)
	}
	cmd := exec.Command(sc, append([]string{"-x"}, files...)...)
	cmd.Dir = "deploy/agent" // so -x follows source "$(dirname "$0")/lib.sh"
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shellcheck: %v\n%s", err, out)
	}
}

func TestAgentScriptsUsageExit2(t *testing.T) {
	for _, s := range []string{"preflight.sh", "bootstrap-secrets.sh", "install.sh", "verify.sh", "teardown.sh", "local.sh", "cnpg-operator.sh"} {
		code, stdout, _ := agentScript(t, nil, s, "--no-such-flag")
		if code != 2 {
			t.Errorf("%s --no-such-flag: exit %d, want 2", s, code)
		}
		if stdout != "" {
			t.Errorf("%s: usage errors go to stderr, stdout got %q", s, stdout)
		}
	}
	if code, _, _ := agentScript(t, nil, "install.sh", "--scenario", "nope"); code != 2 {
		t.Errorf("install.sh unknown scenario: exit %d, want 2", code)
	}
}

func TestAgentPreflightUnknownContextJSON(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	// An empty kubeconfig: nothing on this machine is touched or contacted.
	kc := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(kc, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := agentScript(t, []string{"KUBECONFIG=" + kc}, "preflight.sh", "--context", "no-such-context", "--json")
	if code != 3 {
		t.Fatalf("preflight on a missing context: exit %d, want 3", code)
	}
	r := parseOne(t, "preflight", stdout)
	if *r.OK {
		t.Fatal("preflight on a missing context must report ok=false")
	}
}

func TestAgentLocalJSONAndExposure(t *testing.T) {
	dir := t.TempDir()
	code, stdout, _ := agentScript(t, nil, "local.sh", "status", "--data-dir", dir, "--json")
	if code != 1 {
		t.Fatalf("status of a stopped relay: exit %d, want 1", code)
	}
	if r := parseOne(t, "local", stdout); *r.OK {
		t.Fatal("status of a stopped relay must be ok=false")
	}
	// A non-loopback bind is the human's decision: refused without the flag,
	// before anything is started or written.
	code, stdout, _ = agentScript(t, nil, "local.sh", "start", "--data-dir", filepath.Join(dir, "x"), "--addr", "0.0.0.0", "--json")
	r := parseOne(t, "local", stdout)
	if code != 1 || *r.OK || len(r.Checks) != 1 || r.Checks[0].Name != "exposure" {
		t.Fatalf("start --addr 0.0.0.0: exit %d, %s", code, stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, "x")); err == nil {
		t.Fatal("a refused start must not create the data directory")
	}
	code, stdout, _ = agentScript(t, nil, "local.sh", "stop", "--data-dir", dir, "--json")
	if code != 0 || !*parseOne(t, "local", stdout).OK {
		t.Fatalf("stop of a stopped relay must be a no-op success: exit %d %s", code, stdout)
	}
}

// Scenario values files hold settings only; every secret is a Secret made by
// bootstrap-secrets.sh or a file the human wrote.
func TestAgentScenarioValuesHoldNoSecrets(t *testing.T) {
	files, _ := filepath.Glob("deploy/agent/values/*.yaml")
	if len(files) == 0 {
		t.Fatal("no scenario values files")
	}
	bad := regexp.MustCompile(`(?i)(password|token|secret|dsn|databaseUrl|privateKey)\s*:\s*["']?[A-Za-z0-9+/=_-]{8,}`)
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			if bad.MatchString(line) && !strings.Contains(line, "existingSecret") && !strings.Contains(line, "_file:") && !strings.Contains(line, "secretName") {
				t.Errorf("%s: looks like a secret value: %s", f, line)
			}
		}
	}
}

// Every scenario renders with the Secret names install.sh passes, and the
// fail-closed defaults (NetworkPolicy, tunnel off) survive.
func TestAgentScenariosRender(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}
	render := func(chart string, args ...string) (string, error) {
		cmd := exec.Command(helm, append([]string{"template", "t", chart, "--kube-version", "1.30.0", "--api-versions", "postgresql.cnpg.io/v1"}, args...)...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	relay, auth := "deploy/helm/langstroth-relay", "deploy/helm/langstroth-auth"
	v := func(s string) string { return "deploy/agent/values/" + s + ".yaml" }
	backup := filepath.Join(t.TempDir(), "backup.yaml")
	_ = os.WriteFile(backup, []byte("database:\n  cnpg:\n    backups:\n      barmanObjectStore:\n        destinationPath: s3://b/r\n        s3Credentials:\n          accessKeyId: {name: s3, key: id}\n          secretAccessKey: {name: s3, key: key}\n"), 0o600)
	cidrs := filepath.Join(t.TempDir(), "cidrs.yaml")
	_ = os.WriteFile(cidrs, []byte("database:\n  external:\n    cidrs: [10.20.0.15/32]\n"), 0o600)
	cases := map[string][]string{
		"eval-memory":    {relay, "-f", v("eval-memory"), "--set", "config.existingSecret=t-langstroth-relay-env"},
		"team-bundled":   {relay, "-f", v("team-bundled"), "--set", "config.existingSecret=t-langstroth-relay-env", "--set", "database.bundled.auth.existingSecret=a", "--set", "database.bundled.tls.existingSecret=b"},
		"team-cnpg-eval": {relay, "-f", v("team-cnpg-eval"), "--set", "config.existingSecret=t-langstroth-relay-env"},
		"team-cnpg":      {relay, "-f", v("team-cnpg"), "-f", backup, "--set", "config.existingSecret=t-langstroth-relay-env"},
		"team-external":  {relay, "-f", v("team-external"), "-f", cidrs, "--set", "config.existingSecret=t-langstroth-relay-env", "--set", "database.external.existingSecret=d"},
	}
	authBase := []string{auth, "-f", v("auth-common"), "-f", v("auth-example-human"), "--set", "signingKey.existingSecret=k", "--set", "adminToken.existingSecret=a"}
	cases["auth-file"] = append(append([]string{}, authBase...), "-f", v("auth-file"))
	cases["auth-bundled"] = append(append([]string{}, authBase...), "-f", v("auth-bundled"), "--set", "database.bundled.auth.existingSecret=p", "--set", "database.bundled.tls.existingSecret=tls")
	cases["auth-cnpg-eval"] = append(append([]string{}, authBase...), "-f", v("auth-cnpg-eval"))
	cases["auth-external"] = append(append([]string{}, authBase...), "-f", v("auth-external"), "-f", cidrs, "--set", "database.external.existingSecret=d")
	for name, args := range cases {
		out, err := render(args[0], args[1:]...)
		if err != nil {
			t.Errorf("scenario %s does not render: %v\n%s", name, err, out)
			continue
		}
		if !strings.Contains(out, "kind: NetworkPolicy") {
			t.Errorf("scenario %s renders no NetworkPolicy", name)
		}
		if args[0] == relay && !regexp.MustCompile(`name: LANGSTROTH_RELAY_TUNNEL\s+value: "off"`).MatchString(out) {
			t.Errorf("scenario %s must keep the tunnel off", name)
		}
	}
	// team-cnpg keeps backups on: without the human's destination it refuses.
	if out, err := render(relay, "-f", v("team-cnpg"), "--set", "config.existingSecret=x"); err == nil {
		t.Errorf("team-cnpg rendered without a backup destination:\n%.300s", out)
	}
}

// The scripts never fall back to the current kube context.
func TestAgentScriptsRequireContext(t *testing.T) {
	runs := map[string][]string{
		"preflight.sh":         {"--namespace", "x", "--json"},
		"bootstrap-secrets.sh": {"--scenario", "eval-memory", "--namespace", "x", "--json"},
		"install.sh":           {"--scenario", "eval-memory", "--namespace", "x", "--json"},
		"verify.sh":            {"--namespace", "x", "--json"},
		"teardown.sh":          {"--namespace", "x", "--json"},
		"cnpg-operator.sh":     {"status", "--json"},
	}
	for s, args := range runs {
		code, _, stderr := agentScript(t, nil, s, args...)
		if code != 2 || !strings.Contains(stderr, "--context is required") {
			t.Errorf("%s without --context: exit %d, want 2 (%s)", s, code, strings.TrimSpace(stderr))
		}
	}
}

// Flag values reach helm --set: a comma would add keys (proven:
// --image-tag 'dev,networkPolicy.enabled=false' rendered no NetworkPolicy).
func TestAgentInstallRefusesInjectedValues(t *testing.T) {
	for _, args := range [][]string{
		{"--image-tag", "dev,networkPolicy.enabled=false"},
		{"--image-repo", "x,tunnel.mode=open"},
		{"--release", "r,networkPolicy.enabled=false"},
		{"--namespace", "ns\nx"},
	} {
		all := append([]string{"--context", "c", "--scenario", "eval-memory", "--json"}, args...)
		if code, _, _ := agentScript(t, nil, "install.sh", all...); code != 2 {
			t.Errorf("install.sh %v: exit %d, want 2", args, code)
		}
	}
}

func libCall(t *testing.T, stdin, script string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", "-c", "source deploy/agent/lib.sh; "+script)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}

// teardown --delete-data matches this release's PVC names exactly.
func TestAgentTeardownPVCsAreThisReleasesOnly(t *testing.T) {
	in := strings.Join([]string{
		"persistentvolumeclaim/langstroth-relay-data",
		"persistentvolumeclaim/data-langstroth-relay-postgres-0",
		"persistentvolumeclaim/langstroth-relay-db-1",
		"persistentvolumeclaim/langstroth-relay-b-data",
		"persistentvolumeclaim/data-langstroth-relay-b-postgres-0",
		"persistentvolumeclaim/other-langstroth-relay-data",
	}, "\n") + "\n"
	_, out := libCall(t, in, "release_pvcs langstroth-relay")
	got := strings.Fields(out)
	want := []string{"persistentvolumeclaim/langstroth-relay-data", "persistentvolumeclaim/data-langstroth-relay-postgres-0", "persistentvolumeclaim/langstroth-relay-db-1"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("release_pvcs langstroth-relay = %v, want %v", got, want)
	}
}

// install stops (exit 4) when values switch off a fail-closed default.
func TestAgentRenderedFailClosed(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}
	render := func(extra ...string) string {
		args := append([]string{"template", "t", "deploy/helm/langstroth-relay", "--kube-version", "1.30.0",
			"-f", "deploy/agent/values/eval-memory.yaml", "--set", "config.existingSecret=t-env"}, extra...)
		out, err := exec.Command(helm, args...).Output()
		if err != nil {
			t.Fatalf("helm template %v: %v", extra, err)
		}
		return string(out)
	}
	if code, _ := libCall(t, render(), "check_rendered"); code != 0 {
		t.Fatal("the eval-memory defaults must pass check_rendered")
	}
	if code, _ := libCall(t, render("--set", "networkPolicy.enabled=false"), "check_rendered"); code == 0 {
		t.Fatal("networkPolicy.enabled=false passed check_rendered")
	}
	open := render("--set", "tunnel.mode=open")
	if code, _ := libCall(t, open, "check_rendered"); code == 0 {
		t.Fatal("tunnel.mode=open passed check_rendered without the human's approval")
	}
	if code, _ := libCall(t, open, "check_rendered 1"); code != 0 {
		t.Fatal("tunnel.mode=open with --human-approved-exposure must pass")
	}
}

// A host name that only looks like loopback is still exposure.
func TestAgentLocalLoopbackIsLiteral(t *testing.T) {
	dir := t.TempDir()
	code, stdout, _ := agentScript(t, nil, "local.sh", "start", "--data-dir", filepath.Join(dir, "x"), "--addr", "127.0.0.1.nip.io", "--json")
	r := parseOne(t, "local", stdout)
	if code != 1 || len(r.Checks) != 1 || r.Checks[0].Name != "exposure" {
		t.Fatalf("start --addr 127.0.0.1.nip.io: exit %d, %s", code, stdout)
	}
}

// Only the deploy skills' SKILL.md files under .claude/ can be committed.
func TestAgentGitignoreKeepsClaudeDirPrivate(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ignored := func(p string) bool {
		return exec.Command("git", "check-ignore", "-q", "--no-index", p).Run() == nil
	}
	for _, p := range []string{".claude/skills/relay-deploy-k8s/SKILL.md", ".claude/skills/relay-run-local/SKILL.md"} {
		if ignored(p) {
			t.Errorf("%s must be tracked", p)
		}
	}
	for _, p := range []string{".claude/settings.json", ".claude/skills/private/SKILL.md", ".claude/skills/relay-run-local/notes.md", ".claude/worktrees/x"} {
		if !ignored(p) {
			t.Errorf("%s must be ignored", p)
		}
	}
}

// The scripts read LANGSTROTH_* settings and still accept the LIGUS_* names
// from before the rename; two different values are a usage error.
func TestAgentPickEnv(t *testing.T) {
	for _, tc := range []struct {
		env, want string
		code      int
	}{
		{"", "dflt", 0},
		{"LIGUS_NAMESPACE=old", "old", 0},
		{"LANGSTROTH_NAMESPACE=new", "new", 0},
		{"LANGSTROTH_NAMESPACE=same LIGUS_NAMESPACE=same", "same", 0},
		{"LANGSTROTH_NAMESPACE=new LIGUS_NAMESPACE=old", "", 2},
	} {
		code, out := libCall(t, "", "unset LANGSTROTH_NAMESPACE LIGUS_NAMESPACE; export "+tc.env+" X=1; pick_env NS LANGSTROTH_NAMESPACE LIGUS_NAMESPACE dflt; printf %s \"$NS\"")
		if code != tc.code || (code == 0 && out != tc.want) {
			t.Errorf("%q: exit %d %q, want exit %d %q", tc.env, code, out, tc.code, tc.want)
		}
	}
}
