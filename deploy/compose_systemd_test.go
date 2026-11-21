package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const composeDir = "deploy/compose/langstroth-relay"

var relayImageRe = regexp.MustCompile(`image: ghcr\.io/langstroth-ai/langstroth-relay:(\S+)`)

// The compose files pin the published relay image to the release the charts
// ship (Chart.yaml appVersion), never a moving tag.
func TestComposeRelayImagePinnedToRelease(t *testing.T) {
	chart := readRepoFile(t, "deploy/helm/langstroth-relay/Chart.yaml")
	m := regexp.MustCompile(`(?m)^appVersion:\s*"?([^"\s]+)"?`).FindStringSubmatch(chart)
	if m == nil {
		t.Fatal("Chart.yaml has no appVersion")
	}
	for _, f := range []string{"compose.yaml", "compose.standalone.yaml"} {
		src := readRepoFile(t, filepath.Join(composeDir, f))
		tags := relayImageRe.FindAllStringSubmatch(src, -1)
		if len(tags) == 0 {
			t.Fatalf("%s: no relay image", f)
		}
		for _, tag := range tags {
			if tag[1] != m[1] {
				t.Errorf("%s: relay image tag %q, want the chart's appVersion %q", f, tag[1], m[1])
			}
		}
	}
}

// Both variants (with and without the tls profile) are valid compose files.
func TestComposeConfigValidates(t *testing.T) {
	if exec.Command("docker", "compose", "version").Run() != nil {
		t.Skip("docker compose not installed")
	}
	env := append(os.Environ(), "POSTGRES_PASSWORD=0123456789abcdef")
	for _, args := range [][]string{
		{"-f", "compose.yaml"},
		{"-f", "compose.yaml", "--profile", "tls"},
		{"-f", "compose.standalone.yaml"},
		{"-f", "compose.standalone.yaml", "--profile", "tls"},
	} {
		cmd := exec.Command("docker", append(append([]string{"compose"}, args...), "config", "-q")...)
		cmd.Dir, cmd.Env = composeDir, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("docker compose %v config: %v\n%s", args, err, out)
		}
	}
	// compose.yaml refuses to render without a database password.
	cmd := exec.Command("docker", "compose", "-f", "compose.yaml", "config", "-q")
	cmd.Dir = composeDir
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "POSTGRES_PASSWORD=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	if err := cmd.Run(); err == nil {
		t.Error("compose.yaml rendered without POSTGRES_PASSWORD")
	}
}

// The example env holds placeholders only, and every relay setting in it is
// either commented out or a documented name.
func TestComposeEnvExampleHoldsNoSecrets(t *testing.T) {
	src := readRepoFile(t, filepath.Join(composeDir, ".env.example"))
	ref := readRepoFile(t, "docs/reference.md")
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
		name, val, ok := strings.Cut(line, "=")
		if !ok || strings.ContainsAny(name, " \t") {
			continue
		}
		// Rate pairs are documented as `X_RATE` / `_BURST` / `_PER_DAY`.
		doc := name
		for _, suf := range []string{"_BURST", "_PER_DAY"} {
			if base, ok := strings.CutSuffix(name, suf); ok && strings.Contains(ref, "`"+base+"_RATE`") && strings.Contains(ref, "`"+suf+"`") {
				doc = base + "_RATE"
			}
		}
		if strings.HasPrefix(name, "LANGSTROTH_RELAY_") && !strings.Contains(ref, "`"+doc+"`") {
			t.Errorf(".env.example: %s is not in docs/reference.md", name)
		}
		if regexp.MustCompile(`^[0-9a-f]{32,}$`).MatchString(val) {
			t.Errorf(".env.example: %s looks like a real secret", name)
		}
	}
}

// The systemd unit is valid and keeps its hardening.
func TestSystemdUnit(t *testing.T) {
	unit := readRepoFile(t, "deploy/systemd/langstroth-relay.service")
	for _, want := range []string{"DynamicUser=yes", "NoNewPrivileges=yes", "CapabilityBoundingSet=\n", "ProtectSystem=strict",
		"EnvironmentFile=/etc/langstroth-relay/env", "StateDirectory=langstroth-relay", "SystemCallFilter=@system-service"} {
		if !strings.Contains(unit, want) {
			t.Errorf("langstroth-relay.service: missing %q", strings.TrimSpace(want))
		}
	}
	sa, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze not installed")
	}
	// verify resolves ExecStart, so point it at a stand-in binary.
	dir := t.TempDir()
	bin := filepath.Join(dir, "langstroth-relay")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := strings.Replace(unit, "ExecStart=/usr/local/bin/langstroth-relay", "ExecStart="+bin, 1)
	p := filepath.Join(dir, "langstroth-relay.service")
	if err := os.WriteFile(p, []byte(u), 0o644); err != nil {
		t.Fatal(err)
	}
	// Only findings about this unit count: verify also loads the host's own
	// units, which may warn about themselves.
	out, err := exec.Command(sa, "verify", "--man=no", p).CombinedOutput()
	if err != nil || strings.Contains(string(out), "langstroth-relay") {
		t.Errorf("systemd-analyze verify: %v\n%s", err, out)
	}
}
