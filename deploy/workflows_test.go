package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Supply-chain guard for .github/workflows and the Fly deploy. These are
// plain-text checks (no YAML dependency) over files whose shape we control.

func readRepoFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var usesRe = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)`)
var shaPinRe = regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)

// localWorkflowRe is a reusable workflow from this repository: it runs at the
// same commit as its caller, so it needs no pin.
var localWorkflowRe = regexp.MustCompile(`^\./\.github/workflows/[\w.-]+\.ya?ml$`)

// writeScopes lists the only write scopes a workflow may request:
// release.yml pushes images and charts to ghcr.io.
var writeScopes = map[string][]string{".github/workflows/release.yml": {"packages: write"}}

func TestWorkflows_PinnedAndLeastPrivilege(t *testing.T) {
	files, err := filepath.Glob(".github/workflows/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	for _, f := range files {
		src := readRepoFile(t, f)
		if !regexp.MustCompile(`(?m)^permissions:`).MatchString(src) {
			t.Errorf("%s: no top-level permissions block (the token gets the repo default scope)", f)
		}
		if strings.Contains(src, "pull_request_target") {
			t.Errorf("%s: pull_request_target runs fork code with a privileged token", f)
		}
		for _, m := range regexp.MustCompile(`(?m)^\s*([\w-]+:\s*write)`).FindAllStringSubmatch(src, -1) {
			if !slices.Contains(writeScopes[filepath.ToSlash(f)], m[1]) {
				t.Errorf("%s: grants %q; only release.yml may write, and only packages", f, m[1])
			}
		}
		// bash -e does not abort on a failing "! cmd" unless it is the last
		// command, so a negative check written that way is silently skipped.
		for i, line := range strings.Split(src, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "! ") {
				t.Errorf("%s:%d: negative check %q does not trip errexit; use if ...; then exit 1; fi", f, i+1, strings.TrimSpace(line))
			}
		}
		for _, m := range usesRe.FindAllStringSubmatch(src, -1) {
			if !shaPinRe.MatchString(m[1]) && !localWorkflowRe.MatchString(m[1]) {
				t.Errorf("%s: action %q is not pinned to a full commit SHA", f, m[1])
			}
		}
	}
}

// The production deploy must build the OPEN binary from the repo-root
// Dockerfile, run only for a release tag (never a push to main), deploy only
// after ci passed on that same commit, and never configure a token gate
// (which would make the public relay 401 every client).
func TestDeployWorkflow_OnlyTestedOpenRelayFromReleaseTags(t *testing.T) {
	src := readRepoFile(t, ".github/workflows/deploy.yml")

	on := src[strings.Index(src, "\non:"):strings.Index(src, "\nconcurrency:")]
	if !strings.Contains(on, `tags: ["v*"]`) {
		t.Error("deploy must trigger on release tags v*")
	}
	for _, bad := range []string{"branches", "workflow_run", "pull_request"} {
		if strings.Contains(on, bad) {
			t.Errorf("deploy must not trigger on %s: only a release tag deploys", bad)
		}
	}
	if strings.Count(src, "if: startsWith(github.ref, 'refs/tags/v')") != 2 {
		t.Error("both the ci and the deploy job must be limited to refs/tags/v* (a manual dispatch on a branch must not deploy)")
	}
	if !strings.Contains(src, "uses: ./.github/workflows/ci.yml") || !strings.Contains(src, "needs: ci") {
		t.Error("deploy must run ci on the tag and wait for it (needs: ci)")
	}
	if !strings.Contains(src, "ref: ${{ github.sha }}") {
		t.Error("checkout must pin the tagged commit ci tested")
	}
	if strings.Contains(src, "setup-flyctl") {
		t.Error("setup-flyctl installs whatever flyctl the Fly API names, unverified; install a pinned, checksummed release instead")
	}
	if !regexp.MustCompile(`sha256sum -c`).MatchString(src) {
		t.Error("the flyctl download must be verified against a pinned SHA-256")
	}
	if n := strings.Count(src, "flyctl deploy") + strings.Count(src, "fly deploy"); n != 1 {
		t.Errorf("expected exactly one deploy command, found %d", n)
	}
	if !strings.Contains(src, "--env LANGSTROTH_RELAY_REQUIRE_DB=1") || strings.Contains(src, "HIVE_RELAY_REQUIRE_DB") {
		t.Error("the prod deploy must set LANGSTROTH_RELAY_REQUIRE_DB=1 (HIVE_RELAY_* is no longer read and stops the relay)")
	}
	if !strings.Contains(src, "flyctl secrets list --app hive-relay-enterprise --json") || !strings.Contains(src, "^(HIVE|LIGUS)_RELAY_") {
		t.Error("the deploy must refuse while the app holds a HIVE_RELAY_*/LIGUS_RELAY_* secret")
	}
	if !strings.Contains(src, "--app hive-relay-enterprise --config deploy/fly.toml") {
		t.Error("deploy must target hive-relay-enterprise with deploy/fly.toml")
	}
	for _, gate := range []string{"TOKEN_PUBKEY", "ACCESS_TOKENS", "ENTERPRISE", "--dockerfile", "--image", "--build-arg"} {
		if strings.Contains(src, gate) {
			t.Errorf("deploy.yml must not set %s: the public relay is the open binary from the root Dockerfile", gate)
		}
	}

	fly := readRepoFile(t, "deploy/fly.toml")
	if !strings.Contains(fly, `dockerfile = "../Dockerfile"`) {
		t.Error("deploy/fly.toml must build the repo-root Dockerfile")
	}
	for _, gate := range []string{"TOKEN_PUBKEY", "ACCESS_TOKENS"} {
		if strings.Contains(fly, gate) {
			t.Errorf("deploy/fly.toml must not set %s", gate)
		}
	}
	df := readRepoFile(t, "Dockerfile")
	if !strings.Contains(df, "go build -trimpath -ldflags=\"-s -w\" -o /out/langstroth-relay ./cmd/langstroth-relay") {
		t.Error("root Dockerfile must build the open cmd/langstroth-relay binary")
	}
}

// The release publishes images and charts under ghcr.io/langstroth-ai only
// after ci passed, and only for a tag that matches the charts' appVersion.
func TestReleaseWorkflow_PublishesAfterCI(t *testing.T) {
	src := readRepoFile(t, ".github/workflows/release.yml")
	on := src[strings.Index(src, "\non:"):strings.Index(src, "\npermissions:")]
	if !strings.Contains(on, `tags: ["v*"]`) || strings.Contains(on, "branches") || strings.Contains(on, "pull_request") {
		t.Error("release must trigger only on release tags v*")
	}
	if !strings.Contains(src, "uses: ./.github/workflows/ci.yml") || !strings.Contains(src, "needs: ci") {
		t.Error("release must run ci on the tag and wait for it")
	}
	for _, want := range []string{
		"$REGISTRY/langstroth-relay:$VERSION",
		"$REGISTRY/langstroth-auth:$VERSION",
		"REGISTRY: ghcr.io/langstroth-ai",
		`helm push "$f" "oci://$REGISTRY/charts"`,
		"-f deploy/container/Dockerfile \\",
		"-f deploy/container/Dockerfile.langstroth-auth",
		"appVersion is $app, the tag says $version",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("release.yml: missing %q", want)
		}
	}
	if strings.Contains(src, "secrets.FLY_API_TOKEN") {
		t.Error("release.yml must not deploy; deploy.yml does")
	}
}

// The public relay is one always-on machine (per-process pairing, SSE
// fan-out, rate limits and long-lived tunnels), limited by open connections,
// with a health check in the current flyctl schema.
func TestFlyConfig_SingleMachineConnectionsAndHealth(t *testing.T) {
	fly := readRepoFile(t, "deploy/fly.toml")
	for _, want := range []string{
		"auto_stop_machines = false",
		"min_machines_running = 1",
		"[http_service.concurrency]\n    type = \"connections\"\n    soft_limit = 1500\n    hard_limit = 2000",
		"[[http_service.checks]]\n    method = \"GET\"\n    path = \"/v1/health\"\n    interval = \"30s\"\n    timeout = \"5s\"\n    grace_period = \"10s\"",
	} {
		if !strings.Contains(fly, want) {
			t.Errorf("deploy/fly.toml: missing %q", want)
		}
	}
	for _, bad := range []string{"http_checks", `type = "requests"`} {
		if strings.Contains(fly, bad) {
			t.Errorf("deploy/fly.toml: %q is the old form", bad)
		}
	}
	if strings.Contains(fly, "trigger autoscaling") {
		t.Error("deploy/fly.toml: the relay is single-replica; nothing autoscales")
	}
}

// The deploy is the community relay anyone may use, and every community
// limit is off in the binary: the deploy itself must turn the profile on
// (docs/reference.md, "Community limits"), or a stranger can fill the
// database with rooms and blobs at the default per-client write rate.
func TestDeployWorkflow_TurnsOnTheCommunityProfile(t *testing.T) {
	src := readRepoFile(t, ".github/workflows/deploy.yml")
	for _, name := range []string{
		"LANGSTROTH_RELAY_ROOM_MAX_BYTES",
		"LANGSTROTH_RELAY_ROOM_MAX_ENVELOPES",
		"LANGSTROTH_RELAY_MAX_TOTAL_ROOM_BYTES",
		"LANGSTROTH_RELAY_MAX_ROOMS_PER_CLIENT",
		"LANGSTROTH_RELAY_MAX_ROOMS",
		"LANGSTROTH_RELAY_ROOM_RETENTION_DAYS",
		"LANGSTROTH_RELAY_IP_RATE",
		"LANGSTROTH_RELAY_ROOM_RATE",
		"LANGSTROTH_RELAY_BLOB_TOTAL_MAX_BYTES",
		"LANGSTROTH_RELAY_MAX_CONTACT_BYTES",
		"LANGSTROTH_RELAY_MAX_SSE",
		"LANGSTROTH_RELAY_MAX_INFLIGHT_PER_CLIENT",
		"LANGSTROTH_RELAY_BLOB_MAX_INFLIGHT",
		"LANGSTROTH_RELAY_BLOB_DOWNLOAD_INFLIGHT",
		"GOMEMLIMIT",
	} {
		if !regexp.MustCompile(`--env "?` + name + `=[1-9]`).MatchString(src) {
			t.Errorf("the community deploy must set %s", name)
		}
	}
	// SSE streams are long-lived connections: the in-process cap must stay
	// below Fly's per-machine connection hard limit, or streams alone can
	// take every connection and the relay stops answering anything else.
	m := regexp.MustCompile(`--env "?LANGSTROTH_RELAY_MAX_SSE=(\d+)`).FindStringSubmatch(src)
	fly := readRepoFile(t, "deploy/fly.toml")
	h := regexp.MustCompile(`hard_limit = (\d+)`).FindStringSubmatch(fly)
	if m == nil || h == nil {
		t.Fatal("MAX_SSE or the Fly hard_limit not found")
	}
	sse, _ := strconv.Atoi(m[1])
	hard, _ := strconv.Atoi(h[1])
	if sse*10 > hard*7 {
		t.Errorf("LANGSTROTH_RELAY_MAX_SSE=%d leaves too few of Fly's %d connections for requests and tunnels", sse, hard)
	}
}
