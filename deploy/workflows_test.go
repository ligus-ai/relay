package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Supply-chain guard for .github/workflows. These are
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
}

// The root Dockerfile builds the open relay binary.
func TestRootDockerfileBuildsOpenRelay(t *testing.T) {
	df := readRepoFile(t, "Dockerfile")
	if !strings.Contains(df, "go build -trimpath -ldflags=\"-s -w\" -o /out/langstroth-relay ./cmd/langstroth-relay") {
		t.Error("root Dockerfile must build the open cmd/langstroth-relay binary")
	}
}

// No workflow here deploys anything: releases publish images and charts, and
// the community relay is deployed from a separate repository.
func TestNoWorkflowDeploys(t *testing.T) {
	files, err := filepath.Glob(".github/workflows/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows: %v", err)
	}
	for _, f := range files {
		src := readRepoFile(t, f)
		for _, bad := range []string{"flyctl", "FLY_API_TOKEN", "fly deploy"} {
			if strings.Contains(src, bad) {
				t.Errorf("%s: mentions %s; deploys don't belong in this repository", f, bad)
			}
		}
	}
}
