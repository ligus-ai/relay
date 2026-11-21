// Package deploy holds no code: its tests check the deployment artefacts
// (Helm charts, the agent scripts under deploy/agent, the container and Fly
// config and the GitHub workflows) rather than the relay itself.
package deploy

import (
	"fmt"
	"os"
	"testing"
)

// TestMain runs the tests from the repository root, so the paths they name
// (deploy/helm/..., deploy/agent/..., .github/workflows/..., Dockerfile) read
// the same as in the docs and in CI.
func TestMain(m *testing.M) {
	if err := os.Chdir(".."); err != nil {
		fmt.Fprintln(os.Stderr, "deploy tests: chdir to repo root:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
