package langstrothauth

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The example configs under deploy/compose decode strictly and pass
// validation (secrets stubbed), so the docs never ship a config the binary
// refuses.
func TestExampleConfigsAreValid(t *testing.T) {
	paths, _ := filepath.Glob("../../deploy/compose/*/langstroth-auth.json")
	if len(paths) == 0 {
		t.Fatal("no example configs found")
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var c Config
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		for i := range c.Tenants {
			c.Tenants[i].OIDC.ClientSecretFile = ""
			c.Tenants[i].OIDC.ClientSecretEnv = "EXAMPLE_SECRET"
		}
		t.Setenv("EXAMPLE_SECRET", "x")
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
}
