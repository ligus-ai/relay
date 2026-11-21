package langstrothauth

import (
	"os"

	"github.com/langstroth-ai/langstroth-relay/internal/envalias"
)

// Environment-variable names are LANGSTROTH_AUTH_*. The LIGUS_AUTH_* names
// from before the Langstroth rename are not read, and the service refuses to
// start while one is set (removedEnvError), so a forgotten variable can't
// silently drop a setting.
const authEnvPrefix = "LANGSTROTH_AUTH_"

// authEnvName returns name when it is set (even empty, so readSecret reports
// it), else "".
func authEnvName(name string) string {
	if _, set := os.LookupEnv(name); set {
		return name
	}
	return ""
}

// authGetenv reads name.
func authGetenv(name string) string { return os.Getenv(name) }

// removedEnvError refuses to start while a LIGUS_AUTH_* variable is set,
// naming its LANGSTROTH_AUTH_* replacement (never its value).
func removedEnvError(environ []string) error {
	return envalias.Removed(environ, authEnvPrefix, []string{"LIGUS_AUTH_"}, nil)
}
