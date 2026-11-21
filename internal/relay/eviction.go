package relay

import (
	"fmt"
	"strings"
)

// Per-envelope eviction is gone. LANGSTROTH_RELAY_MAX_ENVELOPES (a rolling
// window per room, once on by default at 50 000) and
// LANGSTROTH_RELAY_RETENTION_DAYS (an age cap) dropped a room's oldest
// envelopes, and the oldest is the founder's signed seed: a Ligus client
// folds the whole log from seq 1 and never backfills, so every device that
// joined afterwards was permanently broken. Rooms are now bounded by
// refusal (LANGSTROTH_RELAY_ROOM_MAX_BYTES, _ROOM_MAX_ENVELOPES, 507) and
// expired only whole (LANGSTROTH_RELAY_ROOM_RETENTION_DAYS); see
// docs/tenancy.md.

// removedEvictionSettings maps each removed setting to its replacement.
var removedEvictionSettings = []struct{ name, use string }{
	{"LANGSTROTH_RELAY_MAX_ENVELOPES", "LANGSTROTH_RELAY_ROOM_MAX_ENVELOPES (refuses with 507, never evicts)"},
	{"LANGSTROTH_RELAY_RETENTION_DAYS", "LANGSTROTH_RELAY_ROOM_RETENTION_DAYS (expires whole idle rooms)"},
}

// evictionConfigError refuses to start while a removed eviction setting
// holds anything but 0, so an operator who relied on it learns it is gone
// rather than silently losing the bound.
func evictionConfigError() error {
	for _, s := range removedEvictionSettings {
		v := strings.TrimSpace(getenv(s.name))
		if v == "" || v == "0" {
			continue
		}
		return fmt.Errorf("%s is removed: evicting a room's oldest envelopes drops its seed and breaks every device that joins later. Unset it (or set it to 0) and use %s", s.name, s.use)
	}
	return nil
}
