package relay

import (
	"context"
	"errors"
	"testing"
)

// On Postgres nothing bounded the contacts' storage relay-wide ("the
// database's disk is the bound"): new records at the per-client create rate,
// each with a drop box of up to 4 MiB, let one IPv4 address add gigabytes a
// day and fill the disk the whole relay shares. LANGSTROTH_RELAY_MAX_CONTACT_BYTES
// bounds records plus drops: new records and drops answer contacts_full
// (507), while an existing record can still be refreshed.
func TestPostgresContactBytesCap(t *testing.T) {
	ps := pgStore(t)
	ctx := context.Background()
	if _, err := ps.pool.Exec(ctx, `TRUNCATE relay_contacts, relay_contact_drop`); err != nil {
		t.Fatal(err)
	}
	lim := ContactLimits{MaxBytes: 100}
	kh := sha256hex(newWriteKey())
	cid := newCID()
	if _, err := ps.PutContact(ctx, cid, kh, raw(`"0123456789012345678901234567890123456789"`), 10, 1<<40, lim); err != nil { // 42 bytes
		t.Fatal(err)
	}
	if _, err := ps.AppendContactDrop(ctx, cid, raw(`"01234567890123456789012345678901234567"`), 11, lim); err != nil { // 40: 82
		t.Fatal(err)
	}
	if _, err := ps.AppendContactDrop(ctx, cid, raw(`"01234567890123456789"`), 12, lim); !errors.Is(err, ErrContactsFull) {
		t.Fatalf("drop past the relay-wide contact bytes: %v", err)
	}
	if _, err := ps.PutContact(ctx, newCID(), sha256hex(newWriteKey()), raw(`"0123456789012345678"`), 13, 1<<40, lim); !errors.Is(err, ErrContactsFull) {
		t.Fatalf("new record past the relay-wide contact bytes: %v", err)
	}
	if created, err := ps.PutContact(ctx, cid, kh, raw(`"refreshed"`), 14, 1<<40, lim); err != nil || created {
		t.Fatalf("an existing record is still refreshed: %v %v", created, err)
	}
}
