package relay

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Postgres ContactStore (relay v0.3). Records and drops are TEXT so the relay
// returns the exact bytes it received, like relay_envelopes. Drop-box
// sequences use relay_seq with scope "cdrop:<cid>", started at contactSeqBase
// when the box is created. The global record cap
// (ContactLimits.MaxContacts) applies to the memory store only; here
// ContactLimits.MaxBytes bounds record plus drop bytes across the relay
// (pgContactTotal), so contacts can't fill the disk the rooms share.

const contactsSchemaSQL = `
CREATE TABLE IF NOT EXISTS relay_contacts (
  cid            TEXT PRIMARY KEY,
  write_key_hash TEXT   NOT NULL,
  record         TEXT   NOT NULL,
  updated_at     BIGINT NOT NULL,
  expires_at     BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS relay_contacts_expires ON relay_contacts (expires_at);
CREATE TABLE IF NOT EXISTS relay_contact_drop (
  cid        TEXT   NOT NULL,
  seq        BIGINT NOT NULL,
  blob       TEXT   NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (cid, seq)
);
CREATE INDEX IF NOT EXISTS relay_contact_drop_created ON relay_contact_drop (created_at);
ALTER TABLE relay_contact_drop ADD COLUMN IF NOT EXISTS sender    TEXT    NOT NULL DEFAULT '';
ALTER TABLE relay_contact_drop ADD COLUMN IF NOT EXISTS verified  BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE relay_contact_drop ADD COLUMN IF NOT EXISTS delivered BOOLEAN NOT NULL DEFAULT false;
`

func contactSeqScope(cid string) string { return "cdrop:" + cid }

// pgContactTotal caches the bytes of all records and drops
// (ContactLimits.MaxBytes), re-read at most every pgTotalTTL and counted up
// by each admitted write in between.
type pgContactTotal struct {
	mu    sync.Mutex
	bytes int64
	at    time.Time
}

// admitContactBytes admits add more contact bytes under max (0 = no bound),
// or answers ErrContactsFull.
func (s *postgresStore) admitContactBytes(ctx context.Context, add, max int64) error {
	if max <= 0 {
		return nil
	}
	t := &s.contactTotal
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.at.IsZero() || time.Since(t.at) >= pgTotalTTL {
		var b int64
		if err := s.pool.QueryRow(ctx, `SELECT
  (SELECT coalesce(sum(octet_length(record)), 0) FROM relay_contacts) +
  (SELECT coalesce(sum(octet_length(blob)), 0) FROM relay_contact_drop)`).Scan(&b); err != nil {
			return err
		}
		t.bytes, t.at = b, time.Now()
	}
	if t.bytes+add > max {
		return ErrContactsFull
	}
	t.bytes += add
	return nil
}

// startContactSeqTx starts a new box's seq counter at contactSeqBase(now).
func startContactSeqTx(ctx context.Context, tx pgx.Tx, cid string, now int64) error {
	_, err := tx.Exec(ctx, `
INSERT INTO relay_seq (scope, next_seq) VALUES ($1, $2)
ON CONFLICT (scope) DO UPDATE SET next_seq = GREATEST(relay_seq.next_seq, EXCLUDED.next_seq)`,
		contactSeqScope(cid), int64(contactSeqBase(now)))
	return err
}

// wipeContactTx deletes a record and its drop box. The seq counter stays, so
// a box created again for the cid continues past it (startContactSeqTx).
func wipeContactTx(ctx context.Context, tx pgx.Tx, cid string) error {
	for _, q := range []string{
		`DELETE FROM relay_contact_drop WHERE cid = $1`,
		`DELETE FROM relay_contacts WHERE cid = $1`,
	} {
		if _, err := tx.Exec(ctx, q, cid); err != nil {
			return err
		}
	}
	return nil
}

func (s *postgresStore) PutContact(ctx context.Context, cid, keyHash string, record json.RawMessage, now, expiresAt int64, lim ContactLimits) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
INSERT INTO relay_contacts (cid, write_key_hash, record, updated_at, expires_at) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (cid) DO NOTHING`, cid, keyHash, string(record), now, expiresAt)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 1 {
		if err := s.admitContactBytes(ctx, int64(len(record)), lim.MaxBytes); err != nil {
			return false, err
		}
		// A fresh cid: clear any drop-box leftovers of a pruned predecessor.
		if _, err := tx.Exec(ctx, `DELETE FROM relay_contact_drop WHERE cid = $1`, cid); err != nil {
			return false, err
		}
		if err := startContactSeqTx(ctx, tx, cid, now); err != nil {
			return false, err
		}
		return true, tx.Commit(ctx)
	}
	var stored string
	var exp int64
	if err := tx.QueryRow(ctx, `SELECT write_key_hash, expires_at FROM relay_contacts WHERE cid = $1 FOR UPDATE`, cid).
		Scan(&stored, &exp); err != nil {
		return false, err
	}
	created := false
	if exp <= now {
		// Expired: during the reclaim hold only the old key may create it
		// again; after it the cid is free.
		if now < exp+int64(lim.ReclaimHold/time.Second) && !constantTimeEq(stored, keyHash) {
			return false, ErrContactKey
		}
		if err := s.admitContactBytes(ctx, int64(len(record)), lim.MaxBytes); err != nil {
			return false, err
		}
		if err := wipeContactTx(ctx, tx, cid); err != nil {
			return false, err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO relay_contacts (cid, write_key_hash, record, updated_at, expires_at) VALUES ($1, $2, $3, $4, $5)`,
			cid, keyHash, string(record), now, expiresAt); err != nil {
			return false, err
		}
		if err := startContactSeqTx(ctx, tx, cid, now); err != nil {
			return false, err
		}
		created = true
	} else {
		if !constantTimeEq(stored, keyHash) {
			return false, ErrContactKey
		}
		if _, err := tx.Exec(ctx,
			`UPDATE relay_contacts SET record = $2, updated_at = $3, expires_at = $4 WHERE cid = $1`,
			cid, string(record), now, expiresAt); err != nil {
			return false, err
		}
	}
	return created, tx.Commit(ctx)
}

func (s *postgresStore) GetContact(ctx context.Context, cid string, now int64) (*ContactRecord, error) {
	var r ContactRecord
	var rec string
	err := s.pool.QueryRow(ctx,
		`SELECT write_key_hash, record, updated_at, expires_at FROM relay_contacts WHERE cid = $1 AND expires_at > $2`,
		cid, now).Scan(&r.WriteKeyHash, &rec, &r.UpdatedAt, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.CID, r.Record = cid, json.RawMessage(rec)
	return &r, nil
}

// ownedTx locks the live record and checks keyHash.
func ownedContactTx(ctx context.Context, tx pgx.Tx, cid, keyHash string, now int64, lock string) error {
	var stored string
	err := tx.QueryRow(ctx,
		`SELECT write_key_hash FROM relay_contacts WHERE cid = $1 AND expires_at > $2 `+lock, cid, now).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrContactNotFound
	}
	if err != nil {
		return err
	}
	if !constantTimeEq(stored, keyHash) {
		return ErrContactKey
	}
	return nil
}

func (s *postgresStore) DeleteContact(ctx context.Context, cid, keyHash string, now int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := ownedContactTx(ctx, tx, cid, keyHash, now, "FOR UPDATE"); err != nil {
		return err
	}
	if err := wipeContactTx(ctx, tx, cid); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *postgresStore) AppendContactDrop(ctx context.Context, cid string, blob json.RawMessage, now int64, lim ContactLimits) (uint64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	// FOR UPDATE serializes appends to one box, so each eviction sees the
	// box it trims.
	var one int
	err = tx.QueryRow(ctx, `SELECT 1 FROM relay_contacts WHERE cid = $1 AND expires_at > $2 FOR UPDATE`, cid, now).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrContactNotFound
	}
	if err != nil {
		return 0, err
	}
	if err := s.admitContactBytes(ctx, int64(len(blob)), lim.MaxBytes); err != nil {
		return 0, err
	}
	seq, err := s.nextSeqTx(ctx, tx, contactSeqScope(cid))
	if err != nil {
		return 0, err
	}
	snd := dropSenderFrom(ctx)
	if _, err := tx.Exec(ctx,
		`INSERT INTO relay_contact_drop (cid, seq, blob, created_at, sender, verified) VALUES ($1, $2, $3, $4, $5, $6)`,
		cid, seq, string(blob), now, dropSenderHash(cid, snd), snd.Verified); err != nil {
		return 0, err
	}
	if lim.DropMaxRows > 0 || lim.DropMaxBoxBytes > 0 {
		var rows, bytes int64
		if err := tx.QueryRow(ctx,
			`SELECT COUNT(*), COALESCE(SUM(octet_length(blob)), 0) FROM relay_contact_drop WHERE cid = $1`, cid).
			Scan(&rows, &bytes); err != nil {
			return 0, err
		}
		if (lim.DropMaxRows > 0 && rows > int64(lim.DropMaxRows)) || (lim.DropMaxBoxBytes > 0 && bytes > int64(lim.DropMaxBoxBytes)) {
			if err := evictContactDropsTx(ctx, tx, cid, lim); err != nil {
				return 0, err
			}
		}
	}
	return seq, tx.Commit(ctx)
}

// evictContactDropsTx trims a full box per dropEvictions. Only the eviction
// metadata is read (octet_length, not the blobs).
func evictContactDropsTx(ctx context.Context, tx pgx.Tx, cid string, lim ContactLimits) error {
	rows, err := tx.Query(ctx, `
SELECT seq, octet_length(blob), sender, verified, delivered FROM relay_contact_drop WHERE cid = $1 ORDER BY seq`, cid)
	if err != nil {
		return err
	}
	var drops []ContactDrop
	for rows.Next() {
		var d ContactDrop
		var size int
		if err := rows.Scan(&d.Seq, &size, &d.sender, &d.verified, &d.delivered); err != nil {
			rows.Close()
			return err
		}
		d.Blob = make(json.RawMessage, size) // length only: dropEvictions counts bytes
		drops = append(drops, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	ev := dropEvictions(drops, lim)
	if len(ev) == 0 {
		return nil
	}
	seqs := make([]int64, len(ev))
	for i, j := range ev {
		seqs[i] = int64(drops[j].Seq)
	}
	_, err = tx.Exec(ctx, `DELETE FROM relay_contact_drop WHERE cid = $1 AND seq = ANY($2)`, cid, seqs)
	return err
}

func (s *postgresStore) ContactDropsAfter(ctx context.Context, cid, keyHash string, after uint64, limit, maxBytes int, now int64) ([]ContactDrop, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)
	if err := ownedContactTx(ctx, tx, cid, keyHash, now, ""); err != nil {
		return nil, false, err
	}
	q := `SELECT seq, blob, created_at FROM relay_contact_drop WHERE cid = $1 AND seq > $2 ORDER BY seq`
	args := []any{cid, int64(after)}
	if limit > 0 {
		q += ` LIMIT $3`
		args = append(args, limit+1)
	}
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []ContactDrop{}
	size := 0
	more := false
	for rows.Next() {
		var d ContactDrop
		var blob string
		if err := rows.Scan(&d.Seq, &blob, &d.CreatedAt); err != nil {
			return nil, false, err
		}
		if len(out) > 0 && ((limit > 0 && len(out) >= limit) || (maxBytes > 0 && size+len(blob) > maxBytes)) {
			more = true
			break
		}
		d.Blob = json.RawMessage(blob)
		out = append(out, d)
		size += len(blob)
	}
	if err := rows.Err(); err != nil && !more {
		return nil, false, err
	}
	rows.Close()
	// Served drops count as delivered: a full box evicts them first.
	if len(out) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE relay_contact_drop SET delivered = true
WHERE cid = $1 AND seq >= $2 AND seq <= $3 AND NOT delivered`, cid, int64(out[0].Seq), int64(out[len(out)-1].Seq)); err != nil {
			return nil, false, err
		}
	}
	return out, more, tx.Commit(ctx)
}

func (s *postgresStore) AckContactDrops(ctx context.Context, cid, keyHash string, through uint64, now int64) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if err := ownedContactTx(ctx, tx, cid, keyHash, now, "FOR SHARE"); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM relay_contact_drop WHERE cid = $1 AND seq <= $2`, cid, int64(min(through, 1<<63-1)))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), tx.Commit(ctx)
}

func (s *postgresStore) PruneContacts(ctx context.Context, now int64, dropMaxAge, reclaimHold time.Duration) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var n int64
	expired := `SELECT cid FROM relay_contacts WHERE expires_at <= $1`
	tag, err := tx.Exec(ctx, `DELETE FROM relay_contact_drop WHERE cid IN (`+expired+`)`, now)
	if err != nil {
		return 0, err
	}
	n += tag.RowsAffected()
	// An expired record keeps only its key hash during the reclaim hold.
	if _, err := tx.Exec(ctx, `UPDATE relay_contacts SET record = '' WHERE expires_at <= $1 AND record <> ''`, now); err != nil {
		return 0, err
	}
	tag, err = tx.Exec(ctx, `DELETE FROM relay_contacts WHERE expires_at <= $1`, now-int64(reclaimHold/time.Second))
	if err != nil {
		return 0, err
	}
	n += tag.RowsAffected()
	// Seq counters of records that are gone (expired here, or deleted by their
	// owner since the last prune).
	if _, err := tx.Exec(ctx, `
DELETE FROM relay_seq WHERE scope LIKE 'cdrop:%'
  AND NOT EXISTS (SELECT 1 FROM relay_contacts c WHERE 'cdrop:' || c.cid = relay_seq.scope)`); err != nil {
		return 0, err
	}
	if dropMaxAge > 0 {
		tag, err = tx.Exec(ctx, `DELETE FROM relay_contact_drop WHERE created_at < $1`, now-int64(dropMaxAge/time.Second))
		if err != nil {
			return 0, err
		}
		n += tag.RowsAffected()
	}
	return n, tx.Commit(ctx)
}
