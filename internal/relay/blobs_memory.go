package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// blobStore for the memory store (blobs.go). Blobs live under s.mu and count
// toward the store byte budget (LANGSTROTH_RELAY_MAX_STORE_BYTES). With
// persistence, each blob's bytes are also written to their own file under
// <data dir>/blobs, and the JSON snapshot (rewritten every few seconds)
// holds only their metadata: blob bytes in it would make every flush
// rewrite every attachment.

type memBlob struct {
	meta BlobMeta
	data []byte
}

type memBlobUse struct {
	bytes, count int64
}

// blobOverheadBytes is what the store budget charges for each blob beyond
// its bytes (its map entry and metadata).
const blobOverheadBytes = 256

// blobSnap persists one blob in the snapshot.
type blobSnap struct {
	Room      string `json:"room"`
	ID        string `json:"id"`
	Tenant    string `json:"tenant,omitempty"`
	Uploader  string `json:"uploader"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt,omitempty"`
	Bound     bool   `json:"bound,omitempty"`
	// Data is only read (snapshots written before blob files); the bytes
	// live in blobFile.
	Data []byte `json:"data,omitempty"`
}

// blobDir is where a persisted store keeps blob bytes ("" = not persisted).
func (s *memoryStore) blobDir() string {
	if s.persistPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.persistPath), "blobs")
}

// blobFile is the file holding one blob's bytes: named by a hash of its
// room and id, so nothing a client sends shapes a path.
func (s *memoryStore) blobFile(room, id string) string {
	return filepath.Join(s.blobDir(), sha256hex(room+"\x00"+id))
}

// writeBlobFile writes data to path atomically (temp file and rename),
// owner-only.
func writeBlobFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// blobUseLocked returns the totals of room and, within it, of uploader.
// Caller holds s.mu.
func (s *memoryStore) blobUseLocked(room, uploader string) (roomUse, writerUse memBlobUse) {
	for _, b := range s.blobs[room] {
		roomUse.bytes += b.meta.Size
		roomUse.count++
		if b.meta.Uploader == uploader {
			writerUse.bytes += b.meta.Size
			writerUse.count++
		}
	}
	return roomUse, writerUse
}

func (s *memoryStore) PutBlob(_ context.Context, meta BlobMeta, data []byte, q blobQuota) error {
	if err := s.putBlob(meta, data, q); err != nil {
		return err
	}
	if s.blobDir() == "" {
		return nil
	}
	// Written outside the lock. A delete racing this write can leave the
	// file behind; boot removes files no snapshot lists.
	if err := writeBlobFile(s.blobFile(meta.Room, meta.ID), data); err != nil {
		s.mu.Lock()
		s.dropBlobLocked(meta.Room, meta.ID)
		s.mu.Unlock()
		return fmt.Errorf("storing attachment: %w", err)
	}
	return nil
}

func (s *memoryStore) putBlob(meta BlobMeta, data []byte, q blobQuota) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.workspaces[meta.Room]
	if w == nil || !w.live {
		return errNoRoom
	}
	size := int64(len(data))
	meta.Size = size
	tenant := w.tenant
	meta.Tenant = tenant
	roomUse, writerUse := s.blobUseLocked(meta.Room, meta.Uploader)
	tu := s.blobTenant[tenant]
	if tu == nil {
		tu = &memBlobUse{}
	}
	switch {
	case q.RoomMaxCount > 0 && roomUse.count+1 > q.RoomMaxCount:
		return errQuota(limBlobRoomCount, tenant)
	case q.RoomMaxBytes > 0 && roomUse.bytes+size > q.RoomMaxBytes:
		return errQuota(limBlobRoomBytes, tenant)
	case q.WriterMaxCount > 0 && writerUse.count+1 > q.WriterMaxCount:
		return errQuota(limBlobWriterCount, tenant)
	case q.WriterMaxBytes > 0 && writerUse.bytes+size > q.WriterMaxBytes:
		return errQuota(limBlobWriterBytes, tenant)
	case tenant != "" && q.TenantMaxCount > 0 && tu.count+1 > q.TenantMaxCount:
		return errQuota(limBlobTenantCount, tenant)
	case tenant != "" && q.TenantMaxBytes > 0 && tu.bytes+size > q.TenantMaxBytes:
		return errQuota(limBlobTenantBytes, tenant)
	case q.TotalMaxBytes > 0 && s.blobTotal.bytes+size > q.TotalMaxBytes:
		return errQuota(limBlobTotalBytes, tenant)
	}
	if !s.reserveLocked(size + blobOverheadBytes + int64(len(meta.Room))) {
		return ErrStoreFull
	}
	s.addBlobLocked(&memBlob{meta: meta, data: data})
	return nil
}

// addBlobLocked stores b and counts it (the budget is the caller's).
// Caller holds s.mu.
func (s *memoryStore) addBlobLocked(b *memBlob) {
	if s.blobs == nil {
		s.blobs = map[string]map[string]*memBlob{}
	}
	if s.blobTenant == nil {
		s.blobTenant = map[string]*memBlobUse{}
	}
	m := s.blobs[b.meta.Room]
	if m == nil {
		m = map[string]*memBlob{}
		s.blobs[b.meta.Room] = m
	}
	m[b.meta.ID] = b
	tu := s.blobTenant[b.meta.Tenant]
	if tu == nil {
		tu = &memBlobUse{}
		s.blobTenant[b.meta.Tenant] = tu
	}
	tu.bytes += b.meta.Size
	tu.count++
	s.blobTotal.bytes += b.meta.Size
	s.blobTotal.count++
}

// dropBlobLocked removes one blob, its counts and its budget. Caller holds
// s.mu.
func (s *memoryStore) dropBlobLocked(room, id string) bool {
	m := s.blobs[room]
	b := m[id]
	if b == nil {
		return false
	}
	delete(m, id)
	if len(m) == 0 {
		delete(s.blobs, room)
	}
	if tu := s.blobTenant[b.meta.Tenant]; tu != nil {
		tu.bytes -= b.meta.Size
		if tu.count--; tu.count <= 0 {
			delete(s.blobTenant, b.meta.Tenant)
		}
	}
	s.blobTotal.bytes -= b.meta.Size
	s.blobTotal.count--
	s.storeBytes -= b.meta.Size + blobOverheadBytes + int64(len(room))
	if s.blobDir() != "" {
		_ = os.Remove(s.blobFile(room, id))
	}
	return true
}

// dropRoomBlobsLocked removes every blob of room. Caller holds s.mu.
func (s *memoryStore) dropRoomBlobsLocked(room string) {
	for id := range s.blobs[room] {
		s.dropBlobLocked(room, id)
	}
}

func (s *memoryStore) GetBlob(_ context.Context, room, id string, now int64) (BlobMeta, []byte, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b := s.blobs[room][id]
	if b == nil || (b.meta.ExpiresAt != 0 && b.meta.ExpiresAt <= now) {
		return BlobMeta{}, nil, false, nil
	}
	// Stored bytes are never mutated, so the slice is safe to hand out.
	return b.meta, b.data, true, nil
}

func (s *memoryStore) DeleteBlob(_ context.Context, room, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropBlobLocked(room, id), nil
}

func (s *memoryStore) DeleteBlobAs(_ context.Context, room, id string, by blobDeleter) (blobDeleteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.blobs[room][id]
	switch {
	case b == nil:
		return blobDeleteAbsent, nil
	case !by.mayDelete(b.meta):
		return blobDeleteRefused, nil
	}
	s.dropBlobLocked(room, id)
	return blobDeleteDone, nil
}

func (s *memoryStore) DeleteBlobsByUploader(_ context.Context, room, uploader string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, b := range s.blobs[room] {
		if b.meta.Uploader == uploader && s.dropBlobLocked(room, id) {
			n++
		}
	}
	return n, nil
}

func (s *memoryStore) PruneExpiredBlobs(_ context.Context, now int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for room, m := range s.blobs {
		for id, b := range m {
			if b.meta.ExpiresAt != 0 && b.meta.ExpiresAt <= now && s.dropBlobLocked(room, id) {
				n++
			}
		}
	}
	return n, nil
}

// blobSnapsLocked lists every blob for the snapshot. Caller holds s.mu
// (read).
func (s *memoryStore) blobSnapsLocked() []blobSnap {
	var out []blobSnap
	for _, m := range s.blobs {
		for _, b := range m {
			out = append(out, blobSnap{
				Room: b.meta.Room, ID: b.meta.ID, Tenant: b.meta.Tenant, Uploader: b.meta.Uploader,
				Size: b.meta.Size, SHA256: b.meta.SHA256, CreatedAt: b.meta.CreatedAt, ExpiresAt: b.meta.ExpiresAt,
				Bound: b.meta.Bound,
			})
		}
	}
	return out
}

// restoreBlobsLocked reloads blobs from a snapshot after the workspaces:
// expired ones, ones of a room no longer live, ones whose file is missing
// or doesn't match its size and hash, and malformed ones are dropped. Blob
// files no restored blob uses (deleted ones, uploads after the last flush)
// are removed. Caller holds s.mu.
func (s *memoryStore) restoreBlobsLocked(snaps []blobSnap) {
	s.blobs, s.blobTenant, s.blobTotal = nil, nil, memBlobUse{}
	now := time.Now().Unix()
	dir := s.blobDir()
	keep := map[string]bool{}
	for _, b := range snaps {
		w := s.workspaces[b.Room]
		if w == nil || !w.live || !validBlobID(b.ID) || b.Size <= 0 || (b.ExpiresAt != 0 && b.ExpiresAt <= now) {
			continue
		}
		if len(b.Data) == 0 && dir != "" {
			b.Data, _ = os.ReadFile(s.blobFile(b.Room, b.ID))
		} else if len(b.Data) > 0 && dir != "" {
			// An older snapshot carried the bytes inline: move them out.
			if writeBlobFile(s.blobFile(b.Room, b.ID), b.Data) != nil {
				continue
			}
		}
		sum := sha256.Sum256(b.Data)
		if int64(len(b.Data)) != b.Size || hex.EncodeToString(sum[:]) != b.SHA256 {
			continue
		}
		keep[filepath.Base(s.blobFile(b.Room, b.ID))] = true
		s.storeBytes += b.Size + blobOverheadBytes + int64(len(b.Room))
		s.addBlobLocked(&memBlob{meta: BlobMeta{
			Room: b.Room, ID: b.ID, Tenant: w.tenant, Uploader: b.Uploader, Size: b.Size,
			SHA256: b.SHA256, CreatedAt: b.CreatedAt, ExpiresAt: b.ExpiresAt, Bound: b.Bound,
		}, data: b.Data})
	}
	if dir == "" {
		return
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if name := e.Name(); !keep[name] && (len(name) == 64 || strings.HasSuffix(name, ".tmp")) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}
