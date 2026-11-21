package relay

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// roomStore for the memory store (quota.go).

func (s *memoryStore) RoomTotals(_ context.Context) (int64, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.liveRooms, s.roomBytes, nil
}

func (s *memoryStore) TenantUsage(_ context.Context, tenant string) (int64, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if tu := s.tenantUse[tenant]; tu != nil {
		return tu.bytes, tu.rooms, nil
	}
	return 0, 0, nil
}

func (s *memoryStore) ListRooms(_ context.Context, tenant, after string, limit int) ([]RoomUsage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prefix := tenantRoomPrefix(tenant)
	keys := []string{}
	for id, w := range s.workspaces {
		if w.live && w.tenant == tenant && strings.HasPrefix(id, prefix) && id > after {
			keys = append(keys, id)
		}
	}
	sort.Strings(keys)
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	out := make([]RoomUsage, 0, len(keys))
	for _, id := range keys {
		w := s.workspaces[id]
		out = append(out, RoomUsage{Room: id, Tenant: w.tenant, Bytes: w.roomBytes, Envelopes: int64(len(w.envelopes)), LastWrite: w.lastWrite})
	}
	return out, nil
}

func (s *memoryStore) PurgeRoom(_ context.Context, room string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.workspaces[room]
	if w == nil {
		return false, nil
	}
	had := w.live || len(w.members) > 0 || len(w.invites) > 0 || len(s.blobs[room]) > 0
	s.expireRoomLocked(w)
	s.dropRoomBlobsLocked(room)
	w.members = map[string]*MemberRow{}
	w.invites = map[string]*memInvite{}
	s.dropIfEmptyLocked(room, w)
	return had, nil
}

func (s *memoryStore) PruneIdleRooms(_ context.Context, cutoff int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, w := range s.workspaces {
		if w.live && w.lastWrite < cutoff {
			s.expireRoomLocked(w)
			s.dropRoomBlobsLocked(id)
			s.dropIfEmptyLocked(id, w)
			n++
		}
	}
	return n, nil
}

// dropIfEmptyLocked forgets an expired workspace that has nothing left to
// keep: no sequence (it never held an envelope, so no device has a cursor
// into it), no roster and no invites. Without this, every room created and
// abandoned stayed in memory and in the byte budget forever. Caller holds
// s.mu.
func (s *memoryStore) dropIfEmptyLocked(id string, w *memWorkspace) {
	if w.live || w.nextSeq != 0 || len(w.members) > 0 || len(w.invites) > 0 {
		return
	}
	delete(s.workspaces, id)
	if w.charged {
		s.storeBytes -= int64(wsOverheadBytes + len(id))
	}
}

// expireRoomLocked drops w's envelopes, key rotations and device blobs and
// stops counting it as a room. nextSeq, the roster and invites stay. Caller
// holds s.mu.
func (s *memoryStore) expireRoomLocked(w *memWorkspace) {
	var freed int64
	for _, e := range w.envelopes {
		freed += int64(len(e.Body))
	}
	for _, k := range w.keyring {
		freed += int64(len(k))
	}
	var blobs int64
	for _, b := range w.candidates {
		blobs += int64(len(b))
	}
	for _, b := range w.presence {
		blobs += int64(len(b))
	}
	s.storeBytes -= freed + blobs
	s.addRoomBytesLocked(w, -w.roomBytes)
	w.envelopes, w.envAt, w.envKey, w.dedup, w.keyring = nil, nil, nil, nil, nil
	w.candidates = map[string]json.RawMessage{}
	w.presence = map[string]json.RawMessage{}
	if w.live {
		w.live = false
		s.liveRooms--
		s.tenantUseFor(w.tenant).rooms--
		if w.creator != "" {
			if s.creatorRooms[w.creator]--; s.creatorRooms[w.creator] <= 0 {
				delete(s.creatorRooms, w.creator)
			}
		}
	}
}

// recountRoomsLocked rebuilds the room totals from the workspaces (after a
// restore). Caller holds s.mu.
func (s *memoryStore) recountRoomsLocked() {
	s.liveRooms, s.roomBytes = 0, 0
	s.tenantUse = map[string]*memTenantUse{}
	s.creatorRooms = map[string]int64{}
	for _, w := range s.workspaces {
		w.roomBytes = 0
		for _, e := range w.envelopes {
			w.roomBytes += int64(len(e.Body))
		}
		for _, k := range w.keyring {
			w.roomBytes += int64(len(k))
		}
		if !w.live {
			continue
		}
		s.liveRooms++
		s.roomBytes += w.roomBytes
		tu := s.tenantUseFor(w.tenant)
		tu.rooms++
		tu.bytes += w.roomBytes
		if w.creator != "" {
			s.creatorRooms[w.creator]++
		}
	}
}
