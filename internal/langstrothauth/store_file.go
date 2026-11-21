package langstrothauth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// fileStore keeps everything in memory and, when path is set, rewrites a
// JSON state file (mode 0600, atomic rename) after every change. It suits a
// single langstroth-auth instance (a home lab or a small team). Use the Postgres
// store to run more than one replica.
type fileStore struct {
	mu   sync.Mutex
	path string
	st   fileState
}

type fileState struct {
	Version int                      `json:"version"`
	Users   map[string]User          `json:"users"`   // tenant/id
	Groups  map[string]Group         `json:"groups"`  // tenant/id
	Grants  map[string][]string      `json:"grants"`  // tenant/group
	Refresh map[string]*RefreshToken `json:"refresh"` // hash
}

// NewFileStore opens (or creates) a file store. path "" is memory only.
func NewFileStore(path string) (Store, error) {
	s := &fileStore{path: path, st: fileState{Version: 1, Users: map[string]User{}, Groups: map[string]Group{}, Grants: map[string][]string{}, Refresh: map[string]*RefreshToken{}}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		return s, s.persist()
	case err != nil:
		return nil, err
	}
	if err := checkSecretFilePerms(path); err != nil {
		return nil, fmt.Errorf("state file: %w", err)
	}
	if err := json.Unmarshal(b, &s.st); err != nil {
		return nil, fmt.Errorf("state file: %w", err)
	}
	if s.st.Users == nil {
		s.st.Users = map[string]User{}
	}
	if s.st.Groups == nil {
		s.st.Groups = map[string]Group{}
	}
	if s.st.Grants == nil {
		s.st.Grants = map[string][]string{}
	}
	if s.st.Refresh == nil {
		s.st.Refresh = map[string]*RefreshToken{}
	}
	return s, nil
}

func key(tenant, id string) string { return tenant + "/" + id }

// persist writes the state atomically. Caller holds mu.
func (s *fileStore) persist() error {
	if s.path == "" {
		return nil
	}
	b, err := json.Marshal(&s.st)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	f, err := os.CreateTemp(dir, ".langstroth-auth-state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	ok = true
	return nil
}

// commit persists, rolling back the in-memory change on a write failure so
// memory never runs ahead of disk.
func (s *fileStore) commit(undo func()) error {
	if err := s.persist(); err != nil {
		undo()
		return err
	}
	return nil
}

func (s *fileStore) userClash(u User) bool {
	for _, x := range s.st.Users {
		if x.Tenant != u.Tenant || x.ID == u.ID {
			continue
		}
		if strings.EqualFold(x.UserName, u.UserName) ||
			(u.ExternalID != "" && x.ExternalID == u.ExternalID) ||
			(u.Subject != "" && x.Subject == u.Subject) {
			return true
		}
	}
	return false
}

func (s *fileStore) CreateUser(_ context.Context, u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(u.Tenant, u.ID)
	if _, ok := s.st.Users[k]; ok || s.userClash(u) {
		return ErrConflict
	}
	s.st.Users[k] = u
	return s.commit(func() { delete(s.st.Users, k) })
}

func (s *fileStore) GetUser(_ context.Context, tenant, id string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.st.Users[key(tenant, id)]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (s *fileStore) FindUser(_ context.Context, tenant, attr, value string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if value == "" {
		return User{}, ErrNotFound
	}
	for _, u := range s.st.Users {
		if u.Tenant != tenant {
			continue
		}
		switch attr {
		case "userName":
			if strings.EqualFold(u.UserName, value) {
				return u, nil
			}
		case "externalId":
			if u.ExternalID == value {
				return u, nil
			}
		case "subject":
			if u.Subject == value {
				return u, nil
			}
		}
	}
	return User{}, ErrNotFound
}

func (s *fileStore) ListUsers(_ context.Context, tenant string) ([]User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []User
	for _, u := range s.st.Users {
		if u.Tenant == tenant {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Created < out[j].Created || (out[i].Created == out[j].Created && out[i].ID < out[j].ID)
	})
	return out, nil
}

func (s *fileStore) UpdateUser(_ context.Context, u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(u.Tenant, u.ID)
	old, ok := s.st.Users[k]
	if !ok {
		return ErrNotFound
	}
	if s.userClash(u) {
		return ErrConflict
	}
	s.st.Users[k] = u
	return s.commit(func() { s.st.Users[k] = old })
}

func (s *fileStore) DeleteUser(_ context.Context, tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenant, id)
	if _, ok := s.st.Users[k]; !ok {
		return ErrNotFound
	}
	delete(s.st.Users, k)
	for gk, g := range s.st.Groups {
		if g.Tenant != tenant {
			continue
		}
		var keep []string
		for _, m := range g.Members {
			if m != id {
				keep = append(keep, m)
			}
		}
		g.Members = keep
		s.st.Groups[gk] = g
	}
	for _, rt := range s.st.Refresh {
		if rt.Tenant == tenant && rt.UserID == id {
			rt.Revoked = true
		}
	}
	// A failed write here leaves memory ahead of disk; deletes are
	// revocations, so erring towards "revoked in memory" is the safe side.
	return s.persist()
}

func (s *fileStore) groupClash(g Group) bool {
	for _, x := range s.st.Groups {
		if x.Tenant == g.Tenant && x.ID != g.ID && strings.EqualFold(x.DisplayName, g.DisplayName) {
			return true
		}
	}
	return false
}

func (s *fileStore) CreateGroup(_ context.Context, g Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(g.Tenant, g.ID)
	if _, ok := s.st.Groups[k]; ok || s.groupClash(g) {
		return ErrConflict
	}
	g.Members = sortedUnique(g.Members)
	s.st.Groups[k] = g
	return s.commit(func() { delete(s.st.Groups, k) })
}

func (s *fileStore) GetGroup(_ context.Context, tenant, id string) (Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.st.Groups[key(tenant, id)]
	if !ok {
		return Group{}, ErrNotFound
	}
	g.Members = append([]string(nil), g.Members...)
	return g, nil
}

func (s *fileStore) ListGroups(_ context.Context, tenant string) ([]Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Group
	for _, g := range s.st.Groups {
		if g.Tenant == tenant {
			g.Members = append([]string(nil), g.Members...)
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Created < out[j].Created || (out[i].Created == out[j].Created && out[i].ID < out[j].ID)
	})
	return out, nil
}

func (s *fileStore) UpdateGroup(_ context.Context, g Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(g.Tenant, g.ID)
	old, ok := s.st.Groups[k]
	if !ok {
		return ErrNotFound
	}
	if s.groupClash(g) {
		return ErrConflict
	}
	g.Members = sortedUnique(g.Members)
	s.st.Groups[k] = g
	return s.commit(func() { s.st.Groups[k] = old })
}

func (s *fileStore) DeleteGroup(_ context.Context, tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenant, id)
	if _, ok := s.st.Groups[k]; !ok {
		return ErrNotFound
	}
	delete(s.st.Groups, k)
	return s.persist()
}

func (s *fileStore) UserGroupNames(_ context.Context, tenant, userID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, g := range s.st.Groups {
		if g.Tenant != tenant {
			continue
		}
		for _, m := range g.Members {
			if m == userID {
				out = append(out, g.DisplayName)
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *fileStore) SetGrant(_ context.Context, tenant, group string, workspaces []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenant, group)
	old, had := s.st.Grants[k]
	ws := sortedUnique(workspaces)
	if len(ws) == 0 {
		delete(s.st.Grants, k)
	} else {
		s.st.Grants[k] = ws
	}
	return s.commit(func() {
		if had {
			s.st.Grants[k] = old
		} else {
			delete(s.st.Grants, k)
		}
	})
}

func (s *fileStore) ListGrants(_ context.Context, tenant string) (map[string][]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]string{}
	prefix := tenant + "/"
	for k, ws := range s.st.Grants {
		if g, ok := strings.CutPrefix(k, prefix); ok {
			out[g] = append([]string(nil), ws...)
		}
	}
	return out, nil
}

func (s *fileStore) PutRefresh(_ context.Context, rt RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.st.Refresh[rt.Hash]; ok {
		return ErrConflict
	}
	c := rt
	s.st.Refresh[rt.Hash] = &c
	return s.commit(func() { delete(s.st.Refresh, rt.Hash) })
}

func (s *fileStore) GetRefresh(_ context.Context, hash string) (RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.st.Refresh[hash]
	if !ok {
		return RefreshToken{}, ErrNotFound
	}
	return *rt, nil
}

func (s *fileStore) RotateRefresh(_ context.Context, oldHash string, next RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.st.Refresh[oldHash]
	if !ok {
		return ErrNotFound
	}
	if old.Used || old.Revoked {
		s.revokeFamilyLocked(old.Tenant, old.FamilyID)
		_ = s.persist()
		return ErrRefreshReused
	}
	if _, clash := s.st.Refresh[next.Hash]; clash {
		return ErrConflict
	}
	old.Used = true
	c := next
	s.st.Refresh[next.Hash] = &c
	return s.commit(func() {
		old.Used = false
		delete(s.st.Refresh, next.Hash)
	})
}

func (s *fileStore) revokeFamilyLocked(tenant, family string) {
	for _, rt := range s.st.Refresh {
		if rt.Tenant == tenant && rt.FamilyID == family {
			rt.Revoked = true
		}
	}
}

func (s *fileStore) RevokeFamily(_ context.Context, tenant, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeFamilyLocked(tenant, familyID)
	return s.persist()
}

func (s *fileStore) RevokeUser(_ context.Context, tenant, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, rt := range s.st.Refresh {
		if rt.Tenant == tenant && rt.UserID == userID && !rt.Revoked {
			rt.Revoked = true
			n++
		}
	}
	return n, s.persist()
}

func (s *fileStore) RevokeDevice(_ context.Context, tenant, deviceID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, rt := range s.st.Refresh {
		if rt.Tenant == tenant && rt.DeviceID == deviceID && !rt.Revoked {
			rt.Revoked = true
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, s.persist()
}

func (s *fileStore) PruneRefresh(_ context.Context, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for h, rt := range s.st.Refresh {
		if rt.ExpiresAt < now {
			delete(s.st.Refresh, h)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.persist()
}

func (s *fileStore) Close() error { return nil }
