package langstrothauth

import (
	"errors"
	"os"
	"testing"
)

// storeSuite is the contract every Store implementation must meet, with an
// emphasis on tenant isolation and refresh rotation.
func storeSuite(t *testing.T, s Store) {
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.CreateUser(ctx, User{Tenant: "t1", ID: "a", UserName: "Ann", Active: true, Subject: "sa", ExternalID: "ea", Created: 1, Modified: 1}))
	must(s.CreateUser(ctx, User{Tenant: "t2", ID: "a", UserName: "ann", Active: true, Subject: "sa", Created: 1, Modified: 1}))
	if err := s.CreateUser(ctx, User{Tenant: "t1", ID: "b", UserName: "ANN", Active: true, Created: 2}); !errors.Is(err, ErrConflict) {
		t.Fatalf("case-insensitive userName clash: %v", err)
	}
	if err := s.CreateUser(ctx, User{Tenant: "t1", ID: "b", UserName: "bob", Subject: "sa", Created: 2}); !errors.Is(err, ErrConflict) {
		t.Fatalf("subject clash: %v", err)
	}
	must(s.CreateUser(ctx, User{Tenant: "t1", ID: "b", UserName: "bob", Active: true, Created: 2, Modified: 2}))
	if u, err := s.FindUser(ctx, "t1", "userName", "ANN"); err != nil || u.ID != "a" || u.Tenant != "t1" {
		t.Fatalf("find by userName: %v %+v", err, u)
	}
	if _, err := s.FindUser(ctx, "t3", "subject", "sa"); !errors.Is(err, ErrNotFound) {
		t.Fatal("lookups are tenant-scoped")
	}
	if users, _ := s.ListUsers(ctx, "t1"); len(users) != 2 {
		t.Fatalf("list t1: %d", len(users))
	}

	must(s.CreateGroup(ctx, Group{Tenant: "t1", ID: "g", DisplayName: "eng", Members: []string{"a", "b", "a"}, Created: 1}))
	if err := s.CreateGroup(ctx, Group{Tenant: "t1", ID: "g2", DisplayName: "ENG", Created: 1}); !errors.Is(err, ErrConflict) {
		t.Fatalf("group name clash: %v", err)
	}
	must(s.CreateGroup(ctx, Group{Tenant: "t2", ID: "g", DisplayName: "eng", Members: []string{"a"}, Created: 1}))
	if names, _ := s.UserGroupNames(ctx, "t1", "a"); len(names) != 1 || names[0] != "eng" {
		t.Fatalf("groups of a: %v", names)
	}
	g, _ := s.GetGroup(ctx, "t1", "g")
	if len(g.Members) != 2 {
		t.Fatalf("members deduped: %v", g.Members)
	}
	must(s.SetGrant(ctx, "t1", "eng", []string{"w2", "w1", "w1"}))
	must(s.SetGrant(ctx, "t2", "eng", []string{"x"}))
	gr, _ := s.ListGrants(ctx, "t1")
	if len(gr) != 1 || len(gr["eng"]) != 2 || gr["eng"][0] != "w1" {
		t.Fatalf("grants t1: %v", gr)
	}
	must(s.SetGrant(ctx, "t1", "eng", nil))
	if gr, _ := s.ListGrants(ctx, "t1"); len(gr) != 0 {
		t.Fatalf("grant delete: %v", gr)
	}

	r1 := RefreshToken{Hash: "h1", Tenant: "t1", FamilyID: "f1", UserID: "a", DeviceID: "d", DeviceKey: "k", SessionStart: 1, ExpiresAt: 100, CreatedAt: 1}
	must(s.PutRefresh(ctx, r1))
	r2 := r1
	r2.Hash = "h2"
	must(s.RotateRefresh(ctx, "h1", r2))
	if got, _ := s.GetRefresh(ctx, "h1"); !got.Used {
		t.Fatal("rotated token must be marked used")
	}
	r3 := r1
	r3.Hash = "h3"
	if err := s.RotateRefresh(ctx, "h1", r3); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("reuse: %v", err)
	}
	if got, _ := s.GetRefresh(ctx, "h2"); !got.Revoked {
		t.Fatal("reuse must revoke the family")
	}
	if _, err := s.GetRefresh(ctx, "h3"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the replacement must not be stored on reuse")
	}

	must(s.PutRefresh(ctx, RefreshToken{Hash: "h4", Tenant: "t1", FamilyID: "f4", UserID: "b", ExpiresAt: 100}))
	must(s.PutRefresh(ctx, RefreshToken{Hash: "h5", Tenant: "t2", FamilyID: "f5", UserID: "b", ExpiresAt: 100}))
	if n, _ := s.RevokeUser(ctx, "t1", "b"); n != 1 {
		t.Fatalf("revoke user t1/b: %d", n)
	}
	if got, _ := s.GetRefresh(ctx, "h5"); got.Revoked {
		t.Fatal("revoking t1/b must not touch t2/b")
	}

	// Per-device session revocation: only that device, only that tenant.
	must(s.PutRefresh(ctx, RefreshToken{Hash: "h6", Tenant: "t1", FamilyID: "f6", UserID: "c", DeviceID: "phone", ExpiresAt: 100}))
	must(s.PutRefresh(ctx, RefreshToken{Hash: "h7", Tenant: "t1", FamilyID: "f7", UserID: "c", DeviceID: "laptop", ExpiresAt: 100}))
	must(s.PutRefresh(ctx, RefreshToken{Hash: "h8", Tenant: "t2", FamilyID: "f8", UserID: "c", DeviceID: "phone", ExpiresAt: 100}))
	if n, _ := s.RevokeDevice(ctx, "t1", "phone"); n != 1 {
		t.Fatalf("revoke device t1/phone: %d", n)
	}
	if n, _ := s.RevokeDevice(ctx, "t1", "phone"); n != 0 {
		t.Fatalf("revoke device again: %d", n)
	}
	if got, _ := s.GetRefresh(ctx, "h6"); !got.Revoked {
		t.Fatal("device token not revoked")
	}
	if got, _ := s.GetRefresh(ctx, "h7"); got.Revoked {
		t.Fatal("revoking a device must not touch the person's other devices")
	}
	if got, _ := s.GetRefresh(ctx, "h8"); got.Revoked {
		t.Fatal("revoking t1/phone must not touch t2/phone")
	}

	must(s.DeleteUser(ctx, "t1", "a"))
	if g, _ := s.GetGroup(ctx, "t1", "g"); len(g.Members) != 1 || g.Members[0] != "b" {
		t.Fatalf("delete removes membership: %v", g.Members)
	}
	if g, _ := s.GetGroup(ctx, "t2", "g"); len(g.Members) != 1 {
		t.Fatal("delete in t1 must not touch t2")
	}
	if _, err := s.GetUser(ctx, "t2", "a"); err != nil {
		t.Fatal("t2/a must survive")
	}
	must(s.PruneRefresh(ctx, 1000))
	if _, err := s.GetRefresh(ctx, "h4"); !errors.Is(err, ErrNotFound) {
		t.Fatal("prune")
	}
}

func TestMemoryStoreContract(t *testing.T) {
	s, _ := NewFileStore("")
	storeSuite(t, s)
}

// Postgres contract tests run only when LANGSTROTH_AUTH_TEST_DATABASE_URL points
// at a throwaway database, e.g.
//
//	docker run --rm -e POSTGRES_PASSWORD=auth -p 55433:5432 postgres:16-alpine
//	LANGSTROTH_AUTH_TEST_DATABASE_URL=postgres://postgres:auth@127.0.0.1:55433/postgres go test ./langstrothauth
func TestPostgresStoreContract(t *testing.T) {
	dsn := os.Getenv("LANGSTROTH_AUTH_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set LANGSTROTH_AUTH_TEST_DATABASE_URL to run the Postgres store tests")
	}
	s, err := NewPostgresStore(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ps := s.(*pgStore)
	for _, tbl := range []string{"ligus_auth_group_members", "ligus_auth_groups", "ligus_auth_users", "ligus_auth_grants", "ligus_auth_refresh"} {
		if _, err := ps.pool.Exec(t.Context(), "DELETE FROM "+tbl); err != nil {
			t.Fatal(err)
		}
	}
	storeSuite(t, s)
}
