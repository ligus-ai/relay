package relay

import (
	"encoding/json"
	"net/http"
	"testing"
)

// F-03: an admin could promote itself (or anyone) to owner, demote or remove
// an owner, and the sole owner could be demoted by an upsert (orphaning the
// workspace), because memberUpsert/memberRemove only checked caller >= admin.
func TestMemberRoleEscalationBlocked(t *testing.T) {
	ts, sk := membershipServer(t)
	base := ts.URL + "/v1/workspaces/wsE/members"
	owner := issueToken(sk, TokenClaims{Sub: "github:1"})
	admin := issueToken(sk, TokenClaims{Sub: "github:2"})

	if code, _ := req(t, "POST", base+"/claim", owner, nil); code != http.StatusOK {
		t.Fatalf("claim: %d", code)
	}
	if code, _ := req(t, "POST", base, owner, map[string]string{"account": "github:2", "role": "admin"}); code != http.StatusOK {
		t.Fatalf("owner adds admin: %d", code)
	}

	// Admin promotes itself to owner.
	if code, _ := req(t, "POST", base, admin, map[string]string{"account": "github:2", "role": "owner"}); code != http.StatusForbidden {
		t.Errorf("admin self-promotion to owner: want 403, got %d", code)
	}
	// Admin grants owner to a newcomer.
	if code, _ := req(t, "POST", base, admin, map[string]string{"account": "github:3", "role": "owner"}); code != http.StatusForbidden {
		t.Errorf("admin granting owner: want 403, got %d", code)
	}
	// Admin demotes the owner.
	if code, _ := req(t, "POST", base, admin, map[string]string{"account": "github:1", "role": "viewer"}); code != http.StatusForbidden {
		t.Errorf("admin demoting owner: want 403, got %d", code)
	}
	// Second owner exists; an admin still can't remove an owner.
	if code, _ := req(t, "POST", base, owner, map[string]string{"account": "github:4", "role": "owner"}); code != http.StatusOK {
		t.Fatalf("owner adds a second owner: %d", code)
	}
	if code, _ := req(t, "DELETE", base+"/github:4", admin, nil); code != http.StatusForbidden {
		t.Errorf("admin removing an owner: want 403, got %d", code)
	}
	// The admin can still manage lower ranks.
	if code, _ := req(t, "POST", base, admin, map[string]string{"account": "github:5", "role": "contributor"}); code != http.StatusOK {
		t.Errorf("admin adding a contributor: want 200, got %d", code)
	}

	// Sole-owner demotion by upsert orphans the workspace.
	if code, _ := req(t, "DELETE", base+"/github:4", owner, nil); code != http.StatusOK {
		t.Fatalf("owner removes second owner: %d", code)
	}
	if code, _ := req(t, "POST", base, owner, map[string]string{"account": "github:1", "role": "viewer"}); code != http.StatusConflict {
		t.Errorf("demoting the last owner: want 409, got %d", code)
	}

	code, body := req(t, "GET", base, owner, nil)
	var members []MemberRow
	_ = json.Unmarshal(body, &members)
	owners := 0
	for _, m := range members {
		if m.Role == "owner" {
			owners++
		}
		if m.Account == "github:2" && m.Role != "admin" {
			t.Errorf("admin's role changed to %q", m.Role)
		}
	}
	if code != http.StatusOK || owners != 1 {
		t.Errorf("want exactly one owner left, got %d (%s)", owners, body)
	}
}

// Redeeming an invite must not lower an existing member's role (an owner
// redeeming a viewer invite would otherwise orphan the workspace).
func TestJoinDoesNotDowngrade(t *testing.T) {
	ts, sk := membershipServer(t)
	ws := ts.URL + "/v1/workspaces/wsJ"
	owner := issueToken(sk, TokenClaims{Sub: "github:1"})
	if code, _ := req(t, "POST", ws+"/members/claim", owner, nil); code != http.StatusOK {
		t.Fatalf("claim: %d", code)
	}
	code, body := req(t, "POST", ws+"/invites", owner, map[string]any{"role": "viewer"})
	if code != http.StatusOK {
		t.Fatalf("invite: %d", code)
	}
	var inv struct{ Code string }
	_ = json.Unmarshal(body, &inv)
	if code, _ := req(t, "POST", ws+"/join", owner, map[string]string{"code": inv.Code}); code != http.StatusOK {
		t.Fatalf("join: %d", code)
	}
	_, body = req(t, "GET", ws+"/members", owner, nil)
	var members []MemberRow
	_ = json.Unmarshal(body, &members)
	if len(members) != 1 || members[0].Role != "owner" {
		t.Fatalf("owner was downgraded by redeeming a viewer invite: %s", body)
	}
}

// F-04: the roster of a claimed workspace (member account ids, logins, roles)
// was readable by any caller that passed the entitlement gate, which on an
// open relay with membership on is anyone.
func TestRosterReadRequiresMembership(t *testing.T) {
	ts, sk := membershipServer(t)
	base := ts.URL + "/v1/workspaces/wsR/members"
	owner := issueToken(sk, TokenClaims{Sub: "github:1"})
	stranger := issueToken(sk, TokenClaims{Sub: "github:99"})
	if code, _ := req(t, "POST", base+"/claim", owner, map[string]string{"login": "alice"}); code != http.StatusOK {
		t.Fatalf("claim: %d", code)
	}
	if code, body := req(t, "GET", base, stranger, nil); code != http.StatusForbidden {
		t.Fatalf("non-member roster read: want 403, got %d %s", code, body)
	}
	if code, _ := req(t, "GET", base, owner, nil); code != http.StatusOK {
		t.Fatalf("member roster read: want 200, got %d", code)
	}
}
