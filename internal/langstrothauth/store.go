package langstrothauth

import (
	"context"
	"errors"
	"sort"
)

// Durable state: SCIM users and groups, group -> workspace grants, and
// refresh tokens (hashes only). Every record carries its tenant and every
// lookup takes one, so no call can reach another tenant's rows.
//
// Short-lived state (IdP login transactions, authorization and device codes,
// device-proof nonces) is kept in process memory: it lives for minutes, and a
// restart only means a person starts the sign-in again.

// Store errors.
var (
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrRefreshReused = errors.New("refresh token reuse")
)

// User is a person in one tenant. ID is the stable langstroth-auth user id that
// appears in tokens as sub "<tenant>:<id>".
type User struct {
	Tenant      string `json:"tenant"`
	ID          string `json:"id"`
	UserName    string `json:"userName"`
	ExternalID  string `json:"externalId,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Active      bool   `json:"active"`
	// Subject is the uid (hash of IdP issuer and subject) bound at the first
	// sign-in. Empty until then.
	Subject  string `json:"subject,omitempty"`
	Created  int64  `json:"created"`
	Modified int64  `json:"modified"`
}

// Group is a SCIM group. Members are user ids in the same tenant.
type Group struct {
	Tenant      string   `json:"tenant"`
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	ExternalID  string   `json:"externalId,omitempty"`
	Members     []string `json:"members"`
	Created     int64    `json:"created"`
	Modified    int64    `json:"modified"`
}

// RefreshToken is one refresh token in a rotation family. Only the SHA-256
// of the token is stored.
type RefreshToken struct {
	Hash      string `json:"hash"`
	Tenant    string `json:"tenant"`
	FamilyID  string `json:"familyId"`
	UserID    string `json:"userId"`
	ClientID  string `json:"clientId"`
	DeviceID  string `json:"deviceId"`
	DeviceKey string `json:"deviceKey"` // base64url Ed25519 public key
	// IdPGroups is the groups claim captured at the IdP sign-in (used only
	// when the tenant trusts IdP groups).
	IdPGroups    []string `json:"idpGroups,omitempty"`
	SessionStart int64    `json:"sessionStart"`
	ExpiresAt    int64    `json:"expiresAt"`
	CreatedAt    int64    `json:"createdAt"`
	Used         bool     `json:"used"`
	Revoked      bool     `json:"revoked"`
}

// Store is langstroth-auth's persistence.
type Store interface {
	CreateUser(ctx context.Context, u User) error
	GetUser(ctx context.Context, tenant, id string) (User, error)
	// FindUser looks a user up by "userName", "externalId" or "subject".
	FindUser(ctx context.Context, tenant, attr, value string) (User, error)
	ListUsers(ctx context.Context, tenant string) ([]User, error)
	UpdateUser(ctx context.Context, u User) error
	// DeleteUser removes the user, drops them from every group and revokes
	// their refresh tokens.
	DeleteUser(ctx context.Context, tenant, id string) error

	CreateGroup(ctx context.Context, g Group) error
	GetGroup(ctx context.Context, tenant, id string) (Group, error)
	ListGroups(ctx context.Context, tenant string) ([]Group, error)
	UpdateGroup(ctx context.Context, g Group) error
	DeleteGroup(ctx context.Context, tenant, id string) error
	// UserGroupNames returns the display names of the user's groups.
	UserGroupNames(ctx context.Context, tenant, userID string) ([]string, error)

	// SetGrant replaces a group's workspace grants; an empty list deletes it.
	SetGrant(ctx context.Context, tenant, group string, workspaces []string) error
	ListGrants(ctx context.Context, tenant string) (map[string][]string, error)

	PutRefresh(ctx context.Context, rt RefreshToken) error
	GetRefresh(ctx context.Context, hash string) (RefreshToken, error)
	// RotateRefresh marks old used and stores next, atomically. If old was
	// already used it revokes the whole family and returns ErrRefreshReused.
	RotateRefresh(ctx context.Context, oldHash string, next RefreshToken) error
	RevokeFamily(ctx context.Context, tenant, familyID string) error
	// RevokeUser revokes every refresh token of the user and returns how many.
	RevokeUser(ctx context.Context, tenant, userID string) (int, error)
	// RevokeDevice revokes every refresh token bound to the device (its
	// sign-in session) and returns how many.
	RevokeDevice(ctx context.Context, tenant, deviceID string) (int, error)
	// PruneRefresh deletes refresh tokens that expired before now.
	PruneRefresh(ctx context.Context, now int64) error

	Close() error
}

func sortedUnique(in []string) []string {
	m := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !m[s] {
			m[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
