package langstrothauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// A small SCIM 2.0 service provider (RFC 7643/7644) at /t/{tenant}/scim/v2:
// Users and Groups with create, read, list (eq filters), replace, patch and
// delete. It stores only what provisioning needs (userName, externalId,
// displayName, active; group names and members). Deactivating or deleting a
// user revokes their refresh tokens at once; access tokens already issued
// lapse within the access TTL.

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimErrSchema   = "urn:ietf:params:scim:api:messages:2.0:Error"
	maxSCIMBody     = 1 << 20
	maxGroupMembers = 10000
	maxSCIMField    = 512
)

func scimError(w http.ResponseWriter, status int, scimType, detail string) {
	body := map[string]any{"schemas": []string{scimErrSchema}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		body["scimType"] = scimType
	}
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func scimJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// scimAuthorized checks the tenant's SCIM bearer token.
func (s *Server) scimAuthorized(w http.ResponseWriter, r *http.Request, t *TenantConfig) bool {
	if t.scimTokenHash == "" {
		http.NotFound(w, r)
		return false
	}
	ip := s.clientIP(r)
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !constEq(sha256Hex(strings.TrimSpace(tok)), t.scimTokenHash) {
		if !s.authFail.allow("scim|" + s.limitKey(r)) {
			scimError(w, http.StatusTooManyRequests, "", "too many failed attempts")
			return false
		}
		s.audit.event("scim_auth_failed", t.ID, "ip", ip)
		w.Header().Set("WWW-Authenticate", `Bearer realm="langstroth-auth"`)
		scimError(w, http.StatusUnauthorized, "", "invalid SCIM token")
		return false
	}
	if !s.scimLimit.allow(t.ID + "|" + s.limitKey(r)) {
		scimError(w, http.StatusTooManyRequests, "", "rate limited")
		return false
	}
	return true
}

func (s *Server) handleSCIM(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	if !s.scimAuthorized(w, r, t) {
		return
	}
	parts := strings.Split(strings.Trim(r.PathValue("rest"), "/"), "/")
	res, id := parts[0], ""
	if len(parts) == 2 {
		id = parts[1]
	} else if len(parts) > 2 {
		scimError(w, http.StatusNotFound, "", "not found")
		return
	}
	switch {
	case res == "ServiceProviderConfig" && id == "" && r.Method == http.MethodGet:
		scimJSON(w, http.StatusOK, map[string]any{
			"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
			"patch":                 map[string]bool{"supported": true},
			"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
			"filter":                map[string]any{"supported": true, "maxResults": 200},
			"changePassword":        map[string]bool{"supported": false},
			"sort":                  map[string]bool{"supported": false},
			"etag":                  map[string]bool{"supported": false},
			"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Bearer token", "description": "Per-tenant SCIM token", "primary": true}},
		})
	case res == "ResourceTypes" && id == "" && r.Method == http.MethodGet:
		scimJSON(w, http.StatusOK, map[string]any{"schemas": []string{scimListSchema}, "totalResults": 2, "Resources": []map[string]any{
			{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users", "schema": scimUserSchema},
			{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": scimGroupSchema},
		}})
	case res == "Users":
		s.scimUsers(w, r, t, id)
	case res == "Groups":
		s.scimGroups(w, r, t, id)
	default:
		scimError(w, http.StatusNotFound, "", "not found")
	}
}

func readSCIM(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxSCIMBody)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		scimError(w, http.StatusRequestEntityTooLarge, "", "body too large")
		return false
	}
	if err := json.Unmarshal(b, v); err != nil {
		scimError(w, http.StatusBadRequest, "invalidSyntax", "malformed JSON")
		return false
	}
	return true
}

func (s *Server) location(t *TenantConfig, kind, id string) string {
	return s.issuerURL(t) + "/scim/v2/" + kind + "/" + id
}

func rfc3339(unix int64) string { return time.Unix(unix, 0).UTC().Format(time.RFC3339) }

func (s *Server) userJSON(t *TenantConfig, u User) map[string]any {
	out := map[string]any{
		"schemas": []string{scimUserSchema}, "id": u.ID, "userName": u.UserName, "active": u.Active,
		"meta": map[string]any{"resourceType": "User", "created": rfc3339(u.Created), "lastModified": rfc3339(u.Modified), "location": s.location(t, "Users", u.ID)},
	}
	if u.ExternalID != "" {
		out["externalId"] = u.ExternalID
	}
	if u.DisplayName != "" {
		out["displayName"] = u.DisplayName
	}
	return out
}

func (s *Server) groupJSON(t *TenantConfig, g Group) map[string]any {
	members := make([]map[string]string, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, map[string]string{"value": m, "$ref": s.location(t, "Users", m)})
	}
	out := map[string]any{
		"schemas": []string{scimGroupSchema}, "id": g.ID, "displayName": g.DisplayName, "members": members,
		"meta": map[string]any{"resourceType": "Group", "created": rfc3339(g.Created), "lastModified": rfc3339(g.Modified), "location": s.location(t, "Groups", g.ID)},
	}
	if g.ExternalID != "" {
		out["externalId"] = g.ExternalID
	}
	return out
}

// scimUserIn is the accepted subset of a SCIM User.
type scimUserIn struct {
	UserName    string `json:"userName"`
	ExternalID  string `json:"externalId"`
	DisplayName string `json:"displayName"`
	Name        struct {
		Formatted string `json:"formatted"`
	} `json:"name"`
	Active *flexBool `json:"active"`
}

// flexBool accepts true/false and the strings "True"/"False" some IdPs send.
type flexBool bool

func (b *flexBool) UnmarshalJSON(d []byte) error {
	var v any
	if err := json.Unmarshal(d, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case bool:
		*b = flexBool(x)
	case string:
		p, err := strconv.ParseBool(strings.ToLower(x))
		if err != nil {
			return err
		}
		*b = flexBool(p)
	default:
		return errors.New("not a boolean")
	}
	return nil
}

func validField(v string) bool { return len(v) <= maxSCIMField && !strings.ContainsAny(v, "\x00\r\n") }

func (s *Server) scimUsers(w http.ResponseWriter, r *http.Request, t *TenantConfig, id string) {
	ctx := r.Context()
	now := s.now().Unix()
	switch {
	case id == "" && r.Method == http.MethodGet:
		users, err := s.store.ListUsers(ctx, t.ID)
		if err != nil {
			scimError(w, http.StatusInternalServerError, "", "store error")
			return
		}
		attr, val, err := parseFilter(r.URL.Query().Get("filter"), "userName", "externalId")
		if err != nil {
			scimError(w, http.StatusBadRequest, "invalidFilter", err.Error())
			return
		}
		var res []map[string]any
		for _, u := range users {
			if attr == "userName" && !strings.EqualFold(u.UserName, val) || attr == "externalId" && u.ExternalID != val {
				continue
			}
			res = append(res, s.userJSON(t, u))
		}
		scimList(w, r, res)
	case id == "" && r.Method == http.MethodPost:
		var in scimUserIn
		if !readSCIM(w, r, &in) {
			return
		}
		u := User{Tenant: t.ID, ID: "u" + randToken(15), Active: true, Created: now, Modified: now}
		if !applyUserIn(w, &u, in) {
			return
		}
		if err := s.store.CreateUser(ctx, u); err != nil {
			s.scimStoreErr(w, err)
			return
		}
		s.audit.event("scim_user_created", t.ID, "user", u.ID, "active", u.Active)
		w.Header().Set("Location", s.location(t, "Users", u.ID))
		scimJSON(w, http.StatusCreated, s.userJSON(t, u))
	case id != "" && r.Method == http.MethodGet:
		u, err := s.store.GetUser(ctx, t.ID, id)
		if err != nil {
			s.scimStoreErr(w, err)
			return
		}
		scimJSON(w, http.StatusOK, s.userJSON(t, u))
	case id != "" && r.Method == http.MethodPut:
		u, err := s.store.GetUser(ctx, t.ID, id)
		if err != nil {
			s.scimStoreErr(w, err)
			return
		}
		var in scimUserIn
		if !readSCIM(w, r, &in) {
			return
		}
		was := u.Active
		u.ExternalID, u.DisplayName, u.Active = "", "", true
		if !applyUserIn(w, &u, in) {
			return
		}
		u.Modified = now
		s.saveUser(w, r, t, u, was)
	case id != "" && r.Method == http.MethodPatch:
		u, err := s.store.GetUser(ctx, t.ID, id)
		if err != nil {
			s.scimStoreErr(w, err)
			return
		}
		var patch scimPatch
		if !readSCIM(w, r, &patch) {
			return
		}
		was := u.Active
		for _, op := range patch.Operations {
			if err := patchUser(&u, op); err != nil {
				scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
				return
			}
		}
		if u.UserName == "" || !validField(u.UserName) {
			scimError(w, http.StatusBadRequest, "invalidValue", "userName is required")
			return
		}
		u.Modified = now
		s.saveUser(w, r, t, u, was)
	case id != "" && r.Method == http.MethodDelete:
		if err := s.store.DeleteUser(ctx, t.ID, id); err != nil {
			s.scimStoreErr(w, err)
			return
		}
		s.audit.event("scim_user_deleted", t.ID, "user", id)
		w.WriteHeader(http.StatusNoContent)
	default:
		scimError(w, http.StatusMethodNotAllowed, "", "method not allowed")
	}
}

func applyUserIn(w http.ResponseWriter, u *User, in scimUserIn) bool {
	if strings.TrimSpace(in.UserName) == "" || !validField(in.UserName) || !validField(in.ExternalID) || !validField(in.DisplayName) || !validField(in.Name.Formatted) {
		scimError(w, http.StatusBadRequest, "invalidValue", "userName is required and fields must be short single-line strings")
		return false
	}
	u.UserName = strings.TrimSpace(in.UserName)
	u.ExternalID = in.ExternalID
	u.DisplayName = in.DisplayName
	if u.DisplayName == "" {
		u.DisplayName = in.Name.Formatted
	}
	if in.Active != nil {
		u.Active = bool(*in.Active)
	}
	return true
}

// saveUser stores u and, when it went from active to inactive, revokes
// every refresh token the user holds.
func (s *Server) saveUser(w http.ResponseWriter, r *http.Request, t *TenantConfig, u User, wasActive bool) {
	ctx := r.Context()
	if err := s.store.UpdateUser(ctx, u); err != nil {
		s.scimStoreErr(w, err)
		return
	}
	if wasActive && !u.Active {
		n, err := s.store.RevokeUser(ctx, t.ID, u.ID)
		if err != nil {
			scimError(w, http.StatusInternalServerError, "", "store error")
			return
		}
		s.audit.event("scim_user_deactivated", t.ID, "user", u.ID, "refresh_revoked", n)
	} else {
		s.audit.event("scim_user_updated", t.ID, "user", u.ID, "active", u.Active)
	}
	scimJSON(w, http.StatusOK, s.userJSON(t, u))
}

type scimPatch struct {
	Schemas    []string  `json:"schemas"`
	Operations []patchOp `json:"Operations"`
}

type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

func patchUser(u *User, op patchOp) error {
	kind := strings.ToLower(op.Op)
	if kind != "replace" && kind != "add" && kind != "remove" {
		return fmt.Errorf("unsupported op %q", sanitize(op.Op))
	}
	set := func(path string, raw json.RawMessage) error {
		switch strings.ToLower(path) {
		case "active":
			var b flexBool
			if err := json.Unmarshal(raw, &b); err != nil {
				return errors.New("active must be a boolean")
			}
			u.Active = bool(b)
		case "username", "externalid", "displayname", "name.formatted":
			var v string
			if kind != "remove" {
				if err := json.Unmarshal(raw, &v); err != nil || !validField(v) {
					return fmt.Errorf("%s must be a short string", path)
				}
			}
			switch strings.ToLower(path) {
			case "username":
				u.UserName = strings.TrimSpace(v)
			case "externalid":
				u.ExternalID = v
			default:
				u.DisplayName = v
			}
		}
		// Other attributes (emails, name parts, enterprise extension) are
		// accepted and ignored: langstroth-auth stores no more PII than it needs.
		return nil
	}
	if op.Path != "" {
		return set(op.Path, op.Value)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(op.Value, &m); err != nil {
		return errors.New("a patch without path needs an object value")
	}
	for k, v := range m {
		if err := set(k, v); err != nil {
			return err
		}
	}
	return nil
}

type scimGroupIn struct {
	DisplayName string `json:"displayName"`
	ExternalID  string `json:"externalId"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
}

func (s *Server) scimGroups(w http.ResponseWriter, r *http.Request, t *TenantConfig, id string) {
	ctx := r.Context()
	now := s.now().Unix()
	switch {
	case id == "" && r.Method == http.MethodGet:
		groups, err := s.store.ListGroups(ctx, t.ID)
		if err != nil {
			scimError(w, http.StatusInternalServerError, "", "store error")
			return
		}
		attr, val, err := parseFilter(r.URL.Query().Get("filter"), "displayName", "externalId")
		if err != nil {
			scimError(w, http.StatusBadRequest, "invalidFilter", err.Error())
			return
		}
		excludeMembers := strings.Contains(r.URL.Query().Get("excludedAttributes"), "members")
		var res []map[string]any
		for _, g := range groups {
			if attr == "displayName" && !strings.EqualFold(g.DisplayName, val) || attr == "externalId" && g.ExternalID != val {
				continue
			}
			j := s.groupJSON(t, g)
			if excludeMembers {
				delete(j, "members")
			}
			res = append(res, j)
		}
		scimList(w, r, res)
	case id == "" && r.Method == http.MethodPost:
		var in scimGroupIn
		if !readSCIM(w, r, &in) {
			return
		}
		if strings.TrimSpace(in.DisplayName) == "" || !validField(in.DisplayName) || !validField(in.ExternalID) {
			scimError(w, http.StatusBadRequest, "invalidValue", "displayName is required")
			return
		}
		g := Group{Tenant: t.ID, ID: "g" + randToken(15), DisplayName: strings.TrimSpace(in.DisplayName), ExternalID: in.ExternalID, Created: now, Modified: now}
		for _, m := range in.Members {
			g.Members = append(g.Members, m.Value)
		}
		if !s.checkMembers(w, r, t, g.Members) {
			return
		}
		if err := s.store.CreateGroup(ctx, g); err != nil {
			s.scimStoreErr(w, err)
			return
		}
		g, _ = s.store.GetGroup(ctx, t.ID, g.ID)
		s.audit.event("scim_group_created", t.ID, "group", g.ID, "members", len(g.Members))
		w.Header().Set("Location", s.location(t, "Groups", g.ID))
		scimJSON(w, http.StatusCreated, s.groupJSON(t, g))
	case id != "" && r.Method == http.MethodGet:
		g, err := s.store.GetGroup(ctx, t.ID, id)
		if err != nil {
			s.scimStoreErr(w, err)
			return
		}
		scimJSON(w, http.StatusOK, s.groupJSON(t, g))
	case id != "" && (r.Method == http.MethodPut || r.Method == http.MethodPatch):
		g, err := s.store.GetGroup(ctx, t.ID, id)
		if err != nil {
			s.scimStoreErr(w, err)
			return
		}
		if r.Method == http.MethodPut {
			var in scimGroupIn
			if !readSCIM(w, r, &in) {
				return
			}
			if strings.TrimSpace(in.DisplayName) == "" || !validField(in.DisplayName) || !validField(in.ExternalID) {
				scimError(w, http.StatusBadRequest, "invalidValue", "displayName is required")
				return
			}
			g.DisplayName, g.ExternalID, g.Members = strings.TrimSpace(in.DisplayName), in.ExternalID, nil
			for _, m := range in.Members {
				g.Members = append(g.Members, m.Value)
			}
		} else {
			var patch scimPatch
			if !readSCIM(w, r, &patch) {
				return
			}
			for _, op := range patch.Operations {
				if err := patchGroup(&g, op); err != nil {
					scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
					return
				}
			}
		}
		if !s.checkMembers(w, r, t, g.Members) {
			return
		}
		g.Modified = now
		if err := s.store.UpdateGroup(ctx, g); err != nil {
			s.scimStoreErr(w, err)
			return
		}
		g, _ = s.store.GetGroup(ctx, t.ID, g.ID)
		s.audit.event("scim_group_updated", t.ID, "group", g.ID, "members", len(g.Members))
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		scimJSON(w, http.StatusOK, s.groupJSON(t, g))
	case id != "" && r.Method == http.MethodDelete:
		if err := s.store.DeleteGroup(ctx, t.ID, id); err != nil {
			s.scimStoreErr(w, err)
			return
		}
		s.audit.event("scim_group_deleted", t.ID, "group", id)
		w.WriteHeader(http.StatusNoContent)
	default:
		scimError(w, http.StatusMethodNotAllowed, "", "method not allowed")
	}
}

// checkMembers refuses any member id that is not a user of this tenant, so
// a SCIM client can never pull another tenant's user into its groups.
func (s *Server) checkMembers(w http.ResponseWriter, r *http.Request, t *TenantConfig, members []string) bool {
	if len(members) > maxGroupMembers {
		scimError(w, http.StatusBadRequest, "invalidValue", "too many members")
		return false
	}
	for _, m := range sortedUnique(members) {
		if _, err := s.store.GetUser(r.Context(), t.ID, m); err != nil {
			scimError(w, http.StatusBadRequest, "invalidValue", "member is not a user of this tenant")
			return false
		}
	}
	return true
}

var memberFilterRe = regexp.MustCompile(`^members\[value eq "([^"]+)"\]$`)

func patchGroup(g *Group, op patchOp) error {
	kind := strings.ToLower(op.Op)
	path := op.Path
	readMembers := func(raw json.RawMessage) ([]string, error) {
		var ms []struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(raw, &ms); err != nil {
			return nil, errors.New("members must be an array of {value}")
		}
		var out []string
		for _, m := range ms {
			out = append(out, m.Value)
		}
		return out, nil
	}
	if path == "" {
		// Value object form: {"displayName": ..., "members": [...]}.
		var m map[string]json.RawMessage
		if err := json.Unmarshal(op.Value, &m); err != nil {
			return errors.New("a patch without path needs an object value")
		}
		for k, v := range m {
			if err := patchGroup(g, patchOp{Op: op.Op, Path: k, Value: v}); err != nil {
				return err
			}
		}
		return nil
	}
	if mm := memberFilterRe.FindStringSubmatch(path); mm != nil {
		if kind != "remove" {
			return errors.New("only remove is supported on a member filter")
		}
		g.Members = without(g.Members, mm[1])
		return nil
	}
	switch strings.ToLower(path) {
	case "displayname":
		if kind == "remove" {
			return errors.New("displayName cannot be removed")
		}
		var v string
		if err := json.Unmarshal(op.Value, &v); err != nil || strings.TrimSpace(v) == "" || !validField(v) {
			return errors.New("displayName must be a short string")
		}
		g.DisplayName = strings.TrimSpace(v)
	case "externalid":
		var v string
		if kind != "remove" {
			if err := json.Unmarshal(op.Value, &v); err != nil || !validField(v) {
				return errors.New("externalId must be a short string")
			}
		}
		g.ExternalID = v
	case "members":
		switch kind {
		case "add":
			ms, err := readMembers(op.Value)
			if err != nil {
				return err
			}
			g.Members = append(g.Members, ms...)
		case "replace":
			ms, err := readMembers(op.Value)
			if err != nil {
				return err
			}
			g.Members = ms
		case "remove":
			if len(op.Value) == 0 || string(op.Value) == "null" {
				g.Members = nil
				return nil
			}
			ms, err := readMembers(op.Value)
			if err != nil {
				return err
			}
			for _, m := range ms {
				g.Members = without(g.Members, m)
			}
		default:
			return fmt.Errorf("unsupported op %q", sanitize(op.Op))
		}
	default:
		return fmt.Errorf("unsupported path %q", sanitize(path))
	}
	return nil
}

func without(list []string, v string) []string {
	var out []string
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// parseFilter supports `<attr> eq "<value>"` for the allowed attributes.
func parseFilter(f string, allowed ...string) (attr, val string, err error) {
	f = strings.TrimSpace(f)
	if f == "" {
		return "", "", nil
	}
	parts := strings.SplitN(f, " ", 3)
	if len(parts) != 3 || !strings.EqualFold(parts[1], "eq") {
		return "", "", errors.New("only `attr eq \"value\"` filters are supported")
	}
	for _, a := range allowed {
		if strings.EqualFold(parts[0], a) {
			attr = a
		}
	}
	if attr == "" {
		return "", "", fmt.Errorf("filtering on %q is not supported", sanitize(parts[0]))
	}
	v, uerr := strconv.Unquote(parts[2])
	if uerr != nil {
		return "", "", errors.New("filter value must be a quoted string")
	}
	return attr, v, nil
}

func scimList(w http.ResponseWriter, r *http.Request, all []map[string]any) {
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	if start < 1 {
		start = 1
	}
	count := 100
	if c := r.URL.Query().Get("count"); c != "" {
		count, _ = strconv.Atoi(c)
	}
	if count < 0 {
		count = 0
	}
	if count > 200 {
		count = 200
	}
	page := []map[string]any{}
	if start-1 < len(all) {
		end := start - 1 + count
		if end > len(all) {
			end = len(all)
		}
		page = all[start-1 : end]
	}
	scimJSON(w, http.StatusOK, map[string]any{
		"schemas": []string{scimListSchema}, "totalResults": len(all), "startIndex": start, "itemsPerPage": len(page), "Resources": page,
	})
}

func (s *Server) scimStoreErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		scimError(w, http.StatusNotFound, "", "not found")
	case errors.Is(err, ErrConflict):
		scimError(w, http.StatusConflict, "uniqueness", "a resource with that name or id already exists")
	default:
		scimError(w, http.StatusInternalServerError, "", "store error")
	}
}
