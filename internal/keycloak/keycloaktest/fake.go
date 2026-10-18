// Package keycloaktest is an in-memory stand-in for the parts of Keycloak's admin REST API that maturad uses, for
// tests that should not need a running Keycloak.
package keycloaktest

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	Realm        = "matura"
	ClientID     = "matura-admin"
	ClientSecret = "fake-secret"
)

// Session is a fake SSO session.
type Session struct {
	ID         string            `json:"id"`
	UserID     string            `json:"userId"`
	IPAddress  string            `json:"ipAddress"`
	Start      int64             `json:"start"`
	LastAccess int64             `json:"lastAccess"`
	RememberMe bool              `json:"rememberMe"`
	Clients    map[string]string `json:"clients"`
}

// Credential is a fake stored credential.
type Credential struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	UserLabel   string `json:"userLabel,omitempty"`
	CreatedDate int64  `json:"createdDate"`
}

// Server is a fake Keycloak. Its fields may be read under Lock/Unlock.
type Server struct {
	*httptest.Server
	sync.Mutex

	Sessions     map[string][]Session    // by user id
	Credentials  map[string][]Credential // by user id
	IdPs         map[string]map[string]any
	Mappers      map[string][]map[string]any
	Imports      map[string]map[string]string // import-config answers by fromUrl
	TokenCalls   int
	Logouts      []string                  // user ids signed out everywhere
	Deleted      []string                  // user ids whose accounts were deleted
	ActionEmails []string                  // "<user id>:<actions>" of execute-actions emails sent
	Accounts     map[string]map[string]any // user representations by id
	Down         bool                      // answer 503 to every admin call, as if Keycloak were failing
	Clients      map[string]map[string]any // client representations by internal id
	Secrets      map[string]string         // client secrets by internal id
	ServiceUser  map[string]string         // service-account user id by client internal id
	tokens       map[string]bool
}

// New starts a fake Keycloak for the realm Realm, closed when the test ends.
func New(t testing.TB) *Server {
	f := &Server{Sessions: map[string][]Session{}, Credentials: map[string][]Credential{},
		IdPs: map[string]map[string]any{}, Mappers: map[string][]map[string]any{},
		Imports: map[string]map[string]string{}, Clients: map[string]map[string]any{}, Secrets: map[string]string{},
		ServiceUser: map[string]string{}, Accounts: map[string]map[string]any{}, tokens: map[string]bool{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

// Issuer is the realm's issuer URL on the fake.
func (f *Server) Issuer() string { return f.URL + "/realms/" + Realm }

// ClientByClientID returns the representation of the client with that clientId, or nil.
func (f *Server) ClientByClientID(clientID string) map[string]any {
	f.Lock()
	defer f.Unlock()
	for _, c := range f.Clients {
		if c["clientId"] == clientID {
			return c
		}
	}
	return nil
}

// AddSession records a session for the user and returns its id.
func (f *Server) AddSession(userID, ip string, clients ...string) string {
	f.Lock()
	defer f.Unlock()
	cl := map[string]string{}
	for _, c := range clients {
		cl[randomID()] = c
	}
	now := time.Now().UnixMilli()
	s := Session{ID: randomID(), UserID: userID, IPAddress: ip, Start: now - 60000, LastAccess: now, Clients: cl}
	f.Sessions[userID] = append(f.Sessions[userID], s)
	return s.ID
}

// AddCredential records a credential of the given type for the user and returns its id.
func (f *Server) AddCredential(userID, typ, label string) string {
	f.Lock()
	defer f.Unlock()
	c := Credential{ID: randomID(), Type: typ, UserLabel: label, CreatedDate: time.Now().UnixMilli()}
	f.Credentials[userID] = append(f.Credentials[userID], c)
	return c.ID
}

// AddAccount records an account with this email (also its username) and returns its id.
func (f *Server) AddAccount(email, first, last string) string {
	f.Lock()
	defer f.Unlock()
	id := uuidLike()
	f.Accounts[id] = map[string]any{"id": id, "username": strings.ToLower(email), "email": email,
		"emailVerified": true, "enabled": true, "firstName": first, "lastName": last}
	return id
}

// Account returns a copy of the account's representation, or nil.
func (f *Server) Account(id string) map[string]any {
	f.Lock()
	defer f.Unlock()
	a, ok := f.Accounts[id]
	if !ok {
		return nil
	}
	b, _ := json.Marshal(a)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// ExpireTokens makes every issued access token invalid, as if Keycloak restarted with new keys.
func (f *Server) ExpireTokens() {
	f.Lock()
	defer f.Unlock()
	f.tokens = map[string]bool{}
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// uuidLike returns a random version-4 UUID string, like the ids Keycloak assigns.
func uuidLike() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *Server) serve(w http.ResponseWriter, r *http.Request) {
	f.Lock()
	defer f.Unlock()
	if r.URL.Path == "/realms/"+Realm+"/protocol/openid-connect/token" {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != ClientID ||
			r.PostForm.Get("client_secret") != ClientSecret {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized_client"})
			return
		}
		f.TokenCalls++
		tok := randomID()
		f.tokens[tok] = true
		writeJSON(w, http.StatusOK, map[string]any{"access_token": tok, "expires_in": 300, "token_type": "Bearer"})
		return
	}
	prefix := "/admin/realms/" + Realm + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Realm not found."})
		return
	}
	if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); !ok || !f.tokens[tok] {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.Down {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	route := r.Method + " " + strings.Join(pattern(parts), "/")
	switch route {
	case "GET users":
		email := strings.ToLower(r.URL.Query().Get("email"))
		out := []map[string]any{}
		for _, a := range f.Accounts {
			if e, _ := a["email"].(string); email == "" || strings.ToLower(e) == email {
				out = append(out, a)
			}
		}
		writeJSON(w, http.StatusOK, out)
	case "POST users":
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		email, _ := in["email"].(string)
		for _, a := range f.Accounts {
			if e, _ := a["email"].(string); strings.EqualFold(e, email) {
				writeJSON(w, http.StatusConflict, map[string]string{"errorMessage": "User exists with same email"})
				return
			}
		}
		id := uuidLike()
		in["id"] = id
		if _, ok := in["username"]; !ok {
			in["username"] = strings.ToLower(email)
		}
		f.Accounts[id] = in
		w.Header().Set("Location", f.URL+prefix+"users/"+id)
		w.WriteHeader(http.StatusCreated)
	case "GET users/*":
		a, ok := f.Accounts[parts[1]]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "User not found"})
			return
		}
		writeJSON(w, http.StatusOK, a)
	case "PUT users/*/execute-actions-email":
		if _, ok := f.Accounts[parts[1]]; !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "User not found"})
			return
		}
		var actions []string
		_ = json.NewDecoder(r.Body).Decode(&actions)
		f.ActionEmails = append(f.ActionEmails, parts[1]+":"+strings.Join(actions, ","))
		w.WriteHeader(http.StatusNoContent)
	case "PUT users/*":
		if _, ok := f.Accounts[parts[1]]; !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "User not found"})
			return
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		in["id"] = parts[1]
		f.Accounts[parts[1]] = in
		w.WriteHeader(http.StatusNoContent)
	case "GET users/*/sessions":
		writeJSON(w, http.StatusOK, orEmpty(f.Sessions[parts[1]]))
	case "POST users/*/logout":
		delete(f.Sessions, parts[1])
		f.Logouts = append(f.Logouts, parts[1])
		w.WriteHeader(http.StatusNoContent)
	case "DELETE sessions/*":
		for uid, list := range f.Sessions {
			for i, s := range list {
				if s.ID == parts[1] {
					f.Sessions[uid] = append(list[:i:i], list[i+1:]...)
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Sesssion not found"})
	case "DELETE users/*":
		f.Deleted = append(f.Deleted, parts[1])
		delete(f.Accounts, parts[1])
		delete(f.Sessions, parts[1])
		delete(f.Credentials, parts[1])
		w.WriteHeader(http.StatusNoContent)
	case "GET users/*/credentials":
		writeJSON(w, http.StatusOK, orEmpty(f.Credentials[parts[1]]))
	case "DELETE users/*/credentials/*":
		list := f.Credentials[parts[1]]
		for i, c := range list {
			if c.ID == parts[3] {
				f.Credentials[parts[1]] = append(list[:i:i], list[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Credential not found"})
	case "POST identity-provider/import-config":
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		cfg, ok := f.Imports[in["fromUrl"]]
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"errorMessage": "Could not import config"})
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	case "POST identity-provider/instances":
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		alias, _ := in["alias"].(string)
		if _, ok := f.IdPs[alias]; ok {
			writeJSON(w, http.StatusConflict, map[string]string{"errorMessage": "Identity Provider " + alias + " already exists"})
			return
		}
		f.IdPs[alias] = in
		w.WriteHeader(http.StatusCreated)
	case "GET identity-provider/instances/*":
		idp, ok := f.IdPs[parts[2]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, idp)
	case "PUT identity-provider/instances/*":
		if _, ok := f.IdPs[parts[2]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.IdPs[parts[2]] = in
		w.WriteHeader(http.StatusNoContent)
	case "DELETE identity-provider/instances/*":
		if _, ok := f.IdPs[parts[2]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.IdPs, parts[2])
		delete(f.Mappers, parts[2])
		w.WriteHeader(http.StatusNoContent)
	case "GET identity-provider/instances/*/mappers":
		writeJSON(w, http.StatusOK, orEmpty(f.Mappers[parts[2]]))
	case "POST identity-provider/instances/*/mappers":
		if _, ok := f.IdPs[parts[2]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		in["id"] = randomID()
		f.Mappers[parts[2]] = append(f.Mappers[parts[2]], in)
		w.WriteHeader(http.StatusCreated)
	case "DELETE identity-provider/instances/*/mappers/*":
		list := f.Mappers[parts[2]]
		for i, m := range list {
			if m["id"] == parts[4] {
				f.Mappers[parts[2]] = append(list[:i:i], list[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	case "POST clients":
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		for _, c := range f.Clients {
			if c["clientId"] == in["clientId"] {
				writeJSON(w, http.StatusConflict, map[string]string{"errorMessage": "Client already exists"})
				return
			}
		}
		id := uuidLike()
		in["id"] = id
		f.Clients[id] = in
		f.Secrets[id] = randomID()
		f.ServiceUser[id] = uuidLike()
		w.WriteHeader(http.StatusCreated)
	case "GET clients":
		out := []map[string]any{}
		for _, c := range f.Clients {
			if q := r.URL.Query().Get("clientId"); q == "" || c["clientId"] == q {
				out = append(out, c)
			}
		}
		writeJSON(w, http.StatusOK, out)
	case "PUT clients/*":
		c, ok := f.Clients[parts[1]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		for k, v := range in {
			c[k] = v
		}
		w.WriteHeader(http.StatusNoContent)
	case "DELETE clients/*":
		if _, ok := f.Clients[parts[1]]; !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "Could not find client"})
			return
		}
		delete(f.Clients, parts[1])
		delete(f.Secrets, parts[1])
		delete(f.ServiceUser, parts[1])
		w.WriteHeader(http.StatusNoContent)
	case "GET clients/*/service-account-user":
		if _, ok := f.Clients[parts[1]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": f.ServiceUser[parts[1]],
			"username": "service-account-" + f.Clients[parts[1]]["clientId"].(string)})
	case "GET clients/*/client-secret", "POST clients/*/client-secret":
		if _, ok := f.Clients[parts[1]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPost {
			f.Secrets[parts[1]] = randomID()
		}
		writeJSON(w, http.StatusOK, map[string]string{"type": "secret", "value": f.Secrets[parts[1]]})
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "fake keycloak does not serve " + route})
	}
}

// pattern replaces ids in an admin path with *, keeping the fixed words.
func pattern(parts []string) []string {
	fixed := map[string]bool{"users": true, "sessions": true, "logout": true, "credentials": true,
		"identity-provider": true, "instances": true, "mappers": true, "import-config": true, "clients": true,
		"service-account-user": true, "client-secret": true, "execute-actions-email": true}
	out := make([]string, len(parts))
	for i, p := range parts {
		if fixed[p] {
			out[i] = p
		} else {
			out[i] = "*"
		}
	}
	return out
}

func orEmpty[T any](list []T) []T {
	if list == nil {
		return []T{}
	}
	return list
}
