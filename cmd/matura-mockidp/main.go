// Command matura-mockidp is a small OpenID Connect provider for tests and CI (TS13, technical specification §17):
// connect a tenant's SSO to it, or have an app sign in against it, without a real Okta or Entra. It signs RS256
// tokens with a key made at start, knows the people given with -user, and asks nothing: the authorization
// endpoint signs in the person named by login_hint (or the first one) at once, or shows a pick list with
// -choose. Never run it where real people sign in.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Person is someone the mock provider signs in.
type Person struct {
	Sub    string   `json:"sub"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Groups []string `json:"groups,omitempty"`
}

// Provider is the mock OIDC provider.
type Provider struct {
	Issuer   string
	People   []Person
	Clients  map[string]string // client id → secret ("" for public clients)
	Choose   bool              // show a pick list instead of signing in at once
	TokenTTL time.Duration

	key   *rsa.PrivateKey
	kid   string
	mu    sync.Mutex
	codes map[string]grant
}

type grant struct {
	person    Person
	clientID  string
	redirect  string
	nonce     string
	challenge string
	scope     string
	expires   time.Time
}

// New makes a provider with a fresh signing key.
func New(issuer string, people []Person, clients map[string]string) (*Provider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(key.PublicKey.N.Bytes())
	return &Provider{Issuer: strings.TrimRight(issuer, "/"), People: people, Clients: clients, key: key,
		kid: base64.RawURLEncoding.EncodeToString(sum[:8]), codes: map[string]grant{}, TokenTTL: 5 * time.Minute}, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func random() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Handler serves the provider's endpoints.
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer": p.Issuer, "authorization_endpoint": p.Issuer + "/authorize", "token_endpoint": p.Issuer + "/token",
			"userinfo_endpoint": p.Issuer + "/userinfo", "jwks_uri": p.Issuer + "/jwks",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"}, "scopes_supported": []string{"openid", "email", "profile"},
			"grant_types_supported":                 []string{"authorization_code", "client_credentials"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
			"claims_supported":                      []string{"sub", "email", "email_verified", "name", "groups"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := p.key.PublicKey
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256",
			"kid": p.kid, "n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())}}})
	})
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /authorize", p.authorize) // the pick list posts back
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /userinfo", p.userinfo)
	return mux
}

var pickPage = template.Must(template.New("pick").Parse(`<!doctype html><meta charset="utf-8"><title>Mock sign-in</title>
<style>body{font:16px system-ui;margin:10vh auto;max-width:24rem}button{display:block;width:100%;margin:.4rem 0;padding:.6rem}</style>
<h1>Mock identity provider</h1><p>Sign in as:</p><form method="post">{{range .Hidden}}<input type="hidden" name="{{.K}}" value="{{.V}}">{{end}}
{{range .People}}<button name="login_hint" value="{{.Email}}">{{.Name}} &lt;{{.Email}}&gt;</button>{{end}}</form>`))

func (p *Provider) person(hint string) (Person, bool) {
	for _, x := range p.People {
		if hint == "" || strings.EqualFold(x.Email, hint) || x.Sub == hint {
			return x, true
		}
	}
	return Person{}, false
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	q := r.Form
	clientID, redirect := q.Get("client_id"), q.Get("redirect_uri")
	if _, ok := p.Clients[clientID]; !ok {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	u, err := url.Parse(redirect)
	if err != nil || u.Scheme == "" || q.Get("response_type") != "code" {
		http.Error(w, "redirect_uri and response_type=code are required", http.StatusBadRequest)
		return
	}
	if p.Choose && r.Method == http.MethodGet && q.Get("login_hint") == "" {
		type kv struct{ K, V string }
		var hidden []kv
		for k, vs := range q {
			hidden = append(hidden, kv{k, vs[0]})
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = pickPage.Execute(w, map[string]any{"Hidden": hidden, "People": p.People})
		return
	}
	person, ok := p.person(q.Get("login_hint"))
	back := u.Query()
	if !ok {
		back.Set("error", "access_denied")
		back.Set("error_description", "no such person")
	} else {
		if q.Get("code_challenge") != "" && q.Get("code_challenge_method") != "S256" {
			http.Error(w, "code_challenge_method must be S256", http.StatusBadRequest)
			return
		}
		code := random()
		p.mu.Lock()
		p.codes[code] = grant{person: person, clientID: clientID, redirect: redirect, nonce: q.Get("nonce"),
			challenge: q.Get("code_challenge"), scope: q.Get("scope"), expires: time.Now().Add(time.Minute)}
		p.mu.Unlock()
		back.Set("code", code)
	}
	if s := q.Get("state"); s != "" {
		back.Set("state", s)
	}
	u.RawQuery = back.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *Provider) clientAuth(r *http.Request) (string, bool) {
	id, secret, basic := r.BasicAuth()
	if !basic {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	want, ok := p.Clients[id]
	return id, ok && (want == "" || want == secret)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	clientID, ok := p.clientAuth(r)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client or wrong secret")
		return
	}
	now := time.Now()
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		code := r.PostForm.Get("code")
		p.mu.Lock()
		g, found := p.codes[code]
		delete(p.codes, code) // single use
		p.mu.Unlock()
		if !found || now.After(g.expires) || g.clientID != clientID || g.redirect != r.PostForm.Get("redirect_uri") {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown, used or expired code, or another client or redirect_uri")
			return
		}
		if g.challenge != "" {
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
				oauthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match")
				return
			}
		}
		claims := map[string]any{"iss": p.Issuer, "sub": g.person.Sub, "aud": clientID, "iat": now.Unix(),
			"exp": now.Add(p.TokenTTL).Unix(), "email": g.person.Email, "email_verified": true, "name": g.person.Name}
		if len(g.person.Groups) > 0 {
			claims["groups"] = g.person.Groups
		}
		if g.nonce != "" {
			claims["nonce"] = g.nonce
		}
		id, err := p.sign(claims)
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		access, _ := p.sign(map[string]any{"iss": p.Issuer, "sub": g.person.Sub, "aud": clientID, "iat": now.Unix(),
			"exp": now.Add(p.TokenTTL).Unix(), "scope": g.scope, "email": g.person.Email})
		writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "id_token": id, "token_type": "Bearer",
			"expires_in": int(p.TokenTTL.Seconds()), "scope": g.scope})
	case "client_credentials":
		access, err := p.sign(map[string]any{"iss": p.Issuer, "sub": clientID, "aud": clientID, "iat": now.Unix(),
			"exp": now.Add(p.TokenTTL).Unix(), "client_id": clientID})
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int(p.TokenTTL.Seconds())})
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "authorization_code or client_credentials")
	}
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims, err := p.verify(tok)
	if !ok || err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	person, found := p.person(fmt.Sprint(claims["sub"]))
	if !found {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sub": person.Sub, "email": person.Email, "email_verified": true,
		"name": person.Name, "groups": person.Groups})
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (p *Provider) sign(claims map[string]any) (string, error) {
	data := b64(map[string]string{"alg": "RS256", "typ": "JWT", "kid": p.kid}) + "." + b64(claims)
	sum := sha256.Sum256([]byte(data))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, cryptoSHA256, sum[:])
	if err != nil {
		return "", err
	}
	return data + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (p *Provider) verify(tok string) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&p.key.PublicKey, cryptoSHA256, sum[:], sig); err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	if exp, _ := claims["exp"].(float64); int64(exp) < time.Now().Unix() {
		return nil, fmt.Errorf("expired")
	}
	return claims, nil
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	addr := flag.String("addr", ":9400", "listen address")
	issuer := flag.String("issuer", "http://localhost:9400", "the issuer URL clients reach it at")
	var users, clients listFlag
	flag.Var(&users, "user", "a person, email[:name[:group,group]] (repeatable; default ana@example.test)")
	flag.Var(&clients, "client", "a client, id[:secret] (repeatable; default client matura with secret matura-secret)")
	choose := flag.Bool("choose", false, "show a pick list instead of signing in the first person at once")
	flag.Parse()
	if len(users) == 0 {
		users = append(users, "ana@example.test:Ana Example")
	}
	if len(clients) == 0 {
		clients = append(clients, "matura:matura-secret")
	}
	var people []Person
	for i, u := range users {
		parts := strings.SplitN(u, ":", 3)
		person := Person{Sub: fmt.Sprintf("mock-%d", i+1), Email: parts[0], Name: parts[0]}
		if len(parts) > 1 && parts[1] != "" {
			person.Name = parts[1]
		}
		if len(parts) > 2 && parts[2] != "" {
			person.Groups = strings.Split(parts[2], ",")
		}
		people = append(people, person)
	}
	cs := map[string]string{}
	for _, c := range clients {
		id, secret, _ := strings.Cut(c, ":")
		cs[id] = secret
	}
	p, err := New(*issuer, people, cs)
	if err != nil {
		log.Fatal(err)
	}
	p.Choose = *choose
	fmt.Fprintf(os.Stderr, "matura-mockidp: issuer %s, %d people, clients %s (test use only)\n", p.Issuer, len(people), clients.String())
	log.Fatal(http.ListenAndServe(*addr, p.Handler()))
}
