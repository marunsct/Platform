package conformance

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// RealmPath is where the test issuer serves its realm, so its URL looks like Matura's (…/realms/matura).
const RealmPath = "/realms/conformance"

// Issuer is a test OIDC issuer: it serves discovery and a JWKS for a freshly generated RSA key and signs tokens
// with it. It also holds a second key that is never published, for "unknown key" tokens.
type Issuer struct {
	key      *rsa.PrivateKey
	stranger *rsa.PrivateKey
	kid      string
	url      string
	ln       net.Listener
	srv      *http.Server
}

// StartIssuer listens on addr (host:port; port 0 picks one) and serves the issuer until Close.
func StartIssuer(addr string) (*Issuer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	i := &Issuer{key: key, stranger: stranger, kid: "conformance-" + uuid.NewString()[:8], ln: ln,
		url: "http://" + ln.Addr().String() + RealmPath}
	i.srv = &http.Server{Handler: i.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = i.srv.Serve(ln) }()
	return i, nil
}

// URL is the issuer URL (the iss claim and MATURA_ISSUER).
func (i *Issuer) URL() string { return i.url }

// JWKSURL is where the public key is published.
func (i *Issuer) JWKSURL() string { return i.url + "/protocol/openid-connect/certs" }

// Close stops the server.
func (i *Issuer) Close() error {
	err := i.srv.Close()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Handler serves /realms/conformance/.well-known/openid-configuration and …/protocol/openid-connect/certs.
func (i *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+RealmPath+"/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                i.url,
			"jwks_uri":                              i.JWKSURL(),
			"authorization_endpoint":                i.url + "/protocol/openid-connect/auth",
			"token_endpoint":                        i.url + "/protocol/openid-connect/token",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"grant_types_supported":                 []string{"authorization_code", "client_credentials"},
		})
	})
	mux.HandleFunc("GET "+RealmPath+"/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, i.JWKS())
	})
	return mux
}

// JWKS is the published key set.
func (i *Issuer) JWKS() map[string]any {
	pub := i.key.PublicKey
	return map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": i.kid, "use": "sig", "alg": "RS256",
		"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
	}}}
}

// Sign signs claims with the published key (RS256, kid set).
func (i *Issuer) Sign(claims jwt.MapClaims) (string, error) { return i.sign(i.key, claims) }

// SignUnknown signs claims with a key that is not in the JWKS, under the published kid.
func (i *Issuer) SignUnknown(claims jwt.MapClaims) (string, error) { return i.sign(i.stranger, claims) }

func (i *Issuer) sign(key *rsa.PrivateKey, claims jwt.MapClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = i.kid
	return t.SignedString(key)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
