package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizationCodeWithPKCE(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	p, err := New("http://"+srv.Listener.Addr().String(), []Person{
		{Sub: "s1", Email: "ana@acme.test", Name: "Ana", Groups: []string{"engineering"}},
		{Sub: "s2", Email: "bo@acme.test", Name: "Bo"}}, map[string]string{"matura": "secret", "spa": ""})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = p.Handler()
	srv.Start()
	defer srv.Close()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	var disc map[string]any
	res, _ := http.Get(srv.URL + "/.well-known/openid-configuration")
	_ = json.NewDecoder(res.Body).Decode(&disc)
	if disc["issuer"] != p.Issuer || disc["token_endpoint"] != p.Issuer+"/token" {
		t.Fatalf("discovery: %v", disc)
	}

	verifier := "a-verifier-that-is-long-enough-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {"matura"}, "redirect_uri": {"http://app.test/cb"}, "response_type": {"code"},
		"scope": {"openid email"}, "state": {"st"}, "nonce": {"n1"}, "login_hint": {"bo@acme.test"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	res, err = noRedirect.Get(srv.URL + "/authorize?" + q.Encode())
	if err != nil || res.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %v %v", res, err)
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	code := loc.Query().Get("code")
	if loc.Host != "app.test" || code == "" || loc.Query().Get("state") != "st" {
		t.Fatalf("redirect: %s", loc)
	}
	exchange := func(form url.Values) (int, map[string]any) {
		res, _ := http.PostForm(srv.URL+"/token", form)
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	base := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://app.test/cb"},
		"client_id": {"matura"}, "client_secret": {"secret"}}
	bad := url.Values{}
	for k, v := range base {
		bad[k] = v
	}
	bad.Set("code_verifier", "wrong")
	if c, out := exchange(bad); c != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: %d %v", c, out)
	}
	// the code was used up by the failed attempt: a fresh one
	res, _ = noRedirect.Get(srv.URL + "/authorize?" + q.Encode())
	loc, _ = url.Parse(res.Header.Get("Location"))
	base.Set("code", loc.Query().Get("code"))
	base.Set("code_verifier", verifier)
	c, tok := exchange(base)
	if c != 200 || tok["id_token"] == nil {
		t.Fatalf("token: %d %v", c, tok)
	}
	claims, err := p.verify(tok["id_token"].(string))
	if err != nil || claims["sub"] != "s2" || claims["email"] != "bo@acme.test" || claims["nonce"] != "n1" || claims["aud"] != "matura" {
		t.Fatalf("id token: %v %v", claims, err)
	}
	if c, _ := exchange(base); c != 400 {
		t.Fatalf("a code used twice: %d", c)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	res, _ = http.DefaultClient.Do(req)
	var info map[string]any
	_ = json.NewDecoder(res.Body).Decode(&info)
	if info["email"] != "bo@acme.test" {
		t.Fatalf("userinfo: %v", info)
	}
	if c, out := exchange(url.Values{"grant_type": {"client_credentials"}, "client_id": {"matura"}, "client_secret": {"nope"}}); c != 401 {
		t.Fatalf("wrong secret: %d %v", c, out)
	}
	// the pick list
	p.Choose = true
	q.Del("login_hint")
	res, _ = noRedirect.Get(srv.URL + "/authorize?" + q.Encode())
	page, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(page), "ana@acme.test") {
		t.Fatalf("pick list: %d", res.StatusCode)
	}
}
