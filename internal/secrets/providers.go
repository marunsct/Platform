package secrets

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Key-encryption keys outside maturad (technical specification §9.1): OpenBao or Vault transit, AWS KMS, Google
// Cloud KMS and Azure Key Vault, each over its HTTP API with no SDK. maturad never sees these keys; it sends a data
// key to be wrapped and gets it back unwrapped when it opens a secret.

// ProviderError is a refusal or failure of the key service; Status is its HTTP status (0 when it was not reached).
type ProviderError struct {
	Provider string
	Status   int
	Body     string
}

func (e *ProviderError) Error() string {
	if e.Status == 0 {
		return e.Provider + ": " + e.Body
	}
	return fmt.Sprintf("%s: HTTP %d: %s", e.Provider, e.Status, e.Body)
}

// Denied says whether the key service refused (key disabled, deleted or access revoked) rather than failed.
func (e *ProviderError) Denied() bool {
	return e.Status == http.StatusForbidden || e.Status == http.StatusUnauthorized || e.Status == http.StatusBadRequest ||
		e.Status == http.StatusNotFound
}

func callJSON(ctx context.Context, c *http.Client, provider string, req *http.Request, out any) error {
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	res, err := c.Do(req.WithContext(ctx))
	if err != nil {
		return &ProviderError{Provider: provider, Body: err.Error()}
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		return &ProviderError{Provider: provider, Status: res.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return &ProviderError{Provider: provider, Status: res.StatusCode, Body: "unexpected answer: " + err.Error()}
	}
	return nil
}

func jsonRequest(method, u string, body any) (*http.Request, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// --- OpenBao / Vault transit --------------------------------------------------------------------------------------

// Transit wraps data keys with an OpenBao (or Vault) transit key: POST /v1/<mount>/encrypt/<key> with the data key
// and the associated data (an aes256-gcm96 or chacha20-poly1305 key binds it).
type Transit struct {
	Addr      string // https://bao.example:8200
	Token     string // a token whose policy allows encrypt and decrypt on the key
	Mount     string // default "transit"
	Key       string // default "matura"
	Namespace string // Vault Enterprise / OpenBao namespace, optional
	Client    *http.Client
}

func (t *Transit) mount() string { return orDefault(t.Mount, "transit") }
func (t *Transit) key() string   { return orDefault(t.Key, "matura") }

func (t *Transit) ID() string { return "transit:" + t.mount() + "/" + t.key() }

func (t *Transit) call(ctx context.Context, op string, body map[string]string, out any) error {
	u := strings.TrimRight(t.Addr, "/") + "/v1/" + url.PathEscape(t.mount()) + "/" + op + "/" + url.PathEscape(t.key())
	req, err := jsonRequest(http.MethodPost, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", t.Token)
	if t.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", t.Namespace)
	}
	return callJSON(ctx, t.Client, "transit", req, out)
}

func (t *Transit) Wrap(ctx context.Context, dataKey, aad []byte) ([]byte, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	err := t.call(ctx, "encrypt", map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dataKey),
		"associated_data": base64.StdEncoding.EncodeToString(aad)}, &out)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(out.Data.Ciphertext, "vault:") {
		return nil, &ProviderError{Provider: "transit", Status: 200, Body: "no ciphertext in the answer"}
	}
	return []byte(out.Data.Ciphertext), nil
}

func (t *Transit) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	err := t.call(ctx, "decrypt", map[string]string{"ciphertext": string(wrapped),
		"associated_data": base64.StdEncoding.EncodeToString(aad)}, &out)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Data.Plaintext)
}

// --- AWS KMS ------------------------------------------------------------------------------------------------------

// AWSKMS wraps data keys with an AWS KMS key (Encrypt / Decrypt, the associated data as encryption context).
// Credentials are the standard AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN variables (for EKS
// pod identity or IRSA, have the environment export them).
type AWSKMS struct {
	KeyID    string // key ARN or alias ARN
	Region   string
	Endpoint string // default https://kms.<region>.amazonaws.com
	Creds    func() (AWSCredentials, error)
	Client   *http.Client
	Now      func() time.Time
}

// AWSCredentials sign requests (SigV4).
type AWSCredentials struct{ AccessKeyID, SecretAccessKey, SessionToken string }

// AWSCredentialsFromEnv reads the standard variables.
func AWSCredentialsFromEnv() (AWSCredentials, error) {
	c := AWSCredentials{AccessKeyID: os.Getenv("AWS_ACCESS_KEY_ID"), SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken: os.Getenv("AWS_SESSION_TOKEN")}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return c, errors.New("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required for AWS KMS")
	}
	return c, nil
}

func (k *AWSKMS) ID() string { return "awskms:" + k.KeyID }

func (k *AWSKMS) endpoint() string {
	if k.Endpoint != "" {
		return strings.TrimRight(k.Endpoint, "/")
	}
	return "https://kms." + k.Region + ".amazonaws.com"
}

func (k *AWSKMS) call(ctx context.Context, target string, body, out any) error {
	creds := AWSCredentialsFromEnv
	if k.Creds != nil {
		creds = k.Creds
	}
	c, err := creds()
	if err != nil {
		return &ProviderError{Provider: "awskms", Body: err.Error()}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, k.endpoint()+"/", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService."+target)
	now := time.Now
	if k.Now != nil {
		now = k.Now
	}
	signV4(req, b, c, k.Region, "kms", now().UTC())
	return callJSON(ctx, k.Client, "awskms", req, out)
}

func (k *AWSKMS) context(aad []byte) map[string]string {
	return map[string]string{"matura": string(aad)}
}

func (k *AWSKMS) Wrap(ctx context.Context, dataKey, aad []byte) ([]byte, error) {
	var out struct{ CiphertextBlob string }
	if err := k.call(ctx, "Encrypt", map[string]any{"KeyId": k.KeyID, "Plaintext": base64.StdEncoding.EncodeToString(dataKey),
		"EncryptionContext": k.context(aad)}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.CiphertextBlob)
}

func (k *AWSKMS) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	var out struct{ Plaintext string }
	if err := k.call(ctx, "Decrypt", map[string]any{"KeyId": k.KeyID, "CiphertextBlob": base64.StdEncoding.EncodeToString(wrapped),
		"EncryptionContext": k.context(aad)}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Plaintext)
}

// signV4 signs req with AWS Signature Version 4.
func signV4(req *http.Request, body []byte, c AWSCredentials, region, service string, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	payload := sha256.Sum256(body)
	req.Header.Set("X-Amz-Date", amzDate)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	req.Header.Set("Host", req.URL.Host)
	names := []string{}
	for h := range req.Header {
		names = append(names, strings.ToLower(h))
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, h := range names {
		v := strings.TrimSpace(req.Header.Get(h))
		if h == "host" {
			v = req.URL.Host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	signed := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{req.Method, path, req.URL.RawQuery, canonHeaders.String(), signed,
		hex.EncodeToString(payload[:])}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	sum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	key := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(key, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKeyID+"/"+scope+", SignedHeaders="+signed+
		", Signature="+sig)
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// --- bearer tokens for Google Cloud and Azure ---------------------------------------------------------------------

// TokenSource gives an OAuth access token for a cloud API.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a fixed token (tests, or a token a sidecar refreshes into the environment).
type StaticToken string

func (t StaticToken) Token(context.Context) (string, error) { return string(t), nil }

// MetadataToken reads a token from a cloud metadata service and caches it until shortly before it expires: Google's
// (URL .../service-accounts/default/token, header Metadata-Flavor: Google) or Azure's managed identity (IMDS,
// header Metadata: true).
type MetadataToken struct {
	URL    string
	Header [2]string
	Client *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// GoogleMetadataToken is the token of the VM's or pod's Google service account.
func GoogleMetadataToken() *MetadataToken {
	return &MetadataToken{URL: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		Header: [2]string{"Metadata-Flavor", "Google"}}
}

// AzureMetadataToken is a managed identity's token for Key Vault.
func AzureMetadataToken() *MetadataToken {
	return &MetadataToken{URL: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" +
		url.QueryEscape("https://vault.azure.net"), Header: [2]string{"Metadata", "true"}}
}

func (m *MetadataToken) Token(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.token != "" && time.Until(m.expires) > time.Minute {
		return m.token, nil
	}
	req, err := http.NewRequest(http.MethodGet, m.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(m.Header[0], m.Header[1])
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   any    `json:"expires_in"` // a number (Google) or a string (Azure)
	}
	if err := callJSON(ctx, m.Client, "metadata", req, &out); err != nil {
		return "", err
	}
	secs := 300.0
	switch v := out.ExpiresIn.(type) {
	case float64:
		secs = v
	case string:
		fmt.Sscan(v, &secs)
	}
	m.token, m.expires = out.AccessToken, time.Now().Add(time.Duration(secs)*time.Second)
	return m.token, nil
}

// --- Google Cloud KMS ---------------------------------------------------------------------------------------------

// GCPKMS wraps data keys with a Cloud KMS symmetric key (encrypt / decrypt with additionalAuthenticatedData).
type GCPKMS struct {
	Key      string // projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>
	Endpoint string // default https://cloudkms.googleapis.com
	Tokens   TokenSource
	Client   *http.Client
}

func (g *GCPKMS) ID() string { return "gcpkms:" + g.Key }

func (g *GCPKMS) call(ctx context.Context, op string, body, out any) error {
	tok, err := g.Tokens.Token(ctx)
	if err != nil {
		return &ProviderError{Provider: "gcpkms", Body: "no access token: " + err.Error()}
	}
	req, err := jsonRequest(http.MethodPost, strings.TrimRight(orDefault(g.Endpoint, "https://cloudkms.googleapis.com"), "/")+
		"/v1/"+g.Key+":"+op, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return callJSON(ctx, g.Client, "gcpkms", req, out)
}

func (g *GCPKMS) Wrap(ctx context.Context, dataKey, aad []byte) ([]byte, error) {
	var out struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := g.call(ctx, "encrypt", map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dataKey),
		"additionalAuthenticatedData": base64.StdEncoding.EncodeToString(aad)}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Ciphertext)
}

func (g *GCPKMS) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	if err := g.call(ctx, "decrypt", map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(wrapped),
		"additionalAuthenticatedData": base64.StdEncoding.EncodeToString(aad)}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Plaintext)
}

// --- Azure Key Vault ----------------------------------------------------------------------------------------------

// AzureKeyVault wraps data keys with a Key Vault (or Managed HSM) RSA key (wrapkey / unwrapkey, RSA-OAEP-256).
// Key Vault's wrap takes no associated data, so a hash of it is wrapped with the data key and checked on unwrap.
type AzureKeyVault struct {
	KeyURL string // https://<vault>.vault.azure.net/keys/<name>/<version>
	Tokens TokenSource
	Client *http.Client
}

func (a *AzureKeyVault) ID() string { return "azurekv:" + a.KeyURL }

func (a *AzureKeyVault) call(ctx context.Context, op string, value []byte) ([]byte, error) {
	tok, err := a.Tokens.Token(ctx)
	if err != nil {
		return nil, &ProviderError{Provider: "azurekv", Body: "no access token: " + err.Error()}
	}
	req, err := jsonRequest(http.MethodPost, strings.TrimRight(a.KeyURL, "/")+"/"+op+"?api-version=7.4",
		map[string]string{"alg": "RSA-OAEP-256", "value": base64.RawURLEncoding.EncodeToString(value)})
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	var out struct {
		Value string `json:"value"`
	}
	if err := callJSON(ctx, a.Client, "azurekv", req, &out); err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(out.Value, "="))
}

func (a *AzureKeyVault) Wrap(ctx context.Context, dataKey, aad []byte) ([]byte, error) {
	return a.call(ctx, "wrapkey", bindAAD(dataKey, aad))
}

func (a *AzureKeyVault) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	plain, err := a.call(ctx, "unwrapkey", wrapped)
	if err != nil {
		return nil, err
	}
	return checkAAD(plain, aad)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
