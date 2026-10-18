package secrets

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// CustomerKeys builds wrappers for tenants' own key-encryption keys (BYOK, technical specification §9.2). The
// installation turns providers on with MATURA_BYOK_PROVIDERS. Cloud KMS keys are reached with the installation's own
// cloud identity, which the tenant grants use of its key (a key policy or IAM binding); an OpenBao or Vault transit
// key with a token the tenant gives, kept sealed.
type CustomerKeys struct {
	Providers []string // allowed: transit, awskms, gcpkms, azurekv
	AllowHTTP bool     // transit over http (development and tests only)
	// Cloud credentials, as for the installation's key (nil: the defaults of RingFromConfig).
	AWSCreds    func() (AWSCredentials, error)
	GCPTokens   TokenSource
	AzureTokens TokenSource
}

// Wrapper builds the wrapper for a tenant's key settings.
func (c *CustomerKeys) Wrapper(provider string, cfg map[string]string) (Wrapper, error) {
	if !slices.Contains(c.Providers, provider) {
		return nil, fmt.Errorf("provider %q is not enabled on this installation (MATURA_BYOK_PROVIDERS: %s)", provider,
			strings.Join(c.Providers, ", "))
	}
	need := func(k string) (string, error) {
		v := strings.TrimSpace(cfg[k])
		if v == "" {
			return "", fmt.Errorf("%s is required for %s", k, provider)
		}
		return v, nil
	}
	switch provider {
	case "transit":
		addr, err := need("addr")
		if err != nil {
			return nil, err
		}
		u, err := url.Parse(addr)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !(c.AllowHTTP && u.Scheme == "http")) {
			return nil, errors.New("addr must be an https URL")
		}
		token, err := need("token")
		if err != nil {
			return nil, err
		}
		return &Transit{Addr: addr, Token: token, Mount: cfg["mount"], Key: cfg["key"], Namespace: cfg["namespace"]}, nil
	case "awskms":
		key, err := need("key_id")
		if err != nil {
			return nil, err
		}
		region, err := need("region")
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(key, "arn:aws") {
			return nil, errors.New("key_id must be the key's ARN (the installation's account reaches it through its key policy)")
		}
		return &AWSKMS{KeyID: key, Region: region, Creds: c.AWSCreds, Endpoint: cfg["endpoint"]}, nil
	case "gcpkms":
		key, err := need("key")
		if err != nil {
			return nil, err
		}
		ts := c.GCPTokens
		if ts == nil {
			ts = GoogleMetadataToken()
		}
		return &GCPKMS{Key: key, Tokens: ts, Endpoint: cfg["endpoint"]}, nil
	case "azurekv":
		key, err := need("key_url")
		if err != nil {
			return nil, err
		}
		if u, err := url.Parse(key); err != nil || u.Scheme != "https" {
			return nil, errors.New("key_url must be an https URL")
		}
		ts := c.AzureTokens
		if ts == nil {
			ts = AzureMetadataToken()
		}
		return &AzureKeyVault{KeyURL: key, Tokens: ts}, nil
	}
	return nil, fmt.Errorf("unknown provider %q", provider)
}

// KeyRef is what is shown of a tenant's key settings (never the token).
func KeyRef(provider string, cfg map[string]string) string {
	switch provider {
	case "transit":
		return strings.TrimRight(cfg["addr"], "/") + "/" + orDefault(cfg["mount"], "transit") + "/" + orDefault(cfg["key"], "matura")
	case "awskms":
		return cfg["key_id"]
	case "gcpkms":
		return cfg["key"]
	case "azurekv":
		return cfg["key_url"]
	}
	return ""
}
