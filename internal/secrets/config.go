package secrets

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// RingConfig picks the key-encryption key (technical specification §9.1).
type RingConfig struct {
	Provider string   // local (default), transit, awskms, gcpkms or azurekv
	LocalKEK string   // MATURA_KEK: the local KEK; with another provider, an earlier KEK that still opens old secrets
	Previous []string // MATURA_KEK_PREVIOUS: earlier local KEKs, comma-separated, kept to open old secrets
	Getenv   func(string) string
}

// ProviderFromEnv reads MATURA_KEK_PROVIDER (default local).
func ProviderFromEnv() string {
	return strings.ToLower(strings.TrimSpace(orDefault(os.Getenv("MATURA_KEK_PROVIDER"), "local")))
}

// RingFromConfig builds the key ring: the provider's key is the primary; local KEKs given are kept so secrets
// sealed under them still open (rotate them away with `POST /admin/v1/keys:rewrap`).
func RingFromConfig(c RingConfig) (*Ring, error) {
	env := c.Getenv
	if env == nil {
		env = os.Getenv
	}
	need := func(name string) (string, error) {
		v := strings.TrimSpace(env(name))
		if v == "" {
			return "", fmt.Errorf("%s is required with MATURA_KEK_PROVIDER=%s", name, c.Provider)
		}
		return v, nil
	}
	var locals []Wrapper
	for _, k := range append([]string{c.LocalKEK}, c.Previous...) {
		if k = strings.TrimSpace(k); k == "" {
			continue
		}
		l, err := NewLocal(k)
		if err != nil {
			return nil, err
		}
		locals = append(locals, l)
	}
	var primary Wrapper
	switch c.Provider {
	case "", "local":
		if c.LocalKEK == "" {
			return nil, errors.New("MATURA_KEK is required with the local key provider")
		}
		return NewRing(locals[0], locals[1:]...), nil
	case "transit":
		addr, err := need("MATURA_TRANSIT_ADDR")
		if err != nil {
			return nil, err
		}
		token := env("MATURA_TRANSIT_TOKEN")
		if f := env("MATURA_TRANSIT_TOKEN_FILE"); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("MATURA_TRANSIT_TOKEN_FILE: %w", err)
			}
			token = strings.TrimSpace(string(b))
		}
		if token == "" {
			return nil, errors.New("MATURA_TRANSIT_TOKEN or MATURA_TRANSIT_TOKEN_FILE is required with the transit provider")
		}
		primary = &Transit{Addr: addr, Token: token, Mount: env("MATURA_TRANSIT_MOUNT"), Key: env("MATURA_TRANSIT_KEY"),
			Namespace: env("MATURA_TRANSIT_NAMESPACE")}
	case "awskms":
		key, err := need("MATURA_AWS_KMS_KEY_ID")
		if err != nil {
			return nil, err
		}
		region := orDefault(env("MATURA_AWS_REGION"), env("AWS_REGION"))
		if region == "" {
			return nil, errors.New("MATURA_AWS_REGION (or AWS_REGION) is required with the awskms provider")
		}
		primary = &AWSKMS{KeyID: key, Region: region, Endpoint: env("MATURA_AWS_KMS_ENDPOINT")}
	case "gcpkms":
		key, err := need("MATURA_GCP_KMS_KEY")
		if err != nil {
			return nil, err
		}
		var ts TokenSource = GoogleMetadataToken()
		if tok := env("MATURA_GCP_ACCESS_TOKEN"); tok != "" {
			ts = StaticToken(tok)
		}
		primary = &GCPKMS{Key: key, Endpoint: env("MATURA_GCP_KMS_ENDPOINT"), Tokens: ts}
	case "azurekv":
		key, err := need("MATURA_AZURE_KEY_URL")
		if err != nil {
			return nil, err
		}
		var ts TokenSource = AzureMetadataToken()
		if tok := env("MATURA_AZURE_ACCESS_TOKEN"); tok != "" {
			ts = StaticToken(tok)
		}
		primary = &AzureKeyVault{KeyURL: key, Tokens: ts}
	default:
		return nil, fmt.Errorf("MATURA_KEK_PROVIDER must be local, transit, awskms, gcpkms or azurekv, got %q", c.Provider)
	}
	return NewRing(primary, locals...), nil
}
