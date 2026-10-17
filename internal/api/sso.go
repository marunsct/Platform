package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/store"
)

// Enterprise SSO (TS13): verified domains, one identity provider per tenant brokered by Keycloak, and home-realm
// discovery.

// TXTResolver looks up DNS TXT records; *net.Resolver is one.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// SetResolver replaces the DNS resolver used for domain verification (tests).
func (s *Server) SetResolver(r TXTResolver) { s.resolver = r }

// AllowHTTPIdentityProviders lets identity-provider discovery and metadata URLs use plain HTTP (development only).
var AllowHTTPIdentityProviders bool

// Keycloak authentication flows the realm defines for tenant identity providers (keycloak/realm/matura-realm.json).
const (
	ssoFirstLoginFlow = "matura sso first login"
	ssoPostLoginFlow  = "matura sso post login"
	challengePrefix   = "_matura-challenge."
	challengeValue    = "matura-verification="
)

type domainOut struct {
	store.Domain
	Verified    bool   `json:"verified"`
	RecordName  string `json:"record_name"`
	RecordValue string `json:"record_value"`
}

func toDomainOut(d store.Domain) domainOut {
	return domainOut{Domain: d, Verified: d.VerifiedAt != nil, RecordName: challengePrefix + d.Domain,
		RecordValue: challengeValue + d.Challenge}
}

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.store.ListDomains(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]domainOut, 0, len(list))
	for _, d := range list {
		out = append(out, toDomainOut(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) addDomain(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		Domain string `json:"domain"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := s.store.AddDomain(r.Context(), sc, tid, in.Domain, base64.RawURLEncoding.EncodeToString(b))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toDomainOut(d))
}

// verifyDomain serves POST …/domains/{domain}:verify: it looks for the TXT record and marks the domain verified.
func (s *Server) verifyDomain(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	name, found := strings.CutSuffix(r.PathValue("domain"), ":verify")
	if !found {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := s.store.GetDomain(r.Context(), sc, tid, name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var resolver TXTResolver = net.DefaultResolver
	if s.resolver != nil {
		resolver = s.resolver
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	records, lookupErr := resolver.LookupTXT(ctx, challengePrefix+d.Domain)
	cancel()
	checkErr := ""
	switch {
	case slices.Contains(records, challengeValue+d.Challenge):
	case lookupErr != nil:
		checkErr = "DNS lookup of " + challengePrefix + d.Domain + " failed: " + lookupErr.Error()
	default:
		checkErr = "no TXT record " + challengeValue + "… with this domain's challenge at " + challengePrefix + d.Domain
	}
	d, err = s.store.RecordDomainCheck(r.Context(), sc, tid, d.Domain, checkErr)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if checkErr != "" {
		problem(w, http.StatusUnprocessableEntity, "domain-not-verified", checkErr)
		return
	}
	writeJSON(w, http.StatusOK, toDomainOut(d))
}

func (s *Server) deleteDomain(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.DeleteDomain(r.Context(), sc, tid, r.PathValue("domain")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ssoOut is a connection plus what the tenant's IdP administrator needs to configure their side.
type ssoOut struct {
	store.SSOConnection
	IdPHint     string `json:"idp_hint"`
	RedirectURI string `json:"redirect_uri"`           // OIDC redirect URI, SAML assertion consumer service URL
	EntityID    string `json:"entity_id,omitempty"`    // SAML service provider entity id
	MetadataURL string `json:"metadata_url,omitempty"` // SAML service provider metadata
	HasSecret   bool   `json:"has_client_secret"`
}

func (s *Server) toSSOOut(c store.SSOConnection) ssoOut {
	broker := s.issuer + "/broker/" + c.Alias + "/endpoint"
	out := ssoOut{SSOConnection: c, IdPHint: c.Alias, RedirectURI: broker, HasSecret: len(c.SealedSecret) > 0}
	if c.Protocol == "saml" {
		out.EntityID, out.MetadataURL = s.issuer, broker+"/descriptor"
	}
	return out
}

func (s *Server) getSSO(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.store.GetSSO(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.toSSOOut(c))
}

type ssoIn struct {
	Protocol          string `json:"protocol"`
	DisplayName       string `json:"display_name"`
	DiscoveryURL      string `json:"discovery_url"` // OIDC: issuer or its /.well-known/openid-configuration
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`
	MetadataURL       string `json:"metadata_url"` // SAML
	EmailAttribute    string `json:"email_attribute"`
	FirstNameAttr     string `json:"first_name_attribute"`
	LastNameAttr      string `json:"last_name_attribute"`
	DefaultTenantRole string `json:"default_tenant_role"`
}

func checkIdPURL(field, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && AllowHTTPIdentityProviders)) {
		return "", &store.InvalidError{Msg: field + " must be an https URL"}
	}
	return u.String(), nil
}

// identityProvider builds the Keycloak identity provider and mappers for a tenant connection.
func (s *Server) identityProvider(ctx context.Context, alias string, in ssoIn) (keycloak.IdentityProvider, []keycloak.IdentityProviderMapper, map[string]string, error) {
	idp := keycloak.IdentityProvider{Alias: alias, DisplayName: in.DisplayName, ProviderID: in.Protocol, Enabled: true,
		TrustEmail: true, HideOnLogin: true, FirstBrokerLoginFlowAlias: ssoFirstLoginFlow,
		PostBrokerLoginFlowAlias: ssoPostLoginFlow}
	mapper := func(name, typ string, cfg map[string]string) keycloak.IdentityProviderMapper {
		cfg["syncMode"] = "INHERIT"
		return keycloak.IdentityProviderMapper{Name: name, IdentityProviderAlias: alias, IdentityProviderMapper: typ,
			Config: cfg}
	}
	var mappers []keycloak.IdentityProviderMapper
	var stored map[string]string
	switch in.Protocol {
	case "oidc":
		u, err := checkIdPURL("discovery_url", in.DiscoveryURL)
		if err != nil {
			return idp, nil, nil, err
		}
		if !strings.Contains(u, "/.well-known/") {
			u = strings.TrimRight(u, "/") + "/.well-known/openid-configuration"
		}
		if in.ClientID == "" || in.ClientSecret == "" {
			return idp, nil, nil, &store.InvalidError{Msg: "client_id and client_secret are required for OIDC"}
		}
		cfg, err := s.kc.ImportConfig(ctx, "oidc", u)
		if err != nil {
			return idp, nil, nil, err
		}
		cfg["clientId"], cfg["clientSecret"] = in.ClientID, in.ClientSecret
		cfg["clientAuthMethod"], cfg["defaultScope"], cfg["syncMode"] = "client_secret_post", "openid email profile", "IMPORT"
		cfg["pkceEnabled"], cfg["pkceMethod"] = "true", "S256"
		cfg["validateSignature"], cfg["useJwksUrl"] = "true", "true"
		idp.Config = cfg
		mappers = []keycloak.IdentityProviderMapper{
			mapper("email", "oidc-user-attribute-idp-mapper", map[string]string{"claim": "email", "user.attribute": "email"}),
			mapper("first name", "oidc-user-attribute-idp-mapper", map[string]string{"claim": "given_name", "user.attribute": "firstName"}),
			mapper("last name", "oidc-user-attribute-idp-mapper", map[string]string{"claim": "family_name", "user.attribute": "lastName"}),
		}
		stored = map[string]string{"discovery_url": u, "client_id": in.ClientID, "issuer": cfg["issuer"]}
	case "saml":
		u, err := checkIdPURL("metadata_url", in.MetadataURL)
		if err != nil {
			return idp, nil, nil, err
		}
		cfg, err := s.kc.ImportConfig(ctx, "saml", u)
		if err != nil {
			return idp, nil, nil, err
		}
		cfg["syncMode"], cfg["principalType"] = "IMPORT", "SUBJECT"
		cfg["nameIDPolicyFormat"] = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
		cfg["postBindingResponse"], cfg["postBindingAuthnRequest"] = "true", "true"
		cfg["wantAssertionsSigned"], cfg["validateSignature"] = "true", "true"
		cfg["allowedClockSkew"] = "120"
		idp.Config = cfg
		attr := func(v, def string) string {
			if v == "" {
				return def
			}
			return v
		}
		email, first, last := attr(in.EmailAttribute, "email"), attr(in.FirstNameAttr, "firstName"), attr(in.LastNameAttr, "lastName")
		mappers = []keycloak.IdentityProviderMapper{
			mapper("email", "saml-user-attribute-idp-mapper", map[string]string{"attribute.name": email, "user.attribute": "email"}),
			mapper("first name", "saml-user-attribute-idp-mapper", map[string]string{"attribute.name": first, "user.attribute": "firstName"}),
			mapper("last name", "saml-user-attribute-idp-mapper", map[string]string{"attribute.name": last, "user.attribute": "lastName"}),
		}
		stored = map[string]string{"metadata_url": u, "idp_entity_id": cfg["idpEntityId"], "email_attribute": email,
			"first_name_attribute": first, "last_name_attribute": last}
	default:
		return idp, nil, nil, &store.InvalidError{Msg: "protocol must be oidc or saml"}
	}
	return idp, mappers, stored, nil
}

func (s *Server) createSSO(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in ssoIn
	if !decode(w, r, &in) {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.needKeycloak(w) {
		return
	}
	t, err := s.store.GetTenant(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if t.Kind != "company" {
		s.fail(w, r, &store.InvalidError{Msg: "single sign-on is for company tenants"})
		return
	}
	if _, err := s.store.GetSSO(r.Context(), sc, tid); err == nil {
		problem(w, http.StatusConflict, "conflict", "this tenant already has an SSO connection; delete it first")
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	domains, err := s.store.ListDomains(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !slices.ContainsFunc(domains, func(d store.Domain) bool { return d.VerifiedAt != nil }) {
		s.fail(w, r, &store.InvalidError{Msg: "verify at least one email domain first (POST …/domains)"})
		return
	}
	if in.DisplayName == "" {
		in.DisplayName = t.Name
	}
	alias := "t-" + t.Slug
	idp, mappers, cfg, err := s.identityProvider(r.Context(), alias, in)
	var inv *store.InvalidError
	switch {
	case errors.As(err, &inv):
		s.fail(w, r, err)
		return
	case errors.Is(err, keycloak.ErrNotFound) || isBadRequest(err):
		problem(w, http.StatusUnprocessableEntity, "invalid",
			"Keycloak could not read the identity provider's discovery document or metadata at that URL")
		return
	case err != nil:
		s.kcFail(w, r, err)
		return
	}
	var sealed []byte
	if in.ClientSecret != "" && in.Protocol == "oidc" {
		if sealed, err = s.keys.Seal([]byte(in.ClientSecret), store.SSOAAD(tid)); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if err := s.kc.PutIdentityProvider(r.Context(), idp, mappers); err != nil {
		s.kcFail(w, r, err)
		return
	}
	c, err := s.store.CreateSSO(r.Context(), sc, store.SSOConnection{TenantID: tid, Alias: alias, Protocol: in.Protocol,
		DisplayName: in.DisplayName, Config: cfg, SealedSecret: sealed, DefaultTenantRole: in.DefaultTenantRole})
	if err != nil {
		if derr := s.kc.DeleteIdentityProvider(context.WithoutCancel(r.Context()), alias); derr != nil {
			s.log.ErrorContext(r.Context(), "removing identity provider after a failed save", "alias", alias, "err", derr)
		}
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.toSSOOut(c))
}

func isBadRequest(err error) bool {
	var kerr *keycloak.Error
	return errors.As(err, &kerr) && kerr.Status == http.StatusBadRequest
}

func (s *Server) deleteSSO(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.needKeycloak(w) {
		return
	}
	c, err := s.store.GetSSO(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.kc.DeleteIdentityProvider(r.Context(), c.Alias); err != nil {
		s.kcFail(w, r, err)
		return
	}
	if err := s.store.DeleteSSO(r.Context(), sc, tid); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// discoverSSO is home-realm discovery (public): for an address in a verified domain of a tenant with SSO it returns
// the Keycloak identity provider alias to pass as kc_idp_hint.
func (s *Server) discoverSSO(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if !strings.Contains(email, "@") || len(email) > 320 {
		problem(w, http.StatusBadRequest, "bad-request", "email must be an email address")
		return
	}
	d, err := s.store.DiscoverSSO(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"sso": false})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"sso": true, "idp_hint": d.Alias, "tenant": d.TenantSlug})
}
