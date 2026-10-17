package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

// Security policies (TS9): maturad enforces the IP allow-list on tenant API calls and the email domains on
// invitations; Keycloak enforces MFA and session limits from the same record.

var errIPNotAllowed = errors.New("this tenant does not allow requests from your network address")

// SetTrustedProxies names the reverse proxies whose X-Forwarded-For maturad believes. Without any, the client
// address is the connection's.
func (s *Server) SetTrustedProxies(p []netip.Prefix) { s.trustedProxies = p }

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.trustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP is the connection's address or, behind trusted proxies, the right-most X-Forwarded-For entry that is
// not one of them.
func (s *Server) clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, _ := netip.ParseAddr(host)
	ip = ip.Unmap()
	if !s.trusted(ip) {
		return ip
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return ip
		}
		if a = a.Unmap(); !s.trusted(a) {
			return a
		}
		ip = a
	}
	return ip
}

// requestID keeps a caller's X-Request-Id when it is short and printable, else makes one.
func requestID(r *http.Request) string {
	if v := r.Header.Get("X-Request-Id"); v != "" && len(v) <= 128 &&
		strings.IndexFunc(v, func(c rune) bool { return c < 0x21 || c > 0x7e }) < 0 {
		return v
	}
	return "req_" + strings.ReplaceAll(uuid.NewString(), "-", "")
}

type cachedPolicy struct {
	policy store.SecurityPolicy
	at     time.Time
}

// policyTTL is how long a replica uses a tenant's policy before reading it again.
const policyTTL = 5 * time.Second

func (s *Server) policy(ctx context.Context, tid uuid.UUID) (store.SecurityPolicy, error) {
	if c, ok := s.policies.Load(tid); ok && time.Since(c.(cachedPolicy).at) < policyTTL {
		return c.(cachedPolicy).policy, nil
	}
	p, err := s.store.SecurityPolicy(ctx, store.Scope{}, tid)
	if err != nil {
		return p, err
	}
	s.policies.Store(tid, cachedPolicy{policy: p, at: time.Now()})
	return p, nil
}

// checkIP refuses a member's request from outside the tenant's allow-list.
func (s *Server) checkIP(r *http.Request, tid uuid.UUID) error {
	p, err := s.policy(r.Context(), tid)
	if err != nil {
		return err
	}
	if !p.AllowsIP(s.clientIP(r)) {
		return errIPNotAllowed
	}
	return nil
}

// auditDenied records a refused request in the tenant's audit log (or the installation's when the path names no
// tenant). It never fails the response.
func (s *Server) auditDenied(r *http.Request, reason string) {
	p := principalFrom(r.Context())
	var tid uuid.UUID
	if v := r.PathValue("tid"); v != "" {
		tid, _ = uuid.Parse(v)
	}
	ctx := context.WithoutCancel(r.Context())
	if err := s.store.RecordAudit(ctx, store.Scope{UserID: p.UserID, Operator: p.Operator}, tid, "authz.denied",
		r.URL.Path, map[string]any{"method": r.Method, "path": r.URL.Path, "reason": reason}); err != nil {
		s.log.WarnContext(ctx, "recording a refused request", "err", err)
	}
}

type policyIO struct {
	RequireMFA          bool     `json:"require_mfa"`
	SessionMaxAge       *int     `json:"session_max_age"`
	IdleTimeout         *int     `json:"idle_timeout"`
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	IPAllowlist         []string `json:"ip_allowlist"`
}

func (s *Server) getSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p, err := s.store.SecurityPolicy(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(p.Version))
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) putSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in policyIO
	if !decode(w, r, &in) {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ver, err := ifMatch(r)
	if err != nil {
		problem(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	p := store.SecurityPolicy{RequireMFA: in.RequireMFA, SessionMaxAge: in.SessionMaxAge, IdleTimeout: in.IdleTimeout,
		AllowedEmailDomains: in.AllowedEmailDomains}
	for _, raw := range in.IPAllowlist {
		raw = strings.TrimSpace(raw)
		pfx, err := netip.ParsePrefix(raw)
		if err != nil {
			a, aerr := netip.ParseAddr(raw)
			if aerr != nil {
				problem(w, http.StatusUnprocessableEntity, "invalid", fmt.Sprintf("%q is not an address or CIDR range", raw))
				return
			}
			pfx = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		p.IPAllowlist = append(p.IPAllowlist, pfx)
	}
	// an admin cannot lock themselves out; operators are not bound by the list
	if ip := s.clientIP(r); !sc.Operator && !p.AllowsIP(ip) {
		problem(w, http.StatusUnprocessableEntity, "invalid",
			"the IP allow-list must include your own address ("+ip.String()+")")
		return
	}
	out, err := s.store.PutSecurityPolicy(r.Context(), sc, tid, p, ver)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.policies.Delete(tid)
	w.Header().Set("ETag", etag(out.Version))
	writeJSON(w, http.StatusOK, out)
}
