package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/marunsct/Platform/internal/readiness"
)

var placeholder = regexp.MustCompile(`\{\{\s*([a-z0-9_]+)\s*\}\}`)

// policyValues are the placeholders the report fills. Organisational facts (who owns a policy, how often backups
// run) are not in it; --set supplies them and they win over these.
func policyValues(rep readiness.Report) map[string]string {
	s := rep.Summary
	day := func(t *time.Time) string {
		if t == nil {
			return "none recorded"
		}
		return t.UTC().Format("2006-01-02")
	}
	v := map[string]string{
		"product_name":              rep.Product,
		"public_url":                s.PublicURL,
		"generated_at":              rep.GeneratedAt.UTC().Format("2006-01-02"),
		"readiness_score":           fmt.Sprintf("%.1f%%", rep.Score),
		"tenants":                   fmt.Sprint(s.Tenants),
		"tenants_mfa":               fmt.Sprint(s.TenantsMFA),
		"tenants_session_limits":    fmt.Sprint(s.TenantsSessionLimits),
		"tenants_domain_restricted": fmt.Sprint(s.TenantsDomains),
		"tenants_ip_allowlist":      fmt.Sprint(s.TenantsIPAllowlist),
		"tenants_audit_streaming":   fmt.Sprint(s.TenantsAuditStream),
		"audit_chains":              fmt.Sprint(s.AuditChains),
		"audit_chains_verified":     fmt.Sprint(s.AuditChainsOK),
		"last_restore_test":         day(s.LastRestoreTest),
		"restore_tests_90d":         fmt.Sprint(s.RestoreTests90d),
		"last_access_review":        day(s.LastAccessReview),
		"last_vulnerability_scan":   day(s.LastVulnScan),
		"audit_retention":           "kept in the control-plane database with no update or delete path for the application",
	}
	v["sign_in_method"] = "OpenID Connect through the installation's identity provider (Keycloak)"
	if s.Auth != "oidc" {
		v["sign_in_method"] = "development header sign-in (" + s.Auth + "); not suitable for production"
	}
	switch {
	case s.Tenants == 0:
		v["mfa_requirement"] = "no organisation is active yet"
	case s.TenantsMFA == s.Tenants:
		v["mfa_requirement"] = "required by the security policy of every organisation"
	default:
		v["mfa_requirement"] = fmt.Sprintf("required by the security policy of %d of %d organisations", s.TenantsMFA, s.Tenants)
	}
	if s.LastRestoreTest != nil {
		res := "passed"
		if !s.LastRestorePassed {
			res = "failed"
		}
		v["last_restore_test_result"] = res
	} else {
		v["last_restore_test_result"] = "not run"
	}
	for _, c := range rep.Controls {
		v["control_"+strings.ReplaceAll(c.ID, "-", "_")] = string(c.Status)
	}
	return v
}

// fillPolicies copies every .md template in dir to out with its placeholders filled, and reports the ones left.
func fillPolicies(dir, out string, rep readiness.Report, sets map[string]string, info io.Writer) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		return err
	}
	var templates []string
	for _, f := range files {
		if !strings.EqualFold(filepath.Base(f), "README.md") {
			templates = append(templates, f)
		}
	}
	if len(templates) == 0 {
		return fmt.Errorf("no policy templates (*.md) in %s", dir)
	}
	values := policyValues(rep)
	for k, v := range sets {
		values[k] = v
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for _, f := range templates {
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var missing []string
		filled := placeholder.ReplaceAllStringFunc(string(raw), func(m string) string {
			key := placeholder.FindStringSubmatch(m)[1]
			if v, ok := values[key]; ok {
				return v
			}
			if !slices.Contains(missing, key) {
				missing = append(missing, key)
			}
			return m
		})
		dst := filepath.Join(out, filepath.Base(f))
		if err := os.WriteFile(dst, []byte(filled), 0o644); err != nil {
			return err
		}
		if len(missing) == 0 {
			fmt.Fprintf(info, "wrote %s\n", dst)
		} else {
			fmt.Fprintf(info, "wrote %s; still to fill (--set key=value or by hand): %s\n", dst, strings.Join(missing, ", "))
		}
	}
	return nil
}
