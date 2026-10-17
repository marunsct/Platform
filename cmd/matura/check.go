package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/marunsct/Platform/internal/readiness"
)

type setFlags map[string]string

func (s setFlags) String() string { return "" }

func (s setFlags) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || strings.TrimSpace(k) == "" {
		return errors.New("want key=value")
	}
	s[strings.TrimSpace(k)] = val
	return nil
}

func check(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("matura check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("url", envOr("MATURA_URL", "http://localhost:8080"), "maturad's address")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	asOSCAL := fs.Bool("oscal", false, "print the report as OSCAL assessment results (JSON)")
	minScore := fs.Float64("min-score", 0, "exit with status 1 when the score (percent) is below this")
	policies := fs.String("policies", "", "directory of policy templates to fill from the report (e.g. docs/templates)")
	out := fs.String("out", "policies", "where --policies writes the filled documents")
	sets := setFlags{}
	fs.Var(sets, "set", "a value for a policy placeholder the report cannot know, key=value (repeatable), e.g. organisation=\"Acme Ltd\"")
	timeout := fs.Duration("timeout", 2*time.Minute, "how long to wait for maturad")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *asJSON && *asOSCAL {
		fmt.Fprintln(stderr, "matura check: choose one of --json and --oscal")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	rep, err := fetchReport(ctx, *base, os.Getenv("MATURA_TOKEN"))
	if err != nil {
		fmt.Fprintln(stderr, "matura check:", err)
		return 2
	}

	switch {
	case *asJSON:
		writeIndented(stdout, rep)
	case *asOSCAL:
		writeIndented(stdout, readiness.OSCAL(rep))
	default:
		printTable(stdout, rep)
	}
	if *policies != "" {
		info := stdout
		if *asJSON || *asOSCAL {
			info = stderr
		}
		if err := fillPolicies(*policies, *out, rep, sets, info); err != nil {
			fmt.Fprintln(stderr, "matura check:", err)
			return 2
		}
	}
	if rep.Score < *minScore {
		fmt.Fprintf(stderr, "matura check: score %.1f%% is below --min-score %.1f%%\n", rep.Score, *minScore)
		return 1
	}
	return 0
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fetchReport(ctx context.Context, base, token string) (readiness.Report, error) {
	var rep readiness.Report
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/admin/v1/readiness", nil)
	if err != nil {
		return rep, err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else if u := os.Getenv("MATURA_DEV_USER"); u != "" {
		// development installs (MATURA_AUTH=dev) only
		req.Header.Set("X-Matura-Dev-User", u)
		req.Header.Set("X-Matura-Dev-Operator", "true")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return rep, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		var p struct {
			Detail string `json:"detail"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 1<<16)).Decode(&p)
		hint := ""
		if res.StatusCode == http.StatusUnauthorized && token == "" {
			hint = " (set MATURA_TOKEN to an operator's access token)"
		}
		return rep, fmt.Errorf("GET /admin/v1/readiness: %s: %s%s", res.Status, p.Detail, hint)
	}
	if err := json.NewDecoder(res.Body).Decode(&rep); err != nil {
		return rep, fmt.Errorf("reading the report: %w", err)
	}
	return rep, nil
}

func writeIndented(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

var statusLabel = map[readiness.Status]string{readiness.Pass: "pass", readiness.Fail: "FAIL", readiness.NotApplicable: "n/a"}

func printTable(w io.Writer, rep readiness.Report) {
	fmt.Fprintf(w, "%s readiness: %d of %d applicable controls pass (%.1f%%), %d not applicable\n\n",
		rep.Product, rep.Passed, rep.Passed+rep.Failed, rep.Score, rep.NotApplicable)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tCONTROL\tEVIDENCE")
	for _, c := range rep.Controls {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", statusLabel[c.Status], c.ID, c.Evidence)
	}
	_ = tw.Flush()
	gaps := 0
	for _, c := range rep.Controls {
		if c.Status != readiness.Fail {
			continue
		}
		if gaps == 0 {
			fmt.Fprintln(w, "\nGaps:")
		}
		gaps++
		fmt.Fprintf(w, "\n%d. %s (%s)\n   %s\n   fix:  %s\n   docs: %s\n", gaps, c.Title, c.ID, c.Evidence, c.Fix, c.Docs)
		if len(c.Refs) > 0 {
			var r []string
			for _, ref := range c.Refs {
				r = append(r, ref.Framework+" "+ref.ID)
			}
			fmt.Fprintf(w, "   maps to: %s\n", strings.Join(r, "; "))
		}
	}
	fmt.Fprintf(w, "\n%s\n", readiness.Notice)
}
