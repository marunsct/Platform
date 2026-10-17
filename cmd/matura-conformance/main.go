// Command matura-conformance checks a running app against the Matura app integration contract (contract §10.4).
// See docs/guide/conformance.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/marunsct/Platform/internal/conformance"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("matura-conformance", flag.ContinueOnError)
	fs.SetOutput(stderr)
	app := fs.String("app", "", "base URL of the running app, e.g. http://localhost:8000 (required)")
	manifest := fs.String("manifest", "", "path to the app's manifest with a conformance section (required)")
	issuerAddr := fs.String("issuer-addr", "127.0.0.1:8099", "address the test issuer listens on")
	secret := fs.String("webhook-secret", "", "webhook signing secret the app uses (generated when empty)")
	audience := fs.String("audience", "", "token audience (defaults to the manifest's client_id, else its slug)")
	wait := fs.Duration("wait", 30*time.Second, "how long to wait for the app to answer before checking")
	asJSON := fs.Bool("json", false, "print a machine-readable JSON report on stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *app == "" || *manifest == "" {
		fmt.Fprintln(stderr, "matura-conformance: --app and --manifest are required")
		fs.Usage()
		return 2
	}
	m, err := conformance.LoadManifest(*manifest)
	if err != nil {
		fmt.Fprintln(stderr, "matura-conformance:", err)
		return 2
	}
	if *secret == "" {
		*secret = conformance.GenerateSecret()
	}
	if *audience == "" {
		*audience = m.Audience()
	}
	iss, err := conformance.StartIssuer(*issuerAddr)
	if err != nil {
		fmt.Fprintln(stderr, "matura-conformance: start issuer:", err)
		return 2
	}
	defer iss.Close()

	info := stdout
	if *asJSON {
		info = stderr
	}
	fmt.Fprintf(info, "Test issuer running. Start the app with:\n\n  MATURA_ISSUER=%s MATURA_AUDIENCE=%s MATURA_WEBHOOK_SECRET=%s\n\n",
		iss.URL(), *audience, *secret)
	fmt.Fprintf(info, "Waiting up to %s for %s ...\n", *wait, *app)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := conformance.WaitForApp(ctx, *app, *wait); err != nil {
		fmt.Fprintln(stderr, "matura-conformance:", err)
		return 1
	}
	c, err := conformance.New(conformance.Config{
		App: *app, Manifest: m, Issuer: iss, Audience: *audience, WebhookSecret: *secret,
	})
	if err != nil {
		fmt.Fprintln(stderr, "matura-conformance:", err)
		return 2
	}
	rep := c.Run(ctx)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		fmt.Fprintln(stdout)
		rep.WriteText(stdout)
	}
	if !rep.OK {
		return 1
	}
	return 0
}
