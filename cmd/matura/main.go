// Command matura is the operator's command line for a Matura installation. `matura check` reads the readiness
// report from maturad and lists every gap with its fix (docs/guide/readiness.md).
package main

import (
	"fmt"
	"io"
	"os"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usage = `usage: matura <command> [flags]

commands:
  check    readiness score, gaps and fixes for an installation (matura check -h)

environment:
  MATURA_URL     maturad's address (default http://localhost:8080)
  MATURA_TOKEN   an operator's bearer token
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "check":
		return check(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "matura: unknown command %q\n\n%s", args[0], usage)
	return 2
}
