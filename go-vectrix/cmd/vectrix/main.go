// Command vectrix is the CLI entrypoint for the Go port of the VectrixSecWave
// pentest toolkit, mirroring pentest.py's main().
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"vectrixgo/internal/runner"
)

// stringSliceFlag implements flag.Value for repeatable string flags
// (-H/--header, --exclude).
type stringSliceFlag []string

func (f *stringSliceFlag) String() string { return strings.Join(*f, ",") }
func (f *stringSliceFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}

	if err := runner.Run(context.Background(), cfg, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
}
