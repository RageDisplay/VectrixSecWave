// Package logging provides a single redirectable sink for the scan's
// human-readable progress output ("[*] ...", "[+] ...", "[!] ...").
//
// The CLI points it at os.Stdout; the GUI points it at a buffer feeding a
// scrollable text widget, so both front-ends share the exact same engine
// output.
package logging

import (
	"fmt"
	"io"
	"os"
	"sync"
)

var (
	mu  sync.Mutex
	out io.Writer = os.Stdout
)

// SetOutput redirects all future log output to w.
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	out = w
}

// Printf writes a formatted line (newline appended) to the current sink.
func Printf(format string, args ...any) {
	mu.Lock()
	w := out
	mu.Unlock()
	fmt.Fprintf(w, format+"\n", args...)
}

// Println writes a line to the current sink.
func Println(args ...any) {
	mu.Lock()
	w := out
	mu.Unlock()
	fmt.Fprintln(w, args...)
}
