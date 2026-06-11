// Package checkpoint provides crash/ban-safe progress tracking for
// multi-target runs, mirroring modules/checkpoint.py.
//
// State lives in <output_dir>/.vectrix_state/<mode>.json and is rewritten
// after every completed target, so at most one target's progress is lost if
// the run dies mid-way.
package checkpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

type Checkpoint struct {
	dir       string
	path      string
	mode      string
	completed map[string]struct{}
}

type fileFormat struct {
	Mode      string   `json:"mode"`
	Targets   []string `json:"targets"`
	Completed []string `json:"completed"`
}

// New creates a checkpoint tracker for outputDir/.vectrix_state/<mode>.json.
func New(outputDir, mode string) *Checkpoint {
	dir := filepath.Join(outputDir, ".vectrix_state")
	return &Checkpoint{
		dir:       dir,
		path:      filepath.Join(dir, mode+".json"),
		mode:      mode,
		completed: make(map[string]struct{}),
	}
}

// Load reads previously completed targets (for --resume).
func (c *Checkpoint) Load() {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	c.completed = make(map[string]struct{}, len(f.Completed))
	for _, t := range f.Completed {
		c.completed[t] = struct{}{}
	}
}

// Reset begins a fresh run: clears prior completion state and writes targets.
func (c *Checkpoint) Reset(targets []string) {
	c.completed = make(map[string]struct{})
	c.write(targets)
}

// IsDone reports whether target was already completed.
func (c *Checkpoint) IsDone(target string) bool {
	_, ok := c.completed[target]
	return ok
}

// Pending returns the subset of targets not yet completed.
func (c *Checkpoint) Pending(targets []string) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		if !c.IsDone(t) {
			out = append(out, t)
		}
	}
	return out
}

// MarkDone records target as completed and persists state.
func (c *Checkpoint) MarkDone(target string, targets []string) {
	c.completed[target] = struct{}{}
	c.write(targets)
}

// Clear removes the state file once the whole run finished cleanly.
func (c *Checkpoint) Clear() {
	os.Remove(c.path)
}

func (c *Checkpoint) write(targets []string) {
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return
	}
	completed := make([]string, 0, len(c.completed))
	for t := range c.completed {
		completed = append(completed, t)
	}
	sort.Strings(completed)

	data, err := json.MarshalIndent(fileFormat{
		Mode:      c.mode,
		Targets:   targets,
		Completed: completed,
	}, "", "  ")
	if err != nil {
		return
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	os.Rename(tmp, c.path)
}
