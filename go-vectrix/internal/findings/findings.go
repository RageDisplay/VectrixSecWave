// Package findings holds the Finding/FindingStore data model shared by every
// check, the report generator and the OWASP Top 10 2021 classification.
package findings

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
)

// Severity mirrors modules/findings.py Severity enum.
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

// AllSeverities lists severities from highest to lowest weight.
var AllSeverities = []Severity{Critical, High, Medium, Low, Info}

// Weight returns the numeric ordering used to rank findings.
func (s Severity) Weight() int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	}
	return 0
}

// Downgrade returns the next-lower severity (used when a candidate finding
// could not be confirmed automatically).
func (s Severity) Downgrade() Severity {
	switch s {
	case Critical:
		return High
	case High:
		return Medium
	case Medium:
		return Low
	default:
		return Low
	}
}

// OWASPCategoryMap maps a substring of Finding.Category (case-insensitive) to
// (OWASP ID, short name). Mirrors modules/findings.py OWASP_CATEGORY_MAP.
// Order matters: the first matching key wins, so more specific keys must come
// before broader ones.
var owaspCategoryMap = []struct {
	key  string
	id   string
	name string
}{
	{"Injection", "A03:2021", "Injection"},
	{"XSS", "A03:2021", "Injection"},
	{"SSRF", "A10:2021", "SSRF"},
	{"CORS", "A05:2021", "Security Misconfiguration"},
	{"Security Headers", "A05:2021", "Security Misconfiguration"},
	{"Authentication", "A07:2021", "Auth & Identification Failures"},
	{"Session Management", "A07:2021", "Auth & Identification Failures"},
	{"CSRF", "A01:2021", "Broken Access Control"},
	{"IDOR", "A01:2021", "Broken Access Control"},
	{"BOLA", "A01:2021", "Broken Access Control"},
	{"Open Redirect", "A01:2021", "Broken Access Control"},
	{"Information Disclosure", "A02:2021", "Cryptographic Failures"},
	{"SSL/TLS", "A02:2021", "Cryptographic Failures"},
	{"Rate Limiting", "A05:2021", "Security Misconfiguration"},
	{"Access Control", "A01:2021", "Broken Access Control"},
	{"XXE", "A03:2021", "Injection"},
	{"Host Header", "A05:2021", "Security Misconfiguration"},
	{"Host Injection", "A05:2021", "Security Misconfiguration"},
}

// OWASPFullNames maps OWASP Top 10 2021 IDs to their full English names.
var OWASPFullNames = map[string]string{
	"A01:2021": "Broken Access Control",
	"A02:2021": "Cryptographic Failures",
	"A03:2021": "Injection",
	"A04:2021": "Insecure Design",
	"A05:2021": "Security Misconfiguration",
	"A06:2021": "Vulnerable & Outdated Components",
	"A07:2021": "Identification & Authentication Failures",
	"A08:2021": "Software & Data Integrity Failures",
	"A09:2021": "Security Logging & Monitoring Failures",
	"A10:2021": "Server-Side Request Forgery",
}

// Finding is a single security observation. Field names map 1:1 onto the
// JSON keys produced by the Python report module.
type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    Severity `json:"severity"`
	Category    string `json:"category"`
	CWE         string `json:"cwe"`
	Target      string `json:"target"`
	URL         string `json:"url"`
	Parameter   string `json:"parameter"`
	Method      string `json:"method"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Reproduction string `json:"reproduction"`
	Remediation string `json:"remediation"`

	// Adaptive confirmation metadata.
	// "confirmed" | "unverified" | "confirmed-deep-dive"
	Status           string   `json:"status"`
	Confidence       float64  `json:"confidence"`
	VerificationLog  []string `json:"verification_log"`
	Artifacts        []string `json:"artifacts"`

	// Kind classifies the underlying technique for candidates produced by a
	// check (e.g. "idor", "ssrf", "disclosure"); empty for deterministic
	// findings.
	Kind string `json:"-"`
}

// NewFinding builds a Finding with sane defaults (random ID, status
// "confirmed", confidence 1.0, GET method).
func NewFinding(title string, sev Severity, category, cwe, url, description, remediation, reproduction string) *Finding {
	method := "GET"
	return &Finding{
		ID:            randomID(),
		Title:         title,
		Severity:      sev,
		Category:      category,
		CWE:           cwe,
		URL:           url,
		Method:        method,
		Description:   description,
		Remediation:   remediation,
		Reproduction:  reproduction,
		Status:        "confirmed",
		Confidence:    1.0,
	}
}

func randomID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}

// OWASP returns (OWASP ID, short name) derived from Category.
func (f *Finding) OWASP() (string, string) {
	lower := strings.ToLower(f.Category)
	for _, m := range owaspCategoryMap {
		if strings.Contains(lower, strings.ToLower(m.key)) {
			return m.id, m.name
		}
	}
	return "A05:2021", "Security Misconfiguration"
}

// DiscardedCandidate records a weak-signal candidate the adaptive pass
// actively refuted. Kept only for the report's transparency appendix.
type DiscardedCandidate struct {
	Title  string
	Kind   string
	Reason string
}

type fingerprint struct {
	title, url, parameter, method string
}

func fingerprintOf(f *Finding) fingerprint {
	return fingerprint{
		title:     strings.TrimSpace(f.Title),
		url:       strings.TrimRight(f.URL, "/"),
		parameter: f.Parameter,
		method:    f.Method,
	}
}

// FindingStore is the thread-safe collection of findings, pending adaptive
// candidates and discarded candidates for one target.
type FindingStore struct {
	mu         sync.Mutex
	findings   []*Finding
	index      map[fingerprint]*Finding
	candidates []*Candidate
	discarded  []DiscardedCandidate
}

// Candidate is a weak-signal finding awaiting adaptive confirmation.
// Context carries check-specific data needed by the verifier (phase 2).
type Candidate struct {
	Finding *Finding
	Kind    string
	Context map[string]any
}

// NewFindingStore creates an empty store.
func NewFindingStore() *FindingStore {
	return &FindingStore{index: make(map[fingerprint]*Finding)}
}

// Add inserts a finding, collapsing exact duplicates (same title/url/param/method).
// On duplicate: highest severity wins, evidence/verification logs/artifacts merge,
// confidence becomes the max of the two.
func (s *FindingStore) Add(f *Finding) {
	key := fingerprintOf(f)
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.index[key]
	if !ok {
		s.findings = append(s.findings, f)
		s.index[key] = f
		return
	}

	if f.Severity.Weight() > existing.Severity.Weight() {
		existing.Severity = f.Severity
	}
	if f.Confidence > existing.Confidence {
		existing.Confidence = f.Confidence
	}
	if f.Evidence != "" && !strings.Contains(existing.Evidence, f.Evidence) {
		existing.Evidence = strings.Trim(existing.Evidence+"\n---\n"+f.Evidence, "\n-")
	}
	for _, entry := range f.VerificationLog {
		found := false
		for _, e := range existing.VerificationLog {
			if e == entry {
				found = true
				break
			}
		}
		if !found {
			existing.VerificationLog = append(existing.VerificationLog, entry)
		}
	}
	for _, art := range f.Artifacts {
		found := false
		for _, e := range existing.Artifacts {
			if e == art {
				found = true
				break
			}
		}
		if !found {
			existing.Artifacts = append(existing.Artifacts, art)
		}
	}
}

// AddCandidate queues a weak-signal finding for adaptive confirmation.
func (s *FindingStore) AddCandidate(c *Candidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidates = append(s.candidates, c)
}

// PopCandidates returns and clears all queued candidates.
func (s *FindingStore) PopCandidates() []*Candidate {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.candidates
	s.candidates = nil
	return c
}

// AddDiscarded records a candidate the adaptive pass refuted.
func (s *FindingStore) AddDiscarded(d DiscardedCandidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.discarded = append(s.discarded, d)
}

// Discarded returns all discarded candidates.
func (s *FindingStore) Discarded() []DiscardedCandidate {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DiscardedCandidate, len(s.discarded))
	copy(out, s.discarded)
	return out
}

// All returns every finding sorted by severity (highest first).
func (s *FindingStore) All() []*Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Finding, len(s.findings))
	copy(out, s.findings)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Severity.Weight() > out[j].Severity.Weight()
	})
	return out
}

// Len returns the number of findings.
func (s *FindingStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.findings)
}

// Counts returns the number of findings per severity.
func (s *FindingStore) Counts() map[Severity]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := map[Severity]int{Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0}
	for _, f := range s.findings {
		counts[f.Severity]++
	}
	return counts
}

// OWASPCounts returns {owasp_id: count} across all findings.
func (s *FindingStore) OWASPCounts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]int)
	for _, f := range s.findings {
		oid, _ := f.OWASP()
		result[oid]++
	}
	return result
}

// Targets returns the sorted list of unique non-empty Target values.
func (s *FindingStore) Targets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := make(map[string]struct{})
	for _, f := range s.findings {
		if f.Target != "" {
			set[f.Target] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
