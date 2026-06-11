// Package scanner ties the crawler, external tools and security checks
// together into per-target scan runs, mirroring pentest.py.
package scanner

// Profile is a named bundle of scan settings (crawl depth, which external
// tools and checks to run, injection tuning, ...). Mirrors pentest.py
// ScanProfile.
//
// Some fields (CheckAuth, CheckInjection, CheckXXE, CheckHostInject,
// CheckAccountEnum, CheckVerbTamper, ChainAnalysis, ...) describe checks that
// are not implemented yet in this Go port; the orchestrator currently skips
// them regardless of the flag value. They are kept here so the profile
// definitions stay a faithful copy of the Python tool and Phase 2 can wire
// them up without reshaping this struct.
type Profile struct {
	Name  string
	Label string

	CrawlDepth int
	MaxPages   int

	// External tools.
	RunWhatweb  bool
	RunWafw00f  bool
	RunNikto    bool
	RunNuclei   bool
	NucleiFull  bool // broader CVE/OAST pass with a larger target cap (aggressive only)
	RunGobuster bool
	RunSqlmap   bool // deep SQLi only in aggressive

	// Check modules.
	CheckHeaders     bool
	CheckSSL         bool
	CheckDisclosure  bool
	CheckAuth        bool
	CheckCORS        bool
	CheckIDOR        bool
	CheckSSRF        bool
	CheckInjection   bool
	CheckXXE         bool
	CheckHostInject  bool
	CheckAccountEnum bool
	CheckVerbTamper  bool

	// Injection tuning.
	InjectionTimebased bool
	InjectionDeepXSS   bool

	// Adaptive confirmation.
	AdaptiveConfirm  bool
	AdaptiveDeepDive bool

	// Attack-chain correlation.
	ChainAnalysis      bool
	ChainActiveExploit bool
}

// Profiles mirrors pentest.py PROFILES.
var Profiles = map[string]*Profile{
	"safe": {
		Name:               "safe",
		Label:              "SAFE — пассивная разведка, никаких payload'ов",
		CrawlDepth:         2,
		MaxPages:           100,
		RunWhatweb:         true,
		RunWafw00f:         true,
		CheckHeaders:       true,
		CheckSSL:           true,
		CheckDisclosure:    true,
		CheckAuth:          true,
		CheckCORS:          true,
	},
	"medium": {
		Name:               "medium",
		Label:              "MEDIUM — стандартный пентест (default)",
		CrawlDepth:         3,
		MaxPages:           200,
		RunWhatweb:         true,
		RunWafw00f:         true,
		RunNikto:           true,
		RunNuclei:          true,
		CheckHeaders:       true,
		CheckSSL:           true,
		CheckDisclosure:    true,
		CheckAuth:          true,
		CheckCORS:          true,
		CheckIDOR:          true,
		CheckSSRF:          true,
		CheckInjection:     true,
		CheckXXE:           true,
		CheckHostInject:    true,
		CheckAccountEnum:   true,
		CheckVerbTamper:    true,
		AdaptiveConfirm:    true,
		AdaptiveDeepDive:   true,
		ChainAnalysis:      true,
	},
	"aggressive": {
		Name:               "aggressive",
		Label:              "AGGRESSIVE — полное покрытие, шумный",
		CrawlDepth:         5,
		MaxPages:           500,
		RunWhatweb:         true,
		RunWafw00f:         true,
		RunNikto:           true,
		RunNuclei:          true,
		NucleiFull:         true,
		RunGobuster:        true,
		RunSqlmap:          true,
		CheckHeaders:       true,
		CheckSSL:           true,
		CheckDisclosure:    true,
		CheckAuth:          true,
		CheckCORS:          true,
		CheckIDOR:          true,
		CheckSSRF:          true,
		CheckInjection:     true,
		CheckXXE:           true,
		CheckHostInject:    true,
		CheckAccountEnum:   true,
		CheckVerbTamper:    true,
		InjectionTimebased: true,
		InjectionDeepXSS:   true,
		AdaptiveConfirm:    true,
		AdaptiveDeepDive:   true,
		ChainAnalysis:      true,
		ChainActiveExploit: true,
	},
}
