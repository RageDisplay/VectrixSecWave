// Package httpsession implements a self-throttling, ban/expiry-aware HTTP
// client. It is the Go port of modules/resilient.py + modules/session.py.
//
// Every check routes its requests through Session.Get/Post/Do, so the whole
// scanner gets global rate limiting, 429/503 backoff and ban / session-expiry
// detection for free.
package httpsession

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"vectrixgo/internal/logging"
)

// AbortReason identifies why a scan was aborted.
type AbortReason string

const (
	ReasonBan            AbortReason = "ban"
	ReasonSessionExpired AbortReason = "session-expired"
)

// ScanAborted is returned (and bubbled all the way up) when the session can
// no longer make useful requests. Mirrors modules/resilient.py ScanAborted.
type ScanAborted struct {
	Reason  AbortReason
	Message string
}

func (e *ScanAborted) Error() string { return e.Message }

// Body markers that typically mean "you've been blocked", not a real 403/429.
var blockBodyRe = regexp.MustCompile(`(?i)(access denied|request blocked|you have been blocked|are you a robot|` +
	`verify you are human|captcha|cf-error|cloudflare|incident id|` +
	`unusual traffic|rate ?limit|too many requests|akamai|imperva|` +
	`web application firewall|forbidden by administrative rules)`)

// Path/redirect markers that mean "you got bounced to a login screen".
var loginPathRe = regexp.MustCompile(`(?i)(/login|/signin|/sign-in|/sso|/oauth|/auth/|/account/login|` +
	`/session/new|/authenticate|returnurl=|redirect_uri=|/adfs/)`)

const DefaultUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// Stats mirrors the per-session counters surfaced in the report meta.
type Stats struct {
	Requests  int `json:"requests"`
	Retries   int `json:"retries"`
	Blocks    int `json:"blocks"`
	Cooldowns int `json:"cooldowns"`
}

// Response is the simplified HTTP result returned to checks: status, headers
// and body are read eagerly so callers never have to manage Body.Close().
type Response struct {
	StatusCode int
	Header     http.Header
	Body       string
	URL        string // final URL after redirects
	Redirected bool
}

// Session is the Go equivalent of ResilientSession (a requests.Session
// subclass in Python).
type Session struct {
	client  *http.Client
	jar     http.CookieJar
	headers http.Header

	basicUser, basicPass string
	hasBasicAuth         bool

	Timeout time.Duration
	Verbose bool
	ProxyURL string

	// Pacing
	Delay  time.Duration
	Jitter time.Duration

	// Retry / ban handling
	MaxRetries          int
	BanPause            time.Duration
	BanPauseMax         time.Duration
	BanBlockThreshold   int
	BanHardLimit        int
	DetectSessionExpiry bool
	AuthConfigured      bool

	mu                 sync.Mutex
	nextStart          time.Time
	consecutiveBlocks  int
	cooldownsUsed      int
	Stats              Stats
}

// New builds a session with sensible defaults (verify=false, like the Python
// tool — these scans routinely target self-signed internal hosts).
func New() *Session {
	jar, _ := cookiejar.New(nil)
	s := &Session{
		jar:                 jar,
		headers:             http.Header{},
		Timeout:             15 * time.Second,
		Delay:               500 * time.Millisecond,
		Jitter:              500 * time.Millisecond,
		MaxRetries:          3,
		BanPause:            30 * time.Second,
		BanPauseMax:         300 * time.Second,
		BanBlockThreshold:   5,
		BanHardLimit:        3,
		DetectSessionExpiry: true,
	}
	s.headers.Set("User-Agent", DefaultUA)
	s.rebuildClient()
	return s
}

func (s *Session) rebuildClient() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if s.ProxyURL != "" {
		if u, err := url.Parse(s.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	s.client = &http.Client{
		Transport: transport,
		Jar:       s.jar,
		Timeout:   60 * time.Second, // hard ceiling; per-request timeout via context below
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if flag, ok := req.Context().Value(redirectFlagKey{}).(*redirectState); ok {
				if loginPathRe.MatchString(req.URL.Path) || loginPathRe.MatchString(req.URL.RawQuery) {
					flag.matchedLogin = true
				}
				flag.redirected = true
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}
}

type redirectFlagKey struct{}

type redirectState struct {
	redirected   bool
	matchedLogin bool
}

// SetProxy configures an HTTP/HTTPS proxy (e.g. Burp/ZAP).
func (s *Session) SetProxy(proxy string) {
	s.ProxyURL = proxy
	s.rebuildClient()
}

// Header returns the default header set sent with every request (mutate
// freely before the scan starts).
func (s *Session) Header() http.Header { return s.headers }

// SetHeader sets a default header sent on every request.
func (s *Session) SetHeader(k, v string) { s.headers.Set(k, v) }

// SetBearerToken sets the Authorization header, adding "Bearer " if missing.
func (s *Session) SetBearerToken(token string) {
	t := strings.TrimSpace(token)
	if !strings.HasPrefix(strings.ToLower(t), "bearer ") {
		t = "Bearer " + t
	}
	s.headers.Set("Authorization", t)
	s.AuthConfigured = true
}

// SetBasicAuth configures HTTP basic auth.
func (s *Session) SetBasicAuth(user, pass string) {
	s.basicUser, s.basicPass, s.hasBasicAuth = user, pass, true
	s.AuthConfigured = true
}

// SetCookie sets a single cookie for domain (matching the request's host if
// domain == "").
func (s *Session) SetCookie(name, value, domain string) {
	if domain == "" {
		domain = "."
	}
	u := &url.URL{Scheme: "https", Host: strings.TrimPrefix(domain, ".")}
	s.jar.SetCookies(u, []*http.Cookie{{Name: name, Value: value, Path: "/"}})
	s.AuthConfigured = true
}

// SetCookieForURL sets cookies that will be sent for requests to base.
func (s *Session) SetCookiesForURL(base *url.URL, cookies []*http.Cookie) {
	s.jar.SetCookies(base, cookies)
	if len(cookies) > 0 {
		s.AuthConfigured = true
	}
}

// CookiesForURL returns the cookies the jar would send for u — used to build
// "k=v; k2=v2" strings for external tool wrappers.
func (s *Session) CookiesForURL(u *url.URL) []*http.Cookie {
	return s.jar.Cookies(u)
}

// CookieString returns "k=v; k2=v2" for the given URL, for handing to
// external tools (nikto, nuclei, ...).
func (s *Session) CookieString(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return ""
	}
	cookies := s.jar.Cookies(u)
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// AuthorizationHeader returns the configured Authorization header, if any.
func (s *Session) AuthorizationHeader() string {
	return s.headers.Get("Authorization")
}

// CurlAuthFlags returns curl flags representing the session auth, for
// reproduction steps. Mirrors session.session_to_curl_flags.
func (s *Session) CurlAuthFlags(rawurl string) string {
	var flags []string
	cookieStr := s.CookieString(rawurl)
	if cookieStr != "" {
		flags = append(flags, fmt.Sprintf(`-b "%s"`, cookieStr))
	}
	for k, v := range s.headers {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "x-api-key" || lk == "x-auth-token" {
			if len(v) > 0 {
				flags = append(flags, fmt.Sprintf(`-H "%s: %s"`, k, v[0]))
			}
		}
	}
	if s.hasBasicAuth {
		flags = append(flags, fmt.Sprintf("-u '%s:%s'", s.basicUser, s.basicPass))
	}
	if s.ProxyURL != "" {
		flags = append(flags, fmt.Sprintf("-x '%s'", s.ProxyURL))
	}
	return strings.Join(flags, " ")
}

// ── Pacing ──────────────────────────────────────────────────────────────────

func (s *Session) throttle() {
	if s.Delay == 0 && s.Jitter == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	wait := s.nextStart.Sub(now)
	if wait > 0 {
		time.Sleep(wait)
		now = time.Now()
	}
	jitter := time.Duration(0)
	if s.Jitter > 0 {
		jitter = time.Duration(rand.Int63n(int64(s.Jitter) + 1))
	}
	interval := s.Delay + jitter
	base := s.nextStart
	if now.After(base) {
		base = now
	}
	s.nextStart = base.Add(interval)
}

// ── Detection helpers ───────────────────────────────────────────────────────

func looksBlocked(statusCode int, body string) bool {
	if statusCode == 429 || statusCode == 503 {
		return true
	}
	if statusCode == 403 {
		snippet := body
		if len(snippet) > 4000 {
			snippet = snippet[:4000]
		}
		return blockBodyRe.MatchString(snippet)
	}
	return false
}

func (s *Session) isSessionExpired(statusCode int, requestedURL string, redirected, redirectedToLogin bool, finalURL string) bool {
	if !(s.DetectSessionExpiry && s.AuthConfigured) {
		return false
	}
	reqPath := ""
	if u, err := url.Parse(requestedURL); err == nil {
		reqPath = u.Path
	}
	// Never flag the login flow itself as "expired".
	if loginPathRe.MatchString(reqPath) {
		return false
	}
	if statusCode == 401 {
		return true
	}
	if redirectedToLogin {
		return true
	}
	if redirected {
		if u, err := url.Parse(finalURL); err == nil && loginPathRe.MatchString(u.Path) {
			return true
		}
	}
	return false
}

// ── Core request ─────────────────────────────────────────────────────────────

// Options configures a single request.
type Options struct {
	Headers        map[string]string
	Body           io.Reader
	AllowRedirects bool // default true
	Timeout        time.Duration
}

// Get performs a GET request.
func (s *Session) Get(rawurl string, headers map[string]string) (*Response, error) {
	return s.Request("GET", rawurl, Options{Headers: headers, AllowRedirects: true})
}

// PostForm performs a POST with application/x-www-form-urlencoded body.
func (s *Session) PostForm(rawurl string, form url.Values, headers map[string]string) (*Response, error) {
	h := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	for k, v := range headers {
		h[k] = v
	}
	return s.Request("POST", rawurl, Options{Headers: h, Body: strings.NewReader(form.Encode()), AllowRedirects: true})
}

// PostJSON performs a POST with a JSON body.
func (s *Session) PostJSON(rawurl string, payload any, headers map[string]string) (*Response, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	h := map[string]string{"Content-Type": "application/json"}
	for k, v := range headers {
		h[k] = v
	}
	return s.Request("POST", rawurl, Options{Headers: h, Body: strings.NewReader(string(b)), AllowRedirects: true})
}

// Request performs an HTTP request through the resilient pipeline:
// throttle -> send -> retry on 429/503 -> evaluate ban/expiry.
// May return *ScanAborted (check with errors.As).
func (s *Session) Request(method, rawurl string, opts Options) (*Response, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = s.Timeout
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	var bodyBytes []byte
	if opts.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(opts.Body)
		if err != nil {
			return nil, err
		}
	}

	attempt := 0
	for {
		s.throttle()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		var bodyReader io.Reader
		if bodyBytes != nil {
			bodyReader = strings.NewReader(string(bodyBytes))
		}
		req, err := http.NewRequestWithContext(ctx, method, rawurl, bodyReader)
		if err != nil {
			cancel()
			return nil, err
		}

		// Default headers first, then per-request overrides.
		for k, vals := range s.headers {
			for _, v := range vals {
				req.Header.Add(k, v)
			}
		}
		for k, v := range opts.Headers {
			req.Header.Set(k, v)
		}
		if s.hasBasicAuth {
			req.SetBasicAuth(s.basicUser, s.basicPass)
		}

		state := &redirectState{}
		req = req.WithContext(context.WithValue(ctx, redirectFlagKey{}, state))

		client := s.client
		if !opts.AllowRedirects {
			noRedirectClient := *s.client
			noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
			client = &noRedirectClient
		}

		resp, err := client.Do(req)
		cancel()
		if err != nil {
			return nil, err
		}

		bodyData, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // cap at 10MB
		resp.Body.Close()
		body := string(bodyData)

		s.mu.Lock()
		s.Stats.Requests++
		s.mu.Unlock()

		// Transient block -> backoff and retry the same request.
		if (resp.StatusCode == 429 || resp.StatusCode == 503) && attempt < s.MaxRetries {
			attempt++
			s.mu.Lock()
			s.Stats.Retries++
			s.mu.Unlock()
			s.backoffSleep(resp, attempt)
			continue
		}

		finalURL := rawurl
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL.String()
		}

		if err := s.evaluate(resp.StatusCode, body, rawurl, state.redirected, state.matchedLogin, finalURL); err != nil {
			return nil, err
		}

		return &Response{
			StatusCode: resp.StatusCode,
			Header:     resp.Header,
			Body:       body,
			URL:        finalURL,
			Redirected: state.redirected,
		}, nil
	}
}

func (s *Session) backoffSleep(resp *http.Response, attempt int) {
	retryAfter := resp.Header.Get("Retry-After")
	var wait time.Duration
	if n, err := strconv.Atoi(retryAfter); err == nil {
		wait = time.Duration(n) * time.Second
	} else {
		base := time.Duration(1<<uint(attempt)) * time.Second
		jitter := time.Duration(rand.Int63n(int64(time.Second)))
		wait = base + jitter
		if wait > s.BanPauseMax {
			wait = s.BanPauseMax
		}
	}
	if s.Verbose {
		logging.Printf("  [~] %d on %s — backoff %.1fs (retry %d/%d)", resp.StatusCode, resp.Request.URL, wait.Seconds(), attempt, s.MaxRetries)
	}
	time.Sleep(wait)
}

func (s *Session) evaluate(statusCode int, body, requestedURL string, redirected, redirectedToLogin bool, finalURL string) error {
	if s.isSessionExpired(statusCode, requestedURL, redirected, redirectedToLogin, finalURL) {
		return &ScanAborted{
			Reason: ReasonSessionExpired,
			Message: fmt.Sprintf(
				"Сессия истекла (HTTP %d / redirect на логин) при запросе %s. "+
					"Обновите cookie/токен и продолжите с --resume.", statusCode, requestedURL),
		}
	}

	if looksBlocked(statusCode, body) {
		s.mu.Lock()
		s.consecutiveBlocks++
		s.Stats.Blocks++
		blocks := s.consecutiveBlocks
		s.mu.Unlock()
		if blocks >= s.BanBlockThreshold {
			return s.enterCooldown(statusCode)
		}
	} else {
		s.mu.Lock()
		s.consecutiveBlocks = 0
		s.mu.Unlock()
	}
	return nil
}

func (s *Session) enterCooldown(statusCode int) error {
	s.mu.Lock()
	s.cooldownsUsed++
	s.Stats.Cooldowns++
	cooldowns := s.cooldownsUsed
	s.consecutiveBlocks = 0
	s.mu.Unlock()

	if cooldowns > s.BanHardLimit {
		return &ScanAborted{
			Reason: ReasonBan,
			Message: fmt.Sprintf(
				"Антифрод/WAF продолжает блокировать после %d пауз (последний статус %d). "+
					"Остановка. Смените IP/подождите и продолжите с --resume.", s.BanHardLimit, statusCode),
		}
	}

	pause := s.BanPause * time.Duration(1<<uint(cooldowns-1))
	if pause > s.BanPauseMax {
		pause = s.BanPauseMax
	}
	logging.Printf("  [!] Похоже на блокировку (антифрод/WAF). Пауза %.0fс для остывания [%d/%d]...",
		pause.Seconds(), cooldowns, s.BanHardLimit)
	time.Sleep(pause)
	return nil
}

// ── Cookie file loading ──────────────────────────────────────────────────────

// LoadCookieFile loads cookies from JSON array (EditThisCookie/Cookie-Editor),
// JSON object, Netscape cookie-jar, or a raw "name=value; name2=value2" string,
// scoping them to base.
func (s *Session) LoadCookieFile(path string, base *url.URL) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := strings.TrimSpace(string(data))

	if strings.HasPrefix(content, "[") {
		var arr []map[string]any
		if err := json.Unmarshal([]byte(content), &arr); err == nil {
			var cookies []*http.Cookie
			for _, c := range arr {
				name, _ := stringField(c, "name", "Name")
				value, _ := stringField(c, "value", "Value")
				if name == "" {
					continue
				}
				cookies = append(cookies, &http.Cookie{Name: name, Value: value, Path: "/"})
			}
			s.SetCookiesForURL(base, cookies)
			return nil
		}
	}

	if strings.HasPrefix(content, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(content), &obj); err == nil {
			var cookies []*http.Cookie
			for k, v := range obj {
				cookies = append(cookies, &http.Cookie{Name: k, Value: fmt.Sprint(v), Path: "/"})
			}
			s.SetCookiesForURL(base, cookies)
			return nil
		}
	}

	// Netscape cookie-jar format: domain \t flag \t path \t secure \t expiry \t name \t value
	if strings.Contains(content, "\tTRUE\t") || strings.Contains(content, "\tFALSE\t") || strings.HasPrefix(content, "# Netscape") {
		var cookies []*http.Cookie
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Split(line, "\t")
			if len(fields) >= 7 {
				cookies = append(cookies, &http.Cookie{Name: fields[5], Value: fields[6], Path: "/"})
			}
		}
		if len(cookies) > 0 {
			s.SetCookiesForURL(base, cookies)
			return nil
		}
	}

	// Fallback: raw "name=value; name2=value2" string.
	var cookies []*http.Cookie
	for _, pair := range strings.Split(content, ";") {
		pair = strings.TrimSpace(pair)
		if k, v, ok := strings.Cut(pair, "="); ok {
			cookies = append(cookies, &http.Cookie{Name: strings.TrimSpace(k), Value: strings.TrimSpace(v), Path: "/"})
		}
	}
	s.SetCookiesForURL(base, cookies)
	return nil
}

func stringField(m map[string]any, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return fmt.Sprint(v), true
		}
	}
	return "", false
}
