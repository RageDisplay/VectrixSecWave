// Package crawler discovers endpoints (pages, forms, JS-referenced URLs and a
// fixed list of "interesting" paths) for a target, mirroring modules/crawler.py.
package crawler

import (
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

// Endpoint is a discovered URL + method + parameters.
type Endpoint struct {
	URL         string
	Method      string
	Params      map[string]string
	BodyParams  map[string]string
	ContentType string
	Source      string // crawl | wordlist | js | form | gobuster
}

// BaseURL returns the URL with query string and fragment stripped.
func (e Endpoint) BaseURL() string {
	u, err := url.Parse(e.URL)
	if err != nil {
		return e.URL
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func (e Endpoint) key() string { return e.Method + " " + e.URL }

// interestingPaths is probed unconditionally after crawling, mirroring
// crawler.py INTERESTING_PATHS.
var interestingPaths = []string{
	"/api", "/api/v1", "/api/v2", "/api/v3", "/api/health", "/api/status",
	"/swagger", "/swagger-ui.html", "/swagger-ui/", "/swagger.json", "/swagger.yaml",
	"/openapi.json", "/openapi.yaml", "/api-docs", "/api/docs", "/graphql",
	"/graphiql", "/.well-known/openapi", "/redoc",
	"/admin", "/admin/", "/administrator", "/manage", "/management",
	"/dashboard", "/console", "/panel",
	"/login", "/logout", "/auth", "/oauth", "/token", "/refresh",
	"/api/login", "/api/auth", "/api/token", "/api/refresh",
	"/forgot-password", "/reset-password", "/register", "/signup",
	"/debug", "/health", "/ping", "/status", "/metrics", "/info",
	"/actuator", "/actuator/env", "/actuator/health", "/actuator/metrics",
	"/actuator/beans", "/actuator/mappings", "/actuator/trace",
	"/env", "/trace", "/beans", "/mappings",
	"/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
	"/config.json", "/config.yaml", "/config.yml",
	"/web.config", "/.htaccess", "/robots.txt", "/sitemap.xml",
	"/server-status", "/server-info",
	"/upload", "/uploads", "/files", "/file", "/download", "/media",
	"/backup", "/backups", "/db", "/database",
	"/app.zip", "/app.tar.gz", "/backup.zip", "/www.zip",
	"/nonexistent-page-pentest-check",
}

// defaultExcludePattern blocks destructive/session-ending paths from being
// requested automatically. Mirrors crawler.py DEFAULT_EXCLUDE_PATTERN.
var defaultExcludePattern = regexp.MustCompile(`(?i)(/logout|/log-?off|/signout|/sign-out|/sessions?/destroy|/disconnect|` +
	`/delete|/remove|/destroy|/drop|/purge|/deactivate|/close-?account|` +
	`/revoke|/wipe|/terminate)`)

var jsURLPattern = regexp.MustCompile(`(?i)(?:url|href|src|action|endpoint|api)["\s]*[:=]["\s]*["']([/][^"'<>\s]{2,})["']`)

type queueItem struct {
	url   string
	depth int
}

// Crawler performs a breadth-first crawl bounded by depth/page count.
type Crawler struct {
	Session  *httpsession.Session
	BaseURL  string
	MaxDepth int
	MaxPages int
	Verbose  bool

	baseHost    string
	userExclude []*regexp.Regexp
	visited     map[string]struct{}
	endpoints   []Endpoint
	endpointSet map[string]struct{}
}

// New creates a crawler. excludePatterns are extra regexes (in addition to
// the built-in destructive-path deny-list) that the crawler must never
// request.
func New(session *httpsession.Session, baseURL string, maxDepth, maxPages int, verbose bool, excludePatterns []string) *Crawler {
	base := strings.TrimSuffix(baseURL, "/")
	host := ""
	if u, err := url.Parse(base); err == nil {
		host = u.Host
	}
	c := &Crawler{
		Session:     session,
		BaseURL:     base,
		MaxDepth:    maxDepth,
		MaxPages:    maxPages,
		Verbose:     verbose,
		baseHost:    host,
		visited:     make(map[string]struct{}),
		endpointSet: make(map[string]struct{}),
	}
	for _, p := range excludePatterns {
		if re, err := regexp.Compile("(?i)" + p); err == nil {
			c.userExclude = append(c.userExclude, re)
		}
	}
	return c
}

func (c *Crawler) isExcluded(rawurl string) bool {
	u, err := url.Parse(rawurl)
	if err != nil {
		return false
	}
	pathQ := u.Path + "?" + u.RawQuery
	if defaultExcludePattern.MatchString(pathQ) {
		return true
	}
	for _, re := range c.userExclude {
		if re.MatchString(rawurl) {
			return true
		}
	}
	return false
}

func (c *Crawler) addEndpoint(ep Endpoint) bool {
	k := ep.key()
	if _, ok := c.endpointSet[k]; ok {
		return false
	}
	c.endpointSet[k] = struct{}{}
	c.endpoints = append(c.endpoints, ep)
	return true
}

func (c *Crawler) hasEndpointURL(u string) bool {
	for _, e := range c.endpoints {
		if e.URL == u {
			return true
		}
	}
	return false
}

// normaliseURL resolves href against source, drops fragments, and applies the
// same-domain + deny-list filters. Returns "" if the URL should be skipped.
func (c *Crawler) normaliseURL(href, source string) string {
	href = strings.TrimSpace(href)
	if href == "" {
		return ""
	}
	for _, prefix := range []string{"#", "javascript:", "mailto:", "tel:", "data:"} {
		if strings.HasPrefix(href, prefix) {
			return ""
		}
	}
	base := source
	if base == "" {
		base = c.BaseURL
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	full := baseURL.ResolveReference(ref)
	if full.Scheme != "http" && full.Scheme != "https" {
		return ""
	}
	if full.Host != c.baseHost {
		return ""
	}
	full.Fragment = ""
	if c.isExcluded(full.String()) {
		if c.Verbose {
			logging.Printf("  [-] excluded (deny-list): %s", full.String())
		}
		return ""
	}
	return full.String()
}

// Crawl runs the BFS crawl and the interesting-paths probe, returning all
// discovered endpoints.
func (c *Crawler) Crawl() []Endpoint {
	logging.Printf("[*] Crawling %s (depth=%d, max=%d)", c.BaseURL, c.MaxDepth, c.MaxPages)

	queue := []queueItem{{url: c.BaseURL, depth: 0}}
	c.visited[c.BaseURL] = struct{}{}

	for len(queue) > 0 && len(c.visited) < c.MaxPages {
		item := queue[0]
		queue = queue[1:]
		queue = c.processPage(item.url, item.depth, queue)
	}

	c.probeInterestingPaths()
	logging.Printf("[*] Crawl complete. Discovered %d endpoints.", len(c.endpoints))
	return c.endpoints
}

func (c *Crawler) processPage(rawurl string, depth int, queue []queueItem) []queueItem {
	resp, err := c.Session.Get(rawurl, nil)
	if err != nil {
		if c.Verbose {
			logging.Printf("  [!] GET %s -> %v", rawurl, err)
		}
		return queue
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if c.Verbose {
		logging.Printf("  [%d] %s", resp.StatusCode, rawurl)
	}

	u, _ := url.Parse(rawurl)
	params := map[string]string{}
	if u != nil {
		for k, v := range u.Query() {
			if len(v) > 0 {
				params[k] = v[0]
			}
		}
	}
	c.addEndpoint(Endpoint{URL: rawurl, Method: "GET", Params: params, Source: "crawl"})

	if depth >= c.MaxDepth {
		return queue
	}
	if !strings.Contains(ct, "text/") && !strings.Contains(ct, "javascript") {
		return queue
	}

	text := resp.Body

	if strings.Contains(ct, "html") {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(text))
		if err == nil {
			queue = c.extractLinks(doc, rawurl, depth, queue)
			c.extractForms(doc, rawurl)
		} else {
			queue = c.extractLinksRegex(text, rawurl, depth, queue)
		}
	}

	if strings.Contains(ct, "javascript") || strings.HasSuffix(rawurl, ".js") {
		c.extractFromJS(text, rawurl)
	}

	return queue
}

func (c *Crawler) extractLinks(doc *goquery.Document, source string, depth int, queue []queueItem) []queueItem {
	doc.Find("a[href]").Each(func(_ int, sel *goquery.Selection) {
		href, _ := sel.Attr("href")
		if norm := c.normaliseURL(href, source); norm != "" {
			if _, seen := c.visited[norm]; !seen {
				c.visited[norm] = struct{}{}
				queue = append(queue, queueItem{url: norm, depth: depth + 1})
			}
		}
	})
	doc.Find("script[src]").Each(func(_ int, sel *goquery.Selection) {
		src, _ := sel.Attr("src")
		if norm := c.normaliseURL(src, source); norm != "" {
			if _, seen := c.visited[norm]; !seen {
				c.visited[norm] = struct{}{}
				queue = append(queue, queueItem{url: norm, depth: depth + 1})
			}
		}
	})
	return queue
}

var hrefRegex = regexp.MustCompile(`href=["']([^"']+)["']`)

func (c *Crawler) extractLinksRegex(text, source string, depth int, queue []queueItem) []queueItem {
	for _, m := range hrefRegex.FindAllStringSubmatch(text, -1) {
		if norm := c.normaliseURL(m[1], source); norm != "" {
			if _, seen := c.visited[norm]; !seen {
				c.visited[norm] = struct{}{}
				queue = append(queue, queueItem{url: norm, depth: depth + 1})
			}
		}
	}
	return queue
}

func (c *Crawler) extractForms(doc *goquery.Document, source string) {
	doc.Find("form").Each(func(_ int, form *goquery.Selection) {
		action, exists := form.Attr("action")
		if !exists {
			action = source
		}
		method := strings.ToUpper(form.AttrOr("method", "GET"))
		formURL := c.normaliseURL(action, source)
		if formURL == "" {
			formURL = source
		}

		bodyParams := map[string]string{}
		form.Find("input, textarea, select").Each(func(_ int, inp *goquery.Selection) {
			name, ok := inp.Attr("name")
			if ok && name != "" {
				bodyParams[name] = inp.AttrOr("value", "test")
			}
		})

		c.addEndpoint(Endpoint{URL: formURL, Method: method, BodyParams: bodyParams, Source: "form"})
	})
}

func (c *Crawler) extractFromJS(text, source string) {
	for _, m := range jsURLPattern.FindAllStringSubmatch(text, -1) {
		if norm := c.normaliseURL(m[1], source); norm != "" {
			if !c.hasEndpointURL(norm) {
				c.addEndpoint(Endpoint{URL: norm, Method: "GET", Source: "js"})
			}
		}
	}
}

func (c *Crawler) probeInterestingPaths() {
	for _, path := range interestingPaths {
		u := c.BaseURL + path
		if c.hasEndpointURL(u) {
			continue
		}
		if c.isExcluded(u) {
			continue
		}
		resp, err := c.Session.Request("GET", u, httpsession.Options{AllowRedirects: false, Timeout: 8 * time.Second})
		if err != nil {
			continue
		}
		if resp.StatusCode != 404 && resp.StatusCode != 410 {
			c.addEndpoint(Endpoint{URL: u, Method: "GET", Source: "wordlist"})
			if c.Verbose {
				logging.Printf("  [+] Found: [%d] %s", resp.StatusCode, u)
			}
		}
	}
}
