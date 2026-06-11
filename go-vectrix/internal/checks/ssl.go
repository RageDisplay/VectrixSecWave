package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

var weakCiphers = []string{
	"RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5",
	"ADH", "AECDH", "aNULL", "eNULL",
}

var weakTLSVersions = []string{"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

var mixedContentRe = regexp.MustCompile(`(?i)(?:src|href|action)\s*=\s*["']http://[^"']+["']`)

// RunSSL checks TLS/SSL configuration for an HTTPS target. Mirrors
// modules/checks/ssl_check.py run().
func RunSSL(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, store *findings.FindingStore) {
	if !strings.HasPrefix(baseURL, "https://") {
		f := findings.NewFinding(
			"Приложение не использует HTTPS",
			findings.Critical,
			"TLS/SSL",
			"CWE-319",
			baseURL,
			"Приложение доступно по HTTP без TLS. "+
				"Весь трафик, включая credentials и сессионные cookies, передаётся в открытом виде.",
			"1. Настройте TLS-сертификат и включите HTTPS.\n"+
				"2. Настройте редирект HTTP → HTTPS (301).\n"+
				"3. Включите HSTS для предотвращения SSL stripping.",
			fmt.Sprintf("curl -v '%s' 2>&1 | head -30", baseURL),
		)
		f.Evidence = fmt.Sprintf("URL: %s", baseURL)
		store.Add(f)
		return
	}

	logging.Println("[*] Checking TLS/SSL configuration...")

	host, port := splitHostPort(baseURL)

	checkHTTPRedirect(session, baseURL, store)
	checkSSLScan(host, port, baseURL, store)
	checkCertGo(host, port, baseURL, store)
	checkMixedContent(session, baseURL, store)
}

func splitHostPort(rawurl string) (host, port string) {
	rest := strings.TrimPrefix(rawurl, "https://")
	rest = strings.SplitN(rest, "/", 2)[0]
	if h, p, err := net.SplitHostPort(rest); err == nil {
		return h, p
	}
	return rest, "443"
}

func checkHTTPRedirect(session *httpsession.Session, baseURL string, store *findings.FindingStore) {
	httpURL := strings.Replace(baseURL, "https://", "http://", 1)
	resp, err := session.Request("GET", httpURL, httpsession.Options{AllowRedirects: false, Timeout: 8 * time.Second})
	if err != nil {
		return
	}

	switch resp.StatusCode {
	case 301, 302, 307, 308:
		location := resp.Header.Get("Location")
		if strings.HasPrefix(location, "http://") {
			f := findings.NewFinding(
				"HTTP редиректит на другой HTTP URL (не HTTPS)",
				findings.High,
				"TLS/SSL",
				"CWE-319",
				httpURL,
				fmt.Sprintf("Location: %s — редирект ведёт на HTTP.", location),
				"Убедитесь что редирект ведёт на https://.",
				fmt.Sprintf("curl -sk -I '%s'", httpURL),
			)
			f.Evidence = fmt.Sprintf("Location: %s", location)
			store.Add(f)
		}
	default:
		location := resp.Header.Get("Location")
		if location == "" {
			location = "нет"
		}
		f := findings.NewFinding(
			"HTTP не перенаправляет на HTTPS",
			findings.High,
			"TLS/SSL",
			"CWE-319",
			httpURL,
			fmt.Sprintf("Запрос к %s вернул HTTP %d без редиректа на HTTPS. "+
				"Пользователи, открывающие сайт по HTTP, не перенаправляются на защищённое соединение.", httpURL, resp.StatusCode),
			"Настройте 301-редирект с HTTP на HTTPS:\n"+
				"  Apache: RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n"+
				"  nginx:  return 301 https://$host$request_uri;",
			fmt.Sprintf("curl -sk -I '%s'", httpURL),
		)
		f.Evidence = fmt.Sprintf("HTTP %d, Location: %s", resp.StatusCode, location)
		store.Add(f)
	}
}

func checkSSLScan(host, port, baseURL string, store *findings.FindingStore) {
	if _, err := exec.LookPath("sslscan"); err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sslscan", "--no-colour", fmt.Sprintf("%s:%s", host, port))
	out, _ := cmd.CombinedOutput()
	output := string(out)
	if ctx.Err() == context.DeadlineExceeded {
		return
	}

	for _, version := range weakTLSVersions {
		pattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(version) + `\s+enabled`)
		if pattern.MatchString(output) {
			sev := findings.High
			if strings.Contains(version, "SSLv") {
				sev = findings.Critical
			}
			f := findings.NewFinding(
				fmt.Sprintf("Устаревший TLS/SSL протокол включён: %s", version),
				sev,
				"TLS/SSL",
				"CWE-326",
				baseURL,
				fmt.Sprintf("Сервер поддерживает %s, который считается небезопасным.\n"+
					"SSLv2/SSLv3: DROWN, POODLE атаки.\n"+
					"TLS 1.0/1.1: BEAST, POODLE-TLS, множество известных атак.", version),
				fmt.Sprintf("Отключите %s. Минимальная версия: TLS 1.2, рекомендуется TLS 1.3.\n"+
					"nginx: ssl_protocols TLSv1.2 TLSv1.3;\n"+
					"Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1", version),
				fmt.Sprintf("sslscan %s:%s", host, port),
			)
			f.Evidence = fmt.Sprintf("sslscan output: %s enabled", version)
			store.Add(f)
		}
	}

	var weakFound []string
	for _, cipher := range weakCiphers {
		pattern := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(cipher) + `\b`)
		if pattern.MatchString(output) {
			weakFound = append(weakFound, cipher)
		}
	}
	if len(weakFound) > 0 {
		f := findings.NewFinding(
			fmt.Sprintf("Слабые шифры TLS: %s", strings.Join(weakFound, ", ")),
			findings.High,
			"TLS/SSL",
			"CWE-326",
			baseURL,
			fmt.Sprintf("Сервер поддерживает небезопасные cipher suites: %s.\n"+
				"Слабые шифры могут быть использованы для расшифровки трафика.", strings.Join(weakFound, ", ")),
			"Используйте только современные cipher suites:\n"+
				"nginx: ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...'\n"+
				"Проверьте: https://ssl-config.mozilla.org/",
			fmt.Sprintf("sslscan %s:%s | grep -i 'accepted\\|cipher'", host, port),
		)
		f.Evidence = fmt.Sprintf("Найдены в sslscan: %v", weakFound)
		store.Add(f)
	}

	lowerOutput := strings.ToLower(output)
	if strings.Contains(lowerOutput, "self-signed") || strings.Contains(lowerOutput, "self signed") {
		f := findings.NewFinding(
			"Самоподписанный TLS-сертификат",
			findings.Medium,
			"TLS/SSL",
			"CWE-295",
			baseURL,
			"Сервер использует самоподписанный сертификат. "+
				"Браузеры показывают предупреждение, пользователи уязвимы к MITM.",
			"Используйте сертификат от доверенного CA (Let's Encrypt, корпоративный CA).",
			fmt.Sprintf("sslscan %s:%s | grep -i 'self'", host, port),
		)
		f.Evidence = "sslscan обнаружил self-signed certificate"
		store.Add(f)
	}
}

func checkCertGo(host, port, baseURL string, store *findings.FindingStore) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{ServerName: host})
	if err != nil {
		var certErr *tls.CertificateVerificationError
		var hostErr x509.HostnameError
		var unknownAuthErr x509.UnknownAuthorityError
		var certInvalidErr x509.CertificateInvalidError
		if errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &unknownAuthErr) || errors.As(err, &certInvalidErr) {
			f := findings.NewFinding(
				"Ошибка верификации TLS-сертификата",
				findings.High,
				"TLS/SSL",
				"CWE-295",
				baseURL,
				"Не удалось верифицировать TLS-сертификат сервера. "+
					"Возможные причины: самоподписанный, истёкший, несоответствие hostname или недоверенный CA.",
				"Установите валидный сертификат от доверенного CA.",
				fmt.Sprintf("curl -v 'https://%s:%s/' 2>&1 | grep -i 'ssl\\|cert\\|verify'", host, port),
			)
			f.Evidence = err.Error()
			store.Add(f)
		}
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return
	}
	cert := certs[0]
	daysLeft := time.Until(cert.NotAfter).Hours() / 24

	switch {
	case daysLeft < 0:
		f := findings.NewFinding(
			"TLS-сертификат просрочен",
			findings.Critical,
			"TLS/SSL",
			"CWE-298",
			baseURL,
			fmt.Sprintf("Сертификат истёк %d дней назад (%s).", -int(daysLeft), cert.NotAfter.Format(time.RFC1123)),
			"Немедленно обновите TLS-сертификат.",
			fmt.Sprintf("echo | openssl s_client -connect %s:%s 2>/dev/null | openssl x509 -noout -dates", host, port),
		)
		f.Evidence = fmt.Sprintf("notAfter: %s", cert.NotAfter.Format(time.RFC1123))
		store.Add(f)
	case daysLeft < 14:
		f := findings.NewFinding(
			fmt.Sprintf("TLS-сертификат истекает через %d дней", int(daysLeft)),
			findings.High,
			"TLS/SSL",
			"CWE-298",
			baseURL,
			fmt.Sprintf("Срок действия сертификата заканчивается: %s.", cert.NotAfter.Format(time.RFC1123)),
			"Обновите сертификат в ближайшее время.",
			fmt.Sprintf("echo | openssl s_client -connect %s:%s 2>/dev/null | openssl x509 -noout -dates", host, port),
		)
		f.Evidence = fmt.Sprintf("notAfter: %s", cert.NotAfter.Format(time.RFC1123))
		store.Add(f)
	}
}

func checkMixedContent(session *httpsession.Session, baseURL string, store *findings.FindingStore) {
	resp, err := session.Get(baseURL, nil)
	if err != nil {
		return
	}
	matches := mixedContentRe.FindAllString(resp.Body, -1)
	if len(matches) > 0 {
		shown := matches
		if len(shown) > 5 {
			shown = shown[:5]
		}
		f := findings.NewFinding(
			"Mixed Content — HTTP-ресурсы на HTTPS-странице",
			findings.Medium,
			"TLS/SSL",
			"CWE-311",
			baseURL,
			"HTTPS-страница загружает ресурсы по HTTP. "+
				"Браузеры блокируют активный mixed content. "+
				"Пассивный mixed content может быть перехвачен MITM-атакой.",
			"1. Замените все http:// ссылки на https://.\n"+
				"2. Используйте protocol-relative URLs (//example.com/resource).\n"+
				"3. Включите CSP upgrade-insecure-requests.",
			fmt.Sprintf("curl -sk '%s' | grep -oE 'src=\"http://[^\"]+\"' | head -10", baseURL),
		)
		f.Evidence = fmt.Sprintf("Найдено %d HTTP-ресурсов:\n%s", len(matches), strings.Join(shown, "\n"))
		store.Add(f)
	}
}
