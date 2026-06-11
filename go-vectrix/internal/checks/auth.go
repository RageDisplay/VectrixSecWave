package checks

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"net/url"
	"regexp"
	"strings"
	"time"

	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

// authCSRFTokenNames matches common CSRF token field names. Mirrors
// modules/checks/auth.py CSRF_TOKEN_NAMES.
var authCSRFTokenNames = regexp.MustCompile(`(?i)^(csrf|_csrf|csrftoken|csrf_token|csrfmiddlewaretoken|` +
	`authenticity_token|_token|anti_csrf|xsrf|_xsrf|` +
	`__RequestVerificationToken|x-csrf-token|x-xsrf-token)$`)

// authCSRFFieldInHTML matches a CSRF hidden-input field name in an HTML page.
var authCSRFFieldInHTML = regexp.MustCompile(`(?i)name=["'](?:csrf|_csrf|csrftoken|csrf_token|csrfmiddlewaretoken|` +
	`authenticity_token|__requestverificationtoken|x-csrf-token)["']`)

// authJWTWeakSecrets is a small dictionary of weak HS256/384/512 secrets.
// Mirrors modules/checks/auth.py JWT_WEAK_SECRETS.
var authJWTWeakSecrets = []string{
	"secret", "password", "123456", "test", "dev", "development",
	"changeme", "qwerty", "admin", "root", "letmein", "welcome",
	"your-256-bit-secret", "your-secret", "jwt-secret", "mysecret",
	"supersecret", "secretkey", "key", "private", "token",
}

// authBypassHeaders maps headers to values used in auth-bypass probing.
// Mirrors modules/checks/auth.py AUTH_BYPASS_HEADERS (insertion order matters).
var authBypassHeaders = []struct {
	header string
	value  string
}{
	{"X-Original-URL", "/admin"},
	{"X-Rewrite-URL", "/admin"},
	{"X-Custom-IP-Authorization", "127.0.0.1"},
	{"X-Forwarded-For", "127.0.0.1"},
	{"X-Remote-IP", "127.0.0.1"},
	{"X-Client-IP", "127.0.0.1"},
	{"X-Host", "localhost"},
	{"X-Forwarded-Host", "localhost"},
}

// authSensitiveURLPattern matches sensitive parameters passed in a URL query
// string. Mirrors modules/checks/auth.py SENSITIVE_URL_PATTERNS.
var authSensitiveURLPattern = regexp.MustCompile(`(?i)[?&](token|access_token|api_key|apikey|secret|password|passwd|` +
	`auth|authorization|session|sessionid|jwt|bearer|key)=([^&\s#]+)`)

// authPasswordInResponsePattern matches a "password" field with a non-empty
// string value in a JSON/HTML response body.
var authPasswordInResponsePattern = regexp.MustCompile(`(?i)"?password"?\s*:\s*"([^"]{1,100})"`)

// authKidSQLMetaChars matches SQL meta-characters that could indicate kid
// injection. Mirrors modules/checks/auth.py r"[\'\"\;\-\-]".
var authKidSQLMetaChars = regexp.MustCompile(`['";\-]`)

// RunAuth checks cookie security flags, JWT issues, sensitive data in URLs,
// auth-bypass headers, session fixation, password leakage in responses and
// missing CSRF tokens. Mirrors modules/checks/auth.py run().
func RunAuth(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, store *findings.FindingStore) {
	logging.Println("[*] Checking authentication/session security...")
	curlAuth := session.CurlAuthFlags(baseURL)

	authCheckCookies(session, baseURL, curlAuth, store)
	authCheckJWT(session, baseURL, curlAuth, store)
	authCheckSensitiveInURL(endpoints, store)
	authCheckAuthBypassHeaders(session, baseURL, curlAuth, store)
	authCheckSessionFixation(session, baseURL, store)
	authCheckPasswordInResponse(session, endpoints, curlAuth, store)
	authCheckCSRF(session, endpoints, curlAuth, store)
}

// ── Cookies ──────────────────────────────────────────────────────────────────

func authCheckCookies(session *httpsession.Session, baseURL, curlAuth string, store *findings.FindingStore) {
	resp, err := session.Get(baseURL, nil)
	if err != nil {
		return
	}

	setCookies := resp.Header["Set-Cookie"]

	seen := make(map[string]struct{})
	for _, sc := range setCookies {
		if sc == "" {
			continue
		}
		cname := strings.TrimSpace(strings.SplitN(sc, "=", 2)[0])
		if _, ok := seen[cname]; ok {
			continue
		}
		seen[cname] = struct{}{}

		scLower := strings.ToLower(sc)
		var flags []string
		if !strings.Contains(scLower, "secure") && strings.HasPrefix(baseURL, "https") {
			flags = append(flags, "отсутствует флаг Secure")
		}
		if !strings.Contains(scLower, "httponly") {
			flags = append(flags, "отсутствует флаг HttpOnly")
		}
		if !strings.Contains(scLower, "samesite") {
			flags = append(flags, "отсутствует атрибут SameSite")
		} else if strings.Contains(scLower, "samesite=none") && !strings.Contains(scLower, "secure") {
			flags = append(flags, "SameSite=None без Secure — небезопасная конфигурация")
		}

		if len(flags) > 0 {
			f := findings.NewFinding(
				fmt.Sprintf("Небезопасные флаги куки '%s'", cname),
				findings.Medium,
				"Session Management",
				"CWE-614",
				baseURL,
				fmt.Sprintf("Cookie '%s' имеет небезопасную конфигурацию:\n• %s", cname, strings.Join(flags, "\n• ")),
				fmt.Sprintf("Установите безопасные флаги:\nSet-Cookie: %s=<value>; Secure; HttpOnly; SameSite=Strict; Path=/", cname),
				fmt.Sprintf("curl -sk %s -I '%s' | grep -i set-cookie", curlAuth, baseURL),
			)
			f.Evidence = fmt.Sprintf("Set-Cookie: %s", truncate(sc, 300))
			store.Add(f)
		}
	}
}

// ── JWT ──────────────────────────────────────────────────────────────────────

func authIsJWT(s string) bool {
	return len(strings.Split(s, ".")) == 3
}

func authCheckJWT(session *httpsession.Session, baseURL, curlAuth string, store *findings.FindingStore) {
	type tokenSource struct {
		source string
		token  string
	}
	var allTokens []tokenSource

	// From Authorization header
	auth := session.AuthorizationHeader()
	if len(auth) >= 7 && strings.EqualFold(auth[:7], "bearer ") {
		token := strings.TrimSpace(auth[7:])
		if authIsJWT(token) {
			allTokens = append(allTokens, tokenSource{"Authorization header", token})
		}
	}

	// From cookies
	if u, err := url.Parse(baseURL); err == nil {
		for _, c := range session.CookiesForURL(u) {
			if c.Value != "" && authIsJWT(c.Value) {
				allTokens = append(allTokens, tokenSource{fmt.Sprintf("Cookie: %s", c.Name), c.Value})
			}
		}
	}

	for _, ts := range allTokens {
		authAnalyzeJWT(ts.token, ts.source, baseURL, curlAuth, session, store)
	}
}

// authB64URLDecode decodes a base64url string, adding padding as necessary.
func authB64URLDecode(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

// authB64URLEncode encodes bytes as unpadded base64url.
func authB64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func authAnalyzeJWT(token, source, baseURL, curlAuth string, session *httpsession.Session, store *findings.FindingStore) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return
	}

	headerRaw, err1 := authB64URLDecode(parts[0])
	payloadRaw, err2 := authB64URLDecode(parts[1])
	if err1 != nil || err2 != nil {
		return
	}

	var header map[string]any
	var payload map[string]any
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return
	}
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return
	}

	alg := ""
	if a, ok := header["alg"].(string); ok {
		alg = strings.ToUpper(a)
	}

	// 1. alg: none attack
	if alg != "NONE" && alg != "" {
		noneToken := authForgeJWTNone(header, parts[1])
		f := findings.NewFinding(
			"JWT: уязвимость 'alg: none' — проверить подстановку токена без подписи",
			findings.High,
			"Authentication",
			"CWE-347",
			baseURL,
			fmt.Sprintf("JWT из '%s' использует алгоритм %s. "+
				"Некоторые библиотеки принимают alg=none (без подписи). "+
				"Это позволяет подделать любой токен.", source, alg),
			"1. Явно валидируйте алгоритм на стороне сервера (whitelist).\n"+
				"2. Никогда не принимайте alg=none в продакшне.\n"+
				"3. Используйте актуальные JWT-библиотеки с патчами CVE-2015-9235.",
			fmt.Sprintf("# Токен с alg=none (без подписи):\n%s\n\n"+
				"# Проверка:\n"+
				"curl -sk -H 'Authorization: Bearer %s' '%s/api/me'", noneToken, noneToken, baseURL),
		)
		f.Evidence = fmt.Sprintf("Header: %s\nPayload: %s", authMapRepr(header), authMapRepr(payload))
		store.Add(f)
	}

	// 2. Слабый секрет (HS256/384/512)
	if alg == "HS256" || alg == "HS384" || alg == "HS512" {
		foundSecret := authBruteForceHS(parts, alg)
		if foundSecret != "" {
			f := findings.NewFinding(
				fmt.Sprintf("JWT: слабый секрет HS256 — '%s'", foundSecret),
				findings.Critical,
				"Authentication",
				"CWE-798",
				baseURL,
				fmt.Sprintf("Секрет для подписи JWT (%s) является словарным словом '%s'. "+
					"Атакующий может подписывать произвольные токены и выдать себя за любого пользователя.", alg, foundSecret),
				"1. Используйте криптографически стойкий случайный секрет (минимум 256 бит).\n"+
					"2. Ротируйте секрет при подозрении на компрометацию.\n"+
					"3. Рассмотрите переход на RS256 (асимметричная криптография).",
				fmt.Sprintf("# Брутфорс через hashcat:\n"+
					"hashcat -a 0 -m 16500 '%s' /usr/share/wordlists/rockyou.txt\n\n"+
					"# Или jwt_tool:\n"+
					"jwt_tool '%s' -C -d /usr/share/wordlists/rockyou.txt", token, token),
			)
			f.Evidence = fmt.Sprintf("Секрет: '%s'\nАлгоритм: %s\nPayload: %s", foundSecret, alg, authMapRepr(payload))
			store.Add(f)
		}
	}

	// 3. Информационные поля — проверяем наличие чувствительных данных
	sensitiveKeys := []string{"password", "passwd", "secret", "ssn", "credit", "card", "cvv"}
	var leaks []string
	for k := range payload {
		kl := strings.ToLower(k)
		for _, s := range sensitiveKeys {
			if strings.Contains(kl, s) {
				leaks = append(leaks, k)
				break
			}
		}
	}
	if len(leaks) > 0 {
		f := findings.NewFinding(
			"JWT: чувствительные данные в payload",
			findings.Medium,
			"Authentication",
			"CWE-312",
			baseURL,
			fmt.Sprintf("JWT payload содержит потенциально чувствительные поля: %s.\n"+
				"JWT payload доступен любому, кто получил токен (base64, не зашифрован).", authListRepr(leaks)),
			"1. Не храните чувствительные данные в JWT payload.\n"+
				"2. Для хранения чувствительных данных используйте JWE (зашифрованный JWT).",
			fmt.Sprintf("# Декодировать payload:\necho '%s' | base64 -d 2>/dev/null | python3 -m json.tool", parts[1]),
		)
		f.Evidence = fmt.Sprintf("Payload: %s", authMapRepr(payload))
		store.Add(f)
	}

	// 3b. kid injection
	authCheckJWTKidInjection(token, header, source, baseURL, store)

	// 3c. Key confusion (RS256/ES256 -> HS256)
	if session != nil {
		authCheckJWTKeyConfusion(header, payload, source, baseURL, curlAuth, session, store)
	}

	// 4. Проверка exp
	exp, hasExp := payload["exp"]
	if !hasExp || exp == nil || authIsZeroNumber(exp) {
		f := findings.NewFinding(
			"JWT: отсутствует срок действия (exp)",
			findings.Medium,
			"Authentication",
			"CWE-613",
			baseURL,
			"JWT не содержит claim 'exp'. Токен действует бессрочно — "+
				"скомпрометированный токен не имеет срока истечения.",
			"1. Добавьте claim 'exp' — рекомендуемое время жизни access token: 15-60 минут.\n"+
				"2. Реализуйте механизм отзыва токенов (refresh token + blacklist).",
			fmt.Sprintf("echo '%s' | base64 -d 2>/dev/null | python3 -m json.tool", parts[1]),
		)
		f.Evidence = fmt.Sprintf("Payload: %s", authMapRepr(payload))
		store.Add(f)
	} else if expNum, ok := authToFloat(exp); ok {
		if expNum > float64(time.Now().Unix())+86400*30 {
			f := findings.NewFinding(
				"JWT: срок действия слишком длинный (>30 дней)",
				findings.Low,
				"Authentication",
				"CWE-613",
				baseURL,
				fmt.Sprintf("JWT expires: %v. Срок действия превышает 30 дней.", authNumRepr(exp)),
				"Сократите время жизни access token до 15-60 минут.",
				fmt.Sprintf("echo '%s' | base64 -d 2>/dev/null", parts[1]),
			)
			f.Evidence = fmt.Sprintf("exp: %v (%s UTC)", authNumRepr(exp), time.Unix(int64(expNum), 0).UTC().Format("2006-01-02 15:04:05"))
			store.Add(f)
		}
	}
}

// authIsZeroNumber returns true only for the case where exp is present but
// effectively falsy (e.g. 0), mirroring Python's `if not exp`.
func authIsZeroNumber(v any) bool {
	f, ok := authToFloat(v)
	if !ok {
		return false
	}
	return f == 0
}

func authToFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

// authNumRepr formats a numeric JSON value without an unnecessary ".0" suffix
// for whole numbers, similar to how Python prints ints vs floats.
func authNumRepr(v any) string {
	if f, ok := authToFloat(v); ok {
		if f == float64(int64(f)) {
			return fmt.Sprintf("%d", int64(f))
		}
		return fmt.Sprintf("%g", f)
	}
	return fmt.Sprintf("%v", v)
}

// authMapRepr renders a decoded JWT header/payload map in a Python-dict-like
// form for evidence strings (e.g. {'alg': 'HS256', 'typ': 'JWT'}).
func authMapRepr(m map[string]any) string {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Sprintf("%v", m)
	}
	return string(b)
}

func authListRepr(items []string) string {
	b, err := json.Marshal(items)
	if err != nil {
		return fmt.Sprintf("%v", items)
	}
	return string(b)
}

// authBruteForceHS tries each weak secret in JWT_WEAK_SECRETS against the
// token's HMAC signature for the given algorithm, returning the matching
// secret or "".
func authBruteForceHS(parts []string, alg string) string {
	sigInput := []byte(parts[0] + "." + parts[1])
	sigBytes, err := authB64URLDecode(parts[2])
	if err != nil {
		return ""
	}

	var hashFn func() hash.Hash
	switch alg {
	case "HS384":
		hashFn = sha512.New384
	case "HS512":
		hashFn = sha512.New
	default:
		hashFn = sha256.New
	}

	for _, secret := range authJWTWeakSecrets {
		mac := hmac.New(hashFn, []byte(secret))
		mac.Write(sigInput)
		expected := mac.Sum(nil)
		if hmac.Equal(expected, sigBytes) {
			return secret
		}
	}
	return ""
}

// authForgeJWTNone builds an "alg: none" forged token: header with alg
// replaced by "none", original payload, and an empty signature segment.
func authForgeJWTNone(header map[string]any, origPayloadB64 string) string {
	h := make(map[string]any, len(header))
	for k, v := range header {
		h[k] = v
	}
	h["alg"] = "none"

	// Mirror Python's json.dumps(h, separators=(",", ":")) — compact, but key
	// ordering may differ from the original since Go maps are unordered and
	// Python preserves insertion order. This does not affect the validity of
	// the forged token.
	headerJSON, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	headerB64 := authB64URLEncode(headerJSON)
	return fmt.Sprintf("%s.%s.", headerB64, origPayloadB64)
}

// ── JWT key confusion + kid injection ──────────────────────────────────────

var authJWKSCandidatePaths = []string{
	"/.well-known/jwks.json",
	"/.well-known/openid-configuration",
	"/oauth/jwks",
	"/api/auth/jwks",
	"/.well-known/keys",
}

// authCheckJWTKeyConfusion implements the RS256/ES256 -> HS256 key-confusion
// attack surface check. Mirrors modules/checks/auth.py _check_jwt_key_confusion.
func authCheckJWTKeyConfusion(header, payload map[string]any, source, baseURL, curlAuth string, session *httpsession.Session, store *findings.FindingStore) {
	alg := ""
	if a, ok := header["alg"].(string); ok {
		alg = strings.ToUpper(a)
	}
	switch alg {
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
	default:
		return
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return
	}
	origin := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

	var publicKeyPEM string
	for _, p := range authJWKSCandidatePaths {
		candURL := origin + p
		r, err := session.Get(candURL, nil)
		if err != nil {
			continue
		}
		if r.StatusCode == 200 && (strings.Contains(r.Body, "keys") || strings.Contains(r.Body, "BEGIN PUBLIC KEY")) {
			publicKeyPEM = truncate(r.Body, 2000)
			break
		}
	}

	if publicKeyPEM == "" {
		// Even without the public key, report the attack surface
		f := findings.NewFinding(
			fmt.Sprintf("JWT: алгоритм %s — потенциальная уязвимость Key Confusion (RS→HS)", alg),
			findings.High,
			"Authentication",
			"CWE-347",
			baseURL,
			fmt.Sprintf("JWT использует асимметричный алгоритм %s (%s). "+
				"Если сервер не привязывает алгоритм при валидации, атакующий "+
				"может подменить alg на HS256 и подписать токен публичным ключом сервера "+
				"как HMAC-секретом.\n\n"+
				"Атака:\n"+
				"1. Получить публичный ключ (JWKS, /api/publickey, утечки)\n"+
				"2. Изменить alg: HS256 в header\n"+
				"3. Подписать HMAC-SHA256 с публичным ключом как секретом\n"+
				"4. Сервер принимает токен если lib не проверяет alg", alg, source),
			"1. Явно передавайте ожидаемый алгоритм при верификации:\n"+
				"   jwt.verify(token, publicKey, { algorithms: ['RS256'] })\n"+
				"2. Никогда не используйте algorithms=['HS256','RS256'] одновременно.\n"+
				"3. Обновите JWT-библиотеку (CVE-2015-9235, CVE-2016-10555).",
			fmt.Sprintf("# Проверить JWKS:\n"+
				"curl -sk %s '%s/.well-known/jwks.json'\n\n"+
				"# Инструмент для атаки:\n"+
				"python3 -c \"\n"+
				"import jwt, json, base64\n"+
				"# Получить pub key и подписать с alg=HS256\n"+
				"forged = jwt.encode(%s, pub_key_bytes, algorithm='HS256')\n\"",
				curlAuth, origin, authMapRepr(payload)),
		)
		f.Evidence = fmt.Sprintf("Header: %s\nPayload: %s\nJWKS endpoint: не найден, ручная проверка требуется",
			authMapRepr(header), authMapRepr(payload))
		store.Add(f)
		return
	}

	// We have a JWKS/key response — report with concrete PoC
	f := findings.NewFinding(
		fmt.Sprintf("JWT: Key Confusion %s→HS256 — публичный ключ доступен", alg),
		findings.Critical,
		"Authentication",
		"CWE-347",
		baseURL,
		fmt.Sprintf("JWT использует %s (%s), и публичный ключ доступен по well-known URL.\n\n"+
			"Атакующий может подписать произвольный токен с alg=HS256, используя "+
			"публичный ключ как HMAC-секрет. Если сервер не зафиксировал алгоритм — "+
			"токен будет принят, что позволяет выдать себя за любого пользователя.", alg, source),
		"1. jwt.verify(token, publicKey, { algorithms: ['RS256'] }) — фиксируйте алгоритм.\n"+
			"2. Используйте раздельные конфиги для RS256 и HS256 путей.\n"+
			"3. Обновите JWT-библиотеки; проверьте CVE-2022-21449 (ECDSA).",
		fmt.Sprintf("# pip install PyJWT cryptography\n"+
			"python3 -c \"\n"+
			"import jwt\n"+
			"# Извлечь публичный ключ из JWKS и конвертировать в PEM\n"+
			"forged_payload = %s\n"+
			"forged_payload['role'] = 'admin'\n"+
			"token = jwt.encode(forged_payload, pub_key_pem, algorithm='HS256')\n"+
			"# Отправить token в заголовке Authorization: Bearer <token>\n\"",
			authMapRepr(payload)),
	)
	f.Evidence = fmt.Sprintf("Алгоритм: %s\nПубличный ключ доступен:\n%s...", alg, truncate(publicKeyPEM, 300))
	store.Add(f)
}

// authCheckJWTKidInjection checks the JWT header's "kid" field for SQL
// injection / path traversal payload acceptance. Mirrors
// modules/checks/auth.py _check_jwt_kid_injection.
func authCheckJWTKidInjection(token string, header map[string]any, source, baseURL string, store *findings.FindingStore) {
	kidVal, ok := header["kid"]
	if !ok {
		return
	}
	kid, ok := kidVal.(string)
	if !ok || kid == "" {
		return
	}

	type issue struct {
		titleSuffix string
		cwe         string
		detail      string
	}
	var issues []issue

	// SQL injection in kid
	if authKidSQLMetaChars.MatchString(kid) {
		issues = append(issues, issue{
			titleSuffix: "kid содержит SQL-мета-символы — возможна SQL-инъекция",
			cwe:         "CWE-89",
			detail: "Некоторые реализации делают SQL-запрос: " +
				"SELECT key FROM keys WHERE id='<kid>'\n" +
				"Payload: ' UNION SELECT 'attacker_secret'-- позволяет задать произвольный секрет",
		})
	}

	// Path traversal in kid
	if strings.Contains(kid, "..") || strings.HasPrefix(kid, "/") {
		issues = append(issues, issue{
			titleSuffix: "kid содержит path traversal — возможно чтение произвольного файла как ключа",
			cwe:         "CWE-22",
			detail: "Если kid используется как путь к файлу с ключом, " +
				"атакующий может указать /dev/null или известный файл " +
				"и подписать токен пустым/предсказуемым ключом.",
		})
	}

	headerParts := strings.SplitN(token, ".", 2)
	headerB64 := ""
	if len(headerParts) > 0 {
		headerB64 = headerParts[0]
	}

	for _, iss := range issues {
		f := findings.NewFinding(
			fmt.Sprintf("JWT kid injection — %s", iss.titleSuffix),
			findings.High,
			"Authentication",
			iss.cwe,
			baseURL,
			fmt.Sprintf("Параметр kid в JWT header: '%s'\nИсточник: %s\n\n%s", kid, source, iss.detail),
			"1. Валидируйте kid по строгому whitelist (UUID, числовой ID).\n"+
				"2. Никогда не используйте kid напрямую в SQL-запросах или как путь к файлу.\n"+
				"3. Храните ключи в key management service (AWS KMS, HashiCorp Vault).",
			fmt.Sprintf("# Декодировать header:\necho '%s' | base64 -d 2>/dev/null\n"+
				"# PoC payload с injected kid:\n"+
				"# kid: \\' UNION SELECT 'mysecret'--", headerB64),
		)
		f.Evidence = fmt.Sprintf("JWT header: %s", authMapRepr(header))
		store.Add(f)
	}
}

// ── Sensitive data in URL ───────────────────────────────────────────────────

func authCheckSensitiveInURL(endpoints []crawler.Endpoint, store *findings.FindingStore) {
	for _, ep := range endpoints {
		m := authSensitiveURLPattern.FindStringSubmatch(ep.URL)
		if m == nil {
			continue
		}
		param := m[1]
		value := m[2]
		if len(value) > 20 {
			value = value[:20]
		}
		value += "..."

		f := findings.NewFinding(
			fmt.Sprintf("Чувствительный параметр '%s' передаётся в URL", param),
			findings.High,
			"Authentication",
			"CWE-598",
			ep.URL,
			fmt.Sprintf("Параметр '%s' (токен/ключ/пароль) передаётся в query string URL. "+
				"Он попадает в логи сервера, историю браузера, Referer-заголовки и аналитику.", param),
			"1. Передавайте credentials только через POST body или HTTP headers.\n"+
				"2. Используйте Authorization: Bearer вместо ?token= в URL.\n"+
				"3. Установите Referrer-Policy: no-referrer.",
			fmt.Sprintf("# Параметр виден в URL:\n%s", ep.URL),
		)
		f.Parameter = param
		f.Evidence = fmt.Sprintf("URL: %s", truncate(ep.URL, 200))
		store.Add(f)
	}
}

// ── Auth bypass headers ──────────────────────────────────────────────────────

func authCheckAuthBypassHeaders(session *httpsession.Session, baseURL, curlAuth string, store *findings.FindingStore) {
	adminURL := baseURL + "/admin"

	normalResp, err := session.Request("GET", adminURL, httpsession.Options{AllowRedirects: false})
	if err != nil {
		return
	}
	normalCode := normalResp.StatusCode
	normalLen := len(normalResp.Body)

	if normalCode == 200 {
		return // Already accessible
	}

	for _, h := range authBypassHeaders {
		header, value := h.header, h.value
		bypassResp, err := session.Request("GET", adminURL, httpsession.Options{
			Headers:        map[string]string{header: value},
			AllowRedirects: false,
		})
		if err != nil {
			continue
		}

		if bypassResp.StatusCode == 200 && len(bypassResp.Body) > 100 {
			if absInt(len(bypassResp.Body)-normalLen) > 200 {
				probeHeader, probeValue := header, value
				probeFn := func() (*httpsession.Response, error) {
					return session.Request("GET", adminURL, httpsession.Options{
						Headers:        map[string]string{probeHeader: probeValue},
						AllowRedirects: false,
					})
				}

				f := findings.NewFinding(
					fmt.Sprintf("Auth Bypass через заголовок '%s'", header),
					findings.High,
					"Authentication",
					"CWE-287",
					adminURL,
					fmt.Sprintf("Установка заголовка '%s: %s' изменяет ответ /admin "+
						"с %d на 200 и заметно меняет размер ответа. "+
						"Изменение размера само по себе не доказывает обход авторизации "+
						"(могла открыться, например, иная страница ошибки) — нужна проверка "+
						"содержимого на admin-специфичные признаки.", header, value, normalCode),
					"1. Не доверяйте заголовкам X-Forwarded-For, X-Real-IP для авторизации.\n"+
						"2. Авторизацию выполняйте на уровне приложения, не реверс-прокси.\n"+
						"3. Используйте middleware для проверки прав доступа.",
					fmt.Sprintf("curl -sk %s -H '%s: %s' '%s'", curlAuth, header, value, adminURL),
				)
				f.Evidence = fmt.Sprintf("Без заголовка: HTTP %d (%d байт), с заголовком: HTTP 200 (%d байт)",
					normalCode, normalLen, len(bypassResp.Body))

				store.AddCandidate(&findings.Candidate{
					Finding: f,
					Kind:    "auth_bypass",
					Context: map[string]any{
						"probe":         probeFn,
						"baseline_resp": normalResp,
						"header":        header,
						"value":         value,
					},
				})
			}
		}
	}
}

// ── Session fixation ─────────────────────────────────────────────────────────

func authCheckSessionFixation(session *httpsession.Session, baseURL string, store *findings.FindingStore) {
	loginGetURL := baseURL + "/login"

	anon := httpsession.New()
	anon.Timeout = session.Timeout
	if _, err := anon.Get(loginGetURL, nil); err != nil {
		return
	}

	loginU, err := url.Parse(loginGetURL)
	if err != nil {
		return
	}

	cookiesBefore := make(map[string]string)
	for _, c := range anon.CookiesForURL(loginU) {
		cookiesBefore[c.Name] = c.Value
	}
	if len(cookiesBefore) == 0 {
		return
	}

	loginPaths := []string{"/login", "/api/login", "/auth/login", "/signin"}
	for _, path := range loginPaths {
		loginPostURL := baseURL + path
		form := url.Values{"username": {"test"}, "password": {"test"}}
		lr, err := anon.PostForm(loginPostURL, form, nil)
		if err != nil {
			continue
		}
		if lr.StatusCode != 200 && lr.StatusCode != 302 {
			continue
		}

		postU, err := url.Parse(loginPostURL)
		if err != nil {
			continue
		}
		cookiesAfter := make(map[string]string)
		for _, c := range anon.CookiesForURL(postU) {
			cookiesAfter[c.Name] = c.Value
		}

		for name, valBefore := range cookiesBefore {
			if valAfter, ok := cookiesAfter[name]; ok && valAfter == valBefore {
				f := findings.NewFinding(
					fmt.Sprintf("Потенциальная Session Fixation — cookie '%s'", name),
					findings.Medium,
					"Session Management",
					"CWE-384",
					loginPostURL,
					fmt.Sprintf("Cookie '%s' не меняет значение после попытки входа. "+
						"Если сессионный ID не перегенерируется при аутентификации — "+
						"возможна атака Session Fixation.", name),
					"1. Перегенерируйте session ID сразу после успешной аутентификации.\n"+
						"2. session_regenerate_id(true) (PHP) / request.session.cycle_key() (Django).",
					fmt.Sprintf("# 1. Получить cookie до логина:\n"+
						"curl -sk -c /tmp/sess.txt '%s'\n"+
						"# 2. Зафиксировать сессию и убедиться что ID не изменился после auth", loginPostURL),
				)
				f.Evidence = fmt.Sprintf("Cookie до: %s...\nCookie после: %s...",
					truncate(valBefore, 30), truncate(cookiesAfter[name], 30))
				store.Add(f)
			}
		}
		break
	}
}

// ── Password in response ─────────────────────────────────────────────────────

func authCheckPasswordInResponse(session *httpsession.Session, endpoints []crawler.Endpoint, curlAuth string, store *findings.FindingStore) {
	for _, ep := range endpoints {
		if ep.Method != "GET" && ep.Method != "HEAD" {
			continue
		}
		resp, err := session.Get(ep.URL, nil)
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			continue
		}
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if !strings.Contains(ct, "json") && !strings.Contains(ct, "html") {
			continue
		}
		m := authPasswordInResponsePattern.FindStringSubmatch(resp.Body)
		if m == nil {
			continue
		}

		f := findings.NewFinding(
			"Пароль в открытом виде в HTTP-ответе",
			findings.Critical,
			"Information Disclosure",
			"CWE-312",
			ep.URL,
			fmt.Sprintf("Ответ %s содержит поле 'password' с непустым значением.", ep.URL),
			"1. Никогда не возвращайте поле password в API-ответах.\n"+
				"2. Хэшируйте пароли с bcrypt/argon2 и не храните plain-text.",
			fmt.Sprintf("curl -sk %s '%s' | python3 -m json.tool | grep -i password", curlAuth, ep.URL),
		)
		f.Evidence = fmt.Sprintf("password: %s...", truncate(m[1], 20))
		store.Add(f)
	}
}

// ── CSRF ──────────────────────────────────────────────────────────────────────

func authCheckCSRF(session *httpsession.Session, endpoints []crawler.Endpoint, curlAuth string, store *findings.FindingStore) {
	reportedURLs := make(map[string]struct{})

	for _, ep := range endpoints {
		switch ep.Method {
		case "POST", "PUT", "PATCH", "DELETE":
		default:
			continue
		}
		if ep.Source != "form" {
			continue
		}
		if _, ok := reportedURLs[ep.URL]; ok {
			continue
		}

		hasCSRF := false
		for k := range ep.BodyParams {
			if authCSRFTokenNames.MatchString(k) {
				hasCSRF = true
				break
			}
		}
		if hasCSRF {
			continue
		}

		// Double-check: fetch the form page and look for CSRF token in hidden inputs
		pageResp, err := session.Get(ep.URL, nil)
		if err == nil {
			pageText := strings.ToLower(pageResp.Body)
			if authCSRFFieldInHTML.MatchString(pageText) {
				continue // Found in HTML — server does have CSRF protection
			}
		}

		reportedURLs[ep.URL] = struct{}{}

		fieldList := make([]string, 0, len(ep.BodyParams))
		for k := range ep.BodyParams {
			fieldList = append(fieldList, k)
		}
		sampleForm := url.Values{}
		for _, k := range fieldList {
			sampleForm.Set(k, "test")
		}
		sampleData := sampleForm.Encode()

		var hiddenInputs strings.Builder
		hiddenCount := len(fieldList)
		if hiddenCount > 3 {
			hiddenCount = 3
		}
		for _, k := range fieldList[:hiddenCount] {
			hiddenInputs.WriteString(fmt.Sprintf("  <input type='hidden' name='%s' value='attacker'>\n", k))
		}

		f := findings.NewFinding(
			fmt.Sprintf("Отсутствует CSRF-токен в форме — %s", ep.URL),
			findings.High,
			"CSRF",
			"CWE-352",
			ep.URL,
			fmt.Sprintf("Форма (%s %s) не содержит CSRF-токена ни в одном поле.\n"+
				"Атакующий может создать вредоносную страницу, которая от имени "+
				"аутентифицированного пользователя выполнит нежелательное действие.\n"+
				"Обнаруженные поля: %s", ep.Method, ep.URL, authListRepr(fieldList)),
			"1. Добавьте синхронизированный CSRF-токен во все формы.\n"+
				"2. Проверяйте Origin/Referer заголовки на стороне сервера.\n"+
				"3. Установите SameSite=Strict или SameSite=Lax на сессионных куки.\n"+
				"4. Для SPA используйте заголовок X-CSRF-Token + Double Submit Cookie.",
			fmt.Sprintf("# Отправка запроса без CSRF-токена (должен быть отклонён):\n"+
				"curl -sk %s -X %s -d '%s' '%s'\n\n"+
				"# PoC HTML (разместить на стороннем домене):\n"+
				"<form method='%s' action='%s'>\n%s  <input type='submit' value='Click me'>\n</form>",
				curlAuth, ep.Method, sampleData, ep.URL, strings.ToLower(ep.Method), ep.URL, hiddenInputs.String()),
		)
		f.Method = ep.Method
		f.Evidence = fmt.Sprintf("Поля формы: %s\nCSRF-токен не найден", authListRepr(fieldList))
		store.Add(f)
	}
}
