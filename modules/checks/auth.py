from __future__ import annotations
import base64
import json
import hashlib
import hmac
import re
import time
from urllib.parse import urlparse, urlencode
import requests

from ..adaptive import Candidate
from ..findings import Finding, Severity
from ..session import session_to_curl_flags


JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "test", "dev", "development",
    "changeme", "qwerty", "admin", "root", "letmein", "welcome",
    "your-256-bit-secret", "your-secret", "jwt-secret", "mysecret",
    "supersecret", "secretkey", "key", "private", "token",
]

AUTH_BYPASS_HEADERS = {
    "X-Original-URL": "/admin",
    "X-Rewrite-URL": "/admin",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "X-Forwarded-For": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1",
    "X-Client-IP": "127.0.0.1",
    "X-Host": "localhost",
    "X-Forwarded-Host": "localhost",
}

SENSITIVE_URL_PATTERNS = re.compile(
    r'[?&](token|access_token|api_key|apikey|secret|password|passwd|'
    r'auth|authorization|session|sessionid|jwt|bearer|key)=([^&\s#]+)',
    re.IGNORECASE,
)


def run(session: requests.Session, base_url: str, endpoints: list, store) -> None:
    print("[*] Checking authentication & session issues...")
    curl_auth = session_to_curl_flags(session)
    timeout = getattr(session, 'timeout', 15)

    _check_cookies(session, base_url, curl_auth, store)
    _check_jwt(session, base_url, curl_auth, store)
    _check_sensitive_in_url(endpoints, store)
    _check_auth_bypass_headers(session, base_url, curl_auth, timeout, store)
    _check_session_fixation(session, base_url, curl_auth, timeout, store)
    _check_password_in_response(session, endpoints, curl_auth, timeout, store)


def _check_cookies(session, base_url, curl_auth, store):
    issues = []
    for cookie in session.cookies:
        name = cookie.name
        secure = getattr(cookie, 'secure', False)
        http_only = getattr(cookie, 'has_nonstandard_attr', lambda x: False)('httponly')

        # Check via raw Set-Cookie
        try:
            resp = requests.get(base_url, timeout=8, verify=False)
            for sc in resp.headers.get_all('set-cookie') if hasattr(resp.headers, 'get_all') else [resp.headers.get('set-cookie', '')]:
                if not sc:
                    continue
                sc_lower = sc.lower()
                cname = sc.split('=')[0].strip()

                flags = []
                if 'secure' not in sc_lower and base_url.startswith('https'):
                    flags.append("отсутствует флаг Secure")
                if 'httponly' not in sc_lower:
                    flags.append("отсутствует флаг HttpOnly")
                if 'samesite' not in sc_lower:
                    flags.append("отсутствует атрибут SameSite")
                elif 'samesite=none' in sc_lower and 'secure' not in sc_lower:
                    flags.append("SameSite=None без Secure — небезопасная конфигурация")

                if flags:
                    issues.append((cname, flags, sc))
        except Exception:
            break

    for cname, flags, raw in issues:
        store.add(Finding(
            title=f"Небезопасные флаги куки '{cname}'",
            severity=Severity.MEDIUM,
            category="Session Management",
            cwe="CWE-614",
            description=(
                f"Cookie '{cname}' имеет небезопасную конфигурацию:\n• "
                + "\n• ".join(flags)
            ),
            url=base_url,
            evidence=f"Set-Cookie: {raw[:300]}",
            remediation=(
                f"Установите безопасные флаги:\n"
                f"Set-Cookie: {cname}=<value>; Secure; HttpOnly; SameSite=Strict; Path=/"
            ),
            reproduction=f"curl -sk {curl_auth} -I '{base_url}' | grep -i set-cookie",
        ))


def _check_jwt(session, base_url, curl_auth, store):
    all_tokens = []

    # From Authorization header
    auth = session.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        if _is_jwt(token):
            all_tokens.append(("Authorization header", token))

    # From cookies
    for cookie in session.cookies:
        val = cookie.value
        if val and _is_jwt(val):
            all_tokens.append((f"Cookie: {cookie.name}", val))

    for source, token in all_tokens:
        _analyze_jwt(token, source, base_url, curl_auth, store)


def _is_jwt(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 3


def _analyze_jwt(token: str, source: str, base_url: str, curl_auth: str, store) -> None:
    parts = token.split(".")
    if len(parts) != 3:
        return

    try:
        header_raw = parts[0]
        payload_raw = parts[1]

        # Pad base64
        def b64decode(s):
            s += "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(s)

        header = json.loads(b64decode(header_raw))
        payload = json.loads(b64decode(payload_raw))
    except Exception:
        return

    alg = header.get("alg", "").upper()

    # 1. alg: none attack
    if alg not in ("NONE", ""):
        none_token = _forge_jwt_none(header, payload, parts[0], parts[1])
        store.add(Finding(
            title=f"JWT: уязвимость 'alg: none' — проверить подстановку токена без подписи",
            severity=Severity.HIGH,
            category="Authentication",
            cwe="CWE-347",
            description=(
                f"JWT из '{source}' использует алгоритм {alg}. "
                "Некоторые библиотеки принимают alg=none (без подписи). "
                "Это позволяет подделать любой токен."
            ),
            url=base_url,
            evidence=f"Header: {header}\nPayload: {payload}",
            remediation=(
                "1. Явно валидируйте алгоритм на стороне сервера (whitelist).\n"
                "2. Никогда не принимайте alg=none в продакшне.\n"
                "3. Используйте актуальные JWT-библиотеки с патчами CVE-2015-9235."
            ),
            reproduction=(
                f"# Токен с alg=none (без подписи):\n"
                f"{none_token}\n\n"
                f"# Проверка:\n"
                f"curl -sk -H 'Authorization: Bearer {none_token}' '{base_url}/api/me'"
            ),
        ))

    # 2. Слабый секрет (HS256)
    if alg in ("HS256", "HS384", "HS512"):
        found_secret = None
        sig_input = f"{parts[0]}.{parts[1]}".encode()
        sig_bytes = _b64url_decode(parts[2])

        hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hfunc = hash_map.get(alg, hashlib.sha256)

        for secret in JWT_WEAK_SECRETS:
            expected = hmac.new(secret.encode(), sig_input, hfunc).digest()
            if hmac.compare_digest(expected, sig_bytes):
                found_secret = secret
                break

        if found_secret:
            store.add(Finding(
                title=f"JWT: слабый секрет HS256 — '{found_secret}'",
                severity=Severity.CRITICAL,
                category="Authentication",
                cwe="CWE-798",
                description=(
                    f"Секрет для подписи JWT ({alg}) является словарным словом '{found_secret}'. "
                    "Атакующий может подписывать произвольные токены и выдать себя за любого пользователя."
                ),
                url=base_url,
                evidence=f"Секрет: '{found_secret}'\nАлгоритм: {alg}\nPayload: {payload}",
                remediation=(
                    "1. Используйте криптографически стойкий случайный секрет (минимум 256 бит).\n"
                    "2. Ротируйте секрет при подозрении на компрометацию.\n"
                    "3. Рассмотрите переход на RS256 (асимметричная криптография)."
                ),
                reproduction=(
                    f"# Брутфорс через hashcat:\n"
                    f"hashcat -a 0 -m 16500 '{token}' /usr/share/wordlists/rockyou.txt\n\n"
                    f"# Или jwt_tool:\n"
                    f"jwt_tool '{token}' -C -d /usr/share/wordlists/rockyou.txt"
                ),
            ))

    # 3. Информационные поля — проверяем наличие чувствительных данных
    sensitive_keys = ["password", "passwd", "secret", "ssn", "credit", "card", "cvv"]
    leaks = [k for k in payload if any(s in k.lower() for s in sensitive_keys)]
    if leaks:
        store.add(Finding(
            title="JWT: чувствительные данные в payload",
            severity=Severity.MEDIUM,
            category="Authentication",
            cwe="CWE-312",
            description=(
                f"JWT payload содержит потенциально чувствительные поля: {leaks}.\n"
                "JWT payload доступен любому, кто получил токен (base64, не зашифрован)."
            ),
            url=base_url,
            evidence=f"Payload: {payload}",
            remediation=(
                "1. Не храните чувствительные данные в JWT payload.\n"
                "2. Для хранения чувствительных данных используйте JWE (зашифрованный JWT)."
            ),
            reproduction=(
                f"# Декодировать payload:\n"
                f"echo '{parts[1]}' | base64 -d 2>/dev/null | python3 -m json.tool"
            ),
        ))

    # 4. Проверка exp
    exp = payload.get("exp")
    if not exp:
        store.add(Finding(
            title="JWT: отсутствует срок действия (exp)",
            severity=Severity.MEDIUM,
            category="Authentication",
            cwe="CWE-613",
            description=(
                "JWT не содержит claim 'exp'. Токен действует бессрочно — "
                "скомпрометированный токен не имеет срока истечения."
            ),
            url=base_url,
            evidence=f"Payload: {payload}",
            remediation=(
                "1. Добавьте claim 'exp' — рекомендуемое время жизни access token: 15-60 минут.\n"
                "2. Реализуйте механизм отзыва токенов (refresh token + blacklist)."
            ),
            reproduction=(
                f"echo '{parts[1]}' | base64 -d 2>/dev/null | python3 -m json.tool"
            ),
        ))
    elif isinstance(exp, (int, float)) and exp > time.time() + 86400 * 30:
        store.add(Finding(
            title="JWT: срок действия слишком длинный (>30 дней)",
            severity=Severity.LOW,
            category="Authentication",
            cwe="CWE-613",
            description=f"JWT expires: {exp}. Срок действия превышает 30 дней.",
            url=base_url,
            evidence=f"exp: {exp} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp))} UTC)",
            remediation="Сократите время жизни access token до 15-60 минут.",
            reproduction=f"echo '{parts[1]}' | base64 -d 2>/dev/null",
        ))


def _check_sensitive_in_url(endpoints, store):
    for ep in endpoints:
        match = SENSITIVE_URL_PATTERNS.search(ep.url)
        if match:
            param = match.group(1)
            value = match.group(2)[:20] + "..."
            store.add(Finding(
                title=f"Чувствительный параметр '{param}' передаётся в URL",
                severity=Severity.HIGH,
                category="Authentication",
                cwe="CWE-598",
                description=(
                    f"Параметр '{param}' (токен/ключ/пароль) передаётся в query string URL. "
                    "Он попадает в логи сервера, историю браузера, Referer-заголовки и аналитику."
                ),
                url=ep.url,
                parameter=param,
                evidence=f"URL: {ep.url[:200]}",
                remediation=(
                    "1. Передавайте credentials только через POST body или HTTP headers.\n"
                    "2. Используйте Authorization: Bearer вместо ?token= в URL.\n"
                    "3. Установите Referrer-Policy: no-referrer."
                ),
                reproduction=f"# Параметр виден в URL:\n{ep.url}",
            ))


def _check_auth_bypass_headers(session, base_url, curl_auth, timeout, store):
    try:
        normal_resp = session.get(base_url + "/admin", timeout=timeout, allow_redirects=False)
        normal_code = normal_resp.status_code
        normal_len = len(normal_resp.text)
    except Exception:
        return

    if normal_code in (200,):
        return  # Already accessible

    for header, value in AUTH_BYPASS_HEADERS.items():
        try:
            bypass_resp = session.get(
                base_url + "/admin",
                headers={header: value},
                timeout=timeout,
                allow_redirects=False,
            )
            if bypass_resp.status_code == 200 and len(bypass_resp.text) > 100:
                if abs(len(bypass_resp.text) - normal_len) > 200:
                    def _probe(_header=header, _value=value, _timeout=timeout):
                        try:
                            return session.get(base_url + "/admin", headers={_header: _value},
                                               timeout=_timeout, allow_redirects=False)
                        except Exception:
                            return None

                    store.add_candidate(Candidate(
                        finding=Finding(
                            title=f"Auth Bypass через заголовок '{header}'",
                            severity=Severity.HIGH,
                            category="Authentication",
                            cwe="CWE-287",
                            description=(
                                f"Установка заголовка '{header}: {value}' изменяет ответ /admin "
                                f"с {normal_code} на 200 и заметно меняет размер ответа. "
                                "Изменение размера само по себе не доказывает обход авторизации "
                                "(могла открыться, например, иная страница ошибки) — нужна проверка "
                                "содержимого на admin-специфичные признаки."
                            ),
                            url=base_url + "/admin",
                            evidence=f"Без заголовка: HTTP {normal_code} ({normal_len} байт), "
                                     f"с заголовком: HTTP 200 ({len(bypass_resp.text)} байт)",
                            remediation=(
                                "1. Не доверяйте заголовкам X-Forwarded-For, X-Real-IP для авторизации.\n"
                                "2. Авторизацию выполняйте на уровне приложения, не реверс-прокси.\n"
                                "3. Используйте middleware для проверки прав доступа."
                            ),
                            reproduction=(
                                f"curl -sk {curl_auth} -H '{header}: {value}' "
                                f"'{base_url}/admin'"
                            ),
                        ),
                        kind="auth_bypass",
                        context={"probe": _probe, "baseline_resp": normal_resp,
                                 "header": header, "value": value},
                    ))
        except Exception:
            pass


def _check_session_fixation(session, base_url, curl_auth, timeout, store):
    try:
        # Get session without auth
        anon_session = requests.Session()
        anon_session.verify = False
        resp1 = anon_session.get(base_url + "/login", timeout=timeout)
        cookies_before = {c.name: c.value for c in anon_session.cookies}

        if not cookies_before:
            return

        # Simulate login
        login_ep = None
        from ..crawler import INTERESTING_PATHS
        for path in ["/login", "/api/login", "/auth/login", "/signin"]:
            try:
                lr = anon_session.post(
                    base_url + path,
                    data={"username": "test", "password": "test"},
                    timeout=timeout,
                    allow_redirects=True,
                )
                if lr.status_code in (200, 302):
                    cookies_after = {c.name: c.value for c in anon_session.cookies}
                    for name, val_before in cookies_before.items():
                        if name in cookies_after and cookies_after[name] == val_before:
                            store.add(Finding(
                                title=f"Потенциальная Session Fixation — cookie '{name}'",
                                severity=Severity.MEDIUM,
                                category="Session Management",
                                cwe="CWE-384",
                                description=(
                                    f"Cookie '{name}' не меняет значение после попытки входа. "
                                    "Если сессионный ID не перегенерируется при аутентификации — "
                                    "возможна атака Session Fixation."
                                ),
                                url=base_url + path,
                                evidence=f"Cookie до: {val_before[:30]}...\nCookie после: {cookies_after[name][:30]}...",
                                remediation=(
                                    "1. Перегенерируйте session ID сразу после успешной аутентификации.\n"
                                    "2. session_regenerate_id(true) (PHP) / request.session.cycle_key() (Django)."
                                ),
                                reproduction=(
                                    f"# 1. Получить cookie до логина:\n"
                                    f"curl -sk -c /tmp/sess.txt '{base_url + path}'\n"
                                    f"# 2. Зафиксировать сессию и убедиться что ID не изменился после auth"
                                ),
                            ))
                    break
            except Exception:
                pass
    except Exception:
        pass


def _check_password_in_response(session, endpoints, curl_auth, timeout, store):
    password_pattern = re.compile(
        r'"?password"?\s*:\s*"([^"]{1,100})"',
        re.IGNORECASE,
    )
    for ep in endpoints:
        if ep.method not in ("GET", "HEAD"):
            continue
        try:
            resp = session.get(ep.url, timeout=timeout)
            if resp.status_code != 200:
                continue
            ct = resp.headers.get("content-type", "")
            if "json" not in ct and "html" not in ct:
                continue
            m = password_pattern.search(resp.text)
            if m:
                store.add(Finding(
                    title="Пароль в открытом виде в HTTP-ответе",
                    severity=Severity.CRITICAL,
                    category="Information Disclosure",
                    cwe="CWE-312",
                    description=f"Ответ {ep.url} содержит поле 'password' с непустым значением.",
                    url=ep.url,
                    evidence=f"password: {m.group(1)[:20]}...",
                    remediation=(
                        "1. Никогда не возвращайте поле password в API-ответах.\n"
                        "2. Хэшируйте пароли с bcrypt/argon2 и не храните plain-text."
                    ),
                    reproduction=f"curl -sk {curl_auth} '{ep.url}' | python3 -m json.tool | grep -i password",
                ))
        except Exception:
            pass


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _forge_jwt_none(header: dict, payload: dict, orig_header_b64: str, orig_payload_b64: str) -> str:
    import copy
    h = copy.deepcopy(header)
    h["alg"] = "none"
    header_b64 = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
    return f"{header_b64}.{orig_payload_b64}."
