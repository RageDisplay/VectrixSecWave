# Web Pentest Toolkit

Автоматизированный инструментарий для тестирования безопасности веб-приложений.  
Запускается на Kali Linux, зависимости только из официальных репозиториев.

## Установка (одна команда)

```bash
sudo apt update && sudo apt install -y \
  python3-requests python3-bs4 \
  nikto nuclei gobuster sqlmap \
  whatweb wafw00f sslscan dirb
```

---

## Режимы сканирования

| Режим | Что делает | Инструменты | Время |
|-------|-----------|-------------|-------|
| `safe` | Только passive: headers, TLS, sensitive paths, технологии. Никаких payload'ов | whatweb, wafw00f | ~30 сек |
| `medium` | + CORS, IDOR, SSRF, rate limit, injection (без sqlmap) | + nikto | ~5–10 мин |
| `aggressive` | + time-based SQLi, nuclei (все CVE-шаблоны), gobuster, sqlmap на найденных параметрах | + nuclei, gobuster, sqlmap | ~20–40 мин |

Режим по умолчанию — `medium`.

### Когда что использовать

- **safe** — первый прогон, хрупкие системы, минимальный след в логах
- **medium** — основной рабочий режим для большинства тестов
- **aggressive** — финальный прогон перед отчётом, когда явно разрешено шуметь

### Отличия по модулям

| Модуль | safe | medium | aggressive |
|--------|------|--------|------------|
| Headers / TLS | + | + | + |
| Auth / JWT (passive) | + | + | + |
| CORS | + | + | + |
| Sensitive paths | + | + | + |
| Injection (error-based) | — | + | + |
| Injection (time-based blind) | — | — | + |
| XSS (расширенные payload'ы) | — | базовые | все |
| IDOR / BOLA | — | + | + |
| SSRF | — | + | + |
| Rate Limiting | — | + | + |
| whatweb / wafw00f | + | + | + |
| nikto | — | + | + |
| nuclei (CVE templates) | — | — | + |
| gobuster | — | — | + |
| sqlmap (на найденных SQLi) | — | — | + |
| Краулинг | depth 2, 100 стр | depth 3, 200 стр | depth 5, 500 стр |

---

## Использование

### Базовый запуск (режим medium по умолчанию)

```bash
python3 pentest.py -u https://target.bank.internal \
  --cookie "session=eyJhb...; csrf_token=abc123"
```

### Выбор режима

```bash
# Тихая разведка
python3 pentest.py -u https://target.bank.internal --cookie "..." --mode safe

# Стандартный пентест (default)
python3 pentest.py -u https://target.bank.internal --cookie "..." --mode medium

# Полный прогон
python3 pentest.py -u https://target.bank.internal --cookie "..." --mode aggressive
```

### С файлом cookie (из браузерного расширения EditThisCookie / Cookie-Editor)

```bash
python3 pentest.py -u https://target.bank.internal \
  --cookie-file cookies.json
```

### С Bearer token

```bash
python3 pentest.py -u https://target.bank.internal \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Через Burp Suite (весь трафик тулкита виден в History)

```bash
python3 pentest.py -u https://target.bank.internal \
  --cookie "session=..." \
  --proxy http://127.0.0.1:8080
```

### Полный прогон с API-ключом и кастомным заголовком

```bash
python3 pentest.py -u https://target.bank.internal \
  --token "eyJ..." \
  -H "X-Tenant-ID: bank123" \
  --mode aggressive \
  --output-dir /tmp/pentest_results
```

### Переопределить параметры краулинга вручную

```bash
python3 pentest.py -u https://target.bank.internal \
  --cookie "..." --mode medium \
  --depth 5 --max-pages 400
```

---

## Форматы cookie-файла

Поддерживаются все распространённые форматы:

| Формат | Источник | Пример |
|--------|---------|--------|
| JSON-массив | EditThisCookie, Cookie-Editor | `[{"name":"session","value":"abc"}]` |
| JSON-словарь | Ручной экспорт | `{"session": "abc", "token": "xyz"}` |
| Netscape | Burp Suite "Save cookies", curl `-c` | `# Netscape HTTP Cookie File ...` |
| Строка | Скопировать из DevTools → Headers | `session=abc; csrf=xyz` |

---

## Что проверяется

| Модуль | Уязвимости |
|--------|-----------|
| Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Cache-Control, Server banner |
| SSL/TLS | SSLv2/3, TLS 1.0/1.1, слабые шифры (RC4/DES/NULL), срок сертификата, mixed content, HTTP→HTTPS redirect |
| Injection | SQLi (error-based + time-blind), XSS reflected, SSTI, CMDi, Path Traversal/LFI, Open Redirect |
| Auth/Session | JWT (alg:none, слабый секрет, no exp, длинный exp), Cookie flags (Secure/HttpOnly/SameSite), чувствительное в URL, auth bypass via headers, session fixation |
| CORS | Origin reflection + credentials, null origin, wildcard + credentials |
| IDOR/BOLA | Числовые ID ±1/2 в path и query params, UUID замена в path |
| SSRF | URL-параметры → 127.0.0.1, cloud metadata (AWS/GCP/Azure), file://, gopher://, blind SSRF |
| Disclosure | Swagger/OpenAPI, Spring Actuator, .env, .git/config, verbose errors/stacktraces, секреты в ответах (AWS keys, JWT secrets, DB URLs), GraphQL introspection |
| Rate Limiting | Login endpoints, API endpoints |
| External tools | nikto, nuclei, whatweb, wafw00f, gobuster, sqlmap |

---

## Структура отчёта

Для каждой находки:
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Точный URL** и параметр
- **CWE** идентификатор
- **Доказательство**: фрагмент ответа, найденный payload, заголовок
- **Как воспроизвести**: готовая `curl`-команда или пошаговый сценарий
- **Рекомендации**: конкретные шаги с примерами конфигурации

Выходные файлы (имя включает режим):
- `reports/pentest_<host>_<mode>_<timestamp>.html` — интерактивный отчёт с фильтрацией по severity
- `reports/pentest_<host>_<mode>_<timestamp>.json` — машиночитаемый формат

---

## Структура проекта

```
web-pentest-toolkit/
├── pentest.py              # Точка входа, CLI, режимы (ScanProfile), оркестратор
├── modules/
│   ├── session.py          # Загрузка сессии (cookie/token/basic/proxy)
│   ├── crawler.py          # Краулер + обнаружение эндпоинтов + форм
│   ├── findings.py         # Модель уязвимости (Finding, FindingStore)
│   ├── report.py           # HTML + JSON отчёт
│   ├── tools.py            # Обёртки: nikto, nuclei, gobuster, sqlmap, whatweb, wafw00f
│   └── checks/
│       ├── headers.py      # Security headers
│       ├── ssl_check.py    # TLS/SSL (+ sslscan)
│       ├── injection.py    # SQLi, XSS, SSTI, CMDi, LFI, Open Redirect
│       ├── auth.py         # Auth/Session/JWT
│       ├── cors.py         # CORS
│       ├── idor.py         # IDOR/BOLA
│       ├── ssrf.py         # SSRF
│       ├── disclosure.py   # Information Disclosure
│       └── ratelimit.py    # Rate Limiting
```
