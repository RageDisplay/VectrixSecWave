# Web Pentest Toolkit (VectrixSecWave)

Автоматизированный инструментарий для тестирования безопасности веб-приложений
с адаптивным движком подтверждения находок (см. [«Адаптивная проверка находок»](#адаптивная-проверка-находок)).
Поддерживает одиночные и групповые проверки (список доменов из файла) с объединённым
отчётом, классифицированным по OWASP Top 10 2021.
Рассчитан на Kali Linux, зависимости — только из официальных репозиториев.

## Требования

- Kali Linux (или любой Linux с пакетами ниже) и Python 3.10+
- `git` — чтобы склонировать/распаковать архив с инструментом

## Установка

1. Получить код и перейти в каталог:

   ```bash
   git clone <URL_репозитория> vectrixsecwave
   cd vectrixsecwave
   # или, если на руках архив:
   #   tar xf vectrixsecwave.tar.gz && cd vectrixsecwave
   ```

2. Поставить зависимости:

   ```bash
   sudo apt update && sudo apt install -y \
     python3-requests python3-bs4 \
     nikto nuclei gobuster sqlmap \
     whatweb wafw00f sslscan dirb
   ```

   Полный список — в [requirements-kali.txt](requirements-kali.txt).
   Внешние тулзы (`nikto`, `nuclei`, `gobuster`, `sqlmap`, `whatweb`, `wafw00f`, `sslscan`)
   не обязательны — если утилита не установлена, её проверка пропускается с пометкой
   в логе. Без них работает собственный движок (Headers, TLS, Auth/CSRF, CORS, IDOR,
   SSRF, Disclosure, Injection, Rate Limiting, адаптивное подтверждение).

3. Проверить запуск:

   ```bash
   python3 pentest.py --help
   ```

---

## Быстрый старт

```bash
# Одна цель — минимальный запуск (режим medium по умолчанию)
python3 pentest.py -u https://target.bank.internal

# Одна цель с куками текущей сессии
python3 pentest.py -u https://target.bank.internal \
  --cookie "session=eyJhb...; csrf_token=abc123"

# Несколько целей из файла (схема http/https подставляется автоматически)
python3 pentest.py -T domains.txt --mode medium \
  --cookie "session=eyJhb..."
```

Формат `domains.txt` — по одному домену или URL на строку; строки, начинающиеся с `#`,
игнорируются:

```
# Production scope
app.bank.internal
https://api.bank.internal
admin.bank.internal:8443
# 192.168.1.50  — excluded for now
```

Если схема не указана (`app.bank.internal`), инструмент автоматически пробует HTTPS,
при недоступности — HTTP, и начинает сканирование с рабочим вариантом.

После завершения отчёты лежат в `reports/`:
- Для одной цели: `pentest_<host>_<mode>_<timestamp>.html/.json`
- Для группы: дополнительно `pentest_combined_<mode>_<timestamp>.html/.json`

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
| Auth / JWT / CSRF (passive) | + | + | + |
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
| nuclei (по найденным эндпоинтам + теги по технологиям) | — | лёгкий проход | полный проход |
| gobuster | — | — | + |
| sqlmap (на найденных SQLi) | — | — | + |
| Адаптивная проверка кандидатов | — | + | + |
| Анализ цепочек атак | — | SSRF→облачные креды | + auth-цепочки |
| Краулинг | depth 2, 100 стр | depth 3, 200 стр | depth 5, 500 стр |

> В режиме `safe` адаптивная проверка отключена намеренно — сохраняется обещание
> «минимальный след». Слабые сигналы всё равно попадают в отчёт с пометкой
> `unverified` и пониженной на ступень критичностью.

---

## Использование

### Одна цель

```bash
# Режим medium по умолчанию
python3 pentest.py -u https://target.bank.internal \
  --cookie "session=eyJhb...; csrf_token=abc123"

# Тихая разведка
python3 pentest.py -u https://target.bank.internal --mode safe

# Полный прогон
python3 pentest.py -u https://target.bank.internal \
  --cookie "..." --mode aggressive

# С Bearer токеном
python3 pentest.py -u https://target.bank.internal \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Через Burp Suite
python3 pentest.py -u https://target.bank.internal \
  --cookie "session=..." --proxy http://127.0.0.1:8080

# С кастомным заголовком и изменёнными параметрами краулинга
python3 pentest.py -u https://target.bank.internal \
  --token "eyJ..." -H "X-Tenant-ID: bank123" \
  --mode aggressive --depth 5 --max-pages 400 \
  --output-dir /tmp/pentest_results
```

### Группа целей из файла

```bash
# Проверить все домены из файла, режим medium
python3 pentest.py -T domains.txt \
  --cookie "session=eyJhb..."

# Aggressive-прогон всего скоупа
python3 pentest.py -T scope.txt \
  --token "eyJ..." --mode aggressive \
  --output-dir /tmp/engagement_2026
```

Для каждой цели генерируется свой отчёт; после завершения всех — дополнительный
объединённый файл `pentest_combined_<mode>_<timestamp>.html/.json`.

### С cookie-файлом из браузерного расширения

```bash
python3 pentest.py -u https://target.bank.internal \
  --cookie-file cookies.json
```

---

## Форматы cookie-файла

| Формат | Источник | Пример |
|--------|---------|--------|
| JSON-массив | EditThisCookie, Cookie-Editor | `[{"name":"session","value":"abc"}]` |
| JSON-словарь | Ручной экспорт | `{"session": "abc", "token": "xyz"}` |
| Netscape | Burp Suite "Save cookies", curl `-c` | `# Netscape HTTP Cookie File ...` |
| Строка | Скопировать из DevTools → Headers | `session=abc; csrf=xyz` |

---

## Что проверяется

| Модуль | Уязвимости | OWASP 2021 |
|--------|-----------|-----------|
| Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Cache-Control, Server banner | A05 |
| SSL/TLS | SSLv2/3, TLS 1.0/1.1, слабые шифры (RC4/DES/NULL), срок сертификата, mixed content, HTTP→HTTPS redirect | A02 |
| Injection | SQLi (error-based + time-blind), XSS reflected, SSTI, CMDi, Path Traversal/LFI, Open Redirect | A03 |
| Auth / Session | JWT (alg:none, слабый секрет, no exp, длинный exp), Cookie flags (Secure/HttpOnly/SameSite), чувствительное в URL, auth bypass via headers, session fixation | A07 |
| CSRF | Отсутствие CSRF-токена в POST-формах; двойная проверка через повторный GET страницы перед репортом | A01 |
| CORS | Origin reflection + credentials, null origin, wildcard + credentials | A05 |
| IDOR / BOLA | Числовые ID ±1/2 в path и query, UUID замена в path | A01 |
| SSRF | URL-параметры → 127.0.0.1, cloud metadata (AWS/GCP/Azure), file://, gopher://, blind SSRF | A10 |
| Disclosure | Swagger/OpenAPI, Spring Actuator, .env, .git/config, verbose errors, секреты в ответах (AWS keys, JWT secrets, DB URLs), GraphQL introspection | A02 |
| Rate Limiting | Login endpoints, API endpoints | A05 |
| External tools | nikto, nuclei (целево — по эндпоинтам и whatweb-фингерпринту), whatweb, wafw00f, gobuster, sqlmap | — |

---

## OWASP Top 10 в отчётах

Каждая находка автоматически классифицируется по OWASP Top 10 2021 на основе категории.
В HTML-отчёте вверху появляется кликабельная сетка:

```
A01: Broken Access Control   (3)  │  A03: Injection             (5)
A02: Cryptographic Failures  (2)  │  A05: Security Misconfig     (8)
A07: Auth & Identification   (4)  │  A10: SSRF                   (1)
```

Клик по ячейке фильтрует список находок по этой категории.
Повторный клик сбрасывает фильтр. Фильтр по severity и OWASP работают совместно.

В JSON-отчёте добавлены поля:

```json
{
  "owasp_summary": { "A03:2021": 5, "A01:2021": 3, ... },
  "findings": [
    {
      "owasp_id": "A03:2021",
      "owasp_name": "Injection",
      ...
    }
  ]
}
```

---

## Групповые (multi-domain) отчёты

При запуске через `-T domains.txt` для каждой цели создаётся собственный HTML/JSON,
а после всех сканов — **единый объединённый отчёт**:

```
reports/
├── pentest_app.bank.internal_medium_20260609_120000.html
├── pentest_api.bank.internal_medium_20260609_120000.html
├── pentest_admin.bank.internal_medium_20260609_120000.html
├── pentest_combined_medium_20260609_120000.html   ← сводный
└── pentest_combined_medium_20260609_120000.json
```

В сводном HTML:
- **Таблица целей** — строка на домен с колонками CRIT / HIGH / MED / LOW / Endpoints
  (клик по строке фильтрует находки только по этой цели)
- **OWASP-сетка** — суммарно по всем доменам
- **Фильтр по цели** — кнопки «Все цели», `app.bank.internal`, `api.bank.internal`, …
- **Все находки** в одном прокручиваемом списке с лейблом домена на каждой карточке

Консольный итог после групповой проверки:

```
============================================================
[+] ИТОГО по всем целям: 3 доменов, 47 находок
    https://app.bank.internal:   CRIT:2 HIGH:8  MED:12 LOW:5
    https://api.bank.internal:   CRIT:0 HIGH:3  MED:7  LOW:4
    https://admin.bank.internal: CRIT:1 HIGH:5  MED:3  LOW:1
[+] Объединённый отчёт: reports/pentest_combined_medium_20260609_120000.html
============================================================
```

---

## Адаптивная проверка находок

В режимах `medium` и `aggressive` инструмент не просто фиксирует первый слабый
сигнал — он пытается подтвердить или опровергнуть находку отдельной фазой
`modules/adaptive.py`:

```
Краулинг → внешние тулзы → проверки (черновые «кандидаты») → адаптивное подтверждение → отчёт
```

Как это работает:

1. **Слабые сигналы становятся кандидатами** — эвристика IDOR по схожести ответа,
   error-based SQLi по одной regex-сигнатуре, blind SSRF по смене статус-кода,
   header-based auth bypass по дельте ответа, подозрительные пути (`.git/`, `.env` и пр.)
2. **Каждый тип проходит свой верификатор** — повторные дифференциальные запросы:
   true/false-payload для SQLi, сравнение identity-токенов для IDOR, контрольный
   запрос на невалидный адрес для SSRF, поиск admin-маркеров для auth bypass,
   скан на сигнатуры секретов для disclosure.
3. **Вердикт определяет судьбу**:
   - `CONFIRMED` → статус `confirmed-deep-dive`, confidence 1.0
   - `DISCARDED` → не публикуется, попадает в раздел «Отброшено» (с причиной)
   - `INCONCLUSIVE` → публикуется со статусом `unverified`, критичность понижена
4. Извлечённые артефакты (фрагменты `.env`, git-конфигов, ключей) сохраняются
   в `reports/<отчёт>_artifacts/<id>/` и линкуются в HTML и JSON.
5. Для disclosure дополнительно генерируется nuclei-шаблон для скана соседних путей.

В консоли:

```
[*] === Адаптивная проверка кандидатов ===
  [+] CONFIRMED: Доступен чувствительный путь: /.env (.env file)
  [+] CONFIRMED: Доступен чувствительный путь: /.git/config (Git config)
[+] Адаптивная проверка завершена: подтверждено — 2, отброшено — 1, требуют ручной проверки — 0
```

---

## Анализ цепочек атак

После адаптивного подтверждения модуль `modules/chains.py` коррелирует подтверждённые
находки в цепочки эксплуатации:

```
… → адаптивное подтверждение → анализ цепочек атак → отчёт
```

- **SSRF → кража облачных учётных данных** (`medium`/`aggressive`): при доступном
  облачном endpoint (`169.254.169.254`, AWS/GCP/Azure) инструмент запрашивает IAM-роли
  и временные ключи через уязвимый параметр. Если `AccessKeyId`/`SecretAccessKey`
  найдены — дампятся как артефакт, публикуется CRITICAL-находка.
- **Утечка учётных данных → успешный вход** (только `aggressive`): вытаскивает пары
  логин/пароль из дампнутых артефактов, находит форму логина и делает ровно одну
  реальную попытку входа + один контрольный запрос. Доказанный вход → CRITICAL.

В консоли:

```
[*] === Анализ цепочек атак ===
  [+] CONFIRMED: Цепочка: SSRF → кража временных облачных учётных данных
[+] Анализ цепочек атак завершён: построено и подтверждено цепочек — 1
```

---

## Структура отчёта

Для каждой находки:

| Поле | Описание |
|------|---------|
| `severity` | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `owasp_id` / `owasp_name` | OWASP Top 10 2021 категория |
| `cwe` | CWE идентификатор |
| `url` + `parameter` | Точное место уязвимости |
| `evidence` | Фрагмент ответа / payload / заголовок |
| `reproduction` | Готовая `curl`-команда или пошаговый сценарий |
| `remediation` | Конкретные шаги с примерами конфигурации |
| `status` | `confirmed`, `confirmed-deep-dive`, `unverified` |
| `confidence` | 0.0–1.0 |
| `verification_log` | Что именно перепроверялось и с каким результатом |
| `artifacts` | Ссылки на сдампленные файлы-доказательства |
| `target` | Домен (заполняется в групповых сканах) |

Выходные файлы:

```
reports/
├── pentest_<host>_<mode>_<timestamp>.html    — интерактивный HTML (фильтры severity + OWASP)
├── pentest_<host>_<mode>_<timestamp>.json    — машиночитаемый формат
├── pentest_<host>_<mode>_<timestamp>_artifacts/  — дампы секретов (если найдены)
│
│   (только при --targets / нескольких целях:)
├── pentest_combined_<mode>_<timestamp>.html  — сводный HTML по всем целям
└── pentest_combined_<mode>_<timestamp>.json  — сводный JSON
```

---

## Структура проекта

```
web-pentest-toolkit/
├── pentest.py              # Точка входа, CLI (-u / -T), режимы, оркестратор
├── modules/
│   ├── session.py          # Загрузка сессии (cookie/token/basic/proxy)
│   ├── crawler.py          # Краулер + обнаружение эндпоинтов + форм
│   ├── findings.py         # Finding, FindingStore, OWASP-маппинг, Candidate-хранилище
│   ├── adaptive.py         # Адаптивная проверка: верификаторы, дамп артефактов, nuclei-шаблоны
│   ├── chains.py           # Анализ цепочек атак: корреляция → сценарии эксплуатации
│   ├── report.py           # HTML + JSON (OWASP-сетка, групповые отчёты, фильтры)
│   ├── tools.py            # Обёртки: nikto, nuclei, gobuster, sqlmap, whatweb, wafw00f
│   └── checks/
│       ├── headers.py      # Security headers
│       ├── ssl_check.py    # TLS/SSL (+ sslscan)
│       ├── injection.py    # SQLi, XSS, SSTI, CMDi, LFI, Open Redirect
│       ├── auth.py         # Auth / Session / JWT / CSRF
│       ├── cors.py         # CORS
│       ├── idor.py         # IDOR / BOLA
│       ├── ssrf.py         # SSRF
│       ├── disclosure.py   # Information Disclosure
│       └── ratelimit.py    # Rate Limiting
```
