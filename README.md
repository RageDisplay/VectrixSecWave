# Web Pentest Toolkit (VectrixSecWave)

Автоматизированный инструментарий для тестирования безопасности веб-приложений
с адаптивным движком подтверждения находок (см. [«Адаптивная проверка находок»](#адаптивная-проверка-находок)).
Поддерживает одиночные и групповые проверки (список доменов из файла) с объединённым
отчётом, классифицированным по OWASP Top 10 2021.
Рассчитан на Kali Linux, зависимости — только из официальных репозиториев.

Заточен под длинные неприсмотренные прогоны по множеству доменов за антифродом/WAF:
глобальный троттлинг с джиттером, авто-бэкофф и пауза при блокировке, детект
протухшей сессии и **`--resume`** для продолжения прерванного скана.
См. [«Устойчивость: антифрод, бан, время жизни сессии»](#устойчивость-антифрод-бан-время-жизни-сессии).

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
   Вне Kali (venv / другой дистрибутив) Python-пакеты ставятся через pip:

   ```bash
   python3 -m venv .venv && . .venv/bin/activate
   pip install -r requirements.txt
   ```

   Внешние тулзы (`nikto`, `nuclei`, `gobuster`, `sqlmap`, `whatweb`, `wafw00f`, `sslscan`)
   не обязательны — если утилита не установлена, её проверка пропускается с пометкой
   в логе. Без них работает собственный движок (Headers, TLS, Auth/JWT/CSRF, CORS, IDOR,
   SSRF, Disclosure, Injection, XXE, Host Injection, Account Enum,
   Verb Tampering/Mass Assignment, адаптивное подтверждение).

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
| `medium` | + CORS, IDOR, SSRF, injection, XXE, Host Injection, Account Enum, Verb Tampering (без sqlmap) | + nikto | ~5–15 мин |
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
| JWT: alg:none, слабый секрет, kid-инъекция, key confusion | + | + | + |
| CRLF / HTTP Response Splitting | — | + | + |
| CORS | + | + | + |
| Sensitive paths (disclosure) | + | + | + |
| Injection (error-based SQLi, XSS, SSTI, CMDi, LFI) | — | + | + |
| Injection (time-based blind SQLi) | — | — | + |
| XSS (расширенные payload'ы) | — | базовые | все |
| IDOR / BOLA | — | + | + |
| SSRF | — | + | + |
| XXE (file read, SSRF, error-based, param entity) | — | + | + |
| Host Header Injection / password reset poisoning | — | + | + |
| Account Enumeration (status, size, timing, error msg) | — | + | + |
| HTTP Verb Tampering / Method Override bypass | — | + | + |
| Mass Assignment (JSON bait fields) | — | + | + |
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

## Устойчивость: антифрод, бан, время жизни сессии

Прогон большого скоупа за антифродом/WAF и на коротких сессиях ломается не от
нехватки проверок, а от блокировок и протухшей авторизации. Инструмент это
учитывает на уровне HTTP-сессии — никаких ручных пауз не нужно.

### Троттлинг запросов

Все запросы (краулер, проверки, адаптивная фаза) проходят через единый
ограничитель скорости. Старты запросов глобально разносятся на
`--delay` + случайный `0..--jitter`, поэтому:

- трафик выглядит менее роботизированным для антифрода;
- `--workers` ускоряет только за счёт перекрытия сетевых задержек — **суммарная
  скорость запросов не растёт** от числа воркеров (ограничитель общий).

```bash
# Консервативно для чувствительного контура: ~1 запрос в 1.5–2.5 с
python3 pentest.py -T scope.txt --cookie "session=..." \
  --delay 1.5 --jitter 1.0 --workers 2

# Быстро, если антифрод лоялен (троттлинг выключен)
python3 pentest.py -u https://target --delay 0 --jitter 0 --workers 8
```

> Значения по умолчанию (`--delay 0.5 --jitter 0.5 --workers 4`) подобраны как
> компромисс. Для банковского тест-контура обычно стоит увеличить `--delay`.

### Авто-бэкофф и пауза при блокировке

- `429` / `503` повторяются с экспоненциальным бэкоффом, учитывая заголовок
  `Retry-After` (до `--retries` попыток).
- Серия подряд идущих блокировок (включая `403` с телом WAF/«captcha»/«access
  denied») запускает **автоматическую паузу остывания** с нарастающей
  длительностью.
- Если блокировки продолжаются и после пауз — скан **останавливается чисто** и
  сохраняет чекпоинт (см. `--resume`). Сообщение в логе подскажет сменить IP /
  подождать.

### Детект протухшей сессии

Если на аутентифицированный запрос приходит `401` или редирект на страницу
логина (`/login`, `/sso`, `/oauth`, `returnUrl=` …) — это распознаётся как
истёкшая сессия. Скан останавливается, чтобы вы не продолжали впустую
сканировать как неавторизованный пользователь:

```
[!] Сессия истекла (HTTP 401 / redirect на логин) при запросе https://app/api/me.
    Обновите cookie/токен и продолжите с --resume.
```

Отключается через `--no-expiry-detect`. Сама страница логина из скоупа не
считается «протуханием» (ложных срабатываний на ней нет).

### `--resume` — продолжение прерванного прогона

Прогресс по целям пишется в `<output-dir>/.vectrix_state/<mode>.json` после
каждой завершённой цели. Если прогон оборвался (бан, истёкшая сессия, `Ctrl-C`,
убитый шелл) — повторите ту же команду с `--resume`:

```bash
# Первый прогон обрывается после 12 из 40 доменов (бан)
python3 pentest.py -T scope.txt --cookie "session=..." --mode medium

# Обновили cookie / сменили IP — продолжаем с 13-й цели
python3 pentest.py -T scope.txt --cookie "session=НОВАЯ" --mode medium --resume
```

Уже просканированные цели пропускаются; цель, на которой случился обрыв,
сканируется заново с чистого листа. После полного завершения чекпоинт удаляется.

### Безопасный краулинг (deny-list)

Краулер никогда не запрашивает деструктивные/сессионные пути автоматически
(`/logout`, `/signout`, `/delete`, `/destroy`, `/deactivate`, …) — иначе на живой
сессии можно разлогиниться или изменить данные. Список расширяется флагом
`--exclude REGEX` (повторяемый):

```bash
python3 pentest.py -u https://app --cookie "session=..." \
  --exclude "/admin/users/\\d+/disable" --exclude "/billing/charge"
```

> Примечание: deny-list ограничивает **краулинг**. Активные проверки
> (`verbtamper` шлёт `DELETE`/`PUT`, `account_enum` шлёт попытки логина)
> выполняются по своему дизайну в `medium`/`aggressive`. Если контур
> чувствителен к мутациям — используйте `--mode safe`.

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

# Продолжить прерванный прогон (бан / истёкшая сессия / Ctrl-C)
python3 pentest.py -T scope.txt --token "eyJ..." --mode aggressive \
  --output-dir /tmp/engagement_2026 --resume
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
| Injection | SQLi (error-based + time-blind), XSS reflected, SSTI, CMDi, Path Traversal/LFI, Open Redirect, CRLF/HTTP Response Splitting | A03 |
| Auth / Session | JWT (alg:none, слабый секрет, no exp/длинный exp, kid-инъекция SQL+path, RS256→HS256 key confusion), Cookie flags (Secure/HttpOnly/SameSite), auth bypass via headers, session fixation | A07 |
| CSRF | Отсутствие CSRF-токена в POST-формах; двойная проверка через повторный GET страницы перед репортом | A01 |
| CORS | Origin reflection + credentials, null origin, wildcard + credentials | A05 |
| IDOR / BOLA | Числовые ID ±1/2 в path и query, UUID замена в path | A01 |
| SSRF | URL-параметры → 127.0.0.1, cloud metadata (AWS/GCP/Azure), file://, gopher://, blind SSRF | A10 |
| XXE | file:///etc/passwd, AWS/GCP metadata SSRF, error-based, parameter entity, SOAP-обёртка; differential-подтверждение | A03 |
| Host Injection | Host header reflection, X-Forwarded-Host bypass, password reset poisoning | A05 |
| Account Enum | Перебор по: HTTP статусу, размеру ответа (>12%), timing (>400ms), тексту ошибки на login/register/reset | A07 |
| Verb Tampering | HTTP TRACE/XST, метод-обход restricted endpoints (GET→POST/DELETE), X-HTTP-Method-Override bypass | A01 |
| Mass Assignment | Инъекция is_admin/role/price в JSON-эндпоинты, отражение bait-полей в ответе | A01 |
| Disclosure | Swagger/OpenAPI, Spring Actuator, .env, .git/config, verbose errors, секреты в ответах (AWS keys, JWT secrets, DB URLs), GraphQL introspection | A02 |
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
├── requirements.txt        # Python-зависимости для pip/venv (вне Kali)
├── modules/
│   ├── session.py          # Загрузка сессии (cookie/token/basic/proxy)
│   ├── resilient.py        # Троттлинг + бэкофф + детект бана/протухшей сессии (ResilientSession)
│   ├── checkpoint.py       # Прогресс multi-domain прогона для --resume
│   ├── crawler.py          # Краулер + обнаружение эндпоинтов + форм + deny-list
│   ├── findings.py         # Finding, FindingStore (с дедупликацией), OWASP-маппинг
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
│       ├── xxe.py          # XXE (file read, SSRF, error-based, param entity)
│       ├── hostinjection.py# Host Header Injection / password reset poisoning
│       ├── account_enum.py # Account enumeration via response differences
│       └── verbtamper.py   # HTTP Verb Tampering, Method Override, Mass Assignment
└── tests/                  # Юнит-тесты (dedup, deny-list, детект бана/сессии, checkpoint)
```

---

## Тесты

Логика устойчивости, дедупликации и скоупа покрыта юнит-тестами (без сети):

```bash
python3 -m unittest discover -s tests
```

---

## Дедупликация находок

Одинаковые находки (один и тот же заголовок + URL + параметр + метод) больше не
дублируются в отчёте: они схлопываются в одну запись. При схлопывании
сохраняется наибольшая критичность, объединяются `evidence` и
`verification_log`, а `confidence` берётся максимальной. Это убирает шум, когда,
например, отсутствующий security-заголовок виден на десятке эндпоинтов.
