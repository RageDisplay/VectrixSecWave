# VectrixSecWave (Go port)

Go-порт пентест-тулкита VectrixSecWave: тот же функционал, что и у Python-версии
(`pentest.py` + `modules/`), но в виде двух нативных бинарников — CLI (`vectrix`)
и GUI на Fyne (`vectrix-gui`).

Инструмент сам ничего не "ломает" автоматически — он либо использует встроенный
HTTP-движок, либо вызывает уже установленные в системе утилиты:
**whatweb, wafw00f, nikto, nuclei, gobuster, sqlmap**. Если какой-то из них не
найден в `PATH`, соответствующая проверка просто пропускается (с предупреждением).

---

## 1. Требования

- **Go 1.25+** (проверено `go version`)
- Для GUI на Linux дополнительно нужны системные библиотеки X11/OpenGL (см. раздел 3)
- Внешние утилиты (опционально, но крайне желательно для medium/aggressive):
  ```bash
  sudo apt install whatweb wafw00f nikto sqlmap gobuster
  # nuclei через go или из releases:
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  ```

Перед каждым запуском CLI/GUI печатает сводку, какие из этих 6 инструментов
найдены, какие отсутствуют и какие из них реально нужны выбранному режиму:

```
[*] Проверка внешних инструментов ОС:
  [+] whatweb   — найден (сбор технологий стека (whatweb))
  [!] nikto     — НЕ найден (...) — проверка будет пропущена. Установка: apt install nikto
  [ ] gobuster  — не найден, не требуется в этом режиме (...)
```

---

## 2. Сборка под Windows 

Из папки `go-vectrix`:

```powershell
# CLI
go build -o vectrix.exe ./cmd/vectrix

# GUI
go build -o vectrix-gui.exe ./cmd/vectrix-gui
```

Запуск:

```powershell
.\vectrix.exe -mode medium -u https://target.example
.\vectrix-gui.exe
```

---

## 3. Сборка под Kali / Linux

### 3.1. CLI (`vectrix`) — кросс-компиляция прямо с Windows

CLI не использует CGO, поэтому собирается одной командой без доп. инструментов:

```powershell
cd go-vectrix
$env:CGO_ENABLED="0"; $env:GOOS="linux"; $env:GOARCH="amd64"
go build -o vectrix_linux_amd64 ./cmd/vectrix
```

Получится статический ELF-бинарник (~11 МБ). Дальше на Kali:

```bash
chmod +x vectrix_linux_amd64
./vectrix_linux_amd64 -mode medium -u http://target.local
```

### 3.2. GUI (`vectrix-gui`) — нужен CGO + X11/OpenGL

Fyne на Linux требует CGO и системные dev-библиотеки, поэтому простой
кросс-компил с Windows не работает. Два варианта:

**Вариант A (проще всего) — собрать прямо на Kali:**

```bash
sudo apt install golang gcc libgl1-mesa-dev xorg-dev
# скопируй на Kali всю папку go-vectrix (с go.mod/go.sum)
cd go-vectrix
go build -o vectrix-gui ./cmd/vectrix-gui
./vectrix-gui
```

**Вариант B — fyne-cross через Docker (с Windows):**

```powershell
go install fyne.io/fyne/v2/cmd/fyne-cross@latest
# нужен запущенный Docker Desktop
fyne-cross linux -arch=amd64 ./cmd/vectrix-gui
```

Результат появится в `fyne-cross/bin/linux-amd64/vectrix-gui`.

---

## 4. Режимы сканирования (`-mode`)

| Режим        | Краулинг        | Внешние тулзы                                  | Проверки |
|--------------|-----------------|--------------------------------------------------|----------|
| `safe`       | depth=2, 100 стр | whatweb, wafw00f                                 | Headers, SSL/TLS, Auth/JWT/CSRF, CORS, Disclosure — **без payload'ов** |
| `medium`     | depth=3, 200 стр | whatweb, wafw00f, nikto, nuclei                  | + IDOR/BOLA, SSRF, Injection (SQLi/XSS/SSTI/CMDi/LFI/CRLF/Open Redirect), XXE, Host Injection, Account Enum, Verb Tamper/Mass Assignment + адаптивная проверка кандидатов + анализ цепочек атак |
| `aggressive` | depth=5, 500 стр | + gobuster (брутфорс директорий), sqlmap (deep SQLi) | то же, что medium, плюс time-based blind SQLi, расширенный XSS-набор, полный nuclei-прогон, активная эксплуатация в цепочках атак |

`safe` — для production / разрешённых только на пассивную разведку целей.
`medium` — стандартный пентест. `aggressive` — полное покрытие, шумно и медленно.

---

## 5. CLI: основные флаги

```
vectrix -mode <safe|medium|aggressive> -u <URL>   # одна цель
vectrix -mode medium -T targets.txt               # список целей (по одной на строку)
```

| Флаг | По умолчанию | Описание |
|------|--------------|----------|
| `-u`, `-url` | — | Одна целевая ссылка |
| `-T`, `-targets` | — | Файл со списком целей (по строке на URL) |
| `-mode` | `medium` | `safe` \| `medium` \| `aggressive` |
| `-depth` | авто по режиму | Глубина краулинга |
| `-max-pages` | авто по режиму | Лимит страниц краулинга |
| `-timeout` | `15` | HTTP-таймаут (сек.) |
| `-delay` | `0.5` | Минимальная пауза между запросами (0 = выкл.) |
| `-jitter` | `0.5` | Случайная доп. задержка 0..jitter (анти-антибот) |
| `-retries` | `3` | Кол-во ретраев на 429/503 перед "блокировкой" |
| `-workers` | `4` | Параллельных проверок на цель |
| `-cookie` | — | `"name=val; name2=val2"` |
| `-cookie-file` | — | Файл с куками (Netscape / JSON / EditThisCookie) |
| `-token` | — | Bearer-токен (`Authorization: Bearer ...`) |
| `-basic-auth` | — | `user:pass` |
| `-H`, `-header` | — | Доп. заголовок `"Name: value"` (можно несколько раз) |
| `-proxy` | — | `http://127.0.0.1:8080` (например, для Burp) |
| `-exclude` | — | Regex URL, которые краулер никогда не запросит (можно несколько раз) |
| `-no-expiry-detect` | выкл. | Отключить автодетект протухания сессии |
| `-output-dir` | `./reports` | Куда складывать отчёты |
| `-resume` | выкл. | Продолжить прерванный multi-target прогон |
| `-v`, `-verbose` | выкл. | Подробный вывод |

### Примеры

```bash
# Быстрая пассивная разведка
./vectrix_linux_amd64 -mode safe -u https://target.example

# Стандартный пентест с авторизацией по куке
./vectrix_linux_amd64 -mode medium -u https://target.example \
    -cookie "session=abc123" -delay 0.3

# Через Burp как прокси, с Bearer-токеном
./vectrix_linux_amd64 -mode medium -u https://api.target.example \
    -proxy http://127.0.0.1:8080 -token eyJhbGciOi...

# Список целей + продолжение после обрыва
./vectrix_linux_amd64 -mode aggressive -T targets.txt -output-dir ./reports
./vectrix_linux_amd64 -mode aggressive -T targets.txt -output-dir ./reports -resume
```

---

## 6. GUI

`vectrix-gui` — то же самое, но с формой: поля соответствуют CLI-флагам
(цели, режим, авторизация, прокси, паузы и т.д.), лог сканирования стримится
в окно вживую. Кнопка запуска эквивалентна вызову CLI с теми же параметрами.

---

## 7. Отчёты

Каждый запуск кладёт в `<output-dir>` (по умолчанию `./reports`):

- `pentest_<host>_<mode>_<timestamp>.json` — машиночитаемый отчёт
- `pentest_<host>_<mode>_<timestamp>.html` — человекочитаемый отчёт
- `pentest_<host>_<mode>_<timestamp>_artifacts/` — дампы доказательств
  (тела ответов, секреты и т.п. для подтверждённых находок)

При нескольких целях дополнительно собирается общий (combined) отчёт.

---

## 8. Структура проекта (для разработки)

```
go-vectrix/
├── cmd/
│   ├── vectrix/        # CLI entrypoint
│   └── vectrix-gui/     # Fyne GUI entrypoint
└── internal/
    ├── adaptive/        # подтверждение находок (порт modules/adaptive.py)
    ├── chains/          # анализ цепочек атак (порт modules/chains.py)
    ├── checkpoint/       # resume для multi-target
    ├── checks/          # все 13 модулей проверок (headers, auth, injection, ...)
    ├── crawler/         # краулер
    ├── findings/        # модель находок (Finding/FindingStore/Severity)
    ├── httpsession/     # HTTP-клиент с throttling/retry/ban-detection
    ├── logging/
    ├── report/          # JSON/HTML отчёты
    ├── runner/          # общая точка входа для CLI и GUI
    ├── scanner/         # профили (safe/medium/aggressive) + оркестрация
    └── tools/           # обёртки над whatweb/wafw00f/nikto/nuclei/gobuster/sqlmap
```

```bash
go build ./...   # сборка
go vet ./...     # статическая проверка
```
