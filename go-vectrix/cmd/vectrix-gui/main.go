// Command vectrix-gui is a Fyne GUI front-end for the VectrixSecWave Go
// pentest toolkit: every CLI flag from cmd/vectrix has a corresponding form
// field here, and scan progress streams into a live log view.
package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"vectrixgo/internal/runner"
	"vectrixgo/internal/scanner"
)

func main() {
	a := app.New()
	w := a.NewWindow("VectrixSecWave — AppSec Pentest Toolkit")

	ui := newUI(w)
	w.SetContent(ui.layout())
	w.Resize(fyne.NewSize(1180, 780))
	w.ShowAndRun()
}

// ui holds every form widget plus the running-scan state.
type ui struct {
	win fyne.Window

	targets    *widget.Entry
	mode       *widget.Select
	modeDesc   *widget.Label

	cookie     *widget.Entry
	cookieFile *widget.Entry
	token      *widget.Entry
	basicAuth  *widget.Entry
	headers    *widget.Entry

	proxy    *widget.Entry
	depth    *widget.Entry
	maxPages *widget.Entry
	timeout  *widget.Entry
	excludes *widget.Entry
	verbose  *widget.Check

	delay          *widget.Entry
	jitter         *widget.Entry
	retries        *widget.Entry
	workers        *widget.Entry
	noExpiryDetect *widget.Check

	outputDir *widget.Entry
	resume    *widget.Check

	startBtn *widget.Button
	stopBtn  *widget.Button
	status   *widget.Label

	logEntry  *widget.Entry
	logScroll *container.Scroll

	mu     sync.Mutex
	cancel context.CancelFunc
	lw     *logWriter
}

func newUI(w fyne.Window) *ui {
	u := &ui{win: w}

	u.targets = widget.NewMultiLineEntry()
	u.targets.SetPlaceHolder("https://target.example.com\n# по одной цели на строку, # — комментарий")
	u.targets.Wrapping = fyne.TextWrapBreak
	u.targets.SetMinRowsVisible(4)

	u.modeDesc = widget.NewLabel(scanner.Profiles["medium"].Label)
	u.modeDesc.Wrapping = fyne.TextWrapWord

	u.mode = widget.NewSelect([]string{"safe", "medium", "aggressive"}, func(s string) {
		if p, ok := scanner.Profiles[s]; ok {
			u.modeDesc.SetText(p.Label)
		}
	})
	u.mode.SetSelected("medium")

	u.cookie = widget.NewEntry()
	u.cookie.SetPlaceHolder(`name=val; name2=val2`)
	u.cookieFile = widget.NewEntry()
	u.cookieFile.SetPlaceHolder("cookies.json")
	u.token = widget.NewEntry()
	u.token.SetPlaceHolder("eyJhbGc...")
	u.basicAuth = widget.NewEntry()
	u.basicAuth.SetPlaceHolder("user:pass")
	u.headers = widget.NewMultiLineEntry()
	u.headers.SetPlaceHolder("X-API-Key: secret\nName: value (по одному на строку)")
	u.headers.SetMinRowsVisible(2)

	u.proxy = widget.NewEntry()
	u.proxy.SetPlaceHolder("http://127.0.0.1:8080")
	u.depth = widget.NewEntry()
	u.depth.SetPlaceHolder("auto")
	u.maxPages = widget.NewEntry()
	u.maxPages.SetPlaceHolder("auto")
	u.timeout = widget.NewEntry()
	u.timeout.SetText("15")
	u.excludes = widget.NewMultiLineEntry()
	u.excludes.SetPlaceHolder("logout|signout|delete (regex, по одному на строку)")
	u.excludes.SetMinRowsVisible(2)
	u.verbose = widget.NewCheck("Подробный вывод (--verbose)", nil)

	u.delay = widget.NewEntry()
	u.delay.SetText("0.5")
	u.jitter = widget.NewEntry()
	u.jitter.SetText("0.5")
	u.retries = widget.NewEntry()
	u.retries.SetText("3")
	u.workers = widget.NewEntry()
	u.workers.SetText("4")
	u.noExpiryDetect = widget.NewCheck("Отключить детектор истёкшей сессии", nil)

	u.outputDir = widget.NewEntry()
	u.outputDir.SetText("./reports")
	u.resume = widget.NewCheck("Resume (продолжить прерванный запуск)", nil)

	u.startBtn = widget.NewButton("Начать сканирование", u.onStart)
	u.startBtn.Importance = widget.HighImportance
	u.stopBtn = widget.NewButton("Остановить", u.onStop)
	u.stopBtn.Disable()
	u.status = widget.NewLabel("Готово.")

	u.logEntry = widget.NewMultiLineEntry()
	u.logEntry.Wrapping = fyne.TextWrapBreak
	u.logEntry.Disable()
	u.logScroll = container.NewScroll(u.logEntry)
	u.lw = &logWriter{}

	return u
}

func (u *ui) layout() fyne.CanvasObject {
	loadTargetsBtn := widget.NewButton("Загрузить из файла...", u.onLoadTargets)
	cookieFileBtn := widget.NewButton("Обзор...", u.onBrowseCookieFile)
	outputDirBtn := widget.NewButton("Обзор...", u.onBrowseOutputDir)
	openReportsBtn := widget.NewButton("Открыть папку отчётов", u.onOpenReports)

	targetBox := container.NewVBox(
		widget.NewLabelWithStyle("Цели", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		u.targets,
		loadTargetsBtn,
		widget.NewLabelWithStyle("Режим сканирования", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		u.mode,
		u.modeDesc,
	)

	authForm := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Cookie", u.cookie),
			widget.NewFormItem("Cookie-файл", container.NewBorder(nil, nil, nil, cookieFileBtn, u.cookieFile)),
			widget.NewFormItem("Bearer token", u.token),
			widget.NewFormItem("Basic auth", u.basicAuth),
		),
		widget.NewLabel("Доп. заголовки (по одному на строку):"),
		u.headers,
	)

	scanForm := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Proxy", u.proxy),
			widget.NewFormItem("Глубина обхода", u.depth),
			widget.NewFormItem("Макс. страниц", u.maxPages),
			widget.NewFormItem("Таймаут, сек", u.timeout),
		),
		widget.NewLabel("Исключить URL по regex (по одному на строку):"),
		u.excludes,
		u.verbose,
	)

	paceForm := widget.NewForm(
		widget.NewFormItem("Задержка, сек", u.delay),
		widget.NewFormItem("Джиттер, сек", u.jitter),
		widget.NewFormItem("Повторы 429/503", u.retries),
		widget.NewFormItem("Воркеры", u.workers),
		widget.NewFormItem("", u.noExpiryDetect),
	)

	outputForm := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Папка отчётов", container.NewBorder(nil, nil, nil, outputDirBtn, u.outputDir)),
		),
		u.resume,
		openReportsBtn,
	)

	accordion := widget.NewAccordion(
		widget.NewAccordionItem("Аутентификация", authForm),
		widget.NewAccordionItem("Параметры сканирования", scanForm),
		widget.NewAccordionItem("Темп и устойчивость", paceForm),
		widget.NewAccordionItem("Вывод / отчёты", outputForm),
	)

	controls := container.NewVBox(
		targetBox,
		accordion,
		container.NewGridWithColumns(2, u.startBtn, u.stopBtn),
		u.status,
	)

	left := container.NewVScroll(controls)
	left.SetMinSize(fyne.NewSize(380, 0))

	right := container.NewBorder(
		widget.NewLabelWithStyle("Лог сканирования", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nil, nil, nil,
		u.logScroll,
	)

	split := container.NewHSplit(left, right)
	split.Offset = 0.32
	return split
}

// ── Actions ──────────────────────────────────────────────────────────────

func (u *ui) onLoadTargets() {
	dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
		if err != nil || r == nil {
			return
		}
		defer r.Close()
		targets, err := runner.LoadTargetsFile(r.URI().Path())
		if err != nil {
			dialog.ShowError(err, u.win)
			return
		}
		u.targets.SetText(strings.Join(targets, "\n"))
	}, u.win)
}

func (u *ui) onBrowseCookieFile() {
	dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
		if err != nil || r == nil {
			return
		}
		defer r.Close()
		u.cookieFile.SetText(r.URI().Path())
	}, u.win)
}

func (u *ui) onBrowseOutputDir() {
	dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
		if err != nil || uri == nil {
			return
		}
		u.outputDir.SetText(uri.Path())
	}, u.win)
}

func (u *ui) onOpenReports() {
	dir := strings.TrimSpace(u.outputDir.Text)
	if dir == "" {
		dir = "./reports"
	}
	_ = exec.Command("explorer", dir).Start()
}

func (u *ui) onStart() {
	targets := splitLines(u.targets.Text)
	if len(targets) == 0 {
		dialog.ShowInformation("Нет целей", "Укажите хотя бы одну цель (URL или хост).", u.win)
		return
	}

	cfg := runner.Config{
		Targets:        targets,
		Mode:           u.mode.Selected,
		Cookie:         strings.TrimSpace(u.cookie.Text),
		CookieFile:     strings.TrimSpace(u.cookieFile.Text),
		Token:          strings.TrimSpace(u.token.Text),
		BasicAuth:      strings.TrimSpace(u.basicAuth.Text),
		Headers:        splitLines(u.headers.Text),
		Proxy:          strings.TrimSpace(u.proxy.Text),
		Depth:          parseIntDefault(u.depth.Text, 0),
		MaxPages:       parseIntDefault(u.maxPages.Text, 0),
		Timeout:        parseIntDefault(u.timeout.Text, 15),
		Excludes:       splitLines(u.excludes.Text),
		Delay:          parseFloatDefault(u.delay.Text, 0.5),
		Jitter:         parseFloatDefault(u.jitter.Text, 0.5),
		Retries:        parseIntDefault(u.retries.Text, 3),
		Workers:        parseIntDefault(u.workers.Text, 4),
		Verbose:        u.verbose.Checked,
		NoExpiryDetect: u.noExpiryDetect.Checked,
		OutputDir:      strings.TrimSpace(u.outputDir.Text),
		Resume:         u.resume.Checked,
	}
	if _, ok := scanner.Profiles[cfg.Mode]; !ok {
		cfg.Mode = "medium"
	}

	u.logEntry.SetText("")
	u.lw.reset()
	u.startBtn.Disable()
	u.stopBtn.Enable()
	u.status.SetText("Сканирование запущено...")

	ctx, cancel := context.WithCancel(context.Background())
	u.mu.Lock()
	u.cancel = cancel
	u.mu.Unlock()

	stopTicker := u.startLogPump()

	go func() {
		err := runner.Run(ctx, cfg, u.lw)
		stopTicker()
		u.lw.flush(u.logEntry, u.logScroll)

		u.mu.Lock()
		u.cancel = nil
		u.mu.Unlock()

		u.startBtn.Enable()
		u.stopBtn.Disable()
		if err != nil {
			u.status.SetText("Ошибка: " + err.Error())
		} else {
			u.status.SetText("Готово.")
		}
	}()
}

func (u *ui) onStop() {
	u.mu.Lock()
	cancel := u.cancel
	u.mu.Unlock()
	if cancel != nil {
		u.status.SetText("Останавливаю после текущей цели...")
		u.stopBtn.Disable()
		cancel()
	}
}

// startLogPump periodically flushes the log buffer into the GUI text area
// and returns a function that stops the pump.
func (u *ui) startLogPump() func() {
	ticker := time.NewTicker(200 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				u.lw.flush(u.logEntry, u.logScroll)
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()
	return func() { close(done) }
}

// ── Helpers ──────────────────────────────────────────────────────────────

// logWriter buffers scan output and lets the GUI flush it to the log widget
// at a controlled rate.
type logWriter struct {
	mu    sync.Mutex
	text  strings.Builder
	dirty bool
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.text.Write(p)
	w.dirty = true
	return len(p), nil
}

func (w *logWriter) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.text.Reset()
	w.dirty = false
}

func (w *logWriter) flush(entry *widget.Entry, scroll *container.Scroll) {
	w.mu.Lock()
	if !w.dirty {
		w.mu.Unlock()
		return
	}
	text := w.text.String()
	w.dirty = false
	w.mu.Unlock()

	entry.SetText(text)
	scroll.ScrollToBottom()
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

func parseIntDefault(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	var v int
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		return def
	}
	return v
}

func parseFloatDefault(s string, def float64) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	var v float64
	if _, err := fmt.Sscanf(s, "%f", &v); err != nil {
		return def
	}
	return v
}
