package main

import (
	"flag"
	"fmt"

	"vectrixgo/internal/runner"
)

// parseFlags parses os.Args into a runner.Config, mirroring pentest.py's
// argparse setup.
func parseFlags() (runner.Config, error) {
	var urlFlag, targetsFlag, mode, cookie, cookieFile, token, basicAuth, proxy, outputDir string
	var depth, maxPages, timeoutSec, retries, workers int
	var delay, jitter float64
	var verbose, noExpiryDetect, resume bool
	var headers, excludes stringSliceFlag

	flag.StringVar(&urlFlag, "u", "", "Single target URL")
	flag.StringVar(&urlFlag, "url", "", "Single target URL")
	flag.StringVar(&targetsFlag, "T", "", "File with target URLs (one per line)")
	flag.StringVar(&targetsFlag, "targets", "", "File with target URLs (one per line)")
	flag.StringVar(&mode, "mode", "medium", "Scan mode: safe | medium | aggressive")
	flag.StringVar(&cookie, "cookie", "", `Raw cookie string ("name=val; name2=val2")`)
	flag.StringVar(&cookieFile, "cookie-file", "", "Cookie file (Netscape / JSON / EditThisCookie)")
	flag.StringVar(&token, "token", "", "Bearer token (Authorization header)")
	flag.StringVar(&basicAuth, "basic-auth", "", "Basic auth as user:pass")
	flag.Var(&headers, "H", `Extra header "Name: value" (repeatable)`)
	flag.Var(&headers, "header", `Extra header "Name: value" (repeatable)`)
	flag.StringVar(&proxy, "proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	flag.IntVar(&depth, "depth", 0, "Crawl depth (default: auto by mode)")
	flag.IntVar(&maxPages, "max-pages", 0, "Max pages to crawl (default: auto by mode)")
	flag.IntVar(&timeoutSec, "timeout", 15, "HTTP timeout in seconds")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.Var(&excludes, "exclude", "Regex of URLs to never request (repeatable)")
	flag.Float64Var(&delay, "delay", 0.5, "Min delay between request starts, seconds (0 = off)")
	flag.Float64Var(&jitter, "jitter", 0.5, "Random extra delay 0..jitter per request, seconds")
	flag.IntVar(&retries, "retries", 3, "Backoff retries on 429/503 before counting a block")
	flag.IntVar(&workers, "workers", 4, "Concurrent checks per target")
	flag.BoolVar(&noExpiryDetect, "no-expiry-detect", false, "Disable auto auth-session-expiry detection")
	flag.StringVar(&outputDir, "output-dir", "./reports", "Report output directory")
	flag.BoolVar(&resume, "resume", false, "Resume an interrupted multi-target run")
	flag.Parse()

	if urlFlag == "" && targetsFlag == "" {
		return runner.Config{}, fmt.Errorf("Укажите цель: -u URL  или  -T targets.txt")
	}

	var targets []string
	if urlFlag != "" {
		targets = append(targets, urlFlag)
	} else {
		t, err := runner.LoadTargetsFile(targetsFlag)
		if err != nil {
			return runner.Config{}, fmt.Errorf("Файл целей не найден: %s", targetsFlag)
		}
		targets = t
	}

	return runner.Config{
		Targets:        targets,
		Mode:           mode,
		Cookie:         cookie,
		CookieFile:     cookieFile,
		Token:          token,
		BasicAuth:      basicAuth,
		Headers:        []string(headers),
		Proxy:          proxy,
		Depth:          depth,
		MaxPages:       maxPages,
		Timeout:        timeoutSec,
		Excludes:       []string(excludes),
		Delay:          delay,
		Jitter:         jitter,
		Retries:        retries,
		Workers:        workers,
		Verbose:        verbose,
		NoExpiryDetect: noExpiryDetect,
		OutputDir:      outputDir,
		Resume:         resume,
	}, nil
}
