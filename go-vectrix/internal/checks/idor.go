package checks

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

var (
	idPattern     = regexp.MustCompile(`^\d{1,10}$`)
	uuidPattern   = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	pathIDPattern = regexp.MustCompile(`/([\w-]+)/(\d{1,10})(?:/|$)`)
)

var idorParamNames = map[string]struct{}{
	"id": {}, "user_id": {}, "userid": {}, "account_id": {}, "accountid": {},
	"customer_id": {}, "customerid": {}, "uid": {}, "pid": {}, "oid": {},
	"order_id": {}, "orderid": {}, "profile_id": {}, "doc_id": {}, "file_id": {},
}

// RunIDOR checks GET/HEAD endpoints for sequential numeric IDs / UUIDs in the
// path or query string that can be swapped for adjacent values. Mirrors
// modules/checks/idor.py run().
func RunIDOR(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, store *findings.FindingStore) {
	logging.Println("[*] Checking IDOR/BOLA...")
	curlAuth := session.CurlAuthFlags(baseURL)

	for _, ep := range endpoints {
		if ep.Method != "GET" && ep.Method != "HEAD" {
			continue
		}
		checkNumericIDsInPath(session, ep, curlAuth, store)
		checkNumericIDsInParams(session, ep, curlAuth, store)
		checkUUIDInPath(session, ep, curlAuth, store)
	}
}

func checkNumericIDsInPath(session *httpsession.Session, ep crawler.Endpoint, curlAuth string, store *findings.FindingStore) {
	parsed, err := url.Parse(ep.URL)
	if err != nil {
		return
	}
	path := parsed.Path

	for _, m := range pathIDPattern.FindAllStringSubmatchIndex(path, -1) {
		resource := path[m[2]:m[3]]
		currentID, err := strconv.Atoi(path[m[4]:m[5]])
		if err != nil {
			continue
		}

		probes := adjacentIDs(currentID)

		originalResp, err := getResp(session, ep.URL)
		if err != nil {
			continue
		}
		originalLen := len(originalResp.Body)
		originalCode := originalResp.StatusCode
		if originalCode != 200 && originalCode != 201 {
			continue
		}

		for _, probeID := range probes {
			newPath := path[:m[4]] + strconv.Itoa(probeID) + path[m[5]:]
			newU := *parsed
			newU.Path = newPath
			newU.Fragment = ""
			newURL := newU.String()

			resp, err := getResp(session, newURL)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 && absInt(len(resp.Body)-originalLen) < int(float64(len(resp.Body))*0.5) {
				if len(resp.Body) > 50 {
					f := findings.NewFinding(
						fmt.Sprintf("Потенциальный IDOR — /%s/{id} доступен без смены владельца", resource),
						findings.Medium,
						"IDOR / BOLA",
						"CWE-639",
						newURL,
						fmt.Sprintf("Запрос к /%s/%d вернул 200 и ответ, по объёму схожий "+
							"с оригиналом. Текущий ID: %d, проверенный: %d. "+
							"Если пользователь может читать данные другого пользователя — это BOLA "+
							"(Broken Object Level Authorization). Похожий объём ответа сам по себе "+
							"не доказывает доступ к чужим данным — требуется проверка содержимого.",
							resource, probeID, currentID, probeID),
						"1. Проверяйте на стороне сервера, что объект принадлежит аутентифицированному пользователю.\n"+
							"2. Используйте indirect references (UUID) вместо последовательных числовых ID.\n"+
							"3. Централизованная авторизация на уровне ORM/репозитория.",
						fmt.Sprintf("# Оригинальный запрос:\ncurl -sk %s '%s'\n\n"+
							"# Замена ID на соседний:\ncurl -sk %s '%s'", curlAuth, ep.URL, curlAuth, newURL),
					)
					f.Evidence = fmt.Sprintf("Оригинал (%d): HTTP %d, %d байт\n"+
						"Зонд (%d): HTTP %d, %d байт\n"+
						"Фрагмент ответа: %s",
						currentID, originalCode, originalLen,
						probeID, resp.StatusCode, len(resp.Body), truncate(resp.Body, 200))

					store.AddCandidate(&findings.Candidate{
						Finding: f,
						Kind:    "idor",
						Context: map[string]any{"original_resp": originalResp, "probe_resp": resp},
					})
					break // One candidate per endpoint is enough
				}
			}
		}
	}
}

func checkNumericIDsInParams(session *httpsession.Session, ep crawler.Endpoint, curlAuth string, store *findings.FindingStore) {
	parsed, err := url.Parse(ep.URL)
	if err != nil {
		return
	}
	qs := parsed.Query()

	idParams := make(map[string]string)
	for k, v := range qs {
		if len(v) == 0 {
			continue
		}
		if !idPattern.MatchString(v[0]) {
			continue
		}
		if _, ok := idorParamNames[strings.ToLower(k)]; ok {
			idParams[k] = v[0]
		}
	}
	if len(idParams) == 0 {
		return
	}

	originalResp, err := getResp(session, ep.URL)
	if err != nil || (originalResp.StatusCode != 200 && originalResp.StatusCode != 201) {
		return
	}
	originalLen := len(originalResp.Body)

	for param, currentVal := range idParams {
		currentID, err := strconv.Atoi(currentVal)
		if err != nil {
			continue
		}
		for _, probeID := range adjacentIDs(currentID) {
			newQS := cloneValues(qs)
			newQS.Set(param, strconv.Itoa(probeID))
			newU := *parsed
			newU.RawQuery = newQS.Encode()
			newU.Fragment = ""
			newURL := newU.String()

			resp, err := getResp(session, newURL)
			if err != nil {
				continue
			}
			if resp.StatusCode == 200 && len(resp.Body) > 50 {
				if absInt(len(resp.Body)-originalLen) < int(float64(len(resp.Body))*0.6) {
					f := findings.NewFinding(
						fmt.Sprintf("Потенциальный IDOR — параметр '%s'", param),
						findings.High,
						"IDOR / BOLA",
						"CWE-639",
						ep.URL,
						fmt.Sprintf("Параметр '%s=%d' (заменён с %d) "+
							"вернул успешный ответ. Возможна утечка данных другого пользователя.", param, probeID, currentID),
						"1. Авторизация на уровне объекта — проверьте owner_id == current_user.id.\n"+
							"2. Используйте GUID/UUID вместо числовых ID.\n"+
							"3. Логируйте запросы с чужими ID.",
						fmt.Sprintf("# Оригинал:\ncurl -sk %s '%s'\n\n# IDOR:\ncurl -sk %s '%s'", curlAuth, ep.URL, curlAuth, newURL),
					)
					f.Parameter = param
					f.Evidence = fmt.Sprintf("Оригинал (%d): %d байт\nЗонд (%d): %d байт\nОтвет: %s",
						currentID, originalLen, probeID, len(resp.Body), truncate(resp.Body, 200))
					store.Add(f)
					break
				}
			}
		}
	}
}

func checkUUIDInPath(session *httpsession.Session, ep crawler.Endpoint, curlAuth string, store *findings.FindingStore) {
	parsed, err := url.Parse(ep.URL)
	if err != nil {
		return
	}
	uuids := uuidPattern.FindAllString(parsed.Path, -1)
	if len(uuids) == 0 {
		return
	}

	originalResp, err := getResp(session, ep.URL)
	if err != nil || (originalResp.StatusCode != 200 && originalResp.StatusCode != 201) {
		return
	}

	for _, currentUUID := range uuids {
		probeUUID := randomUUID()
		newPath := strings.Replace(parsed.Path, currentUUID, probeUUID, 1)
		newU := *parsed
		newU.Path = newPath
		newU.Fragment = ""
		newURL := newU.String()

		resp, err := getResp(session, newURL)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 && len(resp.Body) > 100 {
			f := findings.NewFinding(
				"Потенциальный IDOR — замена UUID в пути вернула 200",
				findings.Medium,
				"IDOR / BOLA",
				"CWE-639",
				ep.URL,
				fmt.Sprintf("Замена UUID '%s' на случайный '%s' "+
					"вернула HTTP 200. Требует ручной проверки — возможна авторизация без проверки владельца.",
					currentUUID, probeUUID),
				"Убедитесь, что проверяется принадлежность объекта аутентифицированному пользователю.",
				fmt.Sprintf("# Оригинал:\ncurl -sk %s '%s'\n\n# Замена UUID:\ncurl -sk %s '%s'", curlAuth, ep.URL, curlAuth, newURL),
			)
			f.Evidence = fmt.Sprintf("Новый UUID: %s\nСтатус: %d\nОтвет: %s", probeUUID, resp.StatusCode, truncate(resp.Body, 200))
			store.Add(f)
		}
	}
}

func adjacentIDs(current int) []int {
	var probes []int
	for _, delta := range []int{1, 2, -1, -2} {
		candidate := current + delta
		if candidate > 0 {
			probes = append(probes, candidate)
		}
	}
	if len(probes) > 4 {
		probes = probes[:4]
	}
	return probes
}

func getResp(session *httpsession.Session, rawurl string) (*httpsession.Response, error) {
	return session.Get(rawurl, nil)
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[k] = cp
	}
	return out
}

func randomUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
