from __future__ import annotations
import re
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests

from ..adaptive import Candidate
from ..findings import Finding, Severity
from ..session import session_to_curl_flags

# Patterns that look like user/resource identifiers
ID_PATTERN = re.compile(r'(\d{1,10})')
UUID_PATTERN = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    re.IGNORECASE,
)
PATH_ID_PATTERN = re.compile(r'/([\w-]+)/(\d{1,10})(?:/|$)')


def run(session: requests.Session, base_url: str, endpoints: list, store) -> None:
    print("[*] Checking IDOR/BOLA...")
    curl_auth = session_to_curl_flags(session)
    timeout = getattr(session, 'timeout', 15)

    for ep in endpoints:
        if ep.method not in ("GET", "HEAD"):
            continue
        _check_numeric_ids_in_path(session, ep, curl_auth, timeout, store)
        _check_numeric_ids_in_params(session, ep, curl_auth, timeout, store)
        _check_uuid_in_path(session, ep, curl_auth, timeout, store)


def _check_numeric_ids_in_path(session, ep, curl_auth, timeout, store):
    parsed = urlparse(ep.url)
    path = parsed.path

    # Find segments like /users/123 or /api/v1/accounts/456
    for match in PATH_ID_PATTERN.finditer(path):
        resource = match.group(1)
        current_id = int(match.group(2))

        probes = _adjacent_ids(current_id)

        original_resp = _get(session, ep.url, timeout)
        if original_resp is None:
            continue
        original_len = len(original_resp.text)
        original_code = original_resp.status_code

        if original_code not in (200, 201):
            continue

        for probe_id in probes:
            new_path = path[:match.start(2)] + str(probe_id) + path[match.end(2):]
            new_url = urlunparse((
                parsed.scheme, parsed.netloc, new_path,
                parsed.params, parsed.query, ""
            ))
            resp = _get(session, new_url, timeout)
            if resp is None:
                continue

            if resp.status_code == 200 and abs(len(resp.text) - original_len) < len(resp.text) * 0.5:
                if len(resp.text) > 50:
                    store.add_candidate(Candidate(
                        finding=Finding(
                            title=f"Потенциальный IDOR — /{resource}/{{id}} доступен без смены владельца",
                            severity=Severity.MEDIUM,
                            category="IDOR / BOLA",
                            cwe="CWE-639",
                            description=(
                                f"Запрос к /{resource}/{probe_id} вернул 200 и ответ, по объёму схожий "
                                f"с оригиналом. Текущий ID: {current_id}, проверенный: {probe_id}. "
                                "Если пользователь может читать данные другого пользователя — это BOLA "
                                "(Broken Object Level Authorization). Похожий объём ответа сам по себе "
                                "не доказывает доступ к чужим данным — требуется проверка содержимого."
                            ),
                            url=new_url,
                            evidence=(
                                f"Оригинал ({current_id}): HTTP {original_code}, {original_len} байт\n"
                                f"Зонд ({probe_id}): HTTP {resp.status_code}, {len(resp.text)} байт\n"
                                f"Фрагмент ответа: {resp.text[:200]}"
                            ),
                            remediation=(
                                "1. Проверяйте на стороне сервера, что объект принадлежит аутентифицированному пользователю.\n"
                                "2. Используйте indirect references (UUID) вместо последовательных числовых ID.\n"
                                "3. Централизованная авторизация на уровне ORM/репозитория."
                            ),
                            reproduction=(
                                f"# Оригинальный запрос:\n"
                                f"curl -sk {curl_auth} '{ep.url}'\n\n"
                                f"# Замена ID на соседний:\n"
                                f"curl -sk {curl_auth} '{new_url}'"
                            ),
                        ),
                        kind="idor",
                        context={"original_resp": original_resp, "probe_resp": resp},
                    ))
                    break  # One candidate per endpoint is enough


def _check_numeric_ids_in_params(session, ep, curl_auth, timeout, store):
    parsed = urlparse(ep.url)
    qs = parse_qs(parsed.query)

    id_params = {k: v[0] for k, v in qs.items()
                 if v and ID_PATTERN.fullmatch(v[0]) and k.lower() in (
                     "id", "user_id", "userid", "account_id", "accountid",
                     "customer_id", "customerid", "uid", "pid", "oid",
                     "order_id", "orderid", "profile_id", "doc_id", "file_id",
                 )}

    if not id_params:
        return

    original_resp = _get(session, ep.url, timeout)
    if original_resp is None or original_resp.status_code not in (200, 201):
        return
    original_len = len(original_resp.text)

    for param, current_val in id_params.items():
        current_id = int(current_val)
        for probe_id in _adjacent_ids(current_id):
            new_qs = qs.copy()
            new_qs[param] = [str(probe_id)]
            new_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(new_qs, doseq=True), ""
            ))
            resp = _get(session, new_url, timeout)
            if resp is None:
                continue
            if resp.status_code == 200 and len(resp.text) > 50:
                if abs(len(resp.text) - original_len) < len(resp.text) * 0.6:
                    store.add(Finding(
                        title=f"Потенциальный IDOR — параметр '{param}'",
                        severity=Severity.HIGH,
                        category="IDOR / BOLA",
                        cwe="CWE-639",
                        description=(
                            f"Параметр '{param}={probe_id}' (заменён с {current_id}) "
                            "вернул успешный ответ. Возможна утечка данных другого пользователя."
                        ),
                        url=ep.url,
                        parameter=param,
                        evidence=(
                            f"Оригинал ({current_id}): {original_len} байт\n"
                            f"Зонд ({probe_id}): {len(resp.text)} байт\n"
                            f"Ответ: {resp.text[:200]}"
                        ),
                        remediation=(
                            "1. Авторизация на уровне объекта — проверьте owner_id == current_user.id.\n"
                            "2. Используйте GUID/UUID вместо числовых ID.\n"
                            "3. Логируйте запросы с чужими ID."
                        ),
                        reproduction=(
                            f"# Оригинал:\ncurl -sk {curl_auth} '{ep.url}'\n\n"
                            f"# IDOR:\ncurl -sk {curl_auth} '{new_url}'"
                        ),
                    ))
                    break


def _check_uuid_in_path(session, ep, curl_auth, timeout, store):
    parsed = urlparse(ep.url)
    uuids = UUID_PATTERN.findall(parsed.path)
    if not uuids:
        return

    original_resp = _get(session, ep.url, timeout)
    if original_resp is None or original_resp.status_code not in (200, 201):
        return

    for current_uuid in uuids:
        probe_uuid = str(uuid.uuid4())
        new_path = parsed.path.replace(current_uuid, probe_uuid)
        new_url = urlunparse((
            parsed.scheme, parsed.netloc, new_path,
            parsed.params, parsed.query, ""
        ))
        resp = _get(session, new_url, timeout)
        if resp is None:
            continue
        if resp.status_code == 200 and len(resp.text) > 100:
            store.add(Finding(
                title="Потенциальный IDOR — замена UUID в пути вернула 200",
                severity=Severity.MEDIUM,
                category="IDOR / BOLA",
                cwe="CWE-639",
                description=(
                    f"Замена UUID '{current_uuid}' на случайный '{probe_uuid}' "
                    "вернула HTTP 200. Требует ручной проверки — возможна авторизация без проверки владельца."
                ),
                url=ep.url,
                evidence=f"Новый UUID: {probe_uuid}\nСтатус: {resp.status_code}\nОтвет: {resp.text[:200]}",
                remediation=(
                    "Убедитесь, что проверяется принадлежность объекта аутентифицированному пользователю."
                ),
                reproduction=(
                    f"# Оригинал:\ncurl -sk {curl_auth} '{ep.url}'\n\n"
                    f"# Замена UUID:\ncurl -sk {curl_auth} '{new_url}'"
                ),
            ))


def _adjacent_ids(current: int) -> list[int]:
    probes = []
    for delta in (1, 2, -1, -2):
        candidate = current + delta
        if candidate > 0:
            probes.append(candidate)
    return probes[:4]


def _get(session, url, timeout):
    try:
        return session.get(url, timeout=timeout)
    except Exception:
        return None
