"""Read-only checks on one HTTP response and one ordinary TLS connection.

No crawler, payload generation, authentication, form submission or script execution.
Only the requested URL and up to three in-scope redirects are fetched.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import Message
from html.parser import HTMLParser
from http.client import HTTPException
import re
import socket
import ssl
import time
import unicodedata
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from .models import Finding, ScanResult
from . import __version__


MODULES = {
    "headers": "HTTP-заголовки и CSP",
    "cookies": "Атрибуты cookies",
    "tls": "TLS и сертификат",
    "html": "Формы, ресурсы и mixed content",
    "disclosure": "Публичные признаки раскрытия информации",
}
MAX_BODY = 1024 * 1024
MAX_REDIRECTS = 3
MAX_HTML_ELEMENTS = 12000
MAX_HEADER_BYTES = 128 * 1024
MAX_HEADERS = 500
HEADERS_DOC = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
CSP_DOC = "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
COOKIE_DOC = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie"
TLS_DOC = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"


def _clean(value: str, limit: int = 350) -> str:
    """Keep untrusted values from injecting terminal controls or bidi formatting."""
    return "".join(c for c in str(value) if unicodedata.category(c)[0] != "C")[:limit]


def normalize_url(url: str) -> str:
    text = str(url).strip()
    if not text or len(text) > 8192:
        raise ValueError("Введите URL длиной от 1 до 8192 символов.")
    if any(unicodedata.category(c)[0] == "C" for c in text):
        raise ValueError("URL содержит управляющие символы.")
    if "://" not in text:
        text = "https://" + text
    try:
        parts = urlsplit(text)
        if parts.scheme.lower() not in {"http", "https"}:
            raise ValueError("Разрешены только URL с http:// или https://.")
        if not parts.hostname or parts.username is not None or parts.password is not None:
            raise ValueError("Укажите имя хоста без логина и пароля в URL.")
        host = parts.hostname.encode("idna").decode("ascii").lower()
        if any(char.isspace() for char in host) or "\\" in host or "%" in host:
            raise ValueError("Некорректное имя хоста.")
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Порт должен быть в диапазоне 1–65535.")
        netloc = f"[{host}]" if ":" in host else host
        if port is not None:
            netloc += f":{port}"
        path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
        query = quote(parts.query, safe="%=&?/:@!$'()*+,;~-._")
        return urlunsplit((parts.scheme.lower(), netloc, path, query, ""))
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith(("Разрешены", "Укажите", "Некорректное", "Порт")):
            raise
        raise ValueError("Не удалось разобрать HTTP(S) URL.") from None


def display_url(url: str) -> str:
    """Never put URL query values or credentials into saved reports."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        host = f"[{host}]" if ":" in host else host
        if parts.port:
            host += f":{parts.port}"
        query = urlencode([(_clean(k, 100), "[redacted]")
                           for k, _ in parse_qsl(parts.query, keep_blank_values=True)])
        return _clean(urlunsplit((parts.scheme, host, parts.path, query, "")), 1500)
    except (ValueError, UnicodeError):
        return "[URL не отображён]"


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    return parts.scheme, parts.hostname or "", parts.port or (443 if parts.scheme == "https" else 80)


def _redirect_allowed(source: str, target: str) -> bool:
    old, new = _origin(source), _origin(target)
    return old == new or (old == ("http", new[1], 80) and new == ("https", old[1], 443))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class _Response:
    url: str
    status: int
    headers: Message
    body: bytes
    truncated: bool = False


def _fetch(url: str, timeout: float, result: ScanResult) -> _Response:
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
    visited: set[str] = set()
    deadline = time.monotonic() + min(timeout * 4, 60.0)
    current = url
    for index in range(MAX_REDIRECTS + 1):
        if current in visited:
            raise ValueError("Обнаружен цикл перенаправлений.")
        visited.add(current)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Истекло время получения страницы.")
        request = Request(current, headers={"User-Agent": f"Lulz/{__version__} (passive web review)",
                          "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
                          "Accept-Encoding": "identity"}, method="GET")
        result.metadata["http_requests"] += 1
        try:
            response = opener.open(request, timeout=min(timeout, remaining))
        except HTTPError as error:
            response = error
        with response:
            code = response.getcode()
            headers = response.headers
            if code in {301, 302, 303, 307, 308} and headers.get("Location"):
                destination = normalize_url(urljoin(current, headers["Location"]))
                if not _redirect_allowed(current, destination):
                    result.errors.append("Переход на другой origin или понижение HTTPS до HTTP остановлен. "
                                         "При необходимости введите адрес назначения отдельно.")
                    result.metadata["incomplete"] = True
                    return _Response(current, code, headers, b"")
                if index == MAX_REDIRECTS:
                    result.errors.append("Достигнут предел: не более трёх перенаправлений.")
                    result.metadata["incomplete"] = True
                    return _Response(current, code, headers, b"")
                current = destination
                continue
            encoding = headers.get("Content-Encoding", "identity").strip().lower()
            if encoding not in {"", "identity"}:
                result.notes.append("Сервер прислал сжатое содержимое вопреки Accept-Encoding: identity; "
                                    "HTML не анализировался.")
                result.metadata["incomplete"] = True
                return _Response(current, code, headers, b"")
            chunks: list[bytes] = []
            size = 0
            while size <= MAX_BODY:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Истекло время чтения страницы.")
                raw_socket = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
                if raw_socket is not None and raw_socket.fileno() >= 0:
                    raw_socket.settimeout(min(timeout, remaining))
                reader = getattr(response, "read1", response.read)
                data = reader(min(65536, MAX_BODY + 1 - size))
                if not data:
                    break
                chunks.append(data)
                size += len(data)
            body = b"".join(chunks)
            truncated = len(body) > MAX_BODY
            if truncated:
                result.metadata["incomplete"] = True
                result.notes.append("Тело ответа ограничено 1 МиБ; остальное содержимое не анализировалось.")
            return _Response(current, code, headers, body[:MAX_BODY], truncated)
    raise ValueError("Не удалось завершить получение страницы.")


def _add(result: ScanResult, rule: str, title: str, severity: str, category: str,
         description: str, evidence: str, remediation: str, *, cwe: str = "",
         status: str = "observed", references: list[str] | None = None,
         location: str = "") -> None:
    result.findings.append(Finding(rule_id=rule, title=title, severity=severity, category=category,
        description=description, evidence=_clean(evidence, 1000), remediation=remediation,
        location=location or result.metadata.get("final_url", result.target),
        confidence="high" if status == "observed" else "medium", status=status,
        cwe=[cwe] if cwe else [], references=references or [HEADERS_DOC]))


class _HTMLLimit(ValueError):
    pass


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.resources: list[tuple[str, str, bool]] = []
        self.forms: list[dict] = []
        self.current_form: dict | None = None
        self.meta_policies: list[str] = []
        self.base: str | None = None
        self.count = 0
        self.password_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.count += 1
        if self.count > MAX_HTML_ELEMENTS:
            raise _HTMLLimit("Достигнут предел HTML-элементов.")
        values = dict(attrs)
        if tag == "base" and self.base is None and values.get("href"):
            self.base = values["href"]
        if tag == "meta" and (values.get("http-equiv") or "").lower() == "content-security-policy":
            self.meta_policies.append(values.get("content") or "")
        if tag in {"script", "img", "iframe", "audio", "video", "source", "embed"} and values.get("src"):
            self.resources.append((tag, values["src"], bool(values.get("integrity"))))
        if tag == "link" and values.get("href") and "stylesheet" in (values.get("rel") or "").split():
            self.resources.append(("stylesheet", values["href"], bool(values.get("integrity"))))
        if tag == "object" and values.get("data"):
            self.resources.append((tag, values["data"], False))
        if tag == "form":
            form = {"action": values.get("action") or "", "method": (values.get("method") or "get").lower(),
                    "password": False, "line": self.getpos()[0]}
            self.forms.append(form)
            self.current_form = form
        if tag == "input" and (values.get("type") or "").lower() == "password":
            self.password_count += 1
            if self.current_form is not None and values.get("name") and "disabled" not in values and not values.get("form"):
                self.current_form["password"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.current_form = None


def _policies(values: list[str]) -> list[dict[str, list[str]]]:
    parsed = []
    for value in values:
        for raw_policy in value.split(","):
            policy: dict[str, list[str]] = {}
            for entry in raw_policy.split(";"):
                tokens = entry.split()
                if tokens:
                    policy.setdefault(tokens[0].lower(), tokens[1:])
            if policy:
                parsed.append(policy)
    return parsed


def _scripts(policy: dict, element: bool = True) -> list[str] | None:
    if element and "script-src-elem" in policy:
        return policy["script-src-elem"]
    return policy.get("script-src", policy.get("default-src"))


def _has_nonce_or_hash(tokens: list[str]) -> bool:
    return any(re.fullmatch(r"'(?:nonce|sha256|sha384|sha512)-[A-Za-z0-9+/=_-]+'", t) for t in tokens)


def _allows_inline(tokens: list[str] | None) -> bool:
    return tokens is None or ("'unsafe-inline'" in tokens and not _has_nonce_or_hash(tokens))


def _broad_scripts(tokens: list[str] | None) -> bool:
    if tokens is None:
        return True
    if "'strict-dynamic'" in tokens and _has_nonce_or_hash(tokens):
        return False
    return any(t in tokens for t in ("*", "http:", "https:", "data:"))


def _check_headers(response: _Response, page: _Page | None, result: ScanResult) -> None:
    headers = response.headers
    https = urlsplit(response.url).scheme == "https"
    html = page is not None
    if https:
        hsts = headers.get("Strict-Transport-Security", "")
        max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*([0-9]+)\s*(?:;|$)", hsts, re.I)
        if not max_age or not max_age.group(1).strip("0"):
            _add(result, "WEB-HSTS", "HSTS не включён в этом ответе", "low", "headers",
                 "Отсутствует действующий max-age. Это наблюдение о политике HTTPS, не подтверждение эксплуатации.",
                 "Strict-Transport-Security отсутствует, некорректен или max-age=0.",
                 "После проверки поддержки HTTPS включите HSTS; includeSubDomains и preload добавляйте осознанно.")
    if headers.get("X-Content-Type-Options", "").strip().lower() != "nosniff":
        _add(result, "WEB-NOSNIFF", "Не задан X-Content-Type-Options: nosniff", "low", "headers",
             "Явная защита от MIME sniffing в этом ответе отсутствует.", "Значение nosniff не обнаружено.",
             "Возвращайте корректный Content-Type и X-Content-Type-Options: nosniff.")
    if not headers.get("Content-Type"):
        _add(result, "WEB-CONTENT-TYPE", "Ответ не содержит Content-Type", "low", "headers",
             "Тип представления не объявлен сервером; значение риска зависит от содержимого и его происхождения.",
             "Content-Type отсутствует.", "Укажите корректный MIME-тип и кодировку для текстовых ответов.")
    if html:
        raw_policies = headers.get_all("Content-Security-Policy", [])
        header_policies = _policies(raw_policies)
        policies = header_policies + _policies(page.meta_policies)
        if not policies:
            report_only = bool(headers.get("Content-Security-Policy-Report-Only"))
            _add(result, "WEB-CSP-MISSING", "Не обнаружена применяемая CSP", "low", "headers",
                 "CSP — дополнительная защита. Её отсутствие само по себе не доказывает XSS.",
                 "Обнаружена только Report-Only CSP; она не блокирует выполнение." if report_only else "CSP не найдена в заголовках и прочитанной HTML-разметке.",
                 "Разработайте CSP для приложения и сначала проверьте её в Report-Only, затем включите применение.",
                 references=[CSP_DOC])
        else:
            if not header_policies:
                _add(result, "WEB-CSP-META", "CSP доставляется через HTML meta", "info", "headers",
                     "Meta CSP не поддерживает все возможности заголовка, в частности frame-ancestors.",
                     "CSP найдена в meta, заголовок CSP отсутствует.",
                     "По возможности передавайте CSP HTTP-заголовком.", references=[CSP_DOC])
            if any("'unsafe-inline'" in (_scripts(p) or []) for p in policies) and all(_allows_inline(_scripts(p)) for p in policies):
                _add(result, "WEB-CSP-INLINE", "CSP допускает inline-скрипты", "low", "headers",
                     "Наблюдаемая политика содержит эффективное unsafe-inline. Это не является подтверждением XSS.",
                     "unsafe-inline не перекрыт nonce/hash или более строгой параллельной политикой.",
                     "Перейдите на nonce/hash для разрешённых скриптов и проверьте совместимость приложения.", references=[CSP_DOC])
            if all(_broad_scripts(_scripts(p)) for p in policies):
                _add(result, "WEB-CSP-SOURCES", "Широкие источники скриптов в CSP", "low", "headers",
                     "Каждая прочитанная CSP оставляет широкие источники или не ограничивает загрузку скриптов.",
                     "Найдены общий wildcard, широкая схема либо отсутствующее ограничение script-src/default-src.",
                     "Уточните доверенные источники или внедрите строгую политику nonce/hash.", status="review", references=[CSP_DOC])
            if any("'unsafe-eval'" in (_scripts(p, False) or []) for p in policies) and all(_scripts(p, False) is None or "'unsafe-eval'" in _scripts(p, False) for p in policies):
                _add(result, "WEB-CSP-EVAL", "CSP разрешает unsafe-eval", "low", "headers",
                     "Политика допускает динамическое исполнение строк; наличие уязвимого потока данных не проверялось.",
                     "unsafe-eval не запрещён другими прочитанными CSP.",
                     "Уберите зависимость от eval и Function; затем удалите unsafe-eval.", references=[CSP_DOC])
            if all("base-uri" not in p or any(t in p["base-uri"] for t in ("*", "http:", "https:")) for p in policies):
                _add(result, "WEB-CSP-BASE", "CSP не ограничивает base-uri узким списком", "info", "headers",
                     "default-src не заменяет директиву base-uri. Применимость зависит от использования HTML base и обработки разметки.",
                     "В прочитанных CSP нет ограничивающей base-uri; доказательство HTML-инъекции не получено.",
                     "Если base не нужен, задайте base-uri 'none'; иначе ограничьте допустимые адреса, например 'self'.",
                     status="review", references=[CSP_DOC])
        frame_policy = any(p.get("frame-ancestors") and not any(x in p["frame-ancestors"] for x in ("*", "http:", "https:")) for p in header_policies)
        frame_header = headers.get("X-Frame-Options", "").strip().lower() in {"deny", "sameorigin"}
        if not frame_policy and not frame_header:
            _add(result, "WEB-FRAMING", "Не обнаружена ограничивающая политика встраивания", "low", "headers",
                 "Для интерактивной страницы имеет смысл ограничить встраивание во frame. Эксплуатация clickjacking не проверялась.",
                 "Нет ограничивающего frame-ancestors в CSP-заголовке или X-Frame-Options: DENY/SAMEORIGIN.",
                 "Задайте подходящий frame-ancestors; при необходимости поддержите старые браузеры X-Frame-Options.", status="review")
        if not headers.get("Referrer-Policy"):
            _add(result, "WEB-REFERRER", "Referrer-Policy явно не задана", "info", "headers",
                 "Современные браузеры используют собственную политику по умолчанию; явное значение делает поведение предсказуемым.",
                 "Referrer-Policy отсутствует.", "Укажите strict-origin-when-cross-origin либо более строгую политику по требованиям приложения.")
        if re.match(r"^1(?:\s*;|$)", headers.get("X-XSS-Protection", "").strip()):
            _add(result, "WEB-LEGACY-XSS-FILTER", "Включён устаревший X-XSS-Protection", "info", "headers",
                 "Устаревший браузерный XSS-фильтр не заменяет экранирование и CSP; отдельные реализации имели нежелательные эффекты.",
                 "X-XSS-Protection включает режим 1; содержимое параметров заголовка не сохранялось.",
                 "Для современных приложений уберите заголовок либо задайте X-XSS-Protection: 0; используйте контекстное экранирование и CSP.",
                 status="review")
    if headers.get("Access-Control-Allow-Origin", "").strip() == "*" and headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true":
        _add(result, "WEB-CORS-CONFLICT", "Несовместимые параметры CORS", "info", "headers",
             "Браузеры не разрешают credentialed CORS с origin '*'. Сочетание не подтверждает утечку данных.",
             "Access-Control-Allow-Origin: * вместе с Access-Control-Allow-Credentials: true.",
             "Для credentialed CORS используйте проверенный список origin; для публичных ресурсов отключите credentials.")
    result.checks.append({"module": "headers", "name": "HTTP-заголовки", "status": "observed",
                          "detail": "Проверен один ответ; CSP и framing оцениваются только для HTML."})


def _check_cookies(response: _Response, result: ScanResult) -> None:
    cookies = response.headers.get_all("Set-Cookie", [])
    https = urlsplit(response.url).scheme == "https"
    if len(cookies) > 100:
        result.metadata["incomplete"] = True
        result.notes.append("Получено более 100 Set-Cookie; проверены первые 100, остальные пропущены.")
    for index, raw in enumerate(cookies[:100]):
        parts = raw.split(";")
        if "=" not in parts[0]:
            result.notes.append("Один Set-Cookie не удалось разобрать; значение не сохранялось.")
            continue
        name = _clean(parts[0].split("=", 1)[0].strip(), 100)
        attrs = {item.strip().split("=", 1)[0].lower(): item.strip().split("=", 1)[1].strip() if "=" in item else ""
                 for item in parts[1:] if item.strip()}
        location = f"{result.metadata.get('final_url', result.target)} :: cookie {name} #{index + 1}"
        session_like = bool(re.search(r"session|sessid|auth|token|jwt|sid$", name, re.I))
        # Prefix matching is case-sensitive. Localhost browser exceptions are
        # left for manual review, while required attributes are checked exactly.
        secure_origin = https or (urlsplit(response.url).hostname or "").rstrip(".") == "localhost"
        if name.startswith("__Secure-") and ("secure" not in attrs or not secure_origin):
            _add(result, "WEB-COOKIE-PREFIX-SECURE", "Не соблюдены требования префикса __Secure-", "low", "cookies",
                 "В поддерживающих префикс браузерах такая cookie может быть отклонена. Это наблюдение о Set-Cookie, не подтверждение захвата сессии.",
                 f"Cookie {name}: нужен Secure и защищённый источник; значение скрыто.",
                 "Устанавливайте cookie с Secure через HTTPS; проверьте фактическое принятие браузером.",
                 references=[COOKIE_DOC], location=location)
        if name.startswith("__Host-") and ("secure" not in attrs or not secure_origin or attrs.get("path") != "/" or "domain" in attrs):
            _add(result, "WEB-COOKIE-PREFIX-HOST", "Не соблюдены требования префикса __Host-", "low", "cookies",
                 "Префикс требует Secure, Path=/, отсутствие Domain и защищённый источник; поведение зависит от поддержки браузером.",
                 f"Cookie {name}: хотя бы одно требование __Host- не выполнено; значения cookie и Domain скрыты.",
                 "Используйте HTTPS, Secure и Path=/; не задавайте Domain для __Host-cookie.",
                 references=[COOKIE_DOC], location=location)
        if "partitioned" in attrs and "secure" not in attrs:
            _add(result, "WEB-COOKIE-PARTITIONED", "Partitioned cookie без Secure", "low", "cookies",
                 "Разделённое хранение cookies требует Secure в поддерживающих браузерах; cookie может быть отклонена.",
                 f"Cookie {name}: Partitioned присутствует, Secure отсутствует; значение скрыто.",
                 "Устанавливайте Partitioned cookie с Secure через HTTPS и проверяйте поддержку целевыми браузерами.",
                 references=[COOKIE_DOC], location=location)
        if https and "secure" not in attrs:
            _add(result, "WEB-COOKIE-SECURE", "Cookie без флага Secure", "low", "cookies",
                 "Без Secure передача cookie по HTTP не запрещена этим атрибутом. HSTS и логика браузера отдельно не проверялись.",
                 f"Cookie {name}: Secure отсутствует; значение скрыто.",
                 "Для HTTPS-приложения задайте Secure, особенно для cookies сессии.",
                 cwe="CWE-614", references=[COOKIE_DOC], location=location)
        if session_like and "httponly" not in attrs:
            _add(result, "WEB-COOKIE-HTTPONLY", "Cookie с именем сессии без HttpOnly", "low", "cookies",
                 "Назначение cookie предположено только по имени; часть cookies должна быть доступна JavaScript.",
                 f"Cookie {name}: HttpOnly отсутствует; значение скрыто.",
                 "Если cookie хранит идентификатор сессии, включите HttpOnly и проверьте требования клиента.",
                 cwe="CWE-1004", status="review", references=[COOKIE_DOC], location=location)
        same_site = attrs.get("samesite", "").lower()
        if "samesite" not in attrs or same_site not in {"strict", "lax", "none"}:
            _add(result, "WEB-COOKIE-SAMESITE", "SameSite не задан явно или некорректен", "info", "cookies",
                 "Поведение зависит от браузера. Эта находка сама по себе не доказывает CSRF.",
                 f"Cookie {name}: нет корректного явного SameSite; значение cookie скрыто.",
                 "Выберите SameSite=Lax/Strict или обоснованный None; сохраните защиту от CSRF на сервере.",
                 references=[COOKIE_DOC], location=location)
        elif same_site == "none" and "secure" not in attrs:
            _add(result, "WEB-COOKIE-NONE", "SameSite=None без Secure", "low", "cookies",
                 "Современные браузеры требуют Secure для SameSite=None и могут отклонить такую cookie.",
                 f"Cookie {name}: SameSite=None, Secure отсутствует.",
                 "Добавьте Secure и HTTPS либо выберите подходящее другое значение SameSite.",
                 references=[COOKIE_DOC], location=location)
    result.checks.append({"module": "cookies", "name": "Set-Cookie", "status": "observed",
                          "detail": f"Получено cookies: {len(cookies)}. Значения не сохраняются."})


def _check_html(response: _Response, page: _Page | None, result: ScanResult) -> None:
    if page is None:
        result.checks.append({"module": "html", "name": "HTML", "status": "skipped", "detail": "Ответ не является HTML."})
        return
    try:
        base = normalize_url(urljoin(response.url, page.base or ""))
    except ValueError:
        base = response.url
        result.notes.append("Некорректный base URL в HTML пропущен.")
    https = urlsplit(response.url).scheme == "https"
    mixed = []
    no_integrity = []
    for tag, raw_url, integrity in page.resources:
        try:
            resource = urljoin(base, raw_url)
            parts = urlsplit(resource)
            if parts.scheme not in {"http", "https"}:
                continue
            resource = normalize_url(resource)
            parts = urlsplit(resource)
        except ValueError:
            result.notes.append("Некорректный URL ресурса пропущен; ресурс не запрашивался.")
            continue
        if https and parts.scheme == "http":
            mixed.append(f"{tag}: {display_url(resource)}")
        if tag in {"script", "stylesheet"} and parts.scheme in {"http", "https"} and _origin(resource) != _origin(response.url) and not integrity:
            no_integrity.append(f"{tag}: {display_url(resource)}")
    if mixed:
        _add(result, "WEB-MIXED-CONTENT", "В разметке найдены HTTP-ресурсы", "low", "html",
             "HTTPS-страница ссылается на HTTP-ресурсы. Браузер может заблокировать или автоматически обновить их до HTTPS.",
             " | ".join(mixed[:6]), "Замените ссылки ресурсов на HTTPS и проверьте поведение в браузере.",
             cwe="CWE-319", status="review")
    if no_integrity:
        _add(result, "WEB-SRI", "Внешние скрипты/стили без integrity", "info", "html",
             "Для части CDN-ресурсов можно закрепить ожидаемое содержимое через SRI; это не подходит для каждого динамического ресурса.",
             " | ".join(no_integrity[:6]), "Оцените доверие к источникам и добавьте SRI для неизменяемых ресурсов.", status="review")
    if page.password_count and not https:
        _add(result, "WEB-PASSWORD-HTTP", "Поле пароля на HTTP-странице", "medium", "html",
             "Страница с password-полем получена без TLS; канал доставки формы не защищён HTTPS.",
             f"Password-полей: {page.password_count}; схема страницы — HTTP.",
             "Доставляйте страницу и обрабатывайте вход только через HTTPS.", cwe="CWE-319")
    for form in page.forms:
        try:
            action = normalize_url(urljoin(base, form["action"])) if form["action"] else response.url
        except ValueError:
            result.notes.append("Некорректный или не HTTP(S) action формы пропущен; форма не отправлялась.")
            continue
        form_location = f"{result.metadata.get('final_url', result.target)} :: HTML line {form['line']}"
        if form["password"] and form["method"] not in {"post", "dialog"}:
            _add(result, "WEB-PASSWORD-GET", "Форма пароля использует GET", "medium", "html",
                 "Именованное password-поле находится в форме с GET или неизвестным методом (обычно GET по умолчанию). "
                 "JavaScript может менять фактическую отправку; он не выполнялся.",
                 f"Метод: {_clean(form['method'])}; адрес формы: {display_url(action)}.",
                 "Для отправки учётных данных используйте POST через HTTPS и исключите пароли из URL.",
                 cwe="CWE-598", status="review", location=form_location)
        if https and urlsplit(action).scheme == "http":
            _add(result, "WEB-FORM-HTTP", "Форма указывает HTTP-адрес отправки", "medium" if form["password"] else "low", "html",
                 "В action формы указан незашифрованный адрес. Форма не отправлялась; поведение JavaScript не проверялось.",
                 f"action: {display_url(action)}.", "Переведите обработчик и action формы на HTTPS.",
                 cwe="CWE-319", status="review", location=form_location)
    result.checks.append({"module": "html", "name": "Разметка страницы", "status": "observed",
                          "detail": f"Форм: {len(page.forms)}; ресурсов: {len(page.resources)}. Формы не отправлялись; JavaScript не исполнялся."})


def _check_disclosure(response: _Response, text: str, result: ScanResult) -> None:
    visible = [name for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version") if response.headers.get(name)]
    if visible:
        _add(result, "WEB-BANNERS", "Служебные заголовки раскрывают сведения о платформе", "info", "disclosure",
             "Публичный баннер не подтверждает версию установленного компонента или наличие CVE.",
             "Присутствуют заголовки: " + ", ".join(visible) + ". Значения не сохранялись.",
             "При необходимости уберите необязательные служебные заголовки; обновляйте компоненты независимо от баннеров.")
    signatures = {
        "Python traceback": r"Traceback \(most recent call last\):",
        "Django debug page": r"You're seeing this error because you have DEBUG\s*=\s*True",
        "PHP fatal error": r"(?:<b>)?Fatal error(?:</b>)?:\s*(?:Uncaught|Call to|Allowed memory)",
        ".NET stack trace": r"\[\w+(?:Exception|Error)(?:\s*\([^\)]*\))?:[^\n]{0,100}\]",
    }
    hits = [label for label, pattern in signatures.items() if re.search(pattern, text, re.I)]
    if hits:
        _add(result, "WEB-DEBUG", "В ответе есть признаки подробной страницы ошибки", "low", "disclosure",
             "Совпадение текстового шаблона может относиться и к документации. Детали ответа не сохранялись.",
             "Совпавшие признаки: " + ", ".join(hits) + ".", "Проверьте контекст; на production возвращайте краткие ошибки, а детали храните в закрытых логах.",
             cwe="CWE-209", status="review")
    result.checks.append({"module": "disclosure", "name": "Публичные сведения", "status": "observed",
                          "detail": "Проверены только баннеры и шаблоны ошибок в полученном ответе; скрытые пути не запрашивались."})


def _check_tls(url: str, timeout: float, result: ScanResult) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https":
        _add(result, "WEB-HTTP", "URL использует HTTP", "low", "tls",
             "Для указанного URL соединение не защищается TLS. HTTPS на другом адресе не проверялся.",
             "Схема URL: HTTP.", "Используйте HTTPS и корректные перенаправления для этого ресурса.", cwe="CWE-319")
        result.checks.append({"module": "tls", "name": "TLS", "status": "skipped", "detail": "Схема HTTP: TLS-соединение не открывалось."})
        return
    result.metadata["tls_handshakes"] += 1
    try:
        with socket.create_connection((parts.hostname, parts.port or 443), timeout=timeout) as tcp:
            with ssl.create_default_context().wrap_socket(tcp, server_hostname=parts.hostname) as conn:
                certificate = conn.getpeercert()
                protocol = conn.version() or "unknown"
                cipher = conn.cipher()
        result.metadata["tls"] = {"negotiated_protocol": protocol, "cipher": cipher[0] if cipher else "unknown",
                                  "certificate_verified": True}
        not_after = certificate.get("notAfter")
        if not_after:
            expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
            days = (expiry - datetime.now(timezone.utc)).total_seconds() / 86400
            result.metadata["tls"]["certificate_expires"] = expiry.isoformat()
            result.metadata["tls"]["days_remaining"] = round(days, 1)
            if days < 30:
                _add(result, "WEB-CERT-EXPIRY", "Сертификат скоро истечёт", "medium" if days < 7 else "low", "tls",
                     "Обычное TLS-соединение прошло проверку цепочки и имени хоста, но срок сертификата подходит к концу.",
                     f"До окончания: {days:.1f} суток; дата UTC: {expiry.isoformat()}.",
                     "Проверьте автоматическое продление и установку обновлённого сертификата.", references=[TLS_DOC])
        result.checks.append({"module": "tls", "name": "TLS-соединение", "status": "observed",
                              "detail": f"Согласован {protocol}; сертификат проверен системным хранилищем. Старые протоколы, отзыв сертификата и все cipher suites не перебирались."})
    except ssl.SSLCertVerificationError:
        _add(result, "WEB-CERT-INVALID", "Проверка TLS-сертификата не пройдена", "medium", "tls",
             "Системный TLS-клиент не смог подтвердить цепочку доверия, срок или имя. Причину нужно проверить в контексте вашей PKI.",
             "SSLCertVerificationError; обход проверки не выполнялся.",
             "Проверьте имя хоста, срок, цепочку сертификатов и системное хранилище доверия.", references=[TLS_DOC])
        result.errors.append("TLS: проверка сертификата не пройдена; результат неполный.")
    except (OSError, ssl.SSLError, ValueError):
        result.errors.append("TLS: обычное соединение не установлено; настройки TLS не оценены.")


def _analyze_response(response: _Response, result: ScanResult, *, body_available: bool = True,
                      decoded_text: str | None = None) -> None:
    """Shared response analysis. This helper has no transport side effects."""
    selected = result.modules
    result.metadata.update(final_url=display_url(response.url), http_status=response.status,
                           body_bytes=len(response.body), body_available=body_available)
    if response.status >= 400:
        result.errors.append(f"Получен HTTP {response.status}; анализ относится к странице ошибки или ограничению доступа.")
    content_type = response.headers.get_content_type()
    is_html = content_type in {"text/html", "application/xhtml+xml"}
    is_text = content_type.startswith("text/") or content_type in {
        "application/json", "application/problem+json", "application/xml",
        "application/xhtml+xml", "application/javascript", "application/x-javascript",
    } or content_type.endswith(("+json", "+xml"))
    text = ""
    if body_available:
        charset = response.headers.get_content_charset() or "utf-8"
        try:
            text = decoded_text if decoded_text is not None else response.body.decode(charset, errors="replace")
        except LookupError:
            text = response.body.decode("utf-8", errors="replace")
            result.notes.append("Неизвестная кодировка ответа; использована UTF-8 с заменой нечитаемых символов.")
    elif (is_html and any(module in selected for module in ("headers", "html"))) or (is_text and "disclosure" in selected):
        result.metadata["incomplete"] = True
        result.notes.append("Тело ответа отсутствует: относящиеся к нему проверки пропущены; заголовки проанализированы отдельно.")
    page = None
    if body_available and is_html and response.body:
        page = _Page()
        try:
            page.feed(text)
            page.close()
        except (ValueError, RecursionError):
            result.metadata["incomplete"] = True
            result.notes.append("HTML разобран частично: достигнут предел или встретилась неподдерживаемая разметка.")
    if "headers" in selected:
        _check_headers(response, page, result)
        if is_html and not body_available:
            result.checks.append({"module": "headers", "name": "HTML-зависимые заголовки", "status": "skipped",
                                  "detail": "Без тела ответа нельзя оценить meta CSP и интерактивную разметку; отсутствие CSP не утверждается."})
    if "cookies" in selected:
        _check_cookies(response, result)
    if "html" in selected:
        if body_available:
            _check_html(response, page, result)
        else:
            result.checks.append({"module": "html", "name": "HTML", "status": "skipped",
                                  "detail": "Тело ответа недоступно." if is_html else "Ответ не объявлен как HTML."})
    if "disclosure" in selected:
        _check_disclosure(response, text if body_available and is_text else "", result)
        if not body_available and is_text:
            result.checks.append({"module": "disclosure", "name": "Текст ответа", "status": "skipped",
                                  "detail": "Проверены только заголовки; тело ответа отсутствует."})


def _copy_headers(headers) -> Message:
    """Validate bounded response header data without saving its values."""
    if isinstance(headers, Message):
        pairs = list(headers.raw_items())
    elif isinstance(headers, dict):
        pairs = []
        for name, value in headers.items():
            if isinstance(value, (list, tuple)):
                pairs.extend((name, item) for item in value)
            else:
                pairs.append((name, value))
    elif isinstance(headers, (list, tuple)):
        pairs = list(headers)
    else:
        raise ValueError("Заголовки ответа должны быть Message, словарём или списком пар.")
    if len(pairs) > MAX_HEADERS:
        raise ValueError("В ответе больше 500 заголовков; анализ этой записи пропущен.")
    copied = Message()
    size = 0
    for pair in pairs:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError("Некорректная структура заголовка ответа.")
        name, value = pair
        if (not isinstance(name, str) or not isinstance(value, str)
                or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in value)):
            raise ValueError("Заголовок ответа содержит недопустимые имя, тип или управляющие символы.")
        size += len(name.encode("utf-8")) + len(value.encode("utf-8"))
        if size > MAX_HEADER_BYTES:
            raise ValueError("Заголовки ответа превышают лимит 128 КиБ.")
        copied[name] = value
    return copied


def audit_response(url: str, status: int, headers, body: bytes | str,
                   modules: list[str] | None = None, body_available: bool = True) -> ScanResult:
    """Analyze a captured response as data; never fetch URLs or verify TLS.

    ``headers`` may be an email Message, a mapping or duplicate-preserving
    (name, value) pairs. A str body is already decoded (as in HAR); bytes are
    interpreted using the declared Content-Type charset. Query values, raw
    headers and response bodies are never returned in the report.
    """
    available = [key for key in MODULES if key != "tls"]
    selected = available if modules is None else []
    result = ScanResult(kind="response", target=display_url(url) if isinstance(url, str) else "[некорректный URL]", modules=selected,
                        metadata={"http_requests": 0, "tls_handshakes": 0, "incomplete": False})
    try:
        if not isinstance(url, str) or (modules is not None and (not isinstance(modules, (list, tuple)) or not all(isinstance(m, str) for m in modules))):
            raise ValueError("Некорректные типы URL или модулей.")
        if modules is not None:
            selected = list(dict.fromkeys(modules))
            result.modules = selected
        if not selected or any(module not in available for module in selected):
            raise ValueError("Выберите известные пассивные модули; TLS не проверяется по сохранённому ответу.")
        normalized = normalize_url(url)
        result.target = display_url(normalized)
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError("Сохранённый HTTP-статус должен быть числом от 100 до 599.")
        if not isinstance(body, (str, bytes, bytearray)) or not isinstance(body_available, bool):
            raise ValueError("Некорректный тип сохранённого тела ответа.")
        message = _copy_headers(headers)
        decoded = body if isinstance(body, str) else None
        payload = body.encode("utf-8") if isinstance(body, str) else bytes(body)
        truncated = len(payload) > MAX_BODY
        if truncated:
            payload = payload[:MAX_BODY]
            if decoded is not None:
                decoded = payload.decode("utf-8", errors="ignore")
            result.metadata["incomplete"] = True
            result.notes.append("Тело сохранённого ответа ограничено 1 МиБ; остаток не анализировался.")
        if not body_available:
            payload, decoded = b"", None
        _analyze_response(_Response(normalized, status, message, payload, truncated), result,
                          body_available=body_available, decoded_text=decoded)
    except (TypeError, ValueError, UnicodeError):
        # Do not echo exception strings: malformed input can carry credentials.
        result.errors.append("Сохранённый ответ некорректен или превышает лимит заголовков; проверьте URL, статус и структуру данных.")
        result.metadata["incomplete"] = True
    return result.finish()


def scan_url(url: str, modules: list[str] | None = None, timeout: float = 10.0) -> ScanResult:
    """Analyze only the user-provided resource, never probe for vulnerabilities."""
    selected = list(MODULES) if modules is None else list(dict.fromkeys(modules))
    result = ScanResult(kind="web", target=display_url(url), modules=selected,
                        metadata={"http_requests": 0, "tls_handshakes": 0, "incomplete": False})
    result.notes.append("Проверяется один URL. Это анализ наблюдаемой конфигурации, а не подтверждение отсутствия уязвимостей. "
                        "SQLi/XSS payloads, обход путей, отправка форм и исполнение JavaScript не выполняются.")
    try:
        if not selected or any(module not in MODULES for module in selected):
            raise ValueError("Выберите хотя бы один известный модуль веб-проверки.")
        timeout = float(timeout)
        if not 1 <= timeout <= 30:
            raise ValueError("Таймаут должен быть от 1 до 30 секунд.")
        normalized = normalize_url(url)
        result.target = display_url(normalized)
    except (TypeError, ValueError) as exc:
        result.errors.append(_clean(str(exc)))
        return result.finish()
    final_url = normalized
    if any(module != "tls" for module in selected):
        try:
            response = _fetch(normalized, timeout, result)
        except (OSError, URLError, ValueError, ssl.SSLError, HTTPException) as exc:
            certificate_error = isinstance(exc, ssl.SSLCertVerificationError) or isinstance(getattr(exc, "reason", None), ssl.SSLCertVerificationError)
            result.errors.append("HTTP: проверка TLS-сертификата не пройдена." if certificate_error else
                                 "HTTP: не удалось получить страницу (адрес, DNS, сеть, таймаут или ограничение ответа).")
            if "tls" in selected:
                _check_tls(normalized, timeout, result)
            return result.finish()
        final_url = response.url
        _analyze_response(response, result)
    if "tls" in selected:
        _check_tls(final_url, timeout, result)
    return result.finish()
