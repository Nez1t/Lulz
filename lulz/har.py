"""Offline review of HTTP responses recorded in a HAR file.

Request headers, cookies, POST data and bodies never leave this process. No URL
from a capture is fetched, no request is replayed and no JavaScript is executed.
The HAR 1.2 draft format is documented at https://webperfwg.org/specs/HAR/Overview.html.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

from .models import ScanResult
from .web import MODULES as WEB_MODULES, MAX_BODY, audit_response, display_url, normalize_url, _clean


MODULES = {key: value for key, value in WEB_MODULES.items() if key != "tls"}
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_ENTRIES = 500
MAX_TOTAL_BODY_BYTES = 16 * 1024 * 1024
MAX_FINDINGS = 5000
MAX_CAPTURE_HEADERS = 500


def _host_filter(host: str | None) -> str | None:
    if host is None or host == "":
        return None
    if not isinstance(host, str) or any(c in host for c in "/?#@*\\") or any(c.isspace() for c in host):
        raise ValueError("Фильтр host должен содержать только точное имя хоста без URL, wildcard и порта.")
    # Bracketed IPv6 is accepted; bare IPv6 is rejected rather than guessing a port.
    normalized = normalize_url("https://" + host)
    parts = urlsplit(normalized)
    if parts.port is not None:
        raise ValueError("В фильтре host не указывайте порт.")
    name = (parts.hostname or "").rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(name))
    except ValueError:
        if len(name) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                      for label in name.split(".")):
            raise ValueError("Некорректный фильтр имени хоста.") from None
    return name


def _captured_host(url: str) -> str:
    name = (urlsplit(url).hostname or "").rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(name))
    except ValueError:
        return name


def _headers(response: dict) -> list[tuple[str, str]]:
    raw = response.get("headers")
    if not isinstance(raw, list) or len(raw) > MAX_CAPTURE_HEADERS:
        raise ValueError("Отсутствуют заголовки ответа или превышен лимит 500 заголовков.")
    pairs = []
    for header in raw:
        if not isinstance(header, dict) or not isinstance(header.get("name"), str) or not isinstance(header.get("value"), str):
            raise ValueError("Некорректная структура заголовков ответа.")
        pairs.append((header["name"], header["value"]))
    return pairs


def _mime(headers: list[tuple[str, str]]) -> str:
    for name, value in headers:
        if name.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower()
    return "text/plain"  # Mirrors email Message's fallback, without fabricating a header.


def _textual(mime: str) -> bool:
    return mime.startswith("text/") or mime in {
        "application/json", "application/problem+json", "application/xml", "application/xhtml+xml",
        "application/javascript", "application/x-javascript",
    } or mime.endswith(("+json", "+xml"))


def _body(response: dict, method: str, remaining: int, needed: bool) -> tuple[bytes | str, bool, list[str]]:
    """Return only bounded decoded data, availability and fixed diagnostic text."""
    if not needed:
        return b"", False, []
    if response["status"] in {204, 205, 304} or method == "HEAD":
        return b"", True, []
    content = response.get("content")
    if not isinstance(content, dict):
        return b"", False, ["Тело отсутствует или поле content некорректно."]
    text = content.get("text")
    if text is None:
        if type(content.get("size")) is int and content["size"] == 0:
            return b"", True, []
        return b"", False, ["Текст ответа не включён в HAR; проверки тела пропущены."]
    if not isinstance(text, str):
        return b"", False, ["Поле content.text имеет неподдерживаемый тип."]
    if not text:
        if type(content.get("size")) is int and content["size"] > 0:
            return b"", False, ["Текст HAR пуст, хотя указан ненулевой размер тела; проверки тела пропущены."]
        return b"", True, []
    if remaining <= 0:
        return b"", False, ["Достигнут общий бюджет анализа тел 16 МиБ; следующие тела пропущены."]
    encoding = content.get("encoding", "")
    limit = min(MAX_BODY, remaining)
    if encoding in ("", None):
        payload = text.encode("utf-8")
        if len(payload) > limit:
            return payload[:limit].decode("utf-8", errors="ignore"), True, ["Тело ограничено 1 МиБ или остатком общего бюджета; анализ частичный."]
        # HAR text is already HTTP-decoded Unicode. Do not decode it a second
        # time using the original (possibly non-UTF-8) Content-Type charset.
        return text, True, []
    if encoding == "base64":
        compact = "".join(text.split())
        if len(compact) > 4 * ((limit + 2) // 3):
            return b"", False, ["Base64-тело превышает лимит; оно не декодировалось и не анализировалось."]
        try:
            payload = base64.b64decode(compact.encode("ascii"), validate=True)
        except (ValueError, binascii.Error, UnicodeError):
            return b"", False, ["Некорректное base64-тело пропущено."]
        if len(payload) > limit:
            return b"", False, ["Декодированное тело превышает лимит; проверки тела пропущены."]
        return payload, True, []
    return b"", False, ["Неподдерживаемое поле content.encoding; тело не анализировалось."]


def scan_har(path: str, modules: list[str] | None = None, host: str | None = None) -> ScanResult:
    """Audit up to 500 recorded responses with an optional exact-host filter."""
    result = ScanResult(kind="har", target=_clean(str(path), 1500), modules=[], metadata={
        "http_requests": 0, "tls_handshakes": 0, "scope_host": None,
        "entries_total": 0, "entries_considered": 0, "entries_analyzed": 0,
        "entries_filtered": 0, "entries_skipped": 0, "body_bytes_analyzed": 0,
        "body_unavailable": 0, "incomplete": False, "coverage": [],
        "limits": {"file_bytes": MAX_FILE_BYTES, "entries": MAX_ENTRIES,
                   "body_bytes": MAX_BODY, "total_body_bytes": MAX_TOTAL_BODY_BYTES, "findings": MAX_FINDINGS},
    })
    result.notes.extend([
        "HAR анализируется офлайн: запросы не повторяются, URL не открываются, JavaScript и формы не выполняются.",
        "Анализ охватывает только записанные ответы. Сертификаты, реальное согласование TLS и серверная логика по HAR не проверяются.",
        "Cookie, Authorization, POST-данные и тела не сохраняются в отчёте; URL-параметры маскируются. Пути URL и имена файлов могут содержать сведения о проекте.",
    ])
    try:
        if modules is not None and (not isinstance(modules, (list, tuple)) or not all(isinstance(item, str) for item in modules)):
            raise ValueError("Список модулей имеет некорректный тип.")
        selected = list(MODULES) if modules is None else list(dict.fromkeys(modules))
        if not selected or any(module not in MODULES for module in selected):
            raise ValueError("Выберите headers, cookies, html или disclosure; TLS по HAR не проверяется.")
        result.modules = selected
        scope = _host_filter(host)
        result.metadata["scope_host"] = scope
        source = Path(path).expanduser()
        info = source.lstat()
        if source.is_symlink() or not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Выберите обычный HAR-файл; ссылки и reparse points не читаются.")
        if info.st_size > MAX_FILE_BYTES:
            raise ValueError("HAR превышает лимит 25 МиБ.")
        with source.open("rb") as stream:
            payload = stream.read(MAX_FILE_BYTES + 1)
        if len(payload) > MAX_FILE_BYTES:
            raise ValueError("HAR превышает лимит 25 МиБ.")
        data = json.loads(payload.decode("utf-8-sig"))
        if not isinstance(data, dict) or not isinstance(data.get("log"), dict) or not isinstance(data["log"].get("entries"), list):
            raise ValueError("Ожидается HAR JSON с объектом log и массивом entries.")
        entries = data["log"]["entries"]
        result.target = _clean(str(source.resolve()), 1500)
    except (OSError, TypeError, ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ValueError) and not isinstance(exc, (json.JSONDecodeError, UnicodeError)):
            # Only fixed validation messages above are returned; JSON parser
            # errors and OS exceptions may contain captured or private data.
            message = str(exc) if str(exc).startswith(("Список", "Выберите", "Фильтр", "В фильтре", "Некорректный фильтр", "HAR", "Ожидается")) else "Некорректные параметры HAR."
        else:
            message = "Не удалось прочитать HAR: отсутствует файл, доступ, корректная UTF-8/JSON-структура или допустимая вложенность."
        result.errors.append(message)
        result.metadata["incomplete"] = True
        return result.finish()
    result.metadata["entries_total"] = len(entries)
    if len(entries) > MAX_ENTRIES:
        result.metadata["incomplete"] = True
        result.notes.append(f"Проверка ограничена первыми {MAX_ENTRIES} записями HAR; остальные не анализировались.")
    noted = set(result.notes)
    for index, entry in enumerate(entries[:MAX_ENTRIES], 1):
        result.metadata["entries_considered"] += 1
        try:
            if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict) or not isinstance(entry.get("response"), dict):
                raise ValueError("Некорректная структура request/response.")
            request, response = entry["request"], entry["response"]
            if not isinstance(request.get("url"), str):
                raise ValueError("Некорректный URL записи.")
            url = normalize_url(request["url"])
            if scope is not None and _captured_host(url) != scope:
                result.metadata["entries_filtered"] += 1
                continue
            status = response.get("status")
            if type(status) is not int or not 100 <= status <= 599:
                raise ValueError("В записи нет завершённого HTTP-ответа со статусом 100–599.")
            headers = _headers(response)
            method = request.get("method", "")
            if not isinstance(method, str) or not re.fullmatch(r"[A-Za-z]{1,20}", method):
                raise ValueError("Некорректный метод сохранённого запроса.")
            mime = _mime(headers)
            html = mime in {"text/html", "application/xhtml+xml"}
            needed = (html and any(item in selected for item in ("headers", "html"))) or (_textual(mime) and "disclosure" in selected)
            body, available, diagnostics = _body(response, method.upper(),
                MAX_TOTAL_BODY_BYTES - result.metadata["body_bytes_analyzed"], needed)
        except (TypeError, ValueError, UnicodeError):
            result.metadata["entries_skipped"] += 1
            result.metadata["incomplete"] = True
            result.errors.append(f"Запись HAR #{index} пропущена: неподдерживаемый URL либо некорректные request/response, метод, статус или заголовки.")
            continue
        for note in diagnostics:
            result.metadata["incomplete"] = True
            if note not in noted:
                result.notes.append(note)
                noted.add(note)
        observed = audit_response(url, status, headers, body, selected, body_available=available)
        if observed.errors:
            result.errors.extend(f"Запись HAR #{index}: {error}" for error in observed.errors)
        if not observed.to_dict()["complete"]:
            result.metadata["incomplete"] = True
        for note in observed.notes:
            if note not in noted:
                result.notes.append(note)
                noted.add(note)
        byte_count = observed.metadata.get("body_bytes", 0)
        result.metadata["body_bytes_analyzed"] += byte_count
        analyzed = "final_url" in observed.metadata
        result.metadata["entries_analyzed"] += int(analyzed)
        result.metadata["entries_skipped"] += int(not analyzed)
        result.metadata["body_unavailable"] += int(needed and not available)
        shown_url = display_url(url)
        result.metadata["coverage"].append({"entry": index, "url": shown_url,
            "method": method.upper(), "status": status, "analyzed": analyzed, "body_available": available,
            "body_required": needed, "body_bytes_analyzed": byte_count,
            "complete": observed.to_dict()["complete"] and not diagnostics})
        for check in observed.checks:
            result.checks.append({**check, "location": shown_url, "entry": index, "http_status": status})
        for finding in observed.findings:
            finding.location += f" :: HTTP {status}"
            if len(result.findings) < MAX_FINDINGS:
                result.findings.append(finding)
            else:
                result.metadata["incomplete"] = True
                if "Достигнут предел 5000 находок; остальные находки не сохранены." not in noted:
                    note = "Достигнут предел 5000 находок; остальные находки не сохранены."
                    result.notes.append(note)
                    noted.add(note)
    if not result.metadata["entries_analyzed"]:
        result.errors.append("В выбранном охвате HAR нет пригодных для анализа HTTP-ответов.")
        result.metadata["incomplete"] = True
    result.checks.append({"module": "har", "name": "Охват HAR", "status": "partial" if result.metadata["incomplete"] else "completed",
                          "detail": f"Всего записей: {len(entries)}; проанализировано: {result.metadata['entries_analyzed']}; отфильтровано: {result.metadata['entries_filtered']}; пропущено: {result.metadata['entries_skipped']}. Сетевых запросов: 0."})
    return result.finish()
