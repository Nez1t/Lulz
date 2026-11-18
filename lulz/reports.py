"""Readable, escaped, self-contained reports and deterministic report comparison."""
from __future__ import annotations

import base64
from datetime import datetime
from html import escape
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import unicodedata
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from .models import ScanResult, SEVERITIES


LEVEL_NAMES = {"critical": "КРИТИЧЕСКИЙ", "high": "ВЫСОКИЙ", "medium": "СРЕДНИЙ",
               "low": "НИЗКИЙ", "info": "ИНФОРМАЦИЯ"}
STATUS_NAMES = {"observed": "Наблюдение", "review": "Нужна ручная проверка",
                "advisory_match": "Совпадение версии с бюллетенем"}
BASELINE_NAMES = {"new": "Новая", "unchanged": "Без изменений", "updated": "Изменена"}
REPORT_SCRIPT = """(() => {
  'use strict';
  const search = document.getElementById('filter-search');
  const severity = document.getElementById('filter-severity');
  const category = document.getElementById('filter-category');
  const baseline = document.getElementById('filter-baseline');
  const counter = document.getElementById('filter-count');
  const items = Array.from(document.querySelectorAll('article.finding'));
  const haystacks = items.map(item => item.textContent.toLocaleLowerCase());
  function update() {
    const needle = search.value.trim().toLocaleLowerCase();
    let count = 0;
    items.forEach((item, index) => {
      const visible = (!severity.value || item.dataset.severity === severity.value)
        && (!category.value || item.dataset.category === category.value)
        && (!baseline.value || item.dataset.baseline === baseline.value)
        && (!needle || haystacks[index].includes(needle));
      item.hidden = !visible;
      if (visible) count += 1;
    });
    counter.textContent = 'Показано: ' + count + ' из ' + items.length;
  }
  [search, severity, category, baseline].forEach(control => {
    control.addEventListener('input', update);
    control.addEventListener('change', update);
  });
  document.getElementById('filter-reset').addEventListener('click', () => {
    [search, severity, category, baseline].forEach(control => { control.value = ''; });
    update();
    search.focus();
  });
  update();
})();"""


def plain(value: object) -> str:
    """Remove terminal control sequences from any externally supplied value."""
    result = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(value))
    return "".join(c for c in result if c in "\n\t" or unicodedata.category(c)[0] != "C")


def _html(value: object) -> str:
    return escape(plain(value), quote=True)


def _safe_ref(value: str) -> bool:
    if not isinstance(value, str) or any(unicodedata.category(char)[0] == "C" for char in value):
        return False
    try:
        parsed = urlsplit(value)
        return parsed.scheme in ("https", "http") and bool(parsed.hostname) and parsed.username is None and parsed.password is None
    except ValueError:
        return False


def _clean(value):
    if isinstance(value, dict):
        return {plain(k): _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    return plain(value) if isinstance(value, str) else value


def render_html(data: dict) -> str:
    counts = data["summary"]
    cards = "".join(
        f'<div class="metric {level}"><b>{counts.get(level, 0)}</b><span>{LEVEL_NAMES[level]}</span></div>'
        for level in SEVERITIES
    )
    findings = []
    for item in data.get("findings", []):
        severity = item.get("severity", "info")
        if severity not in SEVERITIES:
            severity = "info"
        identifiers = ", ".join(item.get("cwe", []) + item.get("cve", [])) or "Не присвоены"
        refs = "".join(f'<li><a href="{_html(ref)}" rel="noreferrer noopener">{_html(ref)}</a></li>'
                       for ref in item.get("references", []) if _safe_ref(ref))
        baseline_state = item.get("baseline_state", "")
        baseline_label = BASELINE_NAMES.get(baseline_state, "")
        findings.append(f'''<article class="finding {severity}" data-severity="{severity}" data-category="{_html(item.get('category', ''))}" data-baseline="{_html(baseline_state)}">
  <div class="row"><span class="badge {severity}">{LEVEL_NAMES[severity]}</span><code>{_html(item['rule_id'])}</code></div>
  <h2>{_html(item['title'])}</h2>
  <p class="sub">{_html(STATUS_NAMES.get(item.get('status'), item.get('status', '')))} · Уверенность: {_html(item.get('confidence', ''))}{(' · Baseline: ' + _html(baseline_label)) if baseline_label else ''}</p>
  <dl><dt>Где</dt><dd>{_html(item.get('location') or data['target'])}</dd>
  <dt>Класс / CVE</dt><dd>{_html(identifiers)}</dd>
  <dt>Описание</dt><dd>{_html(item['description'])}</dd>
  <dt>Доказательство</dt><dd><pre>{_html(item['evidence'])}</pre></dd>
  <dt>Исправление</dt><dd>{_html(item['remediation'])}</dd></dl>
  {('<details><summary>Источники</summary><ul>' + refs + '</ul></details>') if refs else ''}
</article>''')
    if not findings:
        findings.append('<section class="empty">В выполненных проверках находок нет. Это не подтверждает отсутствие уязвимостей.</section>')
    notices = []
    for title, key, css in (("Ошибки", "errors", "error"), ("Ограничения и примечания", "notes", "note")):
        if data.get(key):
            notices.append(f'<section class="{css}"><h2>{title}</h2><ul>' + "".join(
                f"<li>{_html(note)}</li>" for note in data[key]) + "</ul></section>")
    checks = "".join('<tr>' + "".join(f"<td>{_html(check.get(key, ''))}</td>"
                    for key in ("module", "name", "status", "detail")) + '</tr>'
                    for check in data.get("checks", []))
    complete = "Проверка завершена" if data.get("complete") else "Проверка неполная — см. ограничения"
    if data.get("kind") == "dependencies" and not data.get("metadata", {}).get("online"):
        complete = "Инвентаризация зависимостей — поиск CVE не выполнялся" + ("; результат неполный" if not data.get("complete") else "")
    if data.get("kind") == "project" and "dependencies" in data.get("modules", []):
        dependency = data.get("metadata", {}).get("components", {}).get("dependencies", {})
        if isinstance(dependency, dict) and dependency.get("online") is False:
            complete += " · CVE не проверялись (офлайн)"
    metadata = _html(json.dumps(data.get("metadata", {}), ensure_ascii=False, indent=2))
    categories = sorted({item.get("category", "") for item in data.get("findings", [])})
    category_options = "".join(f'<option value="{_html(category)}">{_html(category or "Без категории")}</option>' for category in categories if category)
    severity_options = "".join(f'<option value="{level}">{LEVEL_NAMES[level]}</option>' for level in SEVERITIES)
    baseline_options = "".join(f'<option value="{state}">{label}</option>' for state, label in BASELINE_NAMES.items())
    script_hash = base64.b64encode(hashlib.sha256(REPORT_SCRIPT.encode("utf-8")).digest()).decode("ascii")
    baseline = data.get("metadata", {}).get("baseline", {})
    baseline_notice = ""
    if isinstance(baseline, dict) and baseline.get("applied"):
        baseline_notice = '<section class="note"><h2>Сравнение с baseline</h2><p>' + _html(
            f"Новые: {baseline.get('new', 0)} · Изменены: {baseline.get('updated', 0)} · Без изменений: {baseline.get('unchanged', 0)} · Больше не наблюдаются: {baseline.get('not_seen', 0)}"
        ) + '</p><p class="sub">Все текущие находки сохранены. Исчезновение находки само по себе не подтверждает исправление.</p></section>'
    return f'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-{script_hash}'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Lulz · отчёт {_html(data['kind'])}</title>
<style>
:root{{--bg:#08110d;--panel:#0f1d15;--ink:#e6f5eb;--muted:#9db4a5;--line:#274132;--green:#69ef9b}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 system-ui,Segoe UI,sans-serif}}
main{{max-width:1120px;margin:auto;padding:42px 28px 70px}}header{{border-bottom:1px solid var(--line);padding-bottom:26px;margin-bottom:24px}}
.brand{{letter-spacing:.2em;color:var(--green);font-size:44px;font-weight:850;line-height:1.2}}.eyebrow{{color:var(--muted);text-transform:uppercase;letter-spacing:.16em;font-size:11px;margin-bottom:12px}}
h1{{font-size:25px;font-weight:600;margin:18px 0 8px;overflow-wrap:anywhere}}h2{{font-size:19px;margin:10px 0}}p{{margin:8px 0}}.sub{{color:var(--muted)}}
.metrics{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:26px 0}}.metric{{padding:16px;background:var(--panel);border:1px solid var(--line);border-radius:10px}}
.metric b{{display:block;font-size:32px;line-height:1.1}}.metric span{{font-size:10px;letter-spacing:.06em;color:var(--muted)}}
.finding{{border:1px solid var(--line);border-left:3px solid var(--green);border-radius:10px;padding:22px 24px;background:var(--panel);margin-bottom:18px}}
.finding.high,.finding.critical{{border-left-color:#ff8c84}}.finding.medium{{border-left-color:#f3cf74}}
.row{{display:flex;gap:14px;align-items:center;flex-wrap:wrap}}.badge{{font-size:10px;letter-spacing:.08em;padding:3px 9px;border-radius:5px;background:#1c3526;color:var(--green)}}
.badge.high,.badge.critical{{background:#492923;color:#ffb1a9}}.badge.medium{{background:#453b21;color:#ffdf90}}
code,pre{{font:12px/1.65 Consolas,ui-monospace,monospace}}code{{color:var(--muted)}}pre{{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}}
dl{{display:grid;grid-template-columns:130px minmax(0,1fr);gap:12px 18px;margin-bottom:0}}dt{{color:var(--muted);font-size:13px}}dd{{margin:0;overflow-wrap:anywhere}}
a{{color:var(--green);overflow-wrap:anywhere}}details{{margin-top:18px}}summary{{cursor:pointer;color:var(--muted)}}
.error,.note,.empty{{padding:18px 24px;border:1px solid var(--line);border-radius:10px;margin:18px 0}}.error{{border-color:#86554b}}
table{{border-collapse:collapse;width:100%;font-size:12px}}th,td{{padding:10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}}
.table-wrap{{overflow:auto}}footer{{margin-top:35px;color:var(--muted);font-size:12px}}.metadata{{max-height:450px;overflow:auto}}
.filters{{display:grid;grid-template-columns:2fr repeat(3,1fr);gap:12px;padding:18px;background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:20px 0}}
.filters label{{display:grid;gap:5px;font-size:12px;color:var(--muted)}}input,select,button{{font:inherit;color:var(--ink);background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:9px;min-width:0}}
input:focus,select:focus,button:focus{{outline:2px solid var(--green);outline-offset:2px}}button{{cursor:pointer}}.filter-footer{{grid-column:1/-1;display:flex;justify-content:space-between;align-items:center;gap:12px}}.filter-footer p{{margin:0}}.finding[hidden]{{display:none}}
@media(max-width:720px){{main{{padding:24px 16px}}.metrics{{grid-template-columns:repeat(2,1fr)}}dl{{grid-template-columns:1fr;gap:3px}}dd{{margin-bottom:12px}}}}
@media(max-width:900px){{.filters{{grid-template-columns:1fr 1fr}}}}
@media print{{:root{{--bg:white;--panel:white;--ink:#14251b;--muted:#42564a;--line:#abbcaf;--green:#126d35}}body{{font-size:11px}}main{{padding:0}}.finding{{break-inside:avoid}}.finding[hidden]{{display:block}}.filters{{display:none}}details{{display:block}}.metadata{{max-height:none}}}}
</style></head><body><main>
<header><div class="eyebrow">Web posture · Source review · Dependency intelligence</div><div class="brand">LULZ</div>
<h1>{_html(data['target'])}</h1><p class="sub">{_html(complete)} · {_html(data['kind'])}</p>
<p class="sub">Начало: {_html(data['started_at'])} · Конец: {_html(data['completed_at'])}</p>
<p class="sub">Модули: {_html(', '.join(data.get('modules', [])))}</p></header>
<section class="metrics">{cards}</section>{baseline_notice}{''.join(notices)}
<section class="filters" aria-label="Фильтры находок">
<label for="filter-search">Поиск по отчёту<input id="filter-search" type="search" autocomplete="off" placeholder="Правило, файл, CWE, CVE…"></label>
<label for="filter-severity">Важность<select id="filter-severity"><option value="">Все уровни</option>{severity_options}</select></label>
<label for="filter-category">Категория<select id="filter-category"><option value="">Все категории</option>{category_options}</select></label>
<label for="filter-baseline">Baseline<select id="filter-baseline"><option value="">Все находки</option>{baseline_options}</select></label>
<div class="filter-footer"><p id="filter-count" role="status" aria-live="polite">Показано: {len(data.get('findings', []))} из {len(data.get('findings', []))}</p><button id="filter-reset" type="button">Сбросить</button></div>
<small class="sub">Фильтры работают локально; при печати выводятся все находки.</small>
</section><noscript><p class="note">JavaScript отключён: все находки показаны без фильтрации.</p></noscript>{''.join(findings)}
<details><summary>Журнал проверок ({len(data.get('checks', []))})</summary><div class="table-wrap"><table>
<thead><tr><th>Модуль</th><th>Проверка</th><th>Статус</th><th>Подробности</th></tr></thead><tbody>{checks}</tbody></table></div></details>
<details><summary>Метаданные и охват</summary><pre class="metadata">{metadata}</pre></details>
<footer>Lulz {_html(data['tool']['version'])} · Схема {_html(data['schema_version'])} · Наблюдение, кандидат на ручную проверку и совпадение с бюллетенем — разные уровни доказательств. Отчёт не является подтверждением эксплуатации.</footer>
</main><script>{REPORT_SCRIPT}</script></body></html>'''


def render_markdown(data: dict) -> str:
    def safe(text):
        value = plain(text).replace("`", "\\`")
        return escape(value, quote=False).replace("[", "\\[").replace("]", "\\]")

    lines = ["# Lulz — отчёт", "", f"**Цель:** {safe(data['target'])}", "",
             f"**Тип:** {safe(data['kind'])} · **Время:** {safe(data['completed_at'])}", "",
             f"**Полнота:** {'завершён' if data.get('complete') else 'неполный'}", "",
             "| Уровень | Количество |", "|---|---:|"]
    lines.extend(f"| {LEVEL_NAMES[level]} | {data['summary'].get(level, 0)} |" for level in SEVERITIES)
    baseline = data.get("metadata", {}).get("baseline", {})
    if isinstance(baseline, dict) and baseline.get("applied"):
        lines.extend(["", "## Baseline", "", safe(f"Новые: {baseline.get('new', 0)}; изменены: {baseline.get('updated', 0)}; без изменений: {baseline.get('unchanged', 0)}; больше не наблюдаются: {baseline.get('not_seen', 0)}."), "",
                      "Все текущие находки сохранены. Исчезновение находки не подтверждает исправление."])
    for key, title in (("errors", "Ошибки"), ("notes", "Ограничения и примечания")):
        if data.get(key):
            lines.extend(["", f"## {title}", ""])
            lines.extend(f"- {safe(item)}" for item in data[key])
    for item in data.get("findings", []):
        identifiers = ", ".join(item.get("cwe", []) + item.get("cve", [])) or "Не присвоены"
        lines.extend(["", f"## {safe(item['rule_id'])} — {safe(item['title'])}", "",
                      f"**Уровень:** {safe(item['severity'])} · **Статус:** {safe(STATUS_NAMES.get(item['status'], item['status']))}", "",
                      f"**Расположение:** {safe(item['location'])}", "",
                      f"**Класс / CVE:** {safe(identifiers)}", "",
                      safe(item['description']), "", "**Доказательство:**", "",
                      safe(item['evidence']), "", "**Исправление:**", "", safe(item['remediation'])])
        if item.get("baseline_state"):
            lines.extend(["", f"**Baseline:** {safe(BASELINE_NAMES.get(item['baseline_state'], item['baseline_state']))}"])
        refs = [ref for ref in item.get("references", []) if _safe_ref(ref)]
        if refs:
            lines.extend(["", "**Источники:**", ""] + [f"- {safe(ref)}" for ref in refs])
    if not data.get("findings"):
        lines.extend(["", "В выполненных проверках находок нет. Это не подтверждает отсутствие уязвимостей."])
    lines.extend(["", "## Журнал проверок", ""])
    for check in data.get("checks", []):
        lines.append(f"- {safe(check.get('module', ''))}: {safe(check.get('name', ''))} — {safe(check.get('status', ''))}. {safe(check.get('detail', ''))}")
    lines.extend(["", "Lulz различает наблюдения, кандидатов для ручной проверки и совпадения версий с бюллетенями.", ""])
    return "\n".join(lines)


def finding_key(item: dict) -> str:
    """Recompute identity; imported fingerprint strings are never trusted."""
    serialized = json.dumps([item["rule_id"], item["location"], item["evidence"]], ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:20]


def significant_fields(item: dict) -> tuple:
    fields = ("title", "severity", "category", "description", "remediation", "confidence", "status")
    return tuple(item.get(key, "") for key in fields) + (
        tuple(sorted(item.get("cwe", []))), tuple(sorted(item.get("cve", []))),
    )


def _sarif_location(value: str, category: str = "") -> dict | None:
    text = plain(value).strip()
    if not text:
        return None
    # A merged dependency location can contain several source paths. Do not
    # invent a single filename when their boundaries are not structured.
    if category == "dependencies" and ", " in text:
        return {"logicalLocations": [{"fullyQualifiedName": text, "kind": "dependency"}]}
    address = text.split(" :: ", 1)[0]
    line = None
    if address.lower().startswith(("http://", "https://")):
        try:
            parts = urlsplit(address)
            if not parts.hostname:
                return None
            host = parts.hostname.encode("idna").decode("ascii")
            host = f"[{host}]" if ":" in host else host
            if parts.port:
                host += f":{parts.port}"
            query = urlencode([(key, "[redacted]") for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
            uri = urlunsplit((parts.scheme.lower(), host, quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~"), query, ""))
            html_line = re.search(r" :: HTML line ([1-9][0-9]*)", text)
            if html_line:
                line = int(html_line.group(1))
        except (ValueError, UnicodeError):
            return None
    else:
        match = re.fullmatch(r"(.*):([1-9][0-9]*)", address)
        if match:
            address, line = match.group(1), int(match.group(2))
        windows = PureWindowsPath(address)
        if windows.is_absolute():
            uri = windows.as_uri()
        elif address.startswith("/"):
            uri = PurePosixPath(address).as_uri()
        else:
            uri = quote(address.replace("\\", "/"), safe="/-._~")
    if not uri:
        return None
    physical = {"artifactLocation": {"uri": uri}}
    if line is not None:
        physical["region"] = {"startLine": line}
    return {"physicalLocation": physical}


def render_sarif(data: dict) -> dict:
    """Produce SARIF 2.1.0 with no source snippets or remote dependencies."""
    levels = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules, indices = [], {}
    for item in data.get("findings", []):
        rule_id = item["rule_id"]
        if rule_id in indices:
            continue
        indices[rule_id] = len(rules)
        rule = {
            "id": rule_id,
            "shortDescription": {"text": item["title"] or rule_id},
            "fullDescription": {"text": item["description"] or item["title"] or rule_id},
            "help": {"text": item["remediation"] or "Проверьте находку в контексте приложения."},
            "defaultConfiguration": {"level": levels.get(item["severity"], "note")},
            "properties": {"tags": list(dict.fromkeys(["security", item.get("category", "")] + item.get("cwe", []) + item.get("cve", [])))},
        }
        refs = [ref for ref in item.get("references", []) if _safe_ref(ref)]
        if refs:
            rule["helpUri"] = refs[0]
        rules.append(rule)
    baseline = data.get("metadata", {}).get("baseline", {})
    has_baseline = isinstance(baseline, dict) and baseline.get("applied") is True and data.get("complete") is True
    results = []
    for item in data.get("findings", []):
        entry = {
            "ruleId": item["rule_id"], "ruleIndex": indices[item["rule_id"]],
            "level": levels.get(item["severity"], "note"),
            "message": {"text": f"{item['title']}\n{STATUS_NAMES.get(item.get('status'), item.get('status', ''))}: {item['description']}\nДоказательство: {item['evidence']}\nИсправление: {item['remediation']}"},
            "partialFingerprints": {"lulzRuleLocationEvidence/v1": finding_key(item)},
            "properties": {"severity": item["severity"], "confidence": item.get("confidence", ""),
                           "status": item.get("status", ""), "category": item.get("category", ""),
                           "cwe": item.get("cwe", []), "cve": item.get("cve", [])},
        }
        location = _sarif_location(item.get("location", ""), item.get("category", ""))
        if location:
            entry["locations"] = [location]
        if has_baseline and item.get("baseline_state") in BASELINE_NAMES:
            entry["baselineState"] = item["baseline_state"]
        results.append(entry)
    invocation = {"executionSuccessful": data.get("complete") is True}
    if data.get("errors"):
        invocation["toolExecutionNotifications"] = [{"level": "error", "message": {"text": message}}
                                                    for message in data["errors"]]
    run = {
        "tool": {"driver": {"name": "Lulz", "version": data.get("tool", {}).get("version", "unknown"),
                            "rules": rules}},
        "results": results, "invocations": [invocation],
        "properties": {"kind": data["kind"], "target": data["target"], "modules": data.get("modules", []),
                       "notes": data.get("notes", []), "complete": data.get("complete") is True},
    }
    if has_baseline:
        run["properties"]["baseline"] = baseline
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]}


def save_reports(result: ScanResult, directory: str | Path) -> dict[str, Path]:
    if not result.completed_at:
        result.finish()
    root = Path(directory).expanduser().resolve()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    kind = re.sub(r"[^a-zA-Z0-9_-]", "_", result.kind)
    folder = root / f"{stamp}_{kind}_{uuid4().hex[:8]}"
    folder.mkdir(parents=True, exist_ok=False)
    data = _clean(result.to_dict())
    contents = {"json": json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                "html": render_html(data), "md": render_markdown(data),
                "sarif": json.dumps(render_sarif(data), ensure_ascii=False, indent=2) + "\n"}
    written = {}
    try:
        for extension, content in contents.items():
            path = folder / f"report.{extension}"
            with path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
            written[extension] = path
    except OSError:
        for path in written.values():
            path.unlink(missing_ok=True)
        try:
            folder.rmdir()
        except OSError:
            pass
        raise
    return written


def load_report(path: str | Path) -> dict:
    source = Path(path).expanduser()
    with source.open("rb") as stream:
        payload = stream.read(20 * 1024 * 1024 + 1)
    if len(payload) > 20 * 1024 * 1024:
        raise ValueError("Отчёт превышает лимит 20 MiB")
    try:
        def invalid_constant(value):
            raise ValueError("JSON-отчёт содержит нечисловую константу")
        data = json.loads(payload.decode("utf-8-sig"), parse_constant=invalid_constant)
    except RecursionError as exc:
        raise ValueError("Слишком глубокая структура JSON-отчёта") from exc
    if (not isinstance(data, dict) or data.get("schema_version") != "1.0"
            or not isinstance(data.get("findings"), list)
            or not isinstance(data.get("target"), str)
            or not isinstance(data.get("kind"), str)
            or not isinstance(data.get("modules"), list)
            or not all(isinstance(item, str) for item in data["modules"])
            or not isinstance(data.get("complete"), bool)
            or not isinstance(data.get("metadata"), dict)):
        raise ValueError("Это не JSON-отчёт Lulz со схемой 1.0")
    if len(data["findings"]) > 50000:
        raise ValueError("Слишком много находок в импортируемом отчёте")
    # Limit nesting before later serialization/rendering can recurse into
    # attacker-controlled metadata. Iteration itself does not use recursion.
    stack, visited = [(data, 0)], 0
    while stack:
        value, depth = stack.pop()
        visited += 1
        if depth > 64 or visited > 500000:
            raise ValueError("Структура JSON-отчёта превышает допустимые пределы")
        if isinstance(value, dict):
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
    for key in ("errors", "notes"):
        if not isinstance(data.get(key), list) or not all(isinstance(item, str) for item in data[key]):
            raise ValueError("Некорректные примечания или ошибки в JSON-отчёте")
    if not isinstance(data.get("checks"), list) or not all(isinstance(check, dict) for check in data["checks"]):
        raise ValueError("Некорректный журнал проверок в JSON-отчёте")
    for check in data["checks"]:
        if any(key in check and not isinstance(check[key], str) for key in ("module", "name", "status", "detail")):
            raise ValueError("Некорректная запись журнала проверок")
    for key in ("started_at", "completed_at"):
        if key in data and not isinstance(data[key], str):
            raise ValueError("Некорректная отметка времени в отчёте")
    for item in data["findings"]:
        if not isinstance(item, dict) or not all(isinstance(item.get(key), str)
                for key in ("rule_id", "location", "evidence", "title", "severity", "category", "description", "remediation", "confidence", "status")):
            raise ValueError("Некорректная структура находки в отчёте")
        if not item["rule_id"] or item["severity"] not in SEVERITIES or item["status"] not in STATUS_NAMES:
            raise ValueError("Некорректный идентификатор, уровень или статус находки")
        for key in ("cwe", "cve", "references"):
            if not isinstance(item.get(key), list) or not all(isinstance(value, str) for value in item[key]):
                raise ValueError("Некорректные идентификаторы или ссылки находки")
        if item.get("baseline_state", "") not in ("", *BASELINE_NAMES):
            raise ValueError("Некорректный baseline-статус находки")
    if data["errors"] or data["metadata"].get("incomplete"):
        data["complete"] = False
    return data


def _dependency_scope(data: dict) -> tuple | None:
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("Некорректные метаданные охвата")
    if data.get("kind") == "dependencies":
        dependency = metadata
    elif data.get("kind") == "project" and "dependencies" in data.get("modules", []):
        components = metadata.get("components", {})
        dependency = components.get("dependencies") if isinstance(components, dict) else None
        if dependency is None:
            dependency = metadata.get("dependencies")
        if not isinstance(dependency, dict):
            raise ValueError("В отчёте проекта отсутствует охват проверки зависимостей")
    else:
        return None
    for key in ("online", "advisories_checked"):
        if key in dependency and not isinstance(dependency[key], bool):
            raise ValueError("Некорректный режим проверки зависимостей")
    return dependency.get("online", False), dependency.get("advisories_checked", False)


def validate_comparable_scope(before: dict, after: dict) -> None:
    if before.get("target") != after.get("target") or before.get("kind") != after.get("kind"):
        raise ValueError("Сравнивать можно только отчёты одного типа и одной цели")
    for value in (before, after):
        if not isinstance(value.get("modules"), list) or not all(isinstance(module, str) for module in value["modules"]):
            raise ValueError("Некорректный состав модулей в отчёте")
    if set(before["modules"]) != set(after["modules"]):
        raise ValueError("Состав модулей различается; выберите отчёты с одинаковым охватом")
    if _dependency_scope(before) != _dependency_scope(after):
        raise ValueError("Охват OSV различается: нельзя сравнивать инвентаризацию с проверкой бюллетеней")
    if before.get("kind") == "har" and before.get("metadata", {}).get("scope_host") != after.get("metadata", {}).get("scope_host"):
        raise ValueError("HAR-отчёты имеют разные фильтры хоста")


def compare_reports(before: dict, after: dict) -> dict:
    validate_comparable_scope(before, after)
    left = {finding_key(item): item for item in before["findings"]}
    right = {finding_key(item): item for item in after["findings"]}
    shared = left.keys() & right.keys()
    updated = {key for key in shared if significant_fields(left[key]) != significant_fields(right[key])}
    return {"new": [right[k] for k in sorted(right.keys() - left.keys())],
            "not_seen": [left[k] for k in sorted(left.keys() - right.keys())],
            "updated": [right[k] for k in sorted(updated)],
            "unchanged": len(shared - updated),
            "partial": not before.get("complete", False) or not after.get("complete", False)}


def report_history(directory: str | Path, limit: int = 20) -> list[dict]:
    root = Path(directory).expanduser()
    if not root.is_dir():
        return []
    paths = sorted(root.glob("*/report.json"), key=lambda path: path.parent.name, reverse=True)
    rows = []
    for path in paths[:limit]:
        if path.is_symlink() or path.parent.is_symlink():
            continue
        try:
            data = load_report(path)
            rows.append({"path": path.resolve(), "target": data["target"], "kind": data["kind"],
                         "count": len(data["findings"]), "completed_at": data.get("completed_at", ""),
                         "complete": data.get("complete", False)})
        except (OSError, ValueError, UnicodeError):
            continue
    return rows
