"""Read exact local dependency versions and optionally query OSV advisories.

No package installation, source execution, target probing or version guessing.
Only ecosystem, package name, version and pagination tokens leave this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from http.client import HTTPException
import json
from pathlib import Path
import re
import ssl
import time
import tomllib
from urllib import error, parse, request

from .models import Finding, ScanResult


OSV_ENDPOINT = "https://api.osv.dev/v1/query"
MAX_PACKAGES = 200
MAX_MANIFESTS = 20
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_PAGES = 10
MAX_AUDIT_SECONDS = 90.0
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_CWE = re.compile(r"CWE-\d+")
_PYPI_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_NPM_NAME = re.compile(r"(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+")
_PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9,._ -]+\])?\s*==\s*([^\s;]+)")
_SEMVER = re.compile(r"v?\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?")
LOCK_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "bom.json", "Pipfile.lock",
              "poetry.lock", "uv.lock", "Cargo.lock", "composer.lock", "go.sum"}
ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm", "composer": "Packagist", "cargo": "crates.io", "golang": "Go"}


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str
    sources: list[str] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str, str]:
        return self.ecosystem, self.name, self.version

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version,
                "ecosystem": self.ecosystem, "sources": self.sources}


def _clean(value: object, limit: int = 240) -> str:
    return "".join(c for c in str(value) if c.isprintable() or c == " ")[:limit]


def _valid_dependency(name: object, version: object, ecosystem: str,
                      source: str) -> Dependency | None:
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    if len(name) > 214 or len(version) > 150:
        return None
    name, version = name.strip(), version.strip()
    if ecosystem == "PyPI":
        if not _PYPI_NAME.fullmatch(name) or not re.fullmatch(r"\d[0-9A-Za-z.!+_-]*", version):
            return None
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif ecosystem == "npm":
        if not _NPM_NAME.fullmatch(name) or not _SEMVER.fullmatch(version):
            return None
    elif ecosystem == "Packagist":
        if not re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_.-]+", name) or not re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:[-.]?(?:alpha|beta|rc|a|b|patch|p)[.-]?\d*)?(?:\+[A-Za-z0-9.-]+)?", version, re.I):
            return None
    elif ecosystem == "crates.io":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name) or not _SEMVER.fullmatch(version):
            return None
    elif ecosystem == "Go":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~!/-]+", name) or "/" not in name or not _SEMVER.fullmatch(version):
            return None
    else:
        return None
    return Dependency(name, version, ecosystem, [source])


def _parse_requirements(text: str, source: str) -> tuple[list[Dependency], int]:
    packages, skipped = [], 0
    # Requirements includes, indexes, direct URLs and range constraints are not
    # followed. Hash continuations are irrelevant to the version inventory.
    logical = []
    pending, first = "", 1
    for number, raw in enumerate(text.splitlines(), 1):
        if not pending:
            first = number
        pending += raw.rstrip().removesuffix("\\") + " "
        if raw.rstrip().endswith("\\"):
            continue
        logical.append((first, pending))
        pending = ""
    if pending:
        logical.append((first, pending))
    for number, raw in logical:
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("--hash="):
            continue
        line = line.split(";", 1)[0].strip()
        line = re.split(r"\s+--hash=", line, maxsplit=1)[0].strip()
        match = _PIN.fullmatch(line)
        dependency = (_valid_dependency(match[1], match[2], "PyPI", f"{source}:{number}")
                      if match else None)
        if dependency:
            packages.append(dependency)
        else:
            skipped += 1
    return packages, skipped


def _parse_npm(data: dict, source: str) -> tuple[list[Dependency], int]:
    packages, skipped = [], 0
    package_map = data.get("packages")
    if isinstance(package_map, dict):
        for path, record in package_map.items():
            if not path:  # The root application is not an installed dependency.
                continue
            if not isinstance(path, str) or not isinstance(record, dict):
                skipped += 1
                continue
            if record.get("link") or "node_modules/" not in path:
                skipped += 1
                continue
            name = record.get("name") or path.rsplit("node_modules/", 1)[-1]
            dependency = _valid_dependency(name, record.get("version"), "npm", source)
            if dependency:
                packages.append(dependency)
            else:
                skipped += 1
    else:
        root = data.get("dependencies")
        if not isinstance(root, dict):
            raise ValueError("В package-lock нет таблицы packages или dependencies.")
        stack, visited = [root], 0
        while stack:
            records = stack.pop()
            for name, record in records.items():
                visited += 1
                if visited > 10000:
                    return packages, skipped + 1
                if not isinstance(record, dict):
                    skipped += 1
                    continue
                dependency = _valid_dependency(name, record.get("version"), "npm", source)
                if dependency:
                    packages.append(dependency)
                else:
                    skipped += 1
                nested = record.get("dependencies")
                if isinstance(nested, dict):
                    stack.append(nested)
    return packages, skipped


def _parse_cyclonedx(data: dict, source: str) -> tuple[list[Dependency], int]:
    packages, skipped = [], 0
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("JSON не является CycloneDX SBOM или npm lockfile.")
    components = data.get("components", [])
    if not isinstance(components, list):
        raise ValueError("CycloneDX components должен быть массивом.")
    stack = list(components)
    visited = 0
    while stack:
        item = stack.pop()
        visited += 1
        if visited > 10000:
            return packages, skipped + len(stack) + 1
        if not isinstance(item, dict):
            skipped += 1
            continue
        children = item.get("components")
        if isinstance(children, list):
            stack.extend(children)
        purl = item.get("purl", "")
        dependency = None
        if isinstance(purl, str) and any(char in purl for char in ("?", "#")):
            skipped += 1  # Qualifiers/subpaths can change registry or version identity.
            continue
        if isinstance(purl, str) and purl.startswith(tuple("pkg:" + key + "/" for key in ECOSYSTEMS)):
            identity = purl.split("?", 1)[0].split("#", 1)[0]
            ecosystem, rest = identity[4:].split("/", 1)
            if "@" in rest and not rest.endswith("@"):
                name, version = rest.rsplit("@", 1)
                name, version = parse.unquote(name), parse.unquote(version)
                declared_version = item.get("version")
                # Conflicting identity fields are not guessed into a match.
                if declared_version in (None, "", version):
                    dependency = _valid_dependency(name, version, ECOSYSTEMS[ecosystem], source)
            elif item.get("version"):
                dependency = _valid_dependency(parse.unquote(rest), item["version"], ECOSYSTEMS[ecosystem], source)
        if dependency:
            packages.append(dependency)
        else:
            skipped += 1
    return packages, skipped


def _public_pypi(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        url = parse.urlsplit(value)
        return url.scheme == "https" and url.hostname in {"pypi.org", "pypi.python.org"} and not url.username
    except ValueError:
        return False


def _parse_toml_lock(text: str, source: str) -> tuple[list[Dependency], int]:
    data = tomllib.loads(text)
    records = data.get("package", [])
    if not isinstance(records, list):
        raise ValueError("В TOML lockfile ожидается массив package.")
    packages, skipped = [], 0
    for record in records:
        if not isinstance(record, dict):
            skipped += 1
            continue
        registry = record.get("source")
        if source == "Cargo.lock":
            if registry is None:
                continue  # Workspace packages are reviewed as local source.
            valid_source = registry in {"registry+https://github.com/rust-lang/crates.io-index", "registry+https://index.crates.io/", "sparse+https://index.crates.io/"} if isinstance(registry, str) else False
            ecosystem = "crates.io"
        else:
            ecosystem = "PyPI"
            if source == "uv.lock":
                if isinstance(registry, dict) and any(key in registry for key in ("editable", "virtual", "directory")):
                    continue
                valid_source = isinstance(registry, dict) and _public_pypi(registry.get("registry"))
            else:
                valid_source = registry is None or isinstance(registry, dict) and _public_pypi(registry.get("url"))
        item = _valid_dependency(record.get("name"), record.get("version"), ecosystem, source) if valid_source else None
        if item:
            packages.append(item)
        else:
            skipped += 1
    return packages, skipped


def _parse_pipfile(data: dict, source: str) -> tuple[list[Dependency], int]:
    packages, skipped = [], 0
    meta = data.get("_meta", {})
    sources = meta.get("sources", []) if isinstance(meta, dict) else []
    indexes = {item.get("name"): _public_pypi(item.get("url")) for item in sources
               if isinstance(item, dict) and isinstance(item.get("name"), str)} if isinstance(sources, list) else {}
    for group in ("default", "develop"):
        records = data.get(group, {})
        if not isinstance(records, dict):
            raise ValueError("Некорректная группа зависимостей Pipfile.lock.")
        for name, record in records.items():
            version = record.get("version") if isinstance(record, dict) else None
            index = record.get("index") if isinstance(record, dict) else None
            if not isinstance(record, dict) or index is not None and not isinstance(index, str) or any(key in record for key in ("git", "hg", "svn", "bzr", "file", "path")) or record.get("editable") is True:
                skipped += 1
                continue
            public = indexes.get(index, False) if index is not None else bool(indexes) and all(indexes.values())
            item = _valid_dependency(name, version[2:], "PyPI", source) if public and isinstance(version, str) and version.startswith("==") else None
            if item:
                packages.append(item)
            else:
                skipped += 1
    return packages, skipped


def _parse_composer(data: dict, source: str) -> tuple[list[Dependency], int]:
    packages, skipped = [], 0
    for group in ("packages", "packages-dev"):
        records = data.get(group, [])
        if not isinstance(records, list):
            raise ValueError("В composer.lock ожидается массив packages / packages-dev.")
        for record in records:
            item = _valid_dependency(record.get("name"), record.get("version"), "Packagist", source) if isinstance(record, dict) else None
            if item:
                packages.append(item)
            else:
                skipped += 1
    return packages, skipped


def _parse_go_sum(text: str, source: str) -> tuple[list[Dependency], int]:
    packages, skipped = [], 0
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 3 or not parts[2].startswith("h1:"):
            skipped += 1
            continue
        if parts[1].endswith("/go.mod"):
            continue
        item = _valid_dependency(parts[0], parts[1], "Go", f"{source}:{number}")
        if item:
            packages.append(item)
        else:
            skipped += 1
    return packages, skipped


def _read_manifest(path: Path) -> tuple[list[Dependency], int]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Ожидался обычный файл; символические ссылки не читаются.")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Манифест превышает лимит 5 МиБ.")
    with path.open("rb") as file:
        raw = file.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("Манифест превышает лимит 5 МиБ.")
    text = raw.decode("utf-8-sig")
    if path.name in {"poetry.lock", "uv.lock", "Cargo.lock"}:
        return _parse_toml_lock(text, path.name)
    if path.name == "go.sum":
        return _parse_go_sum(text, path.name)
    if path.suffix.lower() == ".txt":
        return _parse_requirements(text, path.name)
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("В корне JSON должен находиться объект.")
    if path.name == "Pipfile.lock":
        return _parse_pipfile(data, path.name)
    if path.name == "composer.lock":
        return _parse_composer(data, path.name)
    if data.get("bomFormat") == "CycloneDX":
        return _parse_cyclonedx(data, path.name)
    if path.name in {"package-lock.json", "npm-shrinkwrap.json"} or "lockfileVersion" in data:
        return _parse_npm(data, path.name)
    raise ValueError("Поддерживаются requirements, Pipfile/Poetry/uv, npm, Cargo, Composer, go.sum и CycloneDX JSON.")


def _manifest_paths(path: Path) -> tuple[list[Path], bool]:
    if path.is_symlink():
        raise ValueError("Символические ссылки не читаются.")
    if path.is_file():
        return [path], False
    if not path.is_dir():
        raise ValueError("Указанный путь не существует или недоступен.")
    found = []
    for visited, candidate in enumerate(path.iterdir(), 1):
        if visited > 5000:
            return sorted(found, key=lambda p: p.name)[:MAX_MANIFESTS], True
        name = candidate.name
        accepted = ((name.startswith("requirements") and name.endswith(".txt")) or
                    name in LOCK_NAMES or
                    name.endswith(".cdx.json"))
        if accepted and candidate.is_file():
            found.append(candidate)
            if len(found) > MAX_MANIFESTS:
                return sorted(found, key=lambda p: p.name)[:MAX_MANIFESTS], True
    return sorted(found, key=lambda p: p.name), False


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _post_query(payload: dict, timeout: float) -> dict:
    body = json.dumps(payload, ensure_ascii=True).encode("ascii")
    req = request.Request(OSV_ENDPOINT, data=body, method="POST", headers={
        "User-Agent": "Lulz/1.0.1 dependency-audit",
        "Accept": "application/json", "Content-Type": "application/json",
    })
    opener = request.build_opener(_NoRedirect(), request.HTTPSHandler(context=ssl.create_default_context()))
    deadline = time.monotonic() + timeout
    chunks, size = [], 0
    with opener.open(req, timeout=timeout) as response:
        # read1 returns after one buffered/socket read; the deadline is checked
        # between chunks instead of trusting an unlimited slow response body.
        read_chunk = getattr(response, "read1", response.read)
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("Истёк срок ожидания ответа OSV.")
            chunk = read_chunk(min(65536, MAX_RESPONSE_BYTES + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise ValueError("Ответ OSV превышает лимит 4 МиБ.")
            chunks.append(chunk)
    raw = b"".join(chunks)
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Некорректная структура ответа OSV.")
    return data


def _same_package(record: dict, package: Dependency) -> bool:
    identity = record.get("package")
    if not isinstance(identity, dict) or identity.get("ecosystem") != package.ecosystem:
        return False
    name = identity.get("name")
    if not isinstance(name, str):
        return False
    if package.ecosystem == "PyPI":
        name = re.sub(r"[-_.]+", "-", name).lower()
    if package.ecosystem == "crates.io":
        return name.lower().replace("_", "-") == package.name.lower().replace("_", "-")
    return name == package.name


def _advisory_finding(record: dict, package: Dependency) -> Finding | None:
    if record.get("withdrawn"):
        return None
    advisory_id = record.get("id")
    if not isinstance(advisory_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,150}", advisory_id):
        raise ValueError("Запись OSV не содержит корректного идентификатора.")
    affected = record.get("affected") or []
    if not isinstance(affected, list):
        raise ValueError("Некорректная таблица affected в записи OSV.")
    relevant = [item for item in affected if isinstance(item, dict) and _same_package(item, package)]
    # A record returned for a different named package is not treated as a match.
    if not relevant:
        raise ValueError("OSV вернул запись для другого пакета; совпадение не установлено.")
    database = record.get("database_specific") or {}
    if not isinstance(database, dict):
        database = {}
    values = [database.get("severity")]
    for item in relevant:
        for field_name in ("database_specific", "ecosystem_specific"):
            extra = item.get(field_name)
            if isinstance(extra, dict):
                values.append(extra.get("severity"))
    ranks = {"critical": 0, "high": 1, "medium": 2, "moderate": 2, "low": 3}
    known = [str(value).lower() for value in values if isinstance(value, str) and value.lower() in ranks]
    severity = min(known, key=lambda v: ranks[v]) if known else "info"
    if severity == "moderate":
        severity = "medium"
    identifiers = [advisory_id]
    if isinstance(record.get("aliases"), list):
        identifiers.extend(x for x in record["aliases"] if isinstance(x, str))
    cve = sorted(set(x for x in identifiers if _CVE.fullmatch(x)))
    cwes = database.get("cwe_ids")
    cwe = sorted(set(x for x in cwes if isinstance(x, str) and _CWE.fullmatch(x))) if isinstance(cwes, list) else []
    fixed = set()
    for item in relevant:
        ranges = item.get("ranges") or []
        if not isinstance(ranges, list):
            continue
        for span in ranges:
            if not isinstance(span, dict) or not isinstance(span.get("events"), list):
                continue
            for event in span["events"]:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.add(_clean(event["fixed"], 100))
    references = ["https://osv.dev/vulnerability/" + parse.quote(advisory_id, safe="-._")]
    entries = record.get("references")
    if isinstance(entries, list):
        for entry in entries:
            url = entry.get("url") if isinstance(entry, dict) else None
            if not isinstance(url, str) or len(url) > 1800 or any(ord(c) < 32 for c in url):
                continue
            try:
                parsed = parse.urlsplit(url)
                if parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username and not parsed.password:
                    references.append(url)
            except ValueError:
                continue
            if len(references) >= 8:
                break
    description = ("OSV сопоставил точную версию из локального манифеста с опубликованной записью. "
                   "Это совпадение по зависимости, а не подтверждение эксплуатации или присутствия пакета на сайте.")
    if not known:
        description += " Уровень важности не указан: INFO здесь означает неопределённую оценку, а не низкий риск."
    remediation = "Проверьте применимость записи, обновите зависимость в подходящей ветке и повторите проверку lockfile."
    if fixed:
        remediation += " В записи перечислены исправленные версии/коммиты: " + ", ".join(sorted(fixed)[:8]) + "."
    summary = _clean(record.get("summary") or advisory_id, 180)
    return Finding(
        rule_id="DEP-OSV-" + advisory_id, title=f"{package.name}: {summary}",
        severity=severity, category="dependencies", description=description,
        evidence=f"{package.ecosystem} {package.name}@{package.version}; OSV: {advisory_id}",
        remediation=remediation, location=", ".join(package.sources),
        confidence="high", status="advisory_match", cwe=cwe, cve=cve,
        references=list(dict.fromkeys(references)),
    )


def scan_dependencies(path: str, online: bool = False, timeout: float = 10.0) -> ScanResult:
    """Inventory supplied manifests; online=True explicitly opts into OSV queries."""
    result = ScanResult(kind="dependencies", target=str(path), modules=["dependencies"])
    result.metadata.update({"online": online, "inventory": [], "packages": 0,
                            "checked_packages": 0, "advisory_source": OSV_ENDPOINT if online else None})
    result.notes.append("Манифест описывает заявленные зависимости; наличие пакета в рабочем окружении и на сайте не проверяется.")
    result.notes.append("Поддерживаются точные версии PyPI, npm, Packagist, crates.io и Go; маркеры окружения не вычисляются, dev/условные зависимости включаются в инвентарь.")
    result.notes.append("Локальные workspace-пакеты Cargo/uv не отправляются в OSV. Для Poetry/uv/Cargo/Pipfile учитывается доступная информация об источнике; PURL с qualifiers/subpath пропускаются.")
    result.notes.append("Для requirements/npm/Composer сопоставляются заявленные имена и версии; происхождение частных пакетов и форков этим не подтверждается.")
    try:
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
            raise ValueError("Таймаут должен быть больше 0 и не больше 60 секунд.")
        paths, capped = _manifest_paths(Path(path).expanduser())
        if capped:
            result.metadata["incomplete"] = True
            result.notes.append(f"Достигнут лимит обзора папки: до 5000 записей и {MAX_MANIFESTS} манифестов; остальные не проверены.")
        if not paths:
            raise ValueError("В указанной папке не найдены поддерживаемые lock-файлы, requirements*.txt или CycloneDX SBOM.")
    except (OSError, ValueError, TypeError) as exc:
        result.errors.append(_clean(exc))
        return result.finish()
    inventory = {}
    skipped = 0
    for manifest in paths:
        try:
            if manifest.name == "go.sum":
                result.notes.append("go.sum — инвентарь контрольных сумм: он может содержать неиспользуемые версии; записи только /go.mod не проверяются.")
            packages, count = _read_manifest(manifest)
            skipped += count
            for package in packages:
                if package.key in inventory:
                    known = inventory[package.key]
                    known.sources = list(dict.fromkeys(known.sources + package.sources))
                else:
                    inventory[package.key] = package
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            result.errors.append(f"{_clean(manifest.name)}: {_clean(exc)}")
    packages = sorted(inventory.values(), key=lambda d: d.key)
    result.metadata["manifest_count"] = len(paths)
    result.metadata["skipped_entries"] = skipped
    if skipped:
        result.metadata["incomplete"] = True
        result.notes.append(f"Пропущены записи без поддерживаемой точной версии или экосистемы: {skipped}. Диапазоны версий не угадываются.")
    if len(packages) > MAX_PACKAGES:
        result.metadata["incomplete"] = True
        result.notes.append(f"Инвентарь ограничен первыми {MAX_PACKAGES} из {len(packages)} уникальных пакетов.")
        packages = packages[:MAX_PACKAGES]
    result.metadata["inventory"] = [package.to_dict() for package in packages]
    result.metadata["packages"] = len(packages)
    if not packages:
        result.notes.append("Поддерживаемые зависимости с точными версиями не найдены; вывод об отсутствии уязвимостей невозможен.")
    if not online:
        result.metadata["advisories_checked"] = False
        result.checks.append({"module": "dependencies", "status": "skipped",
                              "detail": "Сетевой поиск OSV выключен. Создан только инвентарь; CVE не проверялись."})
        result.notes.append("Для сопоставления с OSV запустите проверку с online=True или флагом --online.")
        return result.finish()
    result.metadata["advisories_checked"] = False
    deadline = time.monotonic() + MAX_AUDIT_SECONDS
    for package in packages:
        tokens, seen_ids, token = set(), set(), None
        completed = False
        try:
            for page in range(MAX_PAGES):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Исчерпан общий бюджет сетевого поиска OSV (90 секунд).")
                payload = {"package": {"ecosystem": package.ecosystem, "name": package.name},
                           "version": package.version}
                if token:
                    payload["page_token"] = token
                data = _post_query(payload, min(float(timeout), remaining))
                records = data.get("vulns", [])
                if not isinstance(records, list):
                    raise ValueError("Некорректная таблица vulns в ответе OSV.")
                for record in records:
                    if not isinstance(record, dict):
                        raise ValueError("Некорректная запись уязвимости OSV.")
                    identifier = record.get("id")
                    if isinstance(identifier, str) and identifier in seen_ids:
                        continue
                    finding = _advisory_finding(record, package)
                    if finding:
                        result.findings.append(finding)
                    if isinstance(identifier, str):
                        seen_ids.add(identifier)
                token = data.get("next_page_token")
                if token is None or token == "":
                    completed = True
                    break
                if not isinstance(token, str) or len(token) > 8192 or token in tokens:
                    raise ValueError("Некорректная или повторяющаяся пагинация OSV.")
                tokens.add(token)
            if not completed:
                raise ValueError(f"Достигнут лимит {MAX_PAGES} страниц OSV для одного пакета.")
            result.metadata["checked_packages"] += 1
            result.metadata["advisories_checked"] = True
            result.checks.append({"module": "dependencies", "status": "checked",
                                  "detail": f"{package.ecosystem} {package.name}@{package.version}: {len(seen_ids)} записей OSV; применимость требует проверки."})
        except (OSError, ValueError, error.URLError, ssl.SSLError, HTTPException, RecursionError) as exc:
            # External error text can contain arbitrary response data; retain
            # only the exception class, except our own deliberately brief text.
            message = _clean(exc) if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError) else type(exc).__name__
            if isinstance(exc, TimeoutError) and deadline <= time.monotonic():
                message = "Исчерпан общий бюджет 90 секунд."
            result.errors.append(f"OSV {package.name}@{package.version}: {message}")
            result.metadata["incomplete"] = True
            result.checks.append({"module": "dependencies", "status": "error",
                                  "detail": f"{package.name}@{package.version}: проверка не завершена."})
        if time.monotonic() >= deadline:
            result.metadata["incomplete"] = True
            result.notes.append("Достигнут общий лимит времени OSV; оставшиеся пакеты не проверены.")
            break
    if result.metadata["checked_packages"] < len(packages):
        result.metadata["incomplete"] = True
    result.metadata["advisory_matches"] = len(result.findings)
    result.notes.append("Отсутствие записи OSV не доказывает отсутствие уязвимостей. Проверены только перечисленные версии и поддерживаемые экосистемы.")
    return result.finish()
