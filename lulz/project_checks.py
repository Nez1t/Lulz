"""Bounded local secret and infrastructure-configuration review.

No source file is executed, no credential is validated, and no network is used.
Only recognized static settings are evaluated; unresolved expressions stay unknown.
"""
from __future__ import annotations

from collections import Counter
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import stat
from urllib.parse import unquote, urlsplit

from .models import Finding, ScanResult


MODULES = {"config": "Dockerfile и Kubernetes/Terraform JSON", "secrets": "Кандидаты на секреты в локальных файлах"}
MAX_FILES = 1500
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_JSON_NODES = 50000
MAX_FINDINGS = 2500
MAX_LINE_LENGTH = 65536
SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv", "env",
    "__pycache__", "build", "dist", "reports", ".lulz-backups", ".next", ".nuxt", ".tox",
    ".mypy_cache", ".pytest_cache", "site-packages", "coverage"})
TEXT_SUFFIXES = frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".go",
    ".java", ".cs", ".c", ".cpp", ".h", ".sh", ".ps1", ".json", ".yaml", ".yml", ".toml", ".ini",
    ".conf", ".cfg", ".config", ".properties", ".xml", ".tf", ".txt", ".html", ".htm", ".pem", ".key"})
K8S_REF = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
DOCKER_REF = "https://docs.docker.com/reference/dockerfile/"
TF_REF = "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group"
S3_REF = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
SECRET_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
_PLACEHOLDER = re.compile(r"example|sample|dummy|placeholder|changeme|change[_-]?me|replace|redacted|your[_-]|<|>|\$\{|\{\{|\}\}|getenv|environ|secret[_-]?here|token[_-]?here|test(?:ing)?[_-]?(?:key|secret|token)", re.I)
_QUOTED = re.compile(r"[\"']?(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,80})[\"']?\s*(?:=|:)\s*(?P<q>[\"'])(?P<value>[^\r\n]{0,4096}?)(?P=q)")
_BARE = re.compile(r"^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_]{0,80})\s*=\s*(?P<value>[^\s#\"']{1,4096})\s*(?:#.*)?$")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{1,15}://[^\s\"'<>]{1,4096}")
_PEM = re.compile(r"-----BEGIN (?P<kind>(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----\s*(?P<body>[A-Za-z0-9+/=\r\n\t ]{32,16384}?)\s*-----END (?P=kind)-----")


def _clean(value: object, limit: int = 400) -> str:
    return "".join(c for c in str(value) if c.isprintable())[:limit]


def _note(result: ScanResult, message: str, incomplete: bool = False) -> None:
    if message not in result.notes and len(result.notes) < 100:
        result.notes.append(message)
    if incomplete:
        result.metadata["incomplete"] = True


def _add(result: ScanResult, path: Path, rule: str, title: str, module: str,
         evidence: str, description: str, remediation: str, *, line: int | None = None,
         severity: str = "medium", confidence: str = "high", cwe: str = "",
         reference: str = "", status: str = "review") -> None:
    if len(result.findings) >= MAX_FINDINGS:
        _note(result, f"Достигнут предел находок: {MAX_FINDINGS}.", True)
        result.metadata["finding_limit_reached"] = True
        return
    result.findings.append(Finding(rule_id=rule, title=title, severity=severity, category=module,
        evidence=_clean(evidence, 1200), description=description, remediation=remediation,
        location=f"{_clean(path)}:{line}" if line else _clean(path), confidence=confidence,
        status=status, cwe=[cwe] if cwe else [], references=[reference] if reference else []))


def _is_dockerfile(path: Path) -> bool:
    name = path.name.lower()
    return name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")


def _supported(path: Path, selected: set[str]) -> bool:
    name, suffix = path.name.lower(), path.suffix.lower()
    if _is_dockerfile(path):
        return True
    if "secrets" in selected and (suffix in TEXT_SUFFIXES or name.startswith(".env") or name in {"credentials", "config"}):
        return True
    return "config" in selected and suffix in {".json", ".yaml", ".yml", ".tf"}


def _is_link(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _files(root: Path, selected: set[str], result: ScanResult):
    if root.is_file():
        yield root
        return
    pending = [root]
    count = 0
    while pending:
        directory = pending.pop()
        try:
            entries = []
            with os.scandir(directory) as listing:
                for entry in listing:
                    count += 1
                    if count > MAX_ENTRIES:
                        _note(result, f"Достигнут предел обхода: {MAX_ENTRIES} объектов.", True)
                        return
                    entries.append(entry)
            children = []
            for entry in sorted(entries, key=lambda item: (item.name.casefold(), item.name)):
                candidate = Path(entry.path)
                try:
                    if _is_link(candidate):
                        result.metadata["skipped_links"] += 1
                    elif entry.is_dir(follow_symlinks=False):
                        if entry.name.lower() in SKIP_DIRS:
                            result.metadata["skipped_directories"] += 1
                        else:
                            children.append(candidate)
                    elif entry.is_file(follow_symlinks=False) and _supported(candidate, selected):
                        yield candidate
                except OSError:
                    result.errors.append(f"Не удалось проверить объект: {_clean(candidate.name)}.")
            pending.extend(reversed(children))
        except OSError:
            result.errors.append(f"Не удалось прочитать каталог: {_clean(directory.name)}.")


def _entropy(value: str) -> float:
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in Counter(value).values()) if length else 0.0


def _credential_kind(key: str) -> str:
    normalized = re.sub(r"[^a-z]", "", key.lower())
    if normalized.endswith(("password", "passwd", "pwd")):
        return "пароль"
    if normalized.endswith(("apikey", "clientsecret", "secretkey", "accesskey")):
        return "ключ/секрет приложения"
    if normalized.endswith(("accesstoken", "authtoken", "bearertoken", "refreshtoken")):
        return "токен доступа"
    if normalized in {"secret", "secretvalue"}:
        return "секрет"
    return ""


def _possible_secret(value: str, kind: str) -> bool:
    if _PLACEHOLDER.search(value) or value.lower() in {"password", "secret", "undefined", "null", "none"}:
        return False
    if len(value) < (12 if kind == "пароль" else 20) or len(value) > 4096 or len(set(value)) < 6:
        return False
    if value.startswith(("$", "%", "env.", "process.", "os.", "config.", "settings.")):
        return False
    return _entropy(value) >= (3.2 if kind == "пароль" else 3.5)


def _secrets(text: str, path: Path, result: ScanResult) -> None:
    for match in _PEM.finditer(text):
        if len(re.sub(r"\s", "", match["body"])) < 32:
            continue
        _add(result, path, "SEC-PRIVATE-KEY", "В файле найден блок приватного ключа", "secrets",
             "Обнаружены согласованные PEM-маркеры приватного ключа и непустое тело; значение полностью скрыто.",
             "Файл содержит структуру приватного ключа. Криптографическая корректность, происхождение и использование не проверялись.",
             "Проверьте назначение ключа; вынесите рабочий ключ из исходников и замените его, если он был раскрыт.",
             line=text.count("\n", 0, match.start()) + 1, severity="high", cwe="CWE-798", reference=SECRET_REF)
    long_lines = 0
    env_like = path.name.lower().startswith(".env") or path.suffix.lower() in {".ini", ".conf", ".cfg", ".properties"}
    for number, raw in enumerate(text.splitlines(), 1):
        if len(raw) > MAX_LINE_LENGTH:
            long_lines += 1
            continue
        if raw.lstrip().startswith(("#", "//", "<!--", ";")):
            continue
        matches = list(_QUOTED.finditer(raw))
        bare_text = raw
        docker_assignment = _is_dockerfile(path) and bool(re.match(r"\s*(?:ENV|ARG)\s+", raw, re.I))
        if docker_assignment:
            bare_text = re.sub(r"^\s*(?:ENV|ARG)\s+", "", raw, flags=re.I)
        if env_like or docker_assignment:
            bare = _BARE.match(bare_text)
            if bare:
                matches.append(bare)
        found_assignment = False
        for match in matches:
            kind = _credential_kind(match["key"])
            if kind and _possible_secret(match["value"], kind):
                found_assignment = True
                _add(result, path, "SEC-CREDENTIAL-LITERAL", "Статическое значение похоже на секрет", "secrets",
                     f"Категория поля: {kind}; строковый литерал прошёл порог длины и энтропии. Значение полностью скрыто.",
                     "Эвристика сопоставила имя поля со строковым значением; это может быть тестовое или неиспользуемое значение.",
                     "Уточните происхождение; рабочие секреты храните в менеджере секретов, а раскрытые значения замените.",
                     line=number, confidence="medium", cwe="CWE-798", reference=SECRET_REF)
        if found_assignment:
            continue
        for match in _URL.finditer(raw):
            try:
                parsed = urlsplit(match.group(0))
                password = unquote(parsed.password or "")
                username = unquote(parsed.username or "")
                if not parsed.hostname or not username or len(password) < 8 or _PLACEHOLDER.search(password) or _PLACEHOLDER.search(username):
                    continue
                if password.lower() in {"password", "changeme", "postgres", "username"} or password.startswith(("$", "%")):
                    continue
            except ValueError:
                continue
            _add(result, path, "SEC-URL-CREDENTIAL", "Учётные данные встроены в URL", "secrets",
                 "URL содержит непустые userinfo username/password. URL, имя пользователя и пароль полностью скрыты.",
                 "Статический URL включает пароль. Доступность сервиса и действительность учётных данных не проверялись.",
                 "Вынесите учётные данные в менеджер секретов; исключите такие URL из репозитория и логов.",
                 line=number, confidence="medium", cwe="CWE-798", reference=SECRET_REF)
    if long_lines:
        _note(result, f"{_clean(path)}: секреты не проверены в слишком длинных строках ({long_lines}).", True)


def _mapping(value) -> dict:
    return value if isinstance(value, dict) else {}


def _integer(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _kubernetes(document: dict, path: Path, result: ScanResult, prefix: str = "$") -> None:
    kind = document.get("kind")
    if not isinstance(document.get("apiVersion"), str) or not isinstance(kind, str):
        return
    if kind == "List":
        items = document.get("items")
        if isinstance(items, list):
            for index, child in enumerate(items[:1000]):
                if isinstance(child, dict):
                    _kubernetes(child, path, result, f"{prefix}.items[{index}]")
            if len(items) > 1000:
                _note(result, "Kubernetes List ограничен 1000 документами.", True)
        return
    spec = _mapping(document.get("spec"))
    if kind == "Pod":
        pod, pointer = spec, prefix + ".spec"
    elif kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "ReplicationController"}:
        pod, pointer = _mapping(_mapping(spec.get("template")).get("spec")), prefix + ".spec.template.spec"
    elif kind == "CronJob":
        job = _mapping(_mapping(spec.get("jobTemplate")).get("spec"))
        pod, pointer = _mapping(_mapping(job.get("template")).get("spec")), prefix + ".spec.jobTemplate.spec.template.spec"
    else:
        return
    if not pod:
        _note(result, f"{_clean(path)}: у распознанного Kubernetes-объекта нет читаемого PodSpec.", True)
        return
    result.metadata["config_documents"] += 1
    namespaces = [key for key in ("hostNetwork", "hostPID", "hostIPC") if pod.get(key) is True]
    if namespaces:
        _add(result, path, "CFG-K8S-HOST-NAMESPACE", "Pod запрашивает пространства имён узла", "config",
             f"JSON {pointer}: " + ", ".join(key + "=true" for key in namespaces) + ".",
             "Статический манифест ослабляет изоляцию от узла. Фактическое развёртывание и необходимость этих прав не проверялись.",
             "Отключите ненужные hostNetwork/hostPID/hostIPC и согласуйте исключения с политикой кластера.",
             cwe="CWE-250", reference=K8S_REF)
    volumes = pod.get("volumes", [])
    if isinstance(volumes, list) and any(isinstance(v, dict) and isinstance(v.get("hostPath"), dict) for v in volumes):
        _add(result, path, "CFG-K8S-HOSTPATH", "Pod содержит том hostPath", "config",
             f"JSON {pointer}.volumes: есть hostPath; путь узла не сохраняется.",
             "Подключение файловой системы узла требует отдельной оценки путей, прав и режима readOnly.",
             "Предпочитайте управляемые тома; для необходимого hostPath минимизируйте права и доступные пути.",
             cwe="CWE-250", reference=K8S_REF)
    if _mapping(pod.get("os")).get("name") == "windows":
        _note(result, "Linux-правила UID и securityContext не применялись к Pod с os.name=windows.")
        return
    pod_context = _mapping(pod.get("securityContext"))
    for collection in ("containers", "initContainers", "ephemeralContainers"):
        containers = pod.get(collection, [])
        if not isinstance(containers, list):
            _note(result, f"{_clean(path)}: некорректная коллекция Kubernetes containers.", True)
            continue
        for index, container in enumerate(containers):
            if not isinstance(container, dict):
                _note(result, f"{_clean(path)}: некорректная запись контейнера Kubernetes.", True)
                continue
            context = _mapping(container.get("securityContext"))
            address = f"{pointer}.{collection}[{index}].securityContext"
            if context.get("privileged") is True:
                _add(result, path, "CFG-K8S-PRIVILEGED", "Контейнер запрашивает privileged", "config",
                     f"JSON {address}.privileged=true.", "В статическом манифесте запрошены расширенные привилегии контейнера.",
                     "Уберите privileged и выдайте только минимально необходимые полномочия.",
                     severity="high", cwe="CWE-250", reference=K8S_REF)
            user = context.get("runAsUser", pod_context.get("runAsUser"))
            if _integer(user) == 0:
                _add(result, path, "CFG-K8S-ROOT", "Для контейнера задан UID 0", "config",
                     f"JSON {address}: эффективный статический runAsUser=0 (учтён Pod securityContext).",
                     "Манифест задаёт пользователя root. Политики admission и реально применённая спецификация не проверялись.",
                     "Используйте непривилегированный UID и подходящий образ контейнера.", cwe="CWE-250", reference=K8S_REF)
            nonroot = context.get("runAsNonRoot", pod_context.get("runAsNonRoot"))
            if nonroot is False or nonroot is None:
                _add(result, path, "CFG-K8S-NONROOT", "Ограничение runAsNonRoot не включено явно", "config",
                     f"JSON {address}: эффективный runAsNonRoot " + ("false." if nonroot is False else "не указан."),
                     "Это замечание по конфигурации, а не доказательство запуска от root: образ и admission могут задавать другие ограничения.",
                     "При совместимости приложения задайте runAsNonRoot=true на уровне Pod или контейнера.",
                     severity="info", confidence="medium" if nonroot is False else "low", reference=K8S_REF)
            if context.get("allowPrivilegeEscalation") is True:
                _add(result, path, "CFG-K8S-ESCALATION", "Разрешено повышение привилегий контейнера", "config",
                     f"JSON {address}.allowPrivilegeEscalation=true.",
                     "Манифест явно разрешает процессам получать дополнительные привилегии; необходимость требует проверки.",
                     "Установите allowPrivilegeEscalation=false, если приложение не требует исключения.",
                     cwe="CWE-250", reference=K8S_REF)
            additions = _mapping(context.get("capabilities")).get("add", [])
            if isinstance(additions, list):
                sensitive = sorted({cap for cap in additions if isinstance(cap, str) and cap in {"ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "DAC_READ_SEARCH", "DAC_OVERRIDE"}})
                if sensitive:
                    _add(result, path, "CFG-K8S-CAPABILITIES", "Добавлены широкие Linux capabilities", "config",
                         f"JSON {address}.capabilities.add: " + ", ".join(sensitive) + ".",
                         "Заданы возможности, существенно расширяющие полномочия процесса. Проверена только конфигурация.",
                         "Удалите ненужные capabilities; используйте drop: [ALL] и минимальный список исключений.",
                         cwe="CWE-250", reference=K8S_REF)


def _world(value) -> bool:
    if not isinstance(value, str) or "$" in value or "{" in value:
        return False
    try:
        return ipaddress.ip_network(value, strict=False).prefixlen == 0
    except ValueError:
        return False


def _ingress(attributes: dict, path: Path, result: ScanResult, address: str, modern: bool = False) -> None:
    sources = [attributes.get("cidr_ipv4"), attributes.get("cidr_ipv6")] if modern else []
    for key in ("cidr_blocks", "ipv6_cidr_blocks"):
        if isinstance(attributes.get(key), list):
            sources.extend(attributes[key])
    if not any(_world(source) for source in sources):
        return
    protocol = attributes.get("ip_protocol" if modern else "protocol")
    low, high = _integer(attributes.get("from_port")), _integer(attributes.get("to_port"))
    all_protocols = protocol in ("-1", -1) and not isinstance(protocol, bool)
    tcp = protocol in ("tcp", "TCP", "6", 6)
    if all_protocols or tcp and low is not None and high is not None and low <= 0 and high >= 65535:
        _add(result, path, "CFG-TF-SG-ALL", "Ingress разрешает все порты для всего интернета", "config",
             f"{address}: публичный CIDR /0 и все протоколы либо полный диапазон TCP.",
             "Статическая конфигурация содержит широкое разрешение. Наличие ресурса и другие сетевые ограничения не проверялись.",
             "Ограничьте источники и порты необходимыми адресами и службами.", severity="high", cwe="CWE-284", reference=TF_REF)
    elif tcp and low is not None and high is not None:
        ports = [port for port in (22, 3389) if low <= port <= high]
        if ports:
            _add(result, path, "CFG-TF-SG-ADMIN", "Административные порты разрешены для всего интернета", "config",
                 f"{address}: публичный CIDR /0; включены TCP-порты " + ", ".join(map(str, ports)) + ".",
                 "Правило разрешает SSH/RDP из произвольных адресов. Доступность службы и аутентификация не проверялись.",
                 "Ограничьте административный доступ доверенными сетями или управляемым защищённым каналом.",
                 cwe="CWE-284", reference=TF_REF)


def _terraform(document: dict, path: Path, result: ScanResult) -> None:
    resources = document.get("resource")
    if not isinstance(resources, dict):
        return
    supported = {"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule",
                 "aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster", "aws_s3_bucket",
                 "aws_s3_bucket_acl", "aws_s3_bucket_public_access_block", "aws_instance"}
    for resource_type, declarations in sorted(resources.items()):
        if resource_type not in supported or not isinstance(declarations, dict):
            continue
        for index, (_, attributes) in enumerate(sorted(declarations.items()), 1):
            if not isinstance(attributes, dict):
                _note(result, "Некоторые Terraform-объекты не представлены статическими JSON-объектами.")
                continue
            result.metadata["config_documents"] += 1
            address = f"Terraform {resource_type}, объект #{index}"
            if resource_type == "aws_security_group":
                ingress = attributes.get("ingress", [])
                if isinstance(ingress, dict):
                    ingress = [ingress]
                if isinstance(ingress, list):
                    for position, entry in enumerate(ingress):
                        if isinstance(entry, dict):
                            _ingress(entry, path, result, f"{address}, ingress[{position}]")
            elif resource_type == "aws_security_group_rule" and attributes.get("type") == "ingress":
                _ingress(attributes, path, result, address)
            elif resource_type == "aws_vpc_security_group_ingress_rule":
                _ingress(attributes, path, result, address, modern=True)
            elif resource_type in {"aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"} and attributes.get("publicly_accessible") is True:
                _add(result, path, "CFG-TF-DB-PUBLIC", "База данных настроена как publicly_accessible", "config",
                     f"{address}: publicly_accessible=true.",
                     "Запрошена публичная адресация базы. Security groups, маршрутизация и реально развёрнутая среда не проверялись.",
                     "Если внешний доступ не нужен, отключите публичную адресацию и используйте частные сети.",
                     cwe="CWE-284", reference="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html")
            elif resource_type in {"aws_s3_bucket", "aws_s3_bucket_acl"} and attributes.get("acl") in ("public-read", "public-read-write", "authenticated-read"):
                _add(result, path, "CFG-TF-S3-ACL", "S3 ACL предоставляет широкие права", "config",
                     f"{address}: широкая canned ACL (AllUsers/AuthenticatedUsers).",
                     "Конфигурация запрашивает широкую ACL. Block Public Access и Object Ownership могут блокировать её применение.",
                     "Используйте private ACL или отключённые ACL и минимальную политику доступа; проверьте Block Public Access.",
                     cwe="CWE-284", reference=S3_REF)
            elif resource_type == "aws_s3_bucket_public_access_block":
                disabled = [key for key in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets") if attributes.get(key) is False]
                if disabled:
                    _add(result, path, "CFG-TF-S3-BLOCK", "Часть ограничений S3 Block Public Access отключена", "config",
                         f"{address}: " + ", ".join(key + "=false" for key in disabled) + ".",
                         "Отключение ограничения само по себе не делает бакет публичным; общая политика доступа не вычисляется.",
                         "Включите все применимые ограничения и документируйте необходимые исключения.", severity="info", reference=S3_REF)
            elif resource_type == "aws_instance":
                options = attributes.get("metadata_options", [])
                if isinstance(options, dict):
                    options = [options]
                if isinstance(options, list) and any(isinstance(option, dict) and option.get("http_tokens") == "optional" and option.get("http_endpoint") != "disabled" for option in options):
                    _add(result, path, "CFG-TF-IMDS", "Для EC2 не требуется токен IMDSv2", "config",
                         f"{address}: metadata_options.http_tokens=optional при неотключённом endpoint.",
                         "Статическая конфигурация допускает получение метаданных без обязательного токена IMDSv2.",
                         "После проверки совместимости установите http_tokens=required.",
                         reference="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html")


def _docker_instructions(text: str):
    escape_char = "\\"
    current, first = "", 1
    heredoc = []
    for number, raw in enumerate(text.splitlines(), 1):
        if heredoc:
            if raw.strip() == heredoc[0]:
                heredoc.pop(0)
            continue
        if not current and raw.lstrip().startswith("#"):
            match = re.match(r"\s*#\s*escape\s*=\s*([`\\])\s*$", raw, re.I)
            if match:
                escape_char = match[1]
            continue
        if not current:
            first = number
        piece = raw.rstrip()
        continued = piece.endswith(escape_char)
        current += (piece[:-1] if continued else piece) + " "
        if continued:
            continue
        match = re.match(r"\s*([A-Za-z]+)\s+(.+?)\s*$", current)
        current = ""
        if not match:
            continue
        operation, argument = match[1].upper(), match[2]
        heredoc = re.findall(r"<<-?['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", argument)
        yield operation, argument, first


def _docker(text: str, path: Path, result: ScanResult) -> None:
    stages, names = [], {}
    for operation, argument, line in _docker_instructions(text):
        if operation == "FROM":
            try:
                parts = shlex.split(argument)
            except ValueError:
                _note(result, f"{_clean(path)}:{line}: инструкция FROM не разобрана.", True)
                continue
            while parts and parts[0].startswith("--"):
                parts.pop(0)
            if not parts:
                continue
            inherited = names.get(parts[0].lower())
            stage = {"user": inherited.get("user") if inherited else None, "line": line}
            stages.append(stage)
            if len(parts) >= 3 and parts[-2].lower() == "as":
                names[parts[-1].lower()] = stage
        elif operation == "USER" and stages:
            stages[-1]["user"] = argument.strip()
            stages[-1]["line"] = line
        elif operation == "ADD" and stages:
            if re.search(r"\bhttps?://", argument, re.I) and not re.search(r"--checksum(?:=|\s)\S+", argument):
                _add(result, path, "CFG-DOCKER-REMOTE-ADD", "Удалённый ADD не закреплён checksum", "config",
                     "Инструкция ADD содержит HTTP(S)-источник без --checksum; URL не сохраняется.",
                     "Содержимое удалённого источника может меняться; последующая проверка файла в RUN не анализируется.",
                     "Закрепите ожидаемую контрольную сумму или проверяйте подпись и целостность загружаемого артефакта.",
                     line=line, severity="low", confidence="medium", reference=DOCKER_REF)
    if not stages:
        _note(result, f"{_clean(path)}: не найден распознанный FROM; Dockerfile не оценён.", True)
        return
    result.metadata["config_documents"] += 1
    user, line = stages[-1]["user"], stages[-1]["line"]
    if user is None:
        _add(result, path, "CFG-DOCKER-USER-UNSPECIFIED", "Пользователь финального образа не задан явно", "config",
             "В финальной стадии не найден USER; пользователь базового образа неизвестен.",
             "Это замечание для ручной проверки. Базовый образ может уже использовать непривилегированного пользователя.",
             "Проверьте настройки базового образа и при необходимости задайте непривилегированный USER.",
             line=line, severity="info", confidence="low", reference=DOCKER_REF)
    elif "$" not in user and user.split(":", 1)[0].strip().lower() in {"root", "0"}:
        _add(result, path, "CFG-DOCKER-ROOT", "Финальная стадия Dockerfile использует root", "config",
             "Эффективная инструкция USER финальной стадии задаёт root/UID 0; учтено наследование локальной стадии.",
             "Образ будет по умолчанию использовать root, если runtime не переопределит пользователя.",
             "Задайте минимально привилегированного пользователя и проверьте права на нужные файлы.",
             line=line, cwe="CWE-250", reference=DOCKER_REF)


def _configuration(text: str, path: Path, result: ScanResult) -> None:
    if _is_dockerfile(path):
        _docker(text, path, result)
        return
    if path.suffix.lower() == ".tf":
        result.metadata["unsupported_config_files"] += 1
        _note(result, "Terraform HCL (.tf) не разбирается; поддерживается конфигурация Terraform JSON (.tf.json).", True)
        return
    if path.suffix.lower() in {".yaml", ".yml"}:
        recognized = "compose" in path.name.lower() or bool(re.search(r"(?m)^\s*(?:apiVersion\s*:|kind\s*:\s*(?:Pod|Deployment|DaemonSet|StatefulSet|Job|CronJob)\b)", text))
        if recognized:
            result.metadata["unsupported_config_files"] += 1
            _note(result, "Распознаны YAML-конфигурации; структурные проверки YAML не выполняются. Для Kubernetes нужен JSON-экспорт.", True)
        return
    if path.suffix.lower() != ".json":
        return
    try:
        document = json.loads(text)
        stack, count = [document], 0
        while stack:
            item = stack.pop()
            count += 1
            if count > MAX_JSON_NODES:
                raise ValueError("json node limit")
            if isinstance(item, dict):
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
        if isinstance(document, dict):
            _kubernetes(document, path, result)
            _terraform(document, path, result)
    except (ValueError, RecursionError):
        result.errors.append(f"JSON не разобран или превышает предел сложности: {_clean(path)}. Содержимое ошибки скрыто.")


def scan_project_checks(path: str, modules: list[str] | None = None) -> ScanResult:
    selected = set(MODULES if modules is None else modules)
    result = ScanResult(kind="project_checks", target=_clean(path), modules=[key for key in MODULES if key in selected])
    result.metadata.update(files_scanned=0, files_considered=0, bytes_read=0, config_documents=0,
        unsupported_config_files=0, skipped_files=0, skipped_links=0, skipped_directories=0, incomplete=False,
        limits={"files": MAX_FILES, "file_bytes": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES,
                "entries": MAX_ENTRIES, "findings": MAX_FINDINGS})
    result.notes.append("Локальные файлы не выполняются. Секреты не проверяются онлайн и не сохраняются в отчёте; находки требуют проверки контекста.")
    if not selected or selected - MODULES.keys():
        result.errors.append("Укажите модули config и/или secrets.")
        return result.finish()
    try:
        supplied = Path(path).expanduser()
        if _is_link(supplied):
            raise ValueError("link")
        root = supplied.resolve(strict=True)
        if not root.is_dir() and not root.is_file():
            raise ValueError("file type")
    except (OSError, ValueError, RuntimeError):
        result.errors.append("Путь недоступен или не является обычным файлом/каталогом; ссылки и junction не обходятся.")
        return result.finish()
    result.target = _clean(root, 2000)
    scope = root if root.is_dir() else root.parent
    for candidate in _files(root, selected, result):
        if result.metadata.get("finding_limit_reached"):
            break
        if result.metadata["files_considered"] >= MAX_FILES:
            _note(result, f"Достигнут предел анализа: {MAX_FILES} файлов.", True)
            break
        result.metadata["files_considered"] += 1
        relative = candidate.relative_to(scope)
        if not _supported(candidate, selected):
            result.errors.append(f"Неподдерживаемый тип файла: {_clean(relative)}.")
            continue
        try:
            if _is_link(candidate) or not candidate.resolve(strict=True).is_relative_to(scope):
                result.metadata["skipped_links"] += 1
                continue
            remaining = MAX_TOTAL_BYTES - result.metadata["bytes_read"]
            if remaining <= 0:
                _note(result, "Достигнут общий предел чтения 32 MiB.", True)
                break
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            with os.fdopen(os.open(candidate, flags), "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise OSError("nonregular file")
                payload = stream.read(min(MAX_FILE_BYTES + 1, remaining + 1))
        except (OSError, ValueError, RuntimeError):
            result.errors.append(f"Не удалось прочитать файл: {_clean(relative)}.")
            continue
        result.metadata["bytes_read"] += len(payload)
        if result.metadata["bytes_read"] > MAX_TOTAL_BYTES:
            _note(result, "Достигнут общий предел чтения 32 MiB.", True)
            break
        if len(payload) > MAX_FILE_BYTES or b"\x00" in payload:
            result.metadata["skipped_files"] += 1
            _note(result, f"Большой или бинарный файл пропущен: {_clean(relative)}.", True)
            continue
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeError:
            result.errors.append(f"Файл не декодирован как UTF-8: {_clean(relative)}.")
            continue
        result.metadata["files_scanned"] += 1
        if "secrets" in selected:
            _secrets(text, relative, result)
        if "config" in selected:
            _configuration(text, relative, result)
    if not result.metadata["files_scanned"]:
        _note(result, "Подходящих файлов для выбранных проверок не найдено; оценка безопасности не выполнена.", True)
    result.metadata["module_coverage"] = {}
    for module in result.modules:
        detail = (f"Файлов прочитано: {result.metadata['files_scanned']}; поддерживаемых конфигурационных объектов: {result.metadata['config_documents']}."
                  if module == "config" else f"Файлов прочитано: {result.metadata['files_scanned']}; значения секретов скрыты, действительность не проверялась.")
        status = "partial" if result.errors or result.metadata.get("incomplete") else "observed"
        if not result.metadata["files_scanned"] or module == "config" and not result.metadata["config_documents"]:
            status = "skipped"
        result.metadata["module_coverage"][module] = status
        result.checks.append({"module": module, "name": MODULES[module], "status": status, "detail": detail})
    if "config" in selected and not result.metadata["config_documents"]:
        _note(result, "Поддерживаемые Dockerfile/Kubernetes JSON/Terraform JSON объекты не найдены.")
    return result.finish()
