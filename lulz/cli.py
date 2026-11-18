"""Green console UI and automation-friendly command line, without dependencies."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import sys
import textwrap
import threading
import time

from . import __version__
from .models import SEVERITIES
from .reports import LEVEL_NAMES, STATUS_NAMES, compare_reports, load_report, plain, report_history, save_reports


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT / "reports"


class Console:
    def __init__(self, no_color=False):
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                try:
                    stream.reconfigure(encoding="utf-8", errors="replace")
                except (OSError, ValueError):
                    pass
        self.color = not no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()
        if self.color and os.name == "nt":
            try:
                import ctypes
                from ctypes import wintypes
                kernel = ctypes.windll.kernel32
                kernel.GetStdHandle.argtypes = [wintypes.DWORD]
                kernel.GetStdHandle.restype = wintypes.HANDLE
                kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
                kernel.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
                handle = kernel.GetStdHandle(-11 & 0xFFFFFFFF)
                mode = wintypes.DWORD()
                self.color = bool(kernel.GetConsoleMode(handle, ctypes.byref(mode)) and
                                  kernel.SetConsoleMode(handle, mode.value | 4))
            except (AttributeError, OSError):
                self.color = False

    def paint(self, text, style="green"):
        codes = {"green": "92", "dim": "2;32", "bold": "1;92", "warn": "93", "error": "91"}
        value = plain(text)
        return f"\033[{codes.get(style, '92')}m{value}\033[0m" if self.color else value

    def line(self, text="", style=None):
        print(self.paint(text, style) if style else plain(text))

    def banner(self):
        self.line()
        for line in ("  ██╗     ██╗   ██╗██╗     ███████╗", "  ██║     ██║   ██║██║     ╚══███╔╝",
                     "  ██║     ██║   ██║██║       ███╔╝ ", "  ██║     ██║   ██║██║      ███╔╝  ",
                     "  ███████╗╚██████╔╝███████╗███████╗", "  ╚══════╝ ╚═════╝ ╚══════╝╚══════╝"):
            self.line(line, "bold")
        self.line(f"  v{__version__}  /  WEB · HAR · SOURCE · CONFIG · SECRETS · CVE", "green")
        self.line("  " + "─" * 66, "dim")

    def prompt(self, message):
        return input(self.paint(f"  {message} > ", "green")).strip()

    @contextmanager
    def progress(self, label):
        stop = threading.Event()
        enabled = self.color
        started = time.monotonic()
        def animate():
            index = 0
            while not stop.wait(0.15):
                frame = "|/-\\"[index % 4]
                print("\r" + self.paint(f"  [{frame}] {label}  {time.monotonic()-started:.0f}s", "green"),
                      end="", flush=True)
                index += 1
        worker = None
        if enabled:
            worker = threading.Thread(target=animate, daemon=True)
            worker.start()
        else:
            self.line(f"  {label}...", "green")
        try:
            yield
        finally:
            stop.set()
            if worker:
                worker.join(timeout=1)
                print("\r\033[2K", end="", flush=True)


def _short(value, width=180):
    return textwrap.shorten(plain(value), width=width, placeholder=" …")


def show_result(console, result, output):
    console.line()
    incomplete = bool(result.errors or result.metadata.get("incomplete"))
    state = "НЕПОЛНАЯ ПРОВЕРКА" if incomplete else "ПРОВЕРКА ЗАВЕРШЕНА"
    if result.kind == "dependencies" and not result.metadata.get("online"):
        state = "ИНВЕНТАРИЗАЦИЯ · CVE НЕ ПРОВЕРЯЛИСЬ" + (" · НЕПОЛНАЯ" if result.errors or result.metadata.get("incomplete") else "")
    if result.kind == "project" and "dependencies" in result.modules and not result.metadata.get("components", {}).get("dependencies", {}).get("online"):
        state = "ОБЩИЙ АУДИТ · CVE НЕ ПРОВЕРЯЛИСЬ" + (" · НЕПОЛНЫЙ" if incomplete else "")
    console.line(f"  {state}", "warn" if incomplete else "bold")
    console.line(f"  Цель: {_short(result.target)}")
    console.line("  " + " · ".join(f"{level.upper()}: {sum(f.severity == level for f in result.findings)}"
                                        for level in SEVERITIES))
    console.line()
    if result.metadata.get("baseline"):
        console.line("  БАЗОВЫЙ ОТЧЁТ: " + " · ".join(
            f"{label}: {sum(f.baseline_state == value for f in result.findings)}"
            for value, label in (("new", "новые"), ("updated", "изменились"), ("unchanged", "существовали"))), "green")
    for index, finding in enumerate(result.findings[:30], 1):
        style = "error" if finding.severity in ("critical", "high") else "warn" if finding.severity == "medium" else "green"
        console.line(f"  {index:02}. [{finding.severity.upper()}] {_short(finding.title, 110)}", style)
        console.line(f"      {finding.rule_id} · {STATUS_NAMES.get(finding.status, finding.status)} · {finding.confidence}")
        if finding.baseline_state:
            console.line(f"      Baseline: {finding.baseline_state}", "dim")
        identifiers = ", ".join(finding.cwe + finding.cve)
        if identifiers:
            console.line(f"      {identifiers}", "dim")
        if finding.location:
            console.line(f"      {_short(finding.location, 150)}")
        console.line(f"      {_short(finding.evidence, 200)}")
    if len(result.findings) > 30:
        console.line(f"  Ещё {len(result.findings)-30} находок — в полном отчёте.")
    if not result.findings:
        console.line("  В выполненных проверках находок нет; это не подтверждает отсутствие уязвимостей.")
    for error in result.errors:
        console.line(f"  Ошибка: {_short(error)}", "error")
    for note in result.notes[:8]:
        console.line(f"  Примечание: {_short(note)}", "dim")
    paths = save_reports(result, output)
    console.line("\n  ОТЧЁТЫ", "bold")
    for extension, path in paths.items():
        console.line(f"  {extension.upper():4} {path}", "green")
    return paths


def _read_path(console, prompt):
    value = console.prompt(prompt)
    if len(value) > 1 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    return value


def _choose_modules(console, modules):
    keys = list(modules)
    console.line("\n  Выбери проверки:", "bold")
    console.line("  [A] Все модули")
    for index, key in enumerate(keys, 1):
        console.line(f"  [{index}] {modules[key]} ({key})")
    console.line("  [0] Назад")
    while True:
        response = console.prompt("Номера через запятую; Enter = все").lower()
        if response in ("", "a", "all", "все"):
            return keys
        if response == "0":
            return []
        selection = []
        try:
            for token in response.replace(" ", ",").split(","):
                if not token:
                    continue
                if token in keys:
                    key = token
                else:
                    number = int(token)
                    if number < 1 or number > len(keys):
                        raise ValueError
                    key = keys[number-1]
                if key not in selection:
                    selection.append(key)
            if selection:
                return selection
        except ValueError:
            pass
        console.line("  Укажи номера из списка, например 1,3, или A.", "warn")


def show_help(console):
    console.line("\n  КАК РАБОТАЕТ LULZ", "bold")
    for paragraph in (
        "URL: один обычный GET указанной страницы и не более трёх переходов на том же origin; допускается переход того же хоста с HTTP:80 на HTTPS:443. Для TLS — обычное соединение с проверкой сертификата.",
        "Проверки URL: заголовки и CSP, cookies, TLS, HTML/формы, mixed content и видимые признаки раскрытия технической информации. Внешние ресурсы страницы не загружаются.",
        "SQLi / XSS: анализ локальных исходников Python, JavaScript/TypeScript, PHP и шаблонов. Результат содержит файл и строку. Это кандидаты для ручной проверки; исходный код не выполняется.",
        "CVE: чтение lock-файлов или CycloneDX SBOM. Онлайн-поиск OSV получает только имена, экосистемы и версии пакетов. Офлайн-режим строит инвентаризацию без проверки бюллетеней.",
        "HAR: локальный анализ HTTP-ответов из сохранённой браузерной сессии. Можно проверить множество страниц и ограничить анализ одним хостом; запросы из архива не повторяются.",
        "Конфигурация и секреты: Dockerfile, Kubernetes/Terraform JSON, признаки приватных ключей и встроенных учётных данных. Значения секретов в отчёт не попадают.",
        "Общий аудит проекта объединяет исходники, конфигурацию, секреты и зависимости в один отчёт. Быстрый профиль не включает онлайн-поиск; состав проверок доступен в отчёте.",
        "CWE описывает класс ошибки. CVE — идентификатор опубликованной уязвимости: он показывается только при наличии в записи OSV. Совпадение версии не доказывает эксплуатацию в приложении.",
        "Отчёты JSON / HTML / Markdown / SARIF сохраняются в reports. В HTML доступны поиск и фильтры. --baseline сравнивает с сохранённым отчётом; --new-only применяет порог CI только к новым или изменившимся находкам.",
        "Нет загрузки атакующих шаблонов, перебора адресов, отправки форм, подбора паролей или активных SQLi/XSS-запросов. Наличие и отсутствие находок ограничены выбранными модулями и доступными данными.",
    ):
        console.line()
        console.line(textwrap.fill(paragraph, width=88, initial_indent="  ", subsequent_indent="  "))
    console.line("\n  Команды: web / source / deps / har / local / project / history / diff / modules / rules", "green")


def show_history(console, output):
    rows = report_history(output)
    console.line("\n  ПОСЛЕДНИЕ ОТЧЁТЫ", "bold")
    if not rows:
        console.line("  Сохранённых отчётов пока нет.")
    for row in rows:
        console.line(f"  {row['completed_at']} | {row['kind']} | находок: {row['count']}" +
                     (" | неполный" if not row['complete'] else ""), "green")
        console.line(f"    {_short(row['target'])}")
        console.line(f"    {row['path']}")


def show_diff(console, before_path, after_path):
    diff = compare_reports(load_report(before_path), load_report(after_path))
    console.line("\n  СРАВНЕНИЕ ОТЧЁТОВ", "bold")
    console.line(f"  Новые: {len(diff['new'])} · Изменились: {len(diff.get('updated', []))} · Больше не наблюдаются: {len(diff['not_seen'])} · Совпадают: {diff['unchanged']}")
    for key, label in (("new", "+"), ("updated", "~"), ("not_seen", "-")):
        for finding in diff[key]:
            console.line(f"  {label} {finding['rule_id']} {_short(finding['title'], 120)}")
    if diff['partial']:
        console.line("  Один из отчётов неполный: исчезновение находки не означает исправление.", "warn")
    console.line("  Совпадение: правило + расположение + доказательство. Исчезновение находки требует проверки.", "dim")


def interactive(console):
    from .web import MODULES as WEB_MODULES, scan_url
    from .source import MODULES as SOURCE_MODULES, scan_source
    from .dependencies import scan_dependencies
    while True:
        console.banner()
        for line in ("[1] Проверить URL", "[2] SQLi / XSS и другие риски — исходный код",
                     "[3] CVE — зависимости проекта", "[4] История отчётов",
                     "[5] Сравнить два JSON-отчёта", "[6] Справка и охват проверок",
                     "[7] HAR — анализ сохранённой сессии сайта", "[8] Конфигурация и секреты",
                     "[9] Общий аудит проекта", "[0] Выход"):
            console.line("  " + line, "green")
        console.line()
        try:
            choice = console.prompt("Выбор")
            if choice == "0":
                console.line("  Lulz завершён.", "dim")
                return 0
            if choice == "1":
                url = console.prompt("URL сайта, например https://example.com")
                if not url:
                    continue
                modules = _choose_modules(console, WEB_MODULES)
                if not modules:
                    continue
                with console.progress("Проверяю страницу"):
                    result = scan_url(url, modules=modules)
                show_result(console, result, DEFAULT_OUTPUT)
            elif choice == "2":
                path = _read_path(console, "Путь к папке проекта или файлу")
                if not path:
                    continue
                modules = _choose_modules(console, SOURCE_MODULES)
                if not modules:
                    continue
                with console.progress("Анализирую исходники"):
                    result = scan_source(path, modules=modules)
                show_result(console, result, DEFAULT_OUTPUT)
            elif choice == "3":
                path = _read_path(console, "Путь к lock-файлу, SBOM или папке проекта")
                if not path:
                    continue
                console.line("  OSV получает только имена, экосистемы и точные версии зависимостей.", "dim")
                online = console.prompt("Проверить бюллетени онлайн? [y/N]").lower() in ("y", "yes", "д", "да")
                with console.progress("Проверяю зависимости" if online else "Собираю инвентаризацию"):
                    result = scan_dependencies(path, online=online)
                show_result(console, result, DEFAULT_OUTPUT)
            elif choice == "4":
                show_history(console, DEFAULT_OUTPUT)
            elif choice == "5":
                before = _read_path(console, "Первый JSON-отчёт")
                after = _read_path(console, "Второй JSON-отчёт")
                if before and after:
                    show_diff(console, before, after)
            elif choice == "6":
                show_help(console)
            elif choice == "7":
                from .har import MODULES, scan_har
                path = _read_path(console, "Путь к HAR-файлу")
                if not path:
                    continue
                host = console.prompt("Только хост (например example.com); Enter = весь архив") or None
                modules = _choose_modules(console, MODULES)
                if not modules:
                    continue
                with console.progress("Анализирую сохранённую сессию"):
                    result = scan_har(path, modules=modules, host=host)
                show_result(console, result, DEFAULT_OUTPUT)
            elif choice == "8":
                from .project_checks import MODULES, scan_project_checks
                path = _read_path(console, "Папка проекта или файл")
                if not path:
                    continue
                modules = _choose_modules(console, MODULES)
                if not modules:
                    continue
                with console.progress("Проверяю конфигурацию и секреты"):
                    result = scan_project_checks(path, modules=modules)
                show_result(console, result, DEFAULT_OUTPUT)
            elif choice == "9":
                from .project import MODULES, scan_project
                path = _read_path(console, "Папка проекта")
                if not path:
                    continue
                modules = _choose_modules(console, MODULES)
                if not modules:
                    continue
                online = False
                if "dependencies" in modules:
                    console.line("  Для OSV передаются только имена, экосистемы и версии зависимостей.", "dim")
                    online = console.prompt("Проверить зависимости онлайн? [y/N]").lower() in ("y", "yes", "д", "да")
                with console.progress("Выполняю общий аудит проекта"):
                    result = scan_project(path, modules=modules, online=online)
                show_result(console, result, DEFAULT_OUTPUT)
            else:
                console.line("  Выбери пункт от 0 до 9.", "warn")
                continue
        except (OSError, ValueError, UnicodeError) as exc:
            console.line(f"  Ошибка: {_short(exc, 220)}", "error")
        except KeyboardInterrupt:
            console.line("\n  Операция остановлена. Возврат в меню.", "warn")
        except EOFError:
            console.line("\n  Ввод завершён.", "dim")
            return 0
        try:
            console.prompt("Enter — меню")
        except KeyboardInterrupt:
            console.line()
        except EOFError:
            return 0


def _timeout(value):
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Тайм-аут должен быть числом") from exc
    if not 1 <= parsed <= 30:
        raise argparse.ArgumentTypeError("Тайм-аут должен быть от 1 до 30 секунд")
    return parsed


def build_parser():
    parser = argparse.ArgumentParser(prog="lulz", description="Lulz — аудит конфигурации URL, исходников и зависимостей")
    parser.add_argument("--version", action="version", version=f"Lulz {__version__}")
    parser.add_argument("--no-color", action="store_true", help="Отключить цвет ANSI")
    commands = parser.add_subparsers(dest="command")
    for name, help_text in (("web", "Проверка настроек одной страницы"),
                            ("source", "SQLi/XSS и другие кандидаты в исходниках"),
                            ("deps", "Версии зависимостей и бюллетени OSV"),
                            ("har", "Локальный анализ HTTP-архива браузера"),
                            ("local", "Конфигурация и секреты в локальном проекте"),
                            ("project", "Общий аудит исходников, конфигурации, секретов и зависимостей")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("target", help="URL" if name == "web" else "Путь к проекту или файлу")
        command.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Папка отчётов")
        command.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS)
        command.add_argument("--fail-on", choices=SEVERITIES, help="Код 2 при находках этого уровня или выше")
        command.add_argument("--baseline", type=Path, help="Предыдущий совместимый JSON-отчёт Lulz")
        command.add_argument("--new-only", action="store_true", help="Порог --fail-on учитывает только новые/изменившиеся находки; нужен --baseline")
        if name in ("web", "deps", "project"):
            command.add_argument("--timeout", type=_timeout, default=10.0, help="Тайм-аут соединений 1–30 секунд")
        if name in ("deps", "project"):
            command.add_argument("--online", action="store_true", help="Отправить имена и версии пакетов в OSV")
        if name == "har":
            command.add_argument("--host", help="Проверять только точное имя хоста из HAR")
        if name != "deps":
            selection = command.add_mutually_exclusive_group()
            selection.add_argument("--checks", default="all", help="Модули через запятую; all = все")
            selection.add_argument("--profile", choices=("quick", "full"), help="Готовый профиль проверок")
    history = commands.add_parser("history", help="История сохранённых отчётов")
    history.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    diff = commands.add_parser("diff", help="Сравнение двух JSON-отчётов одной цели")
    diff.add_argument("before")
    diff.add_argument("after")
    commands.add_parser("modules", help="Названия доступных модулей и справка")
    commands.add_parser("rules", help="Каталог встроенных правил")
    return parser


def _parse_modules(value, available):
    if value.strip().lower() == "all":
        return list(available)
    selected = list(dict.fromkeys(item.strip().lower() for item in value.split(",") if item.strip()))
    unknown = set(selected) - set(available)
    if not selected or unknown:
        raise ValueError(f"Неизвестный набор модулей: {value}. Доступны: {', '.join(available)}")
    return selected


def _selected(args, available):
    quick = {"web": ["headers", "cookies"], "source": ["sql", "xss"],
             "har": ["headers", "cookies"], "local": ["config", "secrets"],
             "project": ["source", "config", "secrets"]}
    return quick[args.command] if args.profile == "quick" else _parse_modules(args.checks, available)


def main(argv=None):
    args = build_parser().parse_args(argv)
    console = Console(args.no_color)
    if not args.command:
        return interactive(console)
    try:
        if args.command == "modules":
            from .web import MODULES as web
            from .source import MODULES as source
            from .har import MODULES as har
            from .project_checks import MODULES as local
            from .project import MODULES as project
            for label, modules in (("web", web), ("source", source), ("har", har), ("local", local), ("project", project)):
                console.line(f"\n  {label}", "bold")
                for key, title in modules.items():
                    console.line(f"  {key:12} {title}")
            show_help(console)
            return 0
        if args.command == "rules":
            from .catalog import rule_catalog
            rules = rule_catalog()
            console.line(f"\n  КАТАЛОГ ПРАВИЛ: {len(rules)}", "bold")
            for rule in rules:
                console.line(f"  {rule['id']:30} {rule['title']}")
            return 0
        if args.command == "history":
            show_history(console, args.output)
            return 0
        if args.command == "diff":
            show_diff(console, args.before, args.after)
            return 0
        if args.new_only and not args.baseline:
            raise ValueError("--new-only требует --baseline с предыдущим JSON-отчётом")
        if args.baseline:
            baseline = load_report(args.baseline)
            if not baseline.get("complete"):
                raise ValueError("Неполный отчёт нельзя использовать как базовый для CI")
        if args.command == "web":
            from .web import MODULES, scan_url
            selected = _selected(args, MODULES)
            with console.progress("Проверяю страницу"):
                result = scan_url(args.target, modules=selected, timeout=args.timeout)
        elif args.command == "source":
            from .source import MODULES, scan_source
            selected = _selected(args, MODULES)
            with console.progress("Анализирую исходники"):
                result = scan_source(args.target, modules=selected)
        elif args.command == "har":
            from .har import MODULES, scan_har
            with console.progress("Анализирую HAR"):
                result = scan_har(args.target, modules=_selected(args, MODULES), host=args.host)
        elif args.command == "local":
            from .project_checks import MODULES, scan_project_checks
            with console.progress("Проверяю конфигурацию и секреты"):
                result = scan_project_checks(args.target, modules=_selected(args, MODULES))
        elif args.command == "project":
            from .project import MODULES, scan_project
            with console.progress("Выполняю общий аудит проекта"):
                result = scan_project(args.target, modules=_selected(args, MODULES), online=args.online, timeout=args.timeout)
        else:
            from .dependencies import scan_dependencies
            with console.progress("Проверяю зависимости"):
                result = scan_dependencies(args.target, online=args.online, timeout=args.timeout)
        if args.baseline:
            from .baseline import apply_baseline
            try:
                result = apply_baseline(result, args.baseline)
            except (OSError, ValueError, UnicodeError) as exc:
                result.errors.append(f"Базовый отчёт не применён: {exc}")
                result.metadata["incomplete"] = True
        show_result(console, result, args.output)
        if result.errors or result.metadata.get("incomplete"):
            return 1
        if args.fail_on:
            threshold = SEVERITIES.index(args.fail_on)
            if any(f.severity in SEVERITIES and SEVERITIES.index(f.severity) <= threshold and
                   (not args.new_only or f.baseline_state in {"new", "updated"}) for f in result.findings):
                return 2
        return 0
    except KeyboardInterrupt:
        console.line("\n  Операция остановлена пользователем.", "warn")
        return 130
    except (OSError, ValueError, UnicodeError) as exc:
        console.line(f"  Ошибка: {_short(exc, 220)}", "error")
        return 1
