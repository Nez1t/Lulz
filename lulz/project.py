"""Combine independent local checks while retaining coverage and error semantics."""
from __future__ import annotations

from pathlib import Path

from .models import ScanResult


MODULES = {
    "source": "Исходный код: SQLi, XSS, исполнение и настройки",
    "config": "Dockerfile, Kubernetes и Terraform JSON",
    "secrets": "Приватные ключи и признаки встроенных секретов",
    "dependencies": "Зависимости и известные уязвимости OSV",
}


def scan_project(path: str, modules: list[str] | None = None, online: bool = False,
                 timeout: float = 10.0) -> ScanResult:
    selected = list(MODULES) if modules is None else list(dict.fromkeys(modules))
    result = ScanResult(kind="project", target=str(path), modules=selected,
                        metadata={"components": {}, "component_status": {}, "online": online, "incomplete": False})
    try:
        root = Path(path).expanduser()
        if not selected or set(selected) - set(MODULES):
            raise ValueError("Выберите известные разделы полного аудита проекта.")
        if root.is_symlink() or getattr(root, "is_junction", lambda: False)() or not root.is_dir():
            raise ValueError("Для общего аудита выберите обычную папку проекта.")
        result.target = str(root.resolve())
    except (OSError, ValueError, TypeError) as exc:
        result.errors.append(str(exc))
        return result.finish()

    def include(name: str, child: ScanResult) -> None:
        result.findings.extend(child.findings)
        result.checks.extend(dict(check, component=name) for check in child.checks)
        result.notes.extend(f"{name}: {note}" for note in child.notes)
        result.errors.extend(f"{name}: {error}" for error in child.errors)
        result.metadata["components"][name] = child.metadata
        result.metadata["component_status"][name] = "incomplete" if child.errors or child.metadata.get("incomplete") else "completed"
        if child.errors or child.metadata.get("incomplete"):
            result.metadata["incomplete"] = True

    if "source" in selected:
        from .source import scan_source
        include("source", scan_source(result.target))
    local = [item for item in ("config", "secrets") if item in selected]
    if local:
        from .project_checks import scan_project_checks
        include("project_checks", scan_project_checks(result.target, modules=local))
    if "dependencies" in selected:
        from .dependencies import _manifest_paths, scan_dependencies
        try:
            manifests, capped = _manifest_paths(root)
            if manifests or capped:
                include("dependencies", scan_dependencies(result.target, online=online, timeout=timeout))
            else:
                result.metadata["components"]["dependencies"] = {"online": online, "advisories_checked": False,
                    "packages": 0, "manifest_count": 0, "coverage": "no_supported_manifests"}
                result.metadata["component_status"]["dependencies"] = "skipped"
                result.checks.append({"module": "dependencies", "name": "Манифесты проекта", "status": "skipped",
                                      "detail": "Поддерживаемых манифестов в корне проекта нет; зависимости не оценены."})
                result.notes.append("Зависимости: подходящие манифесты не найдены; выбранный раздел не выполнен.")
                result.metadata["incomplete"] = True
        except (OSError, ValueError) as exc:
            result.errors.append(f"dependencies: {exc}")
            result.metadata["incomplete"] = True
    result.metadata["sections_attempted"] = list(result.metadata["components"])
    result.metadata["sections_completed"] = [name for name, state in result.metadata["component_status"].items() if state == "completed"]
    result.notes.insert(0, "Общий аудит объединяет локальные проверки. Эксплуатация и доступность уязвимого кода в работающем приложении не проверяются.")
    return result.finish()
