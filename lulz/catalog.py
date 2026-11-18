"""Read the shipped rule declarations without evaluating inspected code."""
from __future__ import annotations

import ast
from pathlib import Path
import re


def rule_catalog() -> list[dict[str, str]]:
    rules = {}
    for module in ("web", "source", "project_checks"):
        path = Path(__file__).with_name(module + ".py")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for position, argument in enumerate(node.args):
                if not isinstance(argument, ast.Constant) or not isinstance(argument.value, str):
                    continue
                if not re.fullmatch(r"(?:WEB|SRC|CFG|SEC|CONFIG|SECRET)-[A-Z0-9-]+", argument.value):
                    continue
                title = ""
                if position + 1 < len(node.args):
                    next_arg = node.args[position+1]
                    if isinstance(next_arg, ast.Constant) and isinstance(next_arg.value, str):
                        title = next_arg.value
                rules[argument.value] = {"id": argument.value, "title": title or "Локальное правило", "module": module}
    rules["DEP-OSV-*"] = {"id": "DEP-OSV-*", "title": "Совпадение точной версии с опубликованной записью OSV", "module": "dependencies"}
    return [rules[key] for key in sorted(rules)]
