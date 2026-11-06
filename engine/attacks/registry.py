"""Name -> module class, so the CLI/API can select modules by name."""

from __future__ import annotations

from typing import Any

from engine.attacks.data_leakage import DataLeakageModule
from engine.attacks.output_handling import OutputSecurityModule
from engine.attacks.prompt_injection import PromptInjectionModule
from engine.attacks.tool_abuse import ToolSecurityModule
from engine.core.module import AttackModule

MODULES: dict[str, type] = {
    "prompt_injection": PromptInjectionModule,
    "data_leakage": DataLeakageModule,
    "output": OutputSecurityModule,
    "tool_abuse": ToolSecurityModule,
}


def module_class_by_id(module_id: str) -> type:
    """Find a module class from a Finding.category (the module's `id`)."""
    for cls in MODULES.values():
        if cls.id == module_id:
            return cls
    raise KeyError(f"No module with id {module_id!r}")


def build_modules(
    names: list[str], options: dict[str, dict[str, Any]] | None = None
) -> list[AttackModule]:
    """Instantiate modules by name; `options` maps a module name to constructor kwargs."""
    unknown = [n for n in names if n not in MODULES]
    if unknown:
        raise KeyError(f"Unknown module(s): {', '.join(unknown)}. Available: {', '.join(MODULES)}")
    options = options or {}
    return [MODULES[n](**options.get(n, {})) for n in names]
