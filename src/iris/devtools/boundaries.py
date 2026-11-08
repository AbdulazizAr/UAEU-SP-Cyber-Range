"""Static architecture checks, run in CI.

1. Real-clock ban: no module except ``iris/core/vclock.py`` may read the wall clock
   (``datetime.now/utcnow/today``, ``date.today``, ``time.time/time_ns``). Scenario
   content must come from :class:`iris.core.vclock.VClock` (INPUT Part 2, B3).
2. Import boundaries: the Engine never imports generator, oracle or evaluator code;
   the oracle never imports the Engine (INPUT Part 4, 9.5); contracts and core stay leaves.

Usage: ``python -m iris.devtools.boundaries [src_dir]`` (exit code 1 on violations).
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path

CLOCK_ALLOWED = {"iris/core/vclock.py"}

_CLOCK_ATTRS = {
    ("datetime", "now"),
    ("datetime", "utcnow"),
    ("datetime", "today"),
    ("date", "today"),
    ("time", "time"),
    ("time", "time_ns"),
}
_CLOCK_FROM_IMPORTS = {("time", "time"), ("time", "time_ns")}

#: package -> packages it must never import
FORBIDDEN_IMPORTS: dict[str, tuple[str, ...]] = {
    # The Engine may read reference vocabularies (ATT&CK, D3FEND) but never current
    # vulnerability intel, which would leak the future.
    "iris.engine": (
        "iris.generator",
        "iris.oracle",
        "iris.evaluator",
        "iris.packager",
        "iris.synth",
        "iris.references.intel",
    ),
    "iris.oracle": ("iris.engine", "iris.evaluator", "iris.synth"),
    "iris.evaluator": (
        "iris.generator",
        "iris.engine",
        "iris.packager",
        "iris.live",
        "iris.synth",
    ),  # scores key files, not objects
    # The synthetic path is generator-side: it may import core, contracts, generator,
    # references, oracle and packager, but never the Engine or the evaluator (brief §5.2).
    "iris.synth": ("iris.engine", "iris.evaluator"),
    "iris.packager": ("iris.engine", "iris.evaluator"),
    "iris.contracts": ("iris.generator", "iris.oracle", "iris.engine", "iris.evaluator", "iris.references"),
    "iris.core": (
        "iris.generator",
        "iris.oracle",
        "iris.engine",
        "iris.evaluator",
        "iris.contracts",
        "iris.references",
    ),
}


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] {self.detail}"


def _module_name(rel: Path) -> str:
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _dotted(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def check_file(path: Path, rel: Path) -> list[Violation]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    rel_posix = rel.as_posix()
    module = _module_name(rel)
    out: list[Violation] = []

    clock_banned = rel_posix not in CLOCK_ALLOWED
    for node in ast.walk(tree):
        if clock_banned and isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            target = _dotted(node.func.value)
            if target is not None:
                last = target.rsplit(".", 1)[-1]
                if (last, node.func.attr) in _CLOCK_ATTRS:
                    out.append(
                        Violation(
                            rel_posix,
                            node.lineno,
                            "real-clock",
                            f"{target}.{node.func.attr}() - use VClock (iris.core.vclock)",
                        )
                    )
        if clock_banned and isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if (node.module, alias.name) in _CLOCK_FROM_IMPORTS:
                    out.append(
                        Violation(
                            rel_posix, node.lineno, "real-clock", f"from {node.module} import {alias.name}"
                        )
                    )

        imported: list[str] = []
        lineno = 0
        if isinstance(node, ast.Import):
            imported, lineno = [a.name for a in node.names], node.lineno
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported, lineno = [node.module], node.lineno
        elif isinstance(node, ast.ImportFrom) and node.level > 0:
            # resolve ``from ..generator import x`` against this module's package, so a
            # relative import cannot slip past the boundary rules
            pkg_parts = module.split(".") if rel.name == "__init__.py" else module.split(".")[:-1]
            base = pkg_parts[: len(pkg_parts) - (node.level - 1)] if node.level - 1 <= len(pkg_parts) else []
            if base:
                if node.module:
                    imported = [".".join([*base, node.module])]
                else:  # ``from .. import generator``: each name is a submodule
                    imported = [".".join([*base, a.name]) for a in node.names]
                lineno = node.lineno
        for name in imported:
            for pkg, banned in FORBIDDEN_IMPORTS.items():
                if module == pkg or module.startswith(pkg + "."):
                    for b in banned:
                        if name == b or name.startswith(b + "."):
                            out.append(
                                Violation(rel_posix, lineno, "import-boundary", f"{module} imports {name}")
                            )
    return out


def check_tree(src: Path) -> list[Violation]:
    violations: list[Violation] = []
    for path in sorted(src.rglob("*.py")):
        violations.extend(check_file(path, path.relative_to(src)))
    return violations


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    src = Path(args[0]) if args else Path(__file__).resolve().parents[2]
    violations = check_tree(src)
    for v in violations:
        print(v)
    print(f"boundaries: {len(violations)} violation(s) in {src}")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
