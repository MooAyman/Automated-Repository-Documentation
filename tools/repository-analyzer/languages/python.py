"""Conservative Python AST analyzer (stdlib ``ast`` only).

Emits names and structure. Never emits source snippets, defaults, call
arguments, decorator arguments, or string literals.

Cross-file references resolve only when the target is uniquely
identifiable from imports plus the repository symbol index.
"""

from __future__ import annotations

import ast
from typing import Any, NamedTuple


def _qualname(path: str, parts: list[str]) -> str:
    if not parts:
        return path
    return f"{path}::{'.'.join(parts)}"


def _expr_name(node: ast.AST | None) -> str | None:
    """Surface name for bases, decorators, and callees. No arguments."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _expr_name(node.value)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    if isinstance(node, ast.Call):
        return _expr_name(node.func)
    if isinstance(node, ast.Subscript):
        return _expr_name(node.value)
    return None


def _decorator_names(nodes: list[ast.expr]) -> list[str]:
    names: list[str] = []
    for node in nodes:
        name = _expr_name(node)
        if name:
            names.append(name)
    return names


def _parameter_names(args: ast.arguments) -> list[str]:
    names: list[str] = []
    names.extend(arg.arg for arg in args.posonlyargs)
    names.extend(arg.arg for arg in args.args)
    if args.vararg is not None:
        names.append(args.vararg.arg)
    names.extend(arg.arg for arg in args.kwonlyargs)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    return names


def _import_aliases(aliases: list[ast.alias]) -> list[str]:
    names: list[str] = []
    for alias in aliases:
        if alias.name == "*":
            names.append("*")
        elif alias.asname:
            names.append(alias.asname)
        else:
            names.append(alias.name)
    return names


class _Binding(NamedTuple):
    local: str
    module: str
    imported: str
    level: int
    star: bool
    lineno: int


class PythonAnalyzer:
    language = "python"

    def analyze(self, path: str, source: str) -> dict[str, Any]:
        parsed, unparsed, references = self.analyze_repository(
            [{"path": path, "content": source}]
        )
        if unparsed:
            return {"unparsed": True, "reason": unparsed[0]["reason"]}
        return {
            "unparsed": False,
            "file": parsed[0],
            "references": references,
        }

    def analyze_repository(
        self, files: list[dict[str, str]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, str]], list[dict[str, Any]]]:
        units: list[tuple[str, ast.AST, _DefinitionCollector]] = []
        unparsed: list[dict[str, str]] = []
        for item in files:
            path = item["path"]
            try:
                tree = ast.parse(item["content"])
            except SyntaxError:
                unparsed.append({"path": path, "reason": "SyntaxError"})
                continue
            except ValueError:
                unparsed.append({"path": path, "reason": "ValueError"})
                continue
            collector = _DefinitionCollector(path)
            collector.visit(tree)
            units.append((path, tree, collector))

        index = SymbolIndex(units)
        parsed: list[dict[str, Any]] = []
        references: list[dict[str, Any]] = []
        for path, tree, collector in units:
            resolver = _ReferenceResolver(path, collector, index)
            resolver.visit(tree)
            parsed.append(
                {
                    "path": path,
                    "status": "parsed",
                    "classes": collector.classes,
                    "functions": collector.functions,
                    "imports": collector.imports,
                }
            )
            references.extend(resolver.references)
        return parsed, unparsed, references


class _DefinitionCollector(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.scope: list[str] = []
        self.in_class: list[bool] = []
        self.classes: list[dict[str, Any]] = []
        self.functions: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []
        self.bindings: list[_Binding] = []
        self.class_names: set[str] = set()
        self.function_names: set[str] = set()
        self.methods: dict[str, set[str]] = {}

    def _push(self, name: str, is_class: bool) -> None:
        self.scope.append(name)
        self.in_class.append(is_class)

    def _pop(self) -> None:
        self.scope.pop()
        self.in_class.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        bases = [name for name in (_expr_name(base) for base in node.bases) if name]
        self.classes.append(
            {
                "name": node.name,
                "qualname": _qualname(self.path, [*self.scope, node.name]),
                "lineno": node.lineno,
                "bases": bases,
                "decorators": _decorator_names(node.decorator_list),
            }
        )
        self.class_names.add(node.name)
        self.methods.setdefault(node.name, set())
        self._push(node.name, True)
        for child in node.body:
            self.visit(child)
        self._pop()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> None:
        is_method = bool(self.in_class and self.in_class[-1])
        if is_method:
            class_name = self.scope[-1]
            self.methods.setdefault(class_name, set()).add(node.name)
        else:
            self.function_names.add(node.name)
        self.functions.append(
            {
                "name": node.name,
                "qualname": _qualname(self.path, [*self.scope, node.name]),
                "kind": "method" if is_method else "function",
                "lineno": node.lineno,
                "parameters": _parameter_names(node.args),
                "decorators": _decorator_names(node.decorator_list),
                "async": is_async,
            }
        )
        self._push(node.name, False)
        for child in node.body:
            self.visit(child)
        self._pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node, False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node, True)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            self.imports.append(
                {
                    "kind": "import",
                    "module": alias.name,
                    "names": [alias.asname or alias.name],
                    "level": 0,
                    "lineno": node.lineno,
                }
            )
            self.bindings.append(
                _Binding(local, alias.name, "", 0, False, node.lineno)
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.imports.append(
            {
                "kind": "from",
                "module": node.module or "",
                "names": _import_aliases(node.names),
                "level": node.level,
                "lineno": node.lineno,
            }
        )
        for alias in node.names:
            if alias.name == "*":
                self.bindings.append(
                    _Binding("*", node.module or "", "*", node.level, True, node.lineno)
                )
                continue
            local = alias.asname or alias.name
            self.bindings.append(
                _Binding(local, node.module or "", alias.name, node.level, False, node.lineno)
            )

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


class SymbolIndex:
    """Repository-level index of modules and top-level Python symbols."""

    def __init__(self, units: list[tuple[str, ast.AST, _DefinitionCollector]]) -> None:
        self.paths = {path for path, _, _ in units}
        self.classes: dict[tuple[str, str], str] = {}
        self.functions: dict[tuple[str, str], str] = {}
        self.methods: dict[tuple[str, str, str], str] = {}
        for path, _, collector in units:
            for cls in collector.classes:
                rest = cls["qualname"].split("::", 1)[-1]
                if "." not in rest:
                    self.classes[(path, cls["name"])] = cls["qualname"]
            for fn in collector.functions:
                rest = fn["qualname"].split("::", 1)[-1]
                parts = rest.split(".")
                if fn["kind"] == "function" and len(parts) == 1:
                    self.functions[(path, fn["name"])] = fn["qualname"]
                elif fn["kind"] == "method" and len(parts) == 2:
                    self.methods[(path, parts[0], parts[1])] = fn["qualname"]

    def lookup_symbol(self, path: str, name: str) -> str | None:
        function = self.functions.get((path, name))
        class_ = self.classes.get((path, name))
        if function and class_:
            return None
        return function or class_

    def lookup_method(self, path: str, class_name: str, method: str) -> str | None:
        return self.methods.get((path, class_name, method))

    def lookup_module(self, module: str, from_path: str, level: int) -> str | None:
        if level:
            module = _absolute_module(from_path, level, module)
            if module is None:
                return None
        if not module:
            return None
        return _unique_module_path(module, self.paths)

    def lookup_package_init(self, from_path: str, level: int) -> str | None:
        module = _absolute_module(from_path, level, "")
        if not module:
            return None
        return _unique_module_path(module, self.paths)


def _absolute_module(from_path: str, level: int, module: str) -> str | None:
    parts = from_path.replace("\\", "/").split("/")[:-1]
    climb = level - 1
    if climb > len(parts):
        return None
    package = parts[: len(parts) - climb] if climb else parts
    bits = [bit for bit in package if bit]
    if module:
        bits.extend(module.split("."))
    return ".".join(bits)


def _unique_module_path(module: str, paths: set[str]) -> str | None:
    rel = module.replace(".", "/")
    candidates = [rel + ".py", rel + "/__init__.py"]
    found = [path for path in candidates if path in paths]
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        return None
    return None


class _ReferenceResolver(ast.NodeVisitor):
    def __init__(self, path: str, defs: _DefinitionCollector, index: SymbolIndex) -> None:
        self.path = path
        self.defs = defs
        self.index = index
        self.scope: list[str] = []
        self.in_class: list[bool] = []
        self.references: list[dict[str, Any]] = []

    def _from(self) -> str:
        return _qualname(self.path, self.scope)

    def _push(self, name: str, is_class: bool) -> None:
        self.scope.append(name)
        self.in_class.append(is_class)

    def _pop(self) -> None:
        self.scope.pop()
        self.in_class.pop()

    def _enclosing_class(self) -> str | None:
        for name, is_class in zip(reversed(self.scope), reversed(self.in_class)):
            if is_class:
                return name
        return None

    def _add(self, kind: str, to: str, lineno: int, certainty: str, frm: str | None = None) -> None:
        self.references.append(
            {
                "kind": kind,
                "from": frm if frm is not None else self._from(),
                "to": to,
                "lineno": lineno,
                "certainty": certainty,
            }
        )

    def _emit(self, kind: str, surface: str, lineno: int, frm: str | None = None) -> None:
        target = self._resolve(surface)
        if target:
            self._add(kind, target, lineno, "exact", frm=frm)
        else:
            self._add(kind, surface, lineno, "unresolved", frm=frm)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        target = _qualname(self.path, [*self.scope, node.name])
        for decorator in node.decorator_list:
            name = _expr_name(decorator)
            if name:
                self._emit("decorate", name, node.lineno, frm=target)
        self._push(node.name, True)
        for base in node.bases:
            name = _expr_name(base)
            if name:
                self._emit("inherit", name, node.lineno)
        for child in node.body:
            self.visit(child)
        self._pop()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        target = _qualname(self.path, [*self.scope, node.name])
        for decorator in node.decorator_list:
            name = _expr_name(decorator)
            if name:
                self._emit("decorate", name, node.lineno, frm=target)
        self._push(node.name, False)
        for child in node.body:
            self.visit(child)
        self._pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            path = self.index.lookup_module(alias.name, self.path, 0)
            if path:
                self._add("import", path, node.lineno, "exact")
            else:
                self._add("import", alias.name, node.lineno, "unresolved")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                path = self.index.lookup_module(node.module or "", self.path, node.level)
                if path:
                    self._add("import", path, node.lineno, "exact")
                else:
                    self._add("import", "*", node.lineno, "unresolved")
                continue
            target = self._resolve_import_symbol(node.module or "", alias.name, node.level)
            if target:
                self._add("import", target, node.lineno, "exact")
            else:
                surface = f"{node.module}.{alias.name}" if node.module else alias.name
                self._add("import", surface, node.lineno, "unresolved")

    def visit_Call(self, node: ast.Call) -> None:
        name = _expr_name(node.func)
        if name:
            self._emit("call", name, node.lineno)
        self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def _resolve(self, surface: str) -> str | None:
        parts = surface.split(".")
        if not parts or not all(parts):
            return None
        if parts[0] in {"self", "cls"}:
            if len(parts) != 2:
                return None
            enclosing = self._enclosing_class()
            if not enclosing:
                return None
            return self.index.lookup_method(self.path, enclosing, parts[1])
        if len(parts) == 2:
            local_method = self.index.lookup_method(self.path, parts[0], parts[1])
            if local_method:
                return local_method
        if len(parts) == 1:
            local = self.index.lookup_symbol(self.path, parts[0])
            if local:
                return local
            return self._resolve_bound_name(parts[0])
        return self._resolve_dotted(parts)

    def _resolve_bound_name(self, local: str) -> str | None:
        matches = [binding for binding in self.defs.bindings if not binding.star and binding.local == local]
        targets: set[str] = set()
        for binding in matches:
            target = self._resolve_binding_symbol(binding)
            if target and "::" in target:
                targets.add(target)
        if len(targets) == 1:
            return next(iter(targets))
        if matches:
            return None
        return self._resolve_star(local)

    def _resolve_star(self, name: str) -> str | None:
        stars = [binding for binding in self.defs.bindings if binding.star]
        if not stars:
            return None
        targets: set[str] = set()
        for binding in stars:
            path = self.index.lookup_module(binding.module, self.path, binding.level)
            if path is None:
                return None
            target = self.index.lookup_symbol(path, name)
            if target:
                targets.add(target)
        if len(targets) == 1:
            return next(iter(targets))
        return None

    def _resolve_binding_symbol(self, binding: _Binding) -> str | None:
        if binding.star:
            return None
        if binding.imported:
            return self._resolve_import_symbol(binding.module, binding.imported, binding.level)
        return self.index.lookup_module(binding.module, self.path, binding.level)

    def _resolve_import_symbol(self, module: str, imported: str, level: int) -> str | None:
        targets: set[str] = set()
        if module:
            path = self.index.lookup_module(module, self.path, level)
            if path:
                symbol = self.index.lookup_symbol(path, imported)
                if symbol:
                    targets.add(symbol)
        if level and not module:
            submodule = self.index.lookup_module(imported, self.path, level)
            init = self.index.lookup_package_init(self.path, level)
            if submodule:
                targets.add(submodule)
            if init:
                symbol = self.index.lookup_symbol(init, imported)
                if symbol:
                    targets.add(symbol)
        elif level and module:
            pass
        if len(targets) == 1:
            return next(iter(targets))
        return None

    def _resolve_dotted(self, parts: list[str]) -> str | None:
        targets: set[str] = set()
        for binding in self.defs.bindings:
            if binding.star:
                continue
            if binding.imported:
                if binding.local != parts[0] or len(parts) != 2:
                    continue
                path = self.index.lookup_module(binding.module, self.path, binding.level)
                if not path:
                    continue
                method = self.index.lookup_method(path, binding.imported, parts[1])
                if method:
                    targets.add(method)
                continue
            prefixes = {binding.local, binding.module}
            for prefix in prefixes:
                prefix_parts = prefix.split(".")
                if parts[: len(prefix_parts)] != prefix_parts:
                    continue
                attr = parts[len(prefix_parts) :]
                path = self.index.lookup_module(binding.module, self.path, binding.level)
                if not path:
                    continue
                if len(attr) == 1:
                    symbol = self.index.lookup_symbol(path, attr[0])
                    if symbol:
                        targets.add(symbol)
                elif len(attr) == 2:
                    method = self.index.lookup_method(path, attr[0], attr[1])
                    if method:
                        targets.add(method)
        if len(targets) == 1:
            return next(iter(targets))
        return None
