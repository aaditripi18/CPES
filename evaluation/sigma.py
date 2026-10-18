"""A small, tested Sigma rule matcher for Sysmon events (evaluation use only).

Implements the parts of the Sigma specification used by Sysmon-category Windows
rules: case-insensitive wildcard equality; modifiers ``contains``, ``startswith``,
``endswith``, ``all``, ``re`` (with ``i``/``m``/``s``), ``windash``, ``exists``,
``cased``; lists are OR unless ``|all``; ``null`` means absent; conditions with
``and``/``or``/``not``, parentheses, ``1 of X*``, ``all of X*`` and ``them``.
Anything else (aggregations, ``base64*``, ``wide``, ``cidr``, ``fieldref``,
numeric comparisons, keyword searches) makes the rule *unsupported*; it is
skipped and counted, never approximated.

Rules are YAML data loaded with ``yaml.safe_load``; nothing in them is executed.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CATEGORY_EIDS = {
    "process_creation": {"1"},
    "driver_load": {"6"},
    "image_load": {"7"},
    "create_remote_thread": {"8"},
    "process_access": {"10"},
    "file_event": {"11"},
    "registry_add": {"12"},
    "registry_delete": {"12"},
    "registry_event": {"12", "13", "14"},
    "registry_set": {"13"},
    "registry_rename": {"14"},
    "pipe_created": {"17", "18"},
}
SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "windash", "exists", "cased"}
WINDASH = ("-", "/", "–", "—", "―")


class Unsupported(Exception):
    """The rule uses a Sigma feature this matcher does not implement."""


@dataclass
class Rule:
    id: str
    title: str
    level: str
    status: str
    tags: tuple[str, ...]
    category: str | None
    service: str | None
    path: str
    eids: frozenset[str]
    fields: frozenset[str]
    match: Callable[[dict[str, Any]], bool] = field(repr=False)


# ----------------------------------------------------------------------- values


def _wildcard_regex(value: str) -> str:
    out, i = [], 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if char == "*" else "." if char == "?" else re.escape(char))
        i += 1
    return "".join(out)


def _value_matcher(value: Any, modifiers: list[str]) -> Callable[[Any], bool]:
    if "exists" in modifiers:
        want = bool(value)
        return lambda actual: (actual is not None) == want
    if value is None:
        return lambda actual: actual is None or actual == ""
    if "re" in modifiers:
        flags = (re.IGNORECASE if "i" in modifiers else 0) | (re.MULTILINE if "m" in modifiers else 0) | (re.DOTALL if "s" in modifiers else 0)
        pattern = re.compile(str(value), flags)
        return lambda actual: actual is not None and bool(pattern.search(str(actual)))
    if isinstance(value, bool):
        value = str(value).lower()
    text = str(value)
    variants = {text}
    if "windash" in modifiers:
        variants = {text.replace("-", dash) for dash in WINDASH} | {text.replace("/", dash) for dash in WINDASH}
    patterns = []
    for variant in variants:
        body = _wildcard_regex(variant)
        if "contains" in modifiers:
            body = f".*{body}.*"
        elif "startswith" in modifiers:
            body = f"{body}.*"
        elif "endswith" in modifiers:
            body = f".*{body}"
        patterns.append(body)
    compiled = re.compile("(?:" + "|".join(patterns) + ")", 0 if "cased" in modifiers else re.IGNORECASE | re.DOTALL)
    return lambda actual: actual is not None and compiled.fullmatch(str(actual)) is not None


def _field_matcher(key: str, value: Any) -> tuple[str, Callable[[dict[str, Any]], bool]]:
    name, *modifiers = key.split("|")
    unknown = [m for m in modifiers if m not in SUPPORTED_MODIFIERS]
    if unknown:
        raise Unsupported(f"modifier(s) {unknown}")
    values = value if isinstance(value, list) else [value]
    if not values:
        raise Unsupported("empty value list")
    matchers = [_value_matcher(v, modifiers) for v in values]
    if "all" in modifiers:
        return name, lambda event: all(m(event.get(name)) for m in matchers)
    return name, lambda event: any(m(event.get(name)) for m in matchers)


def _selection(definition: Any) -> tuple[set[str], Callable[[dict[str, Any]], bool]]:
    if isinstance(definition, dict):
        if not definition:
            raise Unsupported("empty selection")
        compiled = [_field_matcher(str(k), v) for k, v in definition.items()]
        return {n for n, _ in compiled}, lambda event: all(m(event) for _, m in compiled)
    if isinstance(definition, list) and definition and all(isinstance(item, dict) for item in definition):
        parts = [_selection(item) for item in definition]
        return set().union(*(f for f, _ in parts)), lambda event: any(m(event) for _, m in parts)
    raise Unsupported("keyword search or unsupported selection shape")


# -------------------------------------------------------------------- conditions

_TOKEN = re.compile(r"\s*(\(|\)|\b1 of\b|\ball of\b|\bnot\b|\band\b|\bor\b|[A-Za-z0-9_*]+)", re.IGNORECASE)


def _tokens(condition: str) -> list[str]:
    if "|" in condition:
        raise Unsupported("aggregation in condition")
    out, position = [], 0
    while position < len(condition):
        if condition[position].isspace():
            position += 1
            continue
        match = _TOKEN.match(condition, position)
        if not match:
            raise Unsupported(f"cannot parse condition {condition!r}")
        out.append(match.group(1).lower() if match.group(1).lower() in ("and", "or", "not", "1 of", "all of") else match.group(1))
        position = match.end()
    return out


def _compile_condition(condition: str, selections: dict[str, Callable]) -> Callable[[dict[str, Any]], bool]:
    tokens = _tokens(condition)
    position = 0

    def peek():
        return tokens[position] if position < len(tokens) else None

    def take():
        nonlocal position
        position += 1
        return tokens[position - 1]

    def names(pattern: str) -> list[Callable]:
        if pattern == "them":
            chosen = list(selections.values())
        else:
            regex = re.compile(_wildcard_regex(pattern) + "$")
            chosen = [m for n, m in selections.items() if regex.match(n)]
        if not chosen:
            raise Unsupported(f"no selection matches {pattern!r}")
        return chosen

    def primary():
        token = take()
        if token == "(":
            node = expr()
            if take() != ")":
                raise Unsupported("unbalanced parentheses")
            return node
        if token == "not":
            inner = primary()
            return lambda e: not inner(e)
        if token in ("1 of", "all of"):
            chosen = names(take())
            return (lambda e: any(m(e) for m in chosen)) if token == "1 of" else (lambda e: all(m(e) for m in chosen))
        if token not in selections:
            raise Unsupported(f"unknown selection {token!r}")
        return selections[token]

    def conjunction():
        node = primary()
        while peek() == "and":
            take()
            left, right = node, primary()
            node = lambda e, a=left, b=right: a(e) and b(e)
        return node

    def expr():
        node = conjunction()
        while peek() == "or":
            take()
            left, right = node, conjunction()
            node = lambda e, a=left, b=right: a(e) or b(e)
        return node

    result = expr()
    if position != len(tokens):
        raise Unsupported(f"trailing tokens in condition {condition!r}")
    return result


# ------------------------------------------------------------------------- rules


def compile_rule(document: dict, path: str = "") -> Rule:
    logsource = document.get("logsource") or {}
    if logsource.get("product") != "windows":
        raise Unsupported("not a Windows rule")
    category, service = logsource.get("category"), logsource.get("service")
    if category in CATEGORY_EIDS:
        eids = frozenset(CATEGORY_EIDS[category])
    elif service == "sysmon" and not category:
        eids = frozenset({"*"})  # rule selects on EventID itself
    else:
        raise Unsupported(f"log source {category or service!r} is not a Sysmon category")
    detection = dict(document.get("detection") or {})
    if "timeframe" in detection:
        raise Unsupported("timeframe/aggregation")
    condition = detection.pop("condition", None)
    if not condition:
        raise Unsupported("no condition")
    compiled = {name: _selection(definition) for name, definition in detection.items()}
    selections = {name: matcher for name, (_, matcher) in compiled.items()}
    conditions = condition if isinstance(condition, list) else [condition]
    predicates = [_compile_condition(str(c), selections) for c in conditions]
    fields = frozenset().union(*(f for f, _ in compiled.values()))
    return Rule(
        id=str(document.get("id") or path), title=str(document.get("title") or path), level=str(document.get("level") or "unknown"),
        status=str(document.get("status") or "unknown"), tags=tuple(str(t).lower() for t in document.get("tags") or ()),
        category=category, service=service, path=path, eids=eids, fields=fields,
        match=lambda event, ps=predicates: any(p(event) for p in ps),
    )


@dataclass
class RuleSet:
    rules: list[Rule]
    unsupported: dict[str, int]
    skipped_examples: list[tuple[str, str]]

    def for_eid(self, eid: str) -> list[Rule]:
        return [r for r in self.rules if eid in r.eids or "*" in r.eids]


def load_rules(folder: Path) -> RuleSet:
    import yaml

    rules, unsupported, examples = [], {}, []
    for path in sorted(folder.rglob("*.yml")):
        try:
            documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except Exception:  # malformed YAML is counted, not fatal
            unsupported["unparseable yaml"] = unsupported.get("unparseable yaml", 0) + 1
            continue
        if len(documents) != 1 or not isinstance(documents[0], dict):
            unsupported["multi-document / correlation"] = unsupported.get("multi-document / correlation", 0) + 1
            continue
        try:
            rules.append(compile_rule(documents[0], str(path.relative_to(folder))))
        except Unsupported as reason:
            text = str(reason)
            key = "not Sysmon" if "not a Sysmon" in text or "not a Windows" in text else text.split(" ")[0] if text.startswith("modifier") else text[:40]
            unsupported[key] = unsupported.get(key, 0) + 1
            if len(examples) < 20 and key != "not Sysmon":
                examples.append((path.name, text))
    return RuleSet(rules, dict(sorted(unsupported.items(), key=lambda kv: -kv[1])), examples)


def match_events(ruleset: RuleSet, events: Iterable[tuple[str, dict[str, Any]]]) -> list[tuple[int, Rule]]:
    """``events`` are (eid, sysmon-field view) pairs; returns (event position, rule) hits."""

    by_eid: dict[str, list[Rule]] = {}
    hits = []
    for position, (eid, view) in enumerate(events):
        rules = by_eid.setdefault(eid, ruleset.for_eid(eid))
        for rule in rules:
            if rule.match(view):
                hits.append((position, rule))
    return hits
