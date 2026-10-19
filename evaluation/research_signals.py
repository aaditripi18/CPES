"""The four research signals and two research baselines, computed on raw ECS telemetry.

A line-for-line replication of the rules in analysis/corpus_eval_grouped.py, so
they can be recomputed on *modified* telemetry (evasion variants). On the
unmodified corpus they must equal the labelled table's signal columns exactly;
``evaluation.evasion`` checks that before reporting anything.
"""

from __future__ import annotations

from dataclasses import dataclass

SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe"}
LOL = ("fodhelper.exe", "eventvwr.exe", "sdclt.exe", "computerdefaults.exe")
RANK = {"untrusted": 0, "low": 1, "appcontainer": 1, "medium": 2, "high": 3, "system": 4}


def _code(d: dict) -> str:
    return str(d.get("event", {}).get("code"))


def _bn(path: str | None) -> str:
    return (path or "").replace("/", "\\").split("\\")[-1].lower()


def _field(d: dict, *path: str):
    value = d
    for key in path:
        value = (value or {}).get(key) if isinstance(value, dict) else None
    return value


def _system_path(path: str | None) -> bool:
    lowered = (path or "").lower()
    return "\\windows\\" in lowered or "\\program files" in lowered


@dataclass(frozen=True)
class Node:
    guid: str
    parent: str | None
    image: str
    parent_image: str
    path: str
    integrity: str


def nodes(documents) -> dict[str, Node]:
    out: dict[str, Node] = {}
    for d in documents:
        if _code(d) != "1":
            continue
        process = d.get("process", {})
        guid = process.get("entity_id")
        if not guid:
            continue
        parent = process.get("parent") or {}
        out[guid] = Node(  # later duplicates overwrite, as in the script
            guid=guid,
            parent=parent.get("entity_id"),
            image=_bn(process.get("executable")),
            parent_image=_bn(parent.get("executable")),
            path=process.get("executable") or "",
            integrity=((_field(d, "winlog", "event_data", "IntegrityLevel")) or "").lower(),
        )
    return out


def signal_flags(documents) -> dict[str, tuple[str, ...]]:
    documents = list(documents)
    by_guid = nodes(documents)
    inject_src = {_field(d, "process", "entity_id") for d in documents if _code(d) == "8" and _bn(_field(d, "process", "executable")) == "mavinject.exe"}
    pipe_creator: dict[str, str] = {}
    for d in documents:
        if _code(d) == "17":
            pipe_creator.setdefault(_field(d, "file", "name"), _field(d, "user", "name"))
    token = set()
    for d in documents:
        if _code(d) == "18" and _field(d, "user", "name") == "SYSTEM":
            creator = pipe_creator.get(_field(d, "file", "name"))
            if creator and creator != "SYSTEM" and _bn(_field(d, "process", "executable")) in SHELLS:
                token.add(_field(d, "process", "entity_id"))
    flags = {}
    for guid, n in by_guid.items():
        present = []
        if n.image in LOL and n.integrity in ("high", "system"):
            present.append("autoelevation_lolbin")
        if "atomicservice" in n.image or (n.integrity == "system" and n.parent_image == "services.exe" and n.image != "svchost.exe" and not _system_path(n.path)):
            present.append("service_dropped_binary")
        if guid in inject_src or n.image == "mavinject.exe":
            present.append("remote_thread_injection")
        if guid in token:
            present.append("token_impersonation")
        flags[guid] = tuple(present)
    return flags


def baselines(documents) -> dict[str, set[str]]:
    by_guid = nodes(documents)
    rank = lambda level: RANK.get(level, -1)  # noqa: E731
    single_event = {
        n.guid for n in by_guid.values()
        if n.parent in by_guid and rank(by_guid[n.parent].integrity) >= 0 and rank(n.integrity) > rank(by_guid[n.parent].integrity)
    }
    ioc = {n.guid for n in by_guid.values() if (n.image in LOL and n.integrity == "high") or n.image == "mavinject.exe"}
    return {"single_event_research": single_event, "ioc_signature_research": ioc}
