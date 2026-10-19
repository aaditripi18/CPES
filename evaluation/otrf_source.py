"""Read OTRF Security-Datasets archives (zip / tar.gz of JSON-lines logs).

Each archive holds one JSON-lines file of Windows events exported by the OTRF
pipeline: flat records with Sysmon EventData fields at the top level
(``Image``, ``ProcessGuid``, ``IntegrityLevel`` …) plus ``Channel``, ``EventID``
and ``@timestamp``. Archives are only read; member paths are checked so nothing
can be written outside the target folder.
"""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def _members(archive: Path) -> Iterator[tuple[str, bytes]]:
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                if not info.is_dir() and not info.filename.startswith("__MACOSX"):
                    yield info.filename, bundle.read(info)
    elif archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle.getmembers():
                if member.isfile():
                    handle = bundle.extractfile(member)
                    if handle is not None:
                        yield member.name, handle.read()
    else:
        raise ValueError(f"unsupported archive {archive.name}")


def records(archive: Path) -> list[dict]:
    """Every JSON record in the archive, in file order (read in memory, never extracted)."""

    out: list[dict] = []
    for name, payload in _members(archive):
        if not name.lower().endswith(".json"):
            continue
        for line in io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8", errors="replace"):
            line = line.strip()
            if line:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    out.append(value)
    return out


def sysmon_records(archive: Path) -> list[dict]:
    return [r for r in records(archive) if str(r.get("Channel")) == SYSMON_CHANNEL]
