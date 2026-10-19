"""Download the public datasets/rule packs CPES is evaluated on, and verify them.

    python scripts/fetch_external.py            # download missing files, verify all
    python scripts/fetch_external.py --verify   # verify only
    python scripts/fetch_external.py --write-manifest   # (maintainers) re-pin hashes

Everything goes to external/ (git-ignored). Files are data: they are parsed by the
evaluation, never executed. Sources, licences, commits and SHA-256 are pinned in
configs/external-datasets.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "configs" / "external-datasets.json"
EXTERNAL = ROOT / "external"

EVTX_COMMIT = "4ceed2f4706daf601c212a8f91c113dd85349a2c"
EVTX_RAW = f"https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/{EVTX_COMMIT}/Privilege%20Escalation/"
SIGMA_TAG = "r2026-07-01"
OTRF_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
OTRF_FILES = {
    "privilege_escalation": ["empire_uac_shellapi_fodhelper.zip", "empire_invoke_runas.tar.gz", "cmd_service_mod_fax.zip"],
    "defense_evasion": ["psh_cmstp_execution_bypassuac.zip", "empire_dllinjection_LoadLibrary_CreateRemoteThread.zip", "empire_psinject_PEinjection.zip",
                        "psh_mavinject_dll_notepad.zip", "purplesharp_pe_injection_createremotethread.zip",
                        "cmd_disable_eventlog_service_startuptype_modification_via_registry.zip", "psh_disable_eventlog_service_startuptype_modification.zip",
                        "reg_disable_eventlog_service_startuptype_modification_via_registry.zip"],
    "persistence": ["empire_persistence_registry_modification_run_keys_elevated_user.zip", "empire_schtasks_creation_execution_elevated_user.zip",
                    "empire_wmi_local_event_subscriptions_elevated_user.zip"],
    "credential_access": ["cmd_psexec_lsa_secrets_dump.zip", "psh_lsass_memory_dump_comsvcs.zip"],
    "lateral_movement": ["empire_psexec_dcerpc_tcp_svcctl.zip", "empire_smbexec_dcerpc_smb_svcctl.zip", "covenant_sharpsc_create_dcerpc_smb_svcctl.zip",
                         "covenant_sharpsc_start_dcerpc_smb_svcctl.zip", "empire_shell_dcerpc_smb_service_dll_hijack.zip"],
}
SIGMA_RELEASE = f"https://github.com/SigmaHQ/sigma/releases/download/{SIGMA_TAG}/"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as response, target.open("wb") as handle:
        handle.write(response.read())


def entries() -> list[tuple[dict, dict, Path, str]]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    out = []
    for dataset in manifest["datasets"]:
        for item in dataset["files"]:
            path = EXTERNAL / dataset["local_dir"] / item["name"]
            url = item.get("url") or dataset["url_prefix"] + urllib.parse.quote(item["name"])
            out.append((dataset, item, path, url))
    return out


def unpack_sigma() -> None:
    for name, folder in (("sigma_core.zip", "core"), ("sigma_all_rules.zip", "all")):
        archive = EXTERNAL / "sigma" / name
        target = EXTERNAL / "sigma" / folder
        if archive.exists() and not target.exists():
            with zipfile.ZipFile(archive) as bundle:
                for member in bundle.namelist():
                    resolved = (target / member).resolve()
                    if target.resolve() not in resolved.parents and resolved != target.resolve():
                        raise ValueError(f"unsafe path in {name}: {member}")
                bundle.extractall(target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args()
    if args.write_manifest:
        return write_manifest()
    bad = 0
    for dataset, item, path, url in entries():
        if not path.exists() and not args.verify:
            print(f"downloading {item['name']}")
            download(url, path)
        if not path.exists():
            print(f"MISSING  {path.relative_to(ROOT)}")
            bad += 1
        elif sha256(path) != item["sha256"]:
            print(f"MISMATCH {path.relative_to(ROOT)}")
            bad += 1
    if not args.verify:
        unpack_sigma()
    print("all files verified" if not bad else f"{bad} problem(s)")
    return 1 if bad else 0


def write_manifest() -> int:
    evtx_dir = EXTERNAL / "evtx-attack-samples" / "privesc"
    sigma_dir = EXTERNAL / "sigma"
    manifest = {
        "note": "Pinned public inputs. Downloaded by scripts/fetch_external.py into external/ (git-ignored); never redistributed.",
        "datasets": [
            {
                "id": "evtx-attack-samples-privesc",
                "source": "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/tree/" + EVTX_COMMIT + "/Privilege%20Escalation",
                "licence": "GPL-3.0 (data used for evaluation only; not redistributed)",
                "commit": EVTX_COMMIT,
                "local_dir": "evtx-attack-samples/privesc",
                "url_prefix": EVTX_RAW,
                "files": [{"name": p.name, "sha256": sha256(p), "bytes": p.stat().st_size} for p in sorted(evtx_dir.glob("*.evtx"))],
            },
            {
                "id": "sigma-rules",
                "source": "https://github.com/SigmaHQ/sigma/releases/tag/" + SIGMA_TAG,
                "licence": "Detection Rule License (DRL) 1.1 — attribution required",
                "release": SIGMA_TAG,
                "local_dir": "sigma",
                "url_prefix": SIGMA_RELEASE,
                "files": [{"name": n, "sha256": sha256(sigma_dir / n), "bytes": (sigma_dir / n).stat().st_size} for n in ("sigma_core.zip", "sigma_all_rules.zip")],
            },
            {
                "id": "otrf-security-datasets",
                "source": "https://github.com/OTRF/Security-Datasets/tree/" + OTRF_COMMIT + "/datasets/atomic/windows",
                "licence": "MIT",
                "commit": OTRF_COMMIT,
                "local_dir": "otrf/zips",
                "url_prefix": "",
                "files": [
                    {"name": n, "tactic": tactic, "sha256": sha256(EXTERNAL / "otrf" / "zips" / n), "bytes": (EXTERNAL / "otrf" / "zips" / n).stat().st_size,
                     "url": f"https://raw.githubusercontent.com/OTRF/Security-Datasets/{OTRF_COMMIT}/datasets/atomic/windows/{tactic}/host/{n}"}
                    for tactic, names in OTRF_FILES.items() for n in names
                ],
            },
        ],
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {MANIFEST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
