# CPES Sysmon config — v1 → v2 changelog

**Date:** 2026-09-01
**Files:** `configs/sysmon-config-v1.xml` (frozen) → `configs/sysmon-config-v2.xml` (new)
**Status:** Additive, single-delta change. v1 remains the frozen M1 reference; v2 is a documented superset used only for the corpus re-export.

## What changed

| | v1 (frozen) | v2 |
|---|---|---|
| EID 1 ProcessCreate | log all | log all |
| EID 6 DriverLoad | log all | log all |
| EID 7 ImageLoad | log all | log all |
| EID 8 CreateRemoteThread | log all | log all |
| EID 10 ProcessAccess | log all | log all |
| EID 11 FileCreate | log all | log all |
| EID 12/13 RegistryEvent | include (create/delete/setvalue) | include (create/delete/setvalue) |
| **EID 17/18 PipeEvent** | **not logged** | **log all (NEW)** |
| EID 19/20/21 WmiEvent | excluded | excluded |

The **only** difference is the addition of `<PipeEvent onmatch="exclude" />` (named-pipe create/connect).

## Why

The first-pass evaluation (`docs/CPES-Corpus-v2-Evaluation-2026-09-01.md`) identified two limitations:

1. **Label circularity (§5.2).** Attack-outcome processes were labelled by the same mechanism signatures CPES scores. Named-pipe events (EID 17/18) are the *direct, technique-specific* footprint of T1134.001 named-pipe impersonation and are **not** part of CPES's structural feature set (integrity, image, parent, remote-thread). They therefore provide an independent ground-truth channel for the token-theft escalation, letting us label token attacks without reference to CPES's own signals.

2. **Token false positives (§5.3).** The outcome-based `token_impersonation` heuristic ("SYSTEM shell with a non-SCM parent") is noisy. A sharp signal keyed on the impersonation pipe (EID 17 create + EID 18 connect from a non-service process that then yields a SYSTEM context) is far more specific and is expected to remove the false positives.

Registry availability (the third limitation, EID 13 truncated oldest-first) is **not** a config issue — it is fixed in the exporter (`export_corpus_v2.py`, recent-first), not here.

## Reproducibility / provenance

- v1 stays the pinned M1 config; nothing about the v1 corpora changes.
- Any corpus collected under this file is tagged **"collected under config-v2"** in its provenance. The paper's Methods section notes that the token-theft ground-truth labels derive from config-v2's EID 17/18, collected in a bounded session, while the primary telemetry scope is otherwise identical to v1.
- PipeEvent is high-volume; v2 is intended for the short re-export session only, not for long-running collection.
