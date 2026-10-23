# CPES — Contextual Privilege Escalation Scoring

**Local dashboard walkthrough on public data: [docs/DEMO.md](docs/DEMO.md)**

Most privilege-escalation rules look for a symptom: a process whose integrity
level is higher than its parent's. That misses escalations that cause no such
jump (a service binary started by `services.exe`, injected code, a stolen
token), fires on legitimate software that elevates, and never says *which*
process ended up with the privilege.

CPES reads Sysmon telemetry, rebuilds the process tree, traces each privilege
gain back to the evidence of how it happened (a hijacked registry key, a binary
running as SYSTEM from outside the system directories, a remote thread, a
named-pipe impersonation) and adds signed evidence weights into a score. Every
alert decomposes into the signals, weights and raw records behind it:

```
powershell.exe  (Medium)        ← actor: writes HKU\…_Classes\mscfile\shell\open\command
└─ eventvwr.exe (High)          ← outcome: auto-elevating binary
   autoelevation_lolbin  +7.37  ≥ 0.5  →  detected       (public sample, EVTX-ATTACK-SAMPLES)
```

## Results

Every number below is generated from `results/` into
[docs/RESULTS.md](docs/RESULTS.md); the narrative is in
[docs/FINDINGS.md](docs/FINDINGS.md). Each test and its expected outcome were
committed in [docs/design/](docs/design) before it ran.

**On the lab corpus CPES finds the right process; beyond it, a mature rule set
finds more.** Lab corpus: one Windows 11 endpoint, four techniques plus benign
activity, 2,161 process instances (87 attacks), grouped 5-fold cross-validation
with folds split by attack run:

| Detector | Precision | Recall | F1 |
|---|:---:|:---:|:---:|
| **CPES** | 0.986 ± 0.029 | 1.000 ± 0.000 | **0.993 ± 0.015** |
| Single-event integrity rule | 0.982 ± 0.036 | 0.404 ± 0.163 | 0.551 ± 0.136 |
| IOC / signature rule | 1.000 ± 0.000 | 0.567 ± 0.194 | 0.705 ± 0.151 |

These lab figures favour CPES by construction (attack labels come partly from
the same mechanisms). With labels taken only from the execution log, CPES flags
the right technique in **98 of 126** runs with one false alarm.

| Data | CPES | Comparison |
|---|---|---|
| 53 public attack captures, weights frozen ([EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)) | **26/53** with the generic test, 9/53 specific signals alone | SigmaHQ core **42/53** |
| Lab runs, right technique flagged | 98/126 | SigmaHQ core **106/126** |
| Process that gained privilege named (UAC / service runs) | **33/33 · 28/28** (in-sample) | SigmaHQ 0/33 · 0/28 (alerts on the actor) |
| Live replay of the lab corpus | **160/160** alerts equal to hindsight, median 83 s to alert | — |
| 21 held-out OTRF captures | 6/13 escalation captures; injection **4/4** | SigmaHQ core injection 2/4 |
| 100 unused OTRF captures, service rule | 7 alerts, all on Azure vendor agents | — |
| Live VM session, 50 runs, detectors frozen, Defender on | **20/50** (15/30 without the 20 runs Defender intervened in); **0** false alarms; named the privileged process in **15/15** runs where it appeared | SigmaHQ core 30/50, named 0/15; both together 35/50 |

| | Pre-registered expectation | Verdict |
|---|---|---|
| E1 | Pipe evidence lets the package engine detect token impersonation | **supported** (0/8 → 8/8) |
| E4 | The package engine stays well below the research scripts' F1 | **supported** (0.684 vs 0.993) |
| A | The listed-binary UAC signal does not generalise to other UAC methods | **supported** (2/33) |
| B | Renaming the injector defeats name-based signals; structural ones survive | **supported** (18 → 0; renamed service binary, random pipe names: no change) |
| C1 | SigmaHQ detects more public captures than CPES | **supported** (42/53 vs 26/53) |
| C2 | SigmaHQ raises far more alerts outside attack runs | **not supported** (8 alerts vs CPES's 1 false-alarm process) |
| V2 | Adding the generic test (CPES v2) improves held-out detection | **not supported** (6/13 both); v2 not adopted |
| I | Joined CPES + Sigma incidents name the elevated process more often than Sigma | **supported** (90/126 vs 0/126), but no more often than CPES alone |
| S1 | A signature suppressor removes the service rule's vendor false alarms | **not supported** (0 of 7 removed); not adopted |
| L1 | On a second, live corpus CPES detects ≥ 70% of runs | **not supported** (20/50; Defender intervened in all 20 UAC runs) |
| L7 | CPES and Sigma together detect more runs than Sigma alone | **supported** (35 vs 30) |
| S2 | Requiring a service-install event removes the service rule's false alarms | **supported** (4 → 0, service runs kept 20/20); not yet a package setting |

## How it relates to existing tools

[SigmaHQ](https://github.com/SigmaHQ/sigma) rules and EDR products already alert
on privilege escalation, and on breadth they win: on the same public captures
SigmaHQ's core rules detect 42 of 53 to CPES's 26. What CPES adds:

- **The outcome, not just the actor.** Sigma alerts on the tool the attacker ran
  (`reg.exe`, `sc.exe`); CPES names the process that ended up elevated and the
  evidence chain linking it to the actor.
- **An explanation for every score**: signals, signed weights, threshold and the
  exact records, down to the raw event.
- **A generic "unexplained privilege gain" test** for elevation through binaries
  no rule names (an unlisted auto-elevating binary: specific signal 33 → 0,
  generic test 18 → 32).
- **Incidents that join both**: CPES and SigmaHQ alerts correlated, exported as a
  Markdown report, a MITRE ATT&CK Navigator layer and ECS alerts for a SIEM.

## Use it

```
py -3.12 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r dashboard/requirements.txt
python scripts/fetch_external.py           # public captures + SigmaHQ rules, SHA-256 verified
cd dashboard/web; npm ci; npm run build; cd ../..
python dashboard/run_server.py             # http://127.0.0.1:8790
```

Or with Docker (no data in the image; mount the downloaded public data read-only):

```
docker build -t cpes-dashboard .
docker run --rm -p 127.0.0.1:8790:8790 -v "${PWD}/external:/app/external:ro" cpes-dashboard
```

| Page | What it does |
|---|---|
| Datasets | Upload Sysmon JSONL, CSV or raw `.evtx`; every record validated, rejections listed with reasons |
| Detections | Score waterfall, signals, weights and the records behind each alert |
| Lineage | The reconstructed process tree; missing parents drawn as gaps, never guessed |
| Incidents | CPES + SigmaHQ alerts joined; report, ATT&CK layer and ECS export |
| Live | Replay a dataset as a stream, or poll an Elasticsearch index |
| Evaluation | Every protocol below, with recorded provenance |

The package itself (`cpes/`) has no I/O and no hidden defaults: mapping
(`cpes.adapters`), process tree (`cpes.lineage`), re-association
(`cpes.context`), windows (`cpes.windowing`), signals and score
(`cpes.detection`, `cpes.scoring`), live scoring (`cpes.streaming`) and
incident correlation (`cpes.correlation`). Component contracts: [docs/](docs).

## Limitations

- One lab endpoint and one VM session; no multi-host or enterprise traffic.
- On the live session the token-theft tests never reached SYSTEM and Defender stopped 15 of 20 UAC escalations, so the token signal went untested and the UAC signal was tested on only 5 runs.
- Four mechanisms; techniques without a signal are not detected.
- The auto-elevation signal names four binaries and does not generalise to other UAC methods.
- On the lab corpus the injection signal is effectively an image-name rule.
- The service rule raises false alarms on vendor agents installed outside `Program Files`. With service-install events (System 7045 / Security 4697) a fix removed them on the live session (S2), but it is tested on one machine and not yet in the package ([analysis](docs/design/service-rule-feasibility.md)).
- The lab corpora are private (they contain host and account identifiers); lab protocols cannot be re-run from a clone.

## Reproduce

```
python scripts/fetch_external.py     # public data, verified against configs/external-datasets.json
python -m evaluation.run all         # every protocol; results/<protocol>.json + results/ledger.jsonl
python -m evaluation.report          # regenerates docs/RESULTS.md
pytest tests dashboard/tests
```

Each ledger entry records the git commit, whether the code tree was clean, a
fingerprint of the code and the SHA-256 of every input.

## License

MIT — see [LICENSE](LICENSE). Third-party data, rules and fonts:
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
