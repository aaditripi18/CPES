# CPES: presentation study guide

A single document to learn the project from and present it. It is built from the
repository's own docs (README, `docs/FINDINGS.md`, `docs/RESULTS.md`, `docs/design/`);
every number here appears there. If you only have 10 minutes, read sections 1, 2, 6 and 9.

---

## 1. The project in one paragraph

**CPES (Contextual Privilege Escalation Scoring)** detects privilege escalation on Windows
from Sysmon telemetry. Instead of alerting on a single suspicious event, it rebuilds the
**process tree**, finds processes that **gained privilege**, and traces each gain back to
**evidence of how it happened** (a hijacked registry key, a SYSTEM binary running from a
strange folder, a remote thread, a named-pipe impersonation). Each piece of evidence adds a
signed weight to a score; above a threshold, CPES raises an alert that **names the process
that ended up privileged** and shows exactly which records and weights produced the score.

**One-line pitch:** *"Other rules tell you which tool the attacker ran. CPES tells you which
process ended up with the privilege, and shows its working."*

---

## 2. The problem it addresses

Most privilege-escalation rules look for one symptom: a child process with a higher
integrity level than its parent. That approach:

1. **Misses** escalations with no such jump: a service binary started by `services.exe`,
   injected code, a stolen token.
2. **Fires on legitimate software** that elevates (installers, admin tools).
3. **Never says which process ended up with the privilege**, only that something looked odd.

Rule sets like **SigmaHQ** flag the *actor* (`reg.exe`, `sc.exe`, the attacker's PowerShell).
CPES focuses on the *outcome*: the process that is now running elevated.

Example (from a public attack capture):

```
powershell.exe  (Medium)        ← actor: writes HKU\…_Classes\mscfile\shell\open\command
└─ eventvwr.exe (High)          ← outcome: auto-elevating binary
   autoelevation_lolbin  +7.37  ≥ 0.5  →  detected
```

---

## 3. Key terms (glossary)

| Term | Meaning |
|---|---|
| **Privilege escalation** | A process getting more rights than it started with (e.g. Medium → High integrity, or user → SYSTEM). MITRE ATT&CK tactic TA0004. |
| **Integrity level** | Windows' trust label on a process: Low, Medium (normal user), High (admin), System. |
| **Sysmon** | Microsoft Sysinternals tool that logs detailed process, registry, pipe, thread and file events to the Windows event log. |
| **Winlogbeat / Elasticsearch** | Ship Windows event logs into Elasticsearch, where they are stored and queried. |
| **Atomic Red Team** | Open-source library of small, safe scripts that emulate attacker techniques (used to generate attacks in the lab). |
| **SigmaHQ** | The main open-source library of detection rules; our comparison baseline (850 core rules, release r2026-07-01). |
| **UAC bypass (T1548.002)** | Getting admin rights without the UAC prompt, e.g. by hijacking a registry key an auto-elevating program (eventvwr, fodhelper, sdclt, ComputerDefaults) reads. |
| **Service creation (T1543.003)** | Installing a malicious Windows service, which runs as SYSTEM. |
| **Process injection (T1055.001)** | Running code inside another process (lab uses `mavinject.exe`). |
| **Token theft (T1134.001/.002)** | Stealing/impersonating another process's security token, e.g. via named pipes ("Potato" attacks). |
| **Pre-registration** | Writing down the test and its expected result, and committing it to git, *before* running it. |
| **Grouped cross-validation** | Split data into folds by attack run, so the same run never appears in both training and test. |
| **Precision / Recall / F1** | Precision = share of alerts that are real; recall = share of attacks caught; F1 = their harmonic mean. |

---

## 4. How CPES works (the pipeline)

```
Sysmon events (JSONL / CSV / .evtx / Elasticsearch)
   │
   ▼  1. Mapping         cpes.adapters     raw fields → canonical fields; bad records rejected with a reason
   ▼  2. Lineage         cpes.lineage      rebuild the process tree; missing parents shown as gaps, never guessed
   ▼  3. Context         cpes.context      re-associate evidence (registry writes, pipes, remote threads) with processes
   ▼  4. Windows         cpes.windowing    group events into sliding windows (300 s span, 150 s step)
   ▼  5. Signals         cpes.detection    decide which evidence signals are present
   ▼  6. Score           cpes.scoring      score = prior + Σ signed weights of present signals
   ▼  7. Decision        threshold 0.5     alert, with full decomposition (signals, weights, raw records)
   ▼  8. Correlation     cpes.correlation  join CPES alerts with Sigma alerts into incidents
```

The package (`cpes/`) does **no I/O and has no hidden defaults**: every weight and
threshold is passed in, and arithmetic is exact (Decimal), so identical input gives
identical output.

### The four mechanism signals and their weights

| Signal | Detects | Technique | Weight (log-likelihood) |
|---|---|---|---|
| `autoelevation_lolbin` | One of 4 auto-elevating binaries (fodhelper, eventvwr, sdclt, ComputerDefaults) running at High/System | UAC bypass | **+7.37** |
| `remote_thread_injection` | Injection (remote thread / the injector process) | Injection | **+6.77** |
| `service_dropped_binary` | A SYSTEM process running from outside the system directories | Service creation | **+6.10** |
| `token_impersonation` | Named-pipe impersonation reaching SYSTEM | Token theft | **+5.99** |

Weights come from the lab corpus (signed log-likelihood ratios). Any one signal clears the
0.5 threshold on its own, so the score mostly answers *"which mechanism, with what evidence"*.

### The generic test: "unexplained privilege gain"

Fires when a process becomes elevated, **no specific signal explains it**, and the gain
did **not** go through a legitimate path (the `consent.exe` UAC prompt). It's broad on purpose:
it catches elevation through binaries no rule names, at the cost of possible false alarms
on installers.

### Outputs

- An alert per elevated process: score waterfall, signals, weights, the exact records.
- **Incidents** joining CPES and SigmaHQ alerts, exported as a Markdown report, a
  **MITRE ATT&CK Navigator layer**, and **ECS alerts** for a SIEM.
- Live mode: the streaming scorer scores each window as it closes.

---

## 5. Data and method

### Datasets

| Dataset | What it is | Used for |
|---|---|---|
| **Lab corpus (corpus-v3)** | One Windows 11 endpoint; 10 Atomic Red Team tests (4 techniques) + benign activity; **2,161 process instances, 87 attacks** | Development; weights were derived here |
| **EVTX-ATTACK-SAMPLES** | **53 public** attack captures, never seen by CPES | External generalisation test |
| **OTRF Security-Datasets** | **21 held-out** captures (CPES v2 test) + **100 unused** captures (service-rule test) | Held-out tests |
| **vm-live-v1** | A second, live session on a Windows 11 VM: 30 min benign use + **50 attack runs**, detectors frozen, Defender on | Replication on new data |
| **VM2** | Windows Server 2022 VM, 50 attack runs, Defender real-time protection off during attacks | Final pre-registered test (done 2026-10-29) |

Lab data is private (contains host/account identifiers); public data is downloaded and
SHA-256 verified by `scripts/fetch_external.py`, never redistributed.

### How results are kept honest

1. **Pre-registration.** Every test and its expected outcome is committed in `docs/design/`
   before it runs. Failed expectations are reported as failed.
2. **Grouped 5-fold CV**, folds split by attack run (no leakage between train and test).
3. **Labels independent of the detector.** The "E-c" protocol labels a run as detected only if
   CPES flags a process created within **±150 s** of the run's time in the Atomic execution log.
4. **Ledger.** Each result records the git commit, whether the code tree was clean, a code
   fingerprint, and the SHA-256 of every input (`results/ledger.jsonl`).
5. **Frozen detectors** on every new dataset: no tuning after seeing test data.

---

## 6. Headline results

### On the lab corpus (grouped 5-fold CV)

| Detector | Precision | Recall | F1 |
|---|:---:|:---:|:---:|
| **CPES** | 0.986 ± 0.029 | 1.000 ± 0.000 | **0.993 ± 0.015** |
| Single-event integrity rule | 0.982 ± 0.036 | 0.404 ± 0.163 | 0.551 ± 0.136 |
| IOC / signature rule | 1.000 ± 0.000 | 0.567 ± 0.194 | 0.705 ± 0.151 |

**Say clearly:** this favours CPES by construction (labels partly come from the same mechanisms).
With labels only from the execution log, CPES flags the right technique in **98 of 126** runs
with **one** false alarm.

### Beyond the lab

| Data | CPES | Comparison |
|---|---|---|
| 53 public captures (weights frozen) | **26/53** with generic test (9/53 specific signals alone) | SigmaHQ core **42/53** |
| Lab runs, right technique flagged | 98/126 | SigmaHQ **106/126** |
| Process that gained privilege named (UAC / service runs) | **33/33 · 28/28** | SigmaHQ 0/33 · 0/28 |
| Live replay of lab corpus | **160/160** alerts equal to offline, median **83 s** to alert | — |
| 21 held-out OTRF captures | 6/13 escalations; injection **4/4** | SigmaHQ injection 2/4 |
| Live VM session (vm-live-v1), 50 runs | **20/50**, **0** false alarms, named privileged process **15/15** | SigmaHQ 30/50, named 0/15; together **35/50** |
| Second VM (Server 2022), 50 runs | **25/50 = all 25 runs where an escalation happened**; named the privileged process **20/20** | SigmaHQ 35/50, named 0/20; together **40/50** |

### Pre-registered expectations and verdicts

| | Expectation | Verdict |
|---|---|---|
| E1 | Pipe evidence lets the package detect token impersonation | **supported** (0/8 → 8/8) |
| E4 | Package engine stays well below research F1 | **supported** (0.684 vs 0.993) |
| A | The 4-binary UAC list does not generalise | **supported** (2/33) |
| B | Renaming the injector defeats name rules; structural ones survive | **supported** (18 → 0; renamed service binary: no change) |
| C1 | SigmaHQ detects more public captures | **supported** (42 vs 26) |
| C2 | SigmaHQ much noisier outside attacks | **not supported** (8 alerts vs CPES's 1) |
| V2 | CPES v2 (generic test in the score) improves held-out detection | **not supported** (6/13 both) → v2 not adopted |
| I | Joined incidents name the elevated process more than Sigma | **supported** (90/126 vs 0), but no better than CPES alone |
| S1 | Signature suppressor removes service false alarms | **not supported** (0 of 7) → not adopted |
| L1 | Live VM: CPES detects ≥ 70% of runs | **not supported** (20/50; Defender stopped all 20 UAC runs) |
| L7 | CPES + Sigma detect more than Sigma alone | **supported** (35 vs 30) |
| S2 | Requiring a service-install event removes service false alarms | **supported** (4 → 0, service runs kept 20/20) |

**Talking point:** several expectations failed and are reported as failed. That's the strength
of the method, not a weakness.

---

## 7. The ten findings, in plain words

1. **In the lab, CPES finds the process that gained privilege** (F1 0.993; 98/126 runs with log-only labels).
2. **The packaged engine originally scored lower than the research scripts** (0.684). The gap
   came from two name rules, a registry requirement and a missing parent check, not from the scoring.
   A `research-v3` mode now reproduces the research figures exactly (0.993).
3. **Structure generalises, name lists don't.** The 4-binary UAC list caught 2/33 UAC methods on
   public data, but the structural service signal caught 5/7 Potato token attacks it was never designed for.
4. **Renaming breaks name rules, not structure.** Renamed injector: 18/18 → 0/18. Unlisted UAC binary:
   UAC signal 33 → 0, while the generic test rose 18 → 32.
5. **Live scoring loses nothing**: 160/160 alerts identical to offline, median 83 s.
6. **SigmaHQ detects more, but never names the elevated process.** CPES complements a rule set; it doesn't replace one.
7. **A refined model (v2) did not survive held-out data**, so it was not adopted.
8. **Service-rule false alarms** (vendor agents like Defender and Azure outside Program Files) couldn't be
   fixed with Sysmon data alone; a signature suppressor removed 0/7.
9. **Joining CPES and Sigma alerts helps less than hoped**: only 7 incidents truly join both, because
   services re-parent under `services.exe`.
10. **On a second, live corpus**, service 10/10 and injection 5/5 replicated, with zero false alarms;
    UAC fell to 5/20 because **Defender blocked the attacks** (the escalation only completed in 5 runs,
    and CPES caught all 5); token runs never reached SYSTEM. Requiring a service-install event (S2)
    removed all 4 service false alarms.

---

## 8. Limitations (say these before someone asks)

- One lab endpoint and one VM per corpus; no multi-host or enterprise traffic.
- Only four mechanisms; techniques without a signal are not detected.
- The UAC signal names four binaries and doesn't generalise.
- On the lab corpus the injection signal is effectively an image-name rule (`mavinject.exe`).
- The service rule false-alarms on vendor agents installed outside `Program Files`; the S2 fix
  needs service-install events and is tested on one machine.
- In the live session, Defender stopped 15 of 20 UAC escalations and the token tests never reached SYSTEM.
- Lab corpora are private, so lab protocols can't be re-run from a clone (public ones can).

---

## 9. Status: complete (release 0.3.0)

Every pre-registered test now has a recorded verdict. The last one, **VM2**, ran on 2026-10-29 on a Windows Server
2022 VM with Defender's real-time protection off, and its analysis code was committed *before* the session.

| | Expectation | Result |
|---|---|---|
| V1 | CPES detects ≥ 70% of the 50 runs | **not supported** (25/50) |
| V2 | research-v3 mode flags exactly what the research rules flag | **not supported** (one difference) |
| V3–V4b | service-rule fixes keep detections without new false alarms | supported (10/10, 0 vs 0) |
| V5 | CPES + Sigma detect more runs than Sigma alone | supported (40 vs 35) |

**How to explain V1:** only 25 of the 50 runs actually escalated, and CPES caught **all 25**. The other 25 never
escalated: two of the three token tests download their attack script from the internet at run time, and the VM was
isolated on purpose; Event Viewer never elevated on Server 2022; `sdclt.exe` doesn't exist on Server. So the miss
is in the test set, not the detector, and we report the 25/50 anyway because that's what was pre-registered.

**Strongest new number:** CPES named the process that gained privilege in **20 of 20** runs; SigmaHQ in **0 of 20**.

**Adoption (decided by a rule written in advance):** the dashboard default stays the structural mode; the
"service-install check" mode is recommended when the logs include service-install events.

## 10. Demo (5 minutes, public data only)

```
pip install -r requirements.txt -r dashboard/requirements.txt
python scripts/fetch_external.py
cd dashboard/web; npm ci; npm run build; cd ../..
python dashboard/run_server.py        # open http://127.0.0.1:8790
```

| Step | Screen | What to say |
|---|---|---|
| 1 | Overview | "CPES scores escalation over the whole process chain; the dashboard adds no scoring of its own." |
| 2 | Datasets → *UAC bypass via eventvwr.exe* → Start run (tick SigmaHQ) | "Raw event log in, validated record by record." |
| 3 | Incidents → INC-0001 | "Sigma saw the attacker's PowerShell; CPES names `eventvwr.exe` at High integrity and links it to the registry write." |
| 4 | Downloads: report, ATT&CK layer, ECS | "Hand-off formats for an analyst or a SIEM." |
| 5 | Lineage | "Reconstructed process tree; missing parents shown as gaps, never guessed." |
| 6 | *RoguePotato* sample | "No RoguePotato rule, yet the structural service test fires." |
| 7 | *UACME method 56 (WSReset)* sample | "An honest miss: not on the list, so CPES is silent. Our evasion test measured exactly this." |
| 8 | Evaluation | "Every result was pre-registered, with code fingerprint and input hashes." |
| 9 | Live | "Same engine streaming; live matched offline 160/160." |

**Never show the `lab-corpus-*` datasets on screen**: they contain private host identifiers.

---

## 11. Suggested slide outline (12–15 min)

1. Title and one-line pitch
2. The problem: symptom rules, actor vs outcome
3. The idea: process tree + evidence + signed score (show the eventvwr example)
4. Pipeline diagram (section 4)
5. Signals and weights table, plus the generic test
6. Data: lab, public, held-out, live VM
7. Method: pre-registration, grouped CV, ledger
8. Lab results table, with the "favours CPES" caveat
9. Generalisation and the SigmaHQ comparison
10. What failed (V2, S1, L1) and why that matters
11. Live demo (or screenshots)
12. Limitations
13. Status (VM2) and next steps
14. Questions

---

## 12. Likely questions and good answers

**Q: Why not just use Sigma?**
A: Use both. Sigma detects more (42/53 vs 26/53), but it alerts on the actor and named the
elevated process in 0/33 UAC and 0/28 service runs; CPES named it in all of them. Together on the
live VM they caught 35/50 runs vs Sigma's 30.

**Q: F1 0.993 sounds too good.**
A: It is, on its own. The labels partly come from the same mechanisms. That's why we also report
the log-only labels (98/126), the public data (26/53) and the live VM (20/50), all with frozen weights.

**Q: VM2 only detected 25/50. Isn't that a failure?**
A: The expectation (≥ 70%) failed and we say so. But only 25 runs contained an escalation, and CPES caught all 25.
The token tests needed internet access the isolated VM didn't have; that is a finding about the test kit, and it
very likely explains the earlier session's token result too.

**Q: Why did the live VM score only 20/50?**
A: Defender stopped all 20 UAC runs; the escalation completed in only 5, and CPES caught all 5. The
15 token runs never reached SYSTEM. Service (10/10) and injection (5/5) replicated with zero false alarms.
On VM2, with Defender's real-time protection off, the UAC bypasses did escalate and CPES caught all 10.

**Q: Isn't the injection signal just a name match?**
A: On the lab corpus, yes: `mavinject.exe` leaves no remote-thread record there. We say so. On public
OTRF data, real remote-thread evidence detected 4/4 injection captures.

**Q: Couldn't an attacker just rename things?**
A: Name rules break (18 → 0), structural ones don't (renamed service binary, random pipe names: no change).
The generic test catches unlisted UAC binaries (18 → 32).

**Q: How are the weights chosen?**
A: Signed log-likelihood ratios from the labelled lab table; each is above the threshold on its own.
They're frozen before any external test.

**Q: What is pre-registration and why bother?**
A: Writing the expected result into git before running the test, so we can't adjust the test after
seeing the answer. Failed expectations (C2, V2, S1, L1) stayed failed.

**Q: Does it run in real time?**
A: Yes. The streaming scorer replayed the lab corpus with 160/160 alerts identical to offline and a
median 83 s from elevation to alert; the dashboard can also poll Elasticsearch live.

**Q: What would you do next?**
A: Make the token tests run offline so the token signal is finally tested on real escalations, add more hosts
and techniques, and record an actor for service escalations so incidents can cross `services.exe`.

---

## 13. Where things are in the repository

| Path | Contents |
|---|---|
| `README.md` | Overview and headline results |
| `docs/FINDINGS.md` | The narrative of all findings |
| `docs/RESULTS.md` | Every number, generated from `results/` |
| `docs/design/` | Pre-registrations (each test's expectation, written before it ran) |
| `docs/DEMO.md` | The 5-minute demo script |
| `cpes/` | The detection package |
| `dashboard/` | Web dashboard (Python backend + React frontend) |
| `evaluation/` | All evaluation protocols (`python -m evaluation.run all`) |
| `lab/` | Lab setup, VM session scripts, the VM2 runbook |
| `results/` | Recorded results and the provenance ledger |
