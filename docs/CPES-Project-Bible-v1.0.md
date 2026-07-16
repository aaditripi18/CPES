<!-- CPES Project Bible — Official Frozen Document -->

# Contextual Privilege Escalation Scoring (CPES)

### A Context-Aware Multi-Event Correlation Methodology for Runtime Privilege Escalation Detection on Windows Endpoints

---

|                     |                                                              |
| ------------------- | ------------------------------------------------------------ |
| **Project Title**   | Contextual Privilege Escalation Scoring (CPES): A Context-Aware Multi-Event Correlation Methodology for Runtime Privilege Escalation Detection on Windows Endpoints |
| **Version**         | v1.0 (Frozen)                                                 |
| **Date**            | July 16, 2026                                                 |
| **Status**          | Official Project Bible                                        |

---

## Table of Contents

1. [Project Overview](#section-1--project-overview)
2. [Detailed Scope & Boundaries](#section-2--detailed-scope--boundaries)
3. [Terminology & Naming Conventions](#section-3--terminology--naming-conventions)
4. [Research Gap & Literature Review](#section-4--research-gap--literature-review)
5. [System Requirements](#section-5--system-requirements)
6. [System Architecture](#section-6--system-architecture)
7. [Technology Stack](#section-7--technology-stack)
8. [CPES Algorithm](#section-8--cpes-algorithm)
9. [Datasets](#section-9--datasets)
10. [Experimental Setup](#section-10--experimental-setup)
11. [Evaluation](#section-11--evaluation)
12. [Implementation Roadmap](#section-12--implementation-roadmap)
13. [Paper Outline](#section-13--paper-outline)
- [Document Status](#document-status)

---

# Section 1 — Project Overview
*(LOCKED v1.0; §1.6 revised to v1.1; §1.7 amended to v1.1)*

## 1.1 Project Title
*Contextual Privilege Escalation Scoring (CPES): A Context-Aware Multi-Event Correlation Methodology for Runtime Privilege Escalation Detection on Windows Endpoints.*

The title names the contribution (CPES) and the method (context-aware multi-event correlation), and deliberately excludes Elastic and Sysmon, which are infrastructure.

## 1.2 Domain
Cybersecurity — Endpoint Threat Detection / Detection Engineering, with a research focus on host-telemetry behavioral analytics. Sub-areas: adversary behavior modeling (privilege escalation), security event correlation, and reproducible detection methodology.

## 1.3 Background
Windows endpoint attacks increasingly abuse legitimate system behavior rather than known malware signatures, and privilege escalation is a pivotal stage in this chain. Rich runtime host telemetry — process creation, parent-child lineage, integrity-level transitions, command-line arguments, and registry activity — is observable through instrumentation such as Sysmon, and platforms like the Elastic Stack make it practical to collect, index, and query that telemetry. Detection logic built over this telemetry, however, has typically relied on single-event or single-rule triggers, which are prone to false positives because an individual suspicious event is often benign in isolation and only meaningful in context.

## 1.4 Problem Statement
Single-event and single-rule detection of privilege escalation on Windows endpoints produces high false-positive rates, because the maliciousness of an individual event (a process spawn, an integrity elevation, a registry write) is determined by its runtime *context* — its lineage, sequence, and co-occurring activity — which single-event methods discard. There is a need for a detection methodology that reasons over the runtime relationships between privilege-related events, rather than over events in isolation.

## 1.5 Motivation
*Practical:* defenders need privilege-escalation detection that is precise enough to be actionable, rather than alert streams dominated by benign single events. *Research:* a principled, context-aware correlation-and-scoring methodology, evaluated reproducibly and kept independent of any specific backend, contributes a portable and comparable reference approach to the detection literature. *Academic:* this is a B.Tech research project intended, if results are sufficiently strong, for submission to an IEEE/Scopus conference, so reproducibility and experimental rigor are first-class objectives rather than afterthoughts.

## 1.6 High-Level Goal *(REVISED v1.1)*
Design, implement, and evaluate CPES — an **automated, interpretable, chain-level scoring methodology** for Windows privilege escalation that fuses heterogeneous privilege-related signals across a process-lineage chain from a single endpoint's Sysmon telemetry, produces a traceable per-chain score, and is validated through **rigorous benchmarking against a single-event baseline** (and, where feasible, a second baseline). Emphasis is on automated interpretable scoring and benchmarking, not on event correlation as such, which the literature treats as mature.

*Companion note:* "context-aware multi-event correlation" remains an accurate *description of the mechanism*, but is demoted from the *claimed novelty*. The claimed novelty is automated + interpretable + chain-level scoring + benchmarking.

## 1.7 Expected Outcome *(AMENDED v1.1)*
A working, documented, reproducible detection pipeline whose core CPES methodology is cleanly separable from Sysmon and Elastic, such that (a) the contribution can be ported to another telemetry source or log backend, and (b) an independent researcher can reconstruct and re-run the system and its experiments from the project documentation alone.

**Secondary contribution:** a reproducible, labeled, privilege-escalation-specific Sysmon telemetry corpus, subordinate to CPES.

## 1.8 Success Criteria *(qualitative only — quantitative metrics deferred to the Evaluation section)*
Success is determined by demonstrating accurate runtime privilege escalation detection through context-aware multi-event correlation over real host telemetry, while maintaining reproducibility and practical applicability. Specifically, and at a qualitative level: the CPES methodology detects the selected privilege-escalation techniques through contextual correlation rather than single-event triggers; the research contribution is demonstrably independent of the Elastic backend; and the system and its experiments are reproducible by a third party from the documentation alone. Quantitative success — Detection Accuracy, Precision, Recall, F1 Score, False Positive Rate, Detection Latency, CPU Usage, and Memory Usage — is formally defined in the Evaluation section.

## 1.9 Scope (brief overview only)
*In scope:* privilege escalation detection on a single Windows endpoint; runtime host telemetry via Sysmon; a context-aware multi-event correlation and scoring methodology (CPES) that is backend-independent; a carefully selected subset of approximately 5–6 MITRE ATT&CK Privilege Escalation techniques chosen for depth of observation and evaluation; reproducible pipeline, experimentation, and documentation.

*Out of scope:* Linux and non-Windows endpoints; cloud and SaaS security; network-based intrusion detection; multi-host and enterprise deployment; and — deferred to their own sections, not excluded — detailed dataset selection and quantitative evaluation design.

---

# Section 2 — Detailed Scope & Boundaries
*(LOCKED v1.0; §2.3 amended to v1.2)*

## 2.1 Purpose
This section converts the Section 1 scope overview into enforceable boundaries: what the project does, what it deliberately excludes, and the assumptions under which CPES operates. Any later request crossing these boundaries triggers a scope-conflict flag (§2.7) before work proceeds.

## 2.2 In scope *(AMENDED v1.1)*
- **Detection target:** runtime detection of privilege escalation on a single Windows endpoint, limited to a selected subset of ~5–6 MITRE ATT&CK Privilege Escalation (TA0004) techniques. Specific techniques selected in Datasets (Atomic Red Team support + public dataset availability); "the selected techniques" is the placeholder until then.
- **Telemetry source:** host-based runtime telemetry from Sysmon — process creation and lineage, integrity-level information, command-line arguments, registry modifications, image loads, and other privilege-relevant events, restricted to those the selected techniques exercise. Exact Sysmon event-ID set fixed in System Requirements / Experimental Setup.
- **Research contribution:** the CPES methodology (context-aware, multi-event correlation and scoring), specified in Section 8, kept backend-independent.
- **Detection mode:** **near-real-time streaming.** CPES continuously consumes telemetry from Elastic and correlates events within **bounded sliding windows**. No distributed streaming infrastructure is introduced; Elastic performs only collection, indexing, and storage, while CPES performs all runtime analysis.
- **Primary scored unit:** the **process-lineage chain (attack chain).** The detection decision is based on contextual relationships across the lineage, since privilege escalation is inherently a multi-event behavioral process. Finer-grained scoring (per-event/per-process) may be added later as an implementation detail without changing this primary unit.
- **Baseline:** a **required single-event baseline**, plus an **optional second baseline** (provenance-graph or ML-based) *only if realistically implementable/reproducible within the project timeline*, explicitly bounded so it cannot expand into a second research project. *(Committed deliverable, carried from Section 1.)*
- **Reproducible PrivEsc Sysmon corpus:** secondary deliverable / secondary contribution.
- **Infrastructure:** Sysmon (telemetry) and Elastic Stack (collection, indexing, storage, visualization) — infrastructure only, explicitly replaceable, not a contribution.
- **Research deliverables:** reproducible pipeline, controlled experimentation, documentation sufficient for third-party reconstruction.

## 2.3 Out of scope *(hard boundaries; AMENDED v1.2)*
Non-Windows endpoints (Linux, macOS); cloud, SaaS, and container security; network-based intrusion detection and all network telemetry; multi-host, domain, or enterprise deployment; ATT&CK tactics other than Privilege Escalation, except artifacts that are unavoidable side effects of executing a selected technique; automated response, remediation, or prevention (detection only, not EDR response); production-grade real-time hardening (performance is *measured*, not productionized); distributed streaming infrastructure; malware reverse engineering and signature development; **deep black-box / low-interpretability models for the CPES scoring function**; **automatic ATT&CK technique classification/attribution (future work).**

## 2.4 Operating assumptions
The endpoint is a controlled, instrumented lab machine (physical or VM) dedicated to the research. Sysmon is installed and configured before data collection. Attack techniques are executed deliberately and in a controlled manner (e.g., via Atomic Red Team) for observation, not captured from live in-the-wild intrusions. Benign/background activity for false-positive measurement is generated or sourced under conditions defined in Datasets/Experimental Setup. Endpoint configuration (OS build, Sysmon config version) is held fixed and versioned across experiments.

## 2.5 Detection-mode boundary (locked detail)
CPES operates as a **near-real-time runtime detector over bounded sliding windows** of Sysmon telemetry drawn from Elastic. The windowing model (size, overlap, eviction) is a CPES design parameter specified in Section 8 and tuned in Experimental Setup. To preserve reproducibility under this streaming regime, evaluation is performed by **replaying a fixed, versioned telemetry corpus through the identical windowing pipeline**, so operational and experimental code paths are the same while the evaluation input is frozen. *(Replay-for-reproducibility is an open dependency resolved in Experimental Setup — see §2.8.)*

## 2.6 Scored-unit boundary (locked detail)
The primary detection and scoring unit is the **process-lineage chain**. True/false positive accounting in Evaluation is defined at the granularity of the lineage chain. Finer granularity, if introduced, is subordinate to and does not replace this unit.

## 2.7 Scope-change protocol
Any later request that adds a technique beyond the selected subset, a new telemetry source, another OS, network data, response/prevention capability, distributed streaming infrastructure, or a change to the primary scored unit is treated as scope creep. Per standing instruction, work stops and the conflict is flagged against this section before proceeding.

## 2.8 Open dependencies introduced or carried by this section
1. *(carried)* CPES novelty must be closed in Literature Review.
2. *(carried)* Single-event baseline detector — committed deliverable.
3. *(carried)* Selection of ~5–6 ATT&CK PrivEsc techniques — deferred to Datasets.
4. *(new)* **Replay-based reproducibility** under the streaming regime — a fixed versioned corpus replayed through the runtime windowing pipeline; design resolved in Experimental Setup.
5. *(new)* **Sliding-window model** (size/overlap/eviction) — specified in Section 8 (CPES), tuned in Experimental Setup.

---

# Section 3 — Terminology & Naming Conventions
*(LOCKED v1.0)*

## 3.1 Purpose
Single source of truth for terminology across the Project Bible, implementation, experimentation, and paper. Definitions are research-precise and project-specific, not generic. Any new term introduced in a later section is added here. Where two terms are close, the definition names the distinction explicitly. This section is maintained continuously.

## 3.2 Core methodology terms

**CPES (Contextual Privilege Escalation Scoring)** — The research contribution: a context-aware, multi-event correlation and scoring methodology that evaluates the runtime relationships across a process-lineage chain and produces a single quantitative score (the CPES Score) expressing the likelihood that the chain represents privilege escalation. CPES is a *methodology* (specified in Section 8), not the score value, not a rule, not any specific tool. Backend-independent by design.

**Context-Aware Detection** — Detection that determines maliciousness from an event's *runtime context* (lineage, sequence, co-occurring events, integrity state) rather than the event in isolation. The defining property distinguishing CPES from the single-event baseline.

**Runtime Detection** — Detection performed on telemetry describing actual process execution as it occurs, in near-real-time streaming over bounded sliding windows (§2.5). Distinguished from static analysis (no execution) and retrospective forensics. Evaluation uses replay (§3.6) for reproducibility, but the analysis path is the runtime path.

**Multi-Event Correlation** — The CPES operation of relating two or more distinct telemetry events belonging to the same process-lineage chain within a detection window, so their *joint* pattern — not any single member — informs the score. Distinguished from single-event evaluation.

**Runtime Context** — The contemporaneous and ancestral facts surrounding an event that CPES uses to interpret it: parent-child lineage, integrity levels and their transitions, command-line content, associated registry activity, image loads, and temporal ordering, bounded by the active detection window. "Context" always means *runtime* context unless explicitly stated.

## 3.3 Chain and grouping terms

**Process-Lineage Chain** — The **structural** ancestry relationship among processes: a sequence/tree linked by parent-child (and where applicable grandparent) relationships, reconstructed from telemetry. A *factual* object carrying no judgment of maliciousness. The **primary scored unit** (§2.6).

**Attack Chain** — A process-lineage chain (or a distinguished path within one) that CPES has scored as representing privilege escalation — the **evaluative** counterpart of a lineage chain. Every attack chain is a lineage chain; not every lineage chain is an attack chain.

> **Distinction enforced:** *lineage chain = structural fact; attack chain = detection verdict.* Section 2's shorthand "process-lineage chain (attack chain)" is superseded in wording by this separation (the locked §2 decision is unchanged). Interchangeable use in later sections is a terminology error.

**Event Group** — A set of telemetry events assembled by CPES for correlation because they share a lineage chain and fall within the same detection window. The event group is the *input unit* to correlation; the lineage chain is the *scored unit*.

## 3.4 Domain terms

**Privilege Escalation** — The act by which a process or lineage chain obtains a higher privilege or integrity level than it legitimately held; MITRE ATT&CK Tactic TA0004, restricted to the selected techniques. Scope is *detection* from host telemetry, never performance except in the controlled lab (§2.4).

**Integrity-Level Transition** — An observed change in the Windows integrity level associated with a lineage chain (e.g., Medium → High, → System), inferred from telemetry. A primary contextual signal for CPES. Denotes the *transition event/relationship*; "integrity level" alone denotes the static value.

**MITRE ATT&CK Technique** — A specific adversary technique catalogued in MITRE ATT&CK under Tactic TA0004, referenced by canonical ID (e.g., T1548). Used in this project as a *ground-truth labeling vocabulary applied manually*, not as a CPES output.

**Selected Techniques** — The finalized subset of ~5–6 ATT&CK Privilege Escalation techniques chosen for depth of observation and evaluation, selected in Section 9 (Datasets) on Atomic Red Team support and public dataset availability. Until finalized, "the selected techniques" is a placeholder for this future-fixed set.

## 3.5 Windowing terms

**Sliding Window** — The streaming *mechanism*: a window of fixed temporal (or event-count) span advancing over incoming telemetry, optionally overlapping, evicting out-of-bound events.

**Detection Window** — A concrete *instance/contents* of the sliding window active at a moment — the specific bounded set of events available to CPES for correlating one lineage chain. (Sliding window = moving frame; detection window = what's inside it now.)

## 3.6 Telemetry and data terms

**Telemetry** — Structured runtime event data emitted by endpoint instrumentation. Unqualified, it means host-based Sysmon telemetry.

**Sysmon Telemetry** — Telemetry produced by Microsoft Sysinternals Sysmon on the Windows endpoint, limited to the event types the selected techniques exercise (process creation/lineage, integrity information, command line, registry modification, image load, etc.). Concrete event-ID set fixed in System Requirements / Experimental Setup.

**Telemetry Corpus** — The complete, versioned collection of recorded telemetry (attack and benign), serving as the master dataset. Defined and versioned in Datasets.

**Replay Corpus** — The fixed subset (or full snapshot) of the telemetry corpus replayed through the identical CPES windowing pipeline during evaluation, guaranteeing deterministic, reproducible results under the streaming regime (§2.5, dependency §2.8.4). The corpus is the archive; the replay corpus is the experiment's frozen input.

## 3.7 Detection-output and evaluation terms

**CPES Score** — The single scalar output of CPES for a given lineage chain within a detection window, expressing likelihood of privilege escalation. **The canonical detection output** and the sole output of the methodology, and must be decomposable into its contributing signal contributions. A detection occurs when the CPES Score crosses the detection threshold (threshold value deferred to Evaluation).

**Risk Score** — Reserved **exclusively** for external/infrastructure scores (e.g., Elastic risk scoring, Microsoft Defender) when referenced for contrast. **Never** used for CPES output. Within this project, the methodology's output is always the CPES Score.

**Confidence Score** — **Reserved and deferred.** No explicit confidence or uncertainty component is introduced into CPES at this stage; CPES Score remains the sole output. If a future implementation naturally yields a calibrated confidence/uncertainty value, it is formally introduced in the appropriate section at that time. Listed here as *reserved, undefined* to prevent informal use.

**Detection Pipeline** — The end-to-end runtime path: telemetry generation (Sysmon) → collection/storage (Elastic) → retrieval into sliding windows → lineage reconstruction → event grouping → multi-event correlation → CPES scoring → detection decision. Sysmon and Elastic are pipeline *stages*, not the contribution; CPES occupies the analysis stages.

**Single-Event Baseline** — The comparison detector that raises a detection from an individual qualifying event/rule without cross-event correlation. Its sole role is to quantify CPES's false-positive reduction; a committed deliverable (§2.2), not a contribution.

**False Positive (FP)** — A lineage chain flagged by a detector (CPES or baseline) as privilege escalation when its ground-truth label is benign. Counted at lineage-chain granularity (§2.6).

**False Negative (FN)** — A lineage chain whose ground truth is a selected privilege-escalation technique but which the detector fails to flag. Counted at lineage-chain granularity.

**Detection Latency** — Elapsed processing time from the arrival (in replay: the timestamp) of the telemetry event completing a detectable pattern to the moment CPES emits a crossing detection for that chain. A measured performance metric, not production-optimized (§2.3). Operationalization fixed in Evaluation.

## 3.8 Project-role terms

**Research Contribution** — Strictly the CPES methodology and its evaluated demonstration. Not Sysmon, Elastic, the dashboard, or pipeline plumbing.

**Infrastructure** — Supporting, replaceable components that are not the contribution: Sysmon (telemetry generation) and the Elastic Stack (collection, indexing, storage, visualization).

**Backend Independence** — The design property that CPES depends on no Elastic-specific feature and could be ported to another log backend by replacing only the retrieval stage. A success criterion (§1.8) and a design constraint on Section 8.

**Interpretability** *(added under §3.11)* — The hard-constraint property that every detection is decomposable into and traceable to its contributing contextual signals; deep black-box approaches are out of scope.

**Secondary Contribution (PrivEsc Sysmon Corpus)** *(added under §3.11)* — The reproducible, labeled, privilege-escalation-specific Sysmon telemetry corpus, subordinate to the CPES methodology.

## 3.9 Naming conventions

**Files** — `lowercase-kebab-case` for repository files and directories (e.g., `cpes-core/`, `lineage-reconstruction.py`). No spaces, no uppercase. Reproducibility-critical configs carry a version suffix (e.g., `sysmon-config-v1.xml`).

**Modules / packages** — Python `snake_case` (e.g., `cpes_core`, `event_correlation`, `lineage_builder`). The core contribution lives under a top-level package named `cpes`, textually isolating it from infrastructure adapters.

**Variables** — `snake_case` for variables/functions; `UPPER_SNAKE_CASE` for constants (thresholds, window sizes); `PascalCase` for classes. Domain objects use canonical terms verbatim (`lineage_chain`, `attack_chain`, `event_group`, `detection_window`, `cpes_score`) — never ad hoc synonyms.

**Elastic indices** — `cpes-<purpose>-<version>` (e.g., `cpes-telemetry-raw-v1`, `cpes-replay-v1`).

**Figures** — `Figure N` in the paper; source files `fig-NN-short-slug.ext` (e.g., `fig-03-detection-pipeline.svg`).

**Tables** — `Table N` in the paper; source files `tbl-NN-short-slug.ext`.

**Algorithms** — `Algorithm N` in the paper, descriptively named (e.g., *Algorithm 1: CPES Scoring over a Detection Window*). The core algorithm is the *CPES scoring algorithm*, never "the CPES algorithm" loosely, preserving the methodology-vs-implementation distinction.

**Technique references** — Canonical ATT&CK ID plus name on first mention (e.g., *T1548 Abuse Elevation Control Mechanism*), ID alone thereafter.

**Chains, attack chains, event groups** — Strictly per §3.3. Code and prose must not use "chain" bare where the structural/evaluative distinction matters.

## 3.10 Additional standardized terms
- **Endpoint** — the single controlled Windows lab machine under study (§2.4); never a generic host.
- **Benign Activity** — non-attack endpoint activity used to measure false positives; labeled ground-truth-benign. (Blocks "normal"/"clean"/"legitimate" as drifting synonyms.)
- **Detection Threshold** — the CPES-Score cutoff above which a chain is flagged; value deferred to Evaluation, name fixed now.
- **Ground Truth** — the authoritative attack/benign + technique-ID label attached to each lineage chain, established by controlled execution (§2.4).

## 3.11 Maintenance rule
When any later section introduces a term of lasting significance, it is appended here with a version note, and the introducing section cross-references it. Terminology changes that would alter a locked definition require an explicit conflict flag before adoption.

---

# Section 4 — Research Gap & Literature Review
*(LOCKED v1.0)*

## 4.1 Field structure
The literature is organized into three strata: (A) commercial/industry detection, (B) academic provenance-graph host intrusion detection, (C) scoring/correlation work including the closest prior art.

**Stratum A — Commercial/industry.** The signal CPES builds on already ships. Splunk security content flags a low/medium-integrity process spawning a high/system-integrity process, and a system-integrity process spawned by a non-system account, over Sysmon EID 1. Elastic ships prebuilt privilege-escalation rules; Log360 maps 243+ rules to TA0004 and offers manual process-lineage tracing to locate where a process elevated without a legitimate UAC prompt. The intuition "higher-integrity child than parent = suspicious" appears in industry material from 2021. **This is CPES's single-event baseline — justification, not competition.**

**Stratum B — Provenance-graph HIDS.** KAIROS, MAGIC, FLASH, NodLink, ProGrapher, R-CAID (S&P/USENIX/NDSS 2023–2024) perform context-aware multi-entity host detection via provenance graphs. But they target whole-system APT detection, operate at node/graph level, are predominantly learning-based and low-interpretability, reportedly suffer high false-positive rates, and assume enterprise-scale whole-system provenance rather than a single Sysmon endpoint.

**Stratum C — Scoring, correlation, closest prior art.** Weighted MITRE-TTP scoring exists but targets *prioritization* via hand-assigned weights (the "weighted-sum trap"). Event/alert correlation is explicitly a mature, "highly researched area." The single closest work — **Bhardwaj, Sapra & Rahman, MDPI *Future Internet* 17(9):394, Aug 2025** — uses Elasticsearch + Sysmon + Winlogbeat on Windows endpoints, does process-lineage correlation to reconstruct privilege-escalation attack chains, and validates with a confusion matrix (accuracy 0.956, precision 0.876, recall 0.948, F1 0.911) plus a per-event Z-score anomaly baseline, using Atomic-style tests. Same stack, telemetry, unit, and tactic as this project.

## 4.2 Surviving gap (what the closest work does not do)
The Bhardwaj method is **manual, hypothesis-driven threat hunting**: an analyst pivots by hand through Kibana/KQL across the lineage; its "scoring" is a *post-hoc* confusion matrix over manually verified alerts, and its Z-score is per-event-type frequency, not a chain-level score. Therefore it (1) produces no automated chain-level score, (2) is retrospective, not runtime, (3) does not algorithmically fuse heterogeneous privilege signals into one decision, and (4) reports no baseline comparison.

Across all three strata the same four-way gap holds. No located work combines: **(a) privilege-escalation-specific + (b) automated chain-level scoring (not node-level, not per-event frequency, not manual pivoting) + (c) interpretable + (d) explicitly benchmarked against a single-event baseline.** That intersection is CPES's defensible contribution.

## 4.3 Literature summary table

| Work (year) | Stratum | Solves | Mechanism | Limitation | Difference from CPES |
|---|---|---|---|---|---|
| Splunk PrivEsc analytics (2026) | A | Integrity-elevation detection | Single Sysmon EID1 rule | Single-event; FP-prone | Is CPES's baseline |
| Log360 TA0004 (2026) | A | Enterprise PrivEsc coverage | 243+ rules + manual lineage | Rule-per-technique; human-driven | No automated chain score; not portable |
| KAIROS/MAGIC/FLASH/NodLink (2023–24) | B | Whole-system APT detection | Provenance-graph learning | APT-generic; node-level; black-box; high FP; heavy | Not PrivEsc-specific; not interpretable; not single-endpoint |
| ProGrapher/R-CAID (2023–24) | B | APT detection + RCA | Graph embedding / RCA | As above | As above |
| Risk-Based MITRE TTP Scoring (2025) | C | Threat prioritization | Hand-weighted TTP scores | Subjective weights; not detection | Scores techniques, not runtime chains |
| Hierarchical Event Correlation (2024) | C | Reduce alert volume | Hierarchical aggregation | Correlation is mature; not PrivEsc | Generic correlation, not PrivEsc scoring |
| **Bhardwaj et al. (2025)** | C | **PrivEsc on Windows via Elastic+Sysmon** | **Manual KQL pivoting; confusion-matrix + Z-score** | **Manual; retrospective; no automated chain score; no baseline** | **Closest work — CPES automates, scores, and benchmarks what this does by hand** |
| Virkud et al. (2024, USENIX) | C | How EDRs use ATT&CK | Empirical study | Not a detector | Supplies motivation: technique-label ambiguity |

## 4.4 Research-gap table

| Dimension | State of the art | CPES gap |
|---|---|---|
| Target specificity | APT-generic or rule-per-technique | PrivEsc-specific, depth over 5–6 techniques |
| Scoring unit | Node / whole-graph / per-event frequency | Chain-level |
| Automation | Manual pivoting or black-box ML | Automated + interpretable |
| FP claim | Asserted, rarely benchmarked | Measured vs. single-event baseline |
| Runtime | Retrospective hunting | Near-real-time sliding window |
| Portability | Bound to vendor query languages | Backend-independent |
| Data | No shared PrivEsc corpus (closest work) | Reproducible PrivEsc Sysmon corpus (secondary contribution) |

## 4.5 Threats to novelty (ranked)
1. **Severe — Bhardwaj 2025.** Same stack/telemetry/unit/tactic/metrics. Must be the primary related-work anchor; CPES positioned as the automation + scoring + benchmarking it lacks.
2. **High — provenance-graph HIDS.** Need a crisp "why not a GNN" answer (PrivEsc-specificity, interpretability, single-endpoint practicality); ideally use one as the optional second baseline.
3. **High — "context-aware correlation" is mature.** Correlation itself is not claimed as novel (resolved by the §1.6 reframe).
4. **Medium — weighted scoring = desk-reject risk.** The score's derivation must be principled, not hand-tuned (governs §7/§8).
5. **Low-Medium — integrity-transition heuristic is folklore.** It is one input feature, never the contribution.

## 4.6 Reviewer #2 criticism list (anticipated)
- Core idea overlaps Splunk/Elastic/Log360 and Bhardwaj 2025 on an identical stack — differentiation required.
- Is the scoring function a hand-tuned heuristic? Derivation must be principled.
- FP-reduction claim must be quantified against a defined baseline on defined data.
- Why no provenance-graph baseline?
- Is 5–6 techniques on one endpoint generalizable? What benign corpus?
- Where is the dataset? (Now answered by the secondary contribution.)

## 4.7 Recommendations adopted into the project (decisions of record)
1. **Contribution reframed** to automated, interpretable, chain-level scoring + benchmarking (§1.6 v1.1). Scope unchanged.
2. **Baselines:** required single-event baseline; optional second (provenance-graph/ML) baseline **only if reproducible within timeline**, bounded so it cannot become a second project (§2.2 v1.1).
3. **PrivEsc Sysmon corpus promoted to secondary contribution** (§1.7, §2.2 v1.1), subordinate to CPES.
4. **Interpretability is a hard constraint** (§2.3, §8): every detection traceable to contributing contextual signals; deep black-box approaches out of scope.
5. **Anchors:** Bhardwaj 2025 as primary related-work anchor; Virkud 2024 for motivation (commercial EDRs disagree on PrivEsc technique labels — e.g., T1548 vs T1068 for CVE-2021-4034 — motivating an interpretable chain-level score that avoids brittle per-technique labeling).
6. **"Single endpoint" is framed as a practicality feature**, contrasting Stratum B's enterprise-scale requirement.

## 4.8 Bottom line
CPES as originally worded would likely be rejected as overlapping Bhardwaj 2025 + commercial rules + the correlation literature. CPES reframed — automated, interpretable, chain-level scoring with a principled derivation, dual-baseline benchmarking, and a reproducible PrivEsc Sysmon corpus — occupies a genuinely unoccupied intersection and is publishable at a Scopus/IEEE venue. The reframe sharpens the claim without changing endpoint, telemetry, tactic, unit, or infrastructure.

## 4.9 Sources
Primary anchor: Bhardwaj, Sapra & Rahman, *Future Internet* 17(9):394 (2025). Motivation: Virkud et al., USENIX Security (2024). Stratum B: KAIROS, MAGIC, FLASH, NodLink, ProGrapher, R-CAID (S&P/USENIX/NDSS 2023–24). Stratum A: Splunk security content, Elastic prebuilt rules, ManageEngine Log360 (2026). Stratum C: Risk-Based MITRE TTP Scoring (2025); Hierarchical Event Correlation, *Network* (2024). *(Full citations to be formalized in the Paper Outline's reference manager; verify each against the publisher of record before submission.)*

---

# Section 5 — System Requirements
*(LOCKED v1.0)*

## 5.1 Functional Requirements

| ID | Description | Reason | Priority |
|---|---|---|---|
| FR-01 | Collect Sysmon host telemetry from the endpoint into the Elastic Stack for indexing and storage. | Committed telemetry pipeline (§2.2). | M |
| FR-02 | Continuously ingest telemetry from Elastic into CPES for runtime analysis. | Near-real-time streaming posture (§2.5). | M |
| FR-03 | Reconstruct process-lineage chains from ingested telemetry. | Lineage chain is the primary scored unit (§2.6, §3.3). | M |
| FR-04 | Derive runtime context per lineage chain (lineage, integrity-level transitions, command-line, registry, and other privilege-relevant signals the selected techniques exercise). | Context is CPES's input (§3.2). | M |
| FR-05 | Group related events of one lineage chain within a bounded sliding window (detection window). | Committed streaming mechanism (§2.5, §3.5). | M |
| FR-06 | Compute a chain-level CPES Score for each lineage chain within its detection window. | Reframed core contribution (§1.6 v1.1). | M |
| FR-07 | Raise a privilege-escalation detection when a chain's CPES Score crosses the detection threshold (threshold value deferred to Evaluation). | Turns score into decision. | M |
| FR-08 | For every detection, produce an explanation decomposing the CPES Score into its contributing contextual signals, so the detection is traceable to those signals. | Interpretability hard constraint (§2.3, §8). | M |
| FR-09 | Assign ATT&CK technique labels **manually as ground truth during corpus construction**; CPES detects/scores privilege escalation at chain level and is **not** required to classify the technique. | Contribution is detection+scoring, not attribution (finalized decision). | M |
| FR-10 | Log every detection with detail sufficient to reconstruct it (chain identity, score, contributing signals, technique ground-truth label, timestamps). | Enables evaluation, reproducibility, traceability. | M |
| FR-11 | Visualize telemetry and detections through Kibana; no detection logic may depend on Kibana. | Committed visualization infra (§2.2); bounded to protect NFR-02. | O |
| FR-12 | Support evaluation of CPES against the required single-event baseline over identical input. | FP-reduction claim needs like-for-like comparison (§2.2, §4). | M |
| FR-13 | Support evaluation against an optional second (provenance-graph/ML) baseline, if implemented. | Strengthens novelty defense (§4.7); timeline-bounded. | O |
| FR-14 | Export experimental results (detections, scores, per-chain labels, metric inputs) in a portable, analysis-ready form independent of any UI. | Feeds Evaluation; decouples results from dashboard. | M |
| FR-15 | Replay a fixed, versioned telemetry corpus through the identical runtime windowing pipeline to produce deterministic evaluation runs. | Reproducibility under streaming (§2.5, §2.8.4). | M |
| FR-16 | Support construction and labeling (incl. manual technique ground truth) of the reproducible Privilege-Escalation Sysmon corpus (attack + benign). | Corpus is a secondary contribution (§1.7, §2.2 v1.1). | M |

## 5.2 Non-Functional Requirements

| ID | Requirement | Definition & publication relevance |
|---|---|---|
| NFR-01 | Reproducibility | Third party rebuilds and re-runs from documentation alone (§1.8). Headline research-quality claim. |
| NFR-02 | Backend independence | CPES depends on no Elastic-specific feature; only retrieval is Elastic-bound (§3.8). Portability criterion; differentiator. |
| NFR-03 | Interpretability | Every detection decomposable into contributing signals (§2.3, §8). Novelty moat vs. Stratum-B black boxes (§4.5). |
| NFR-04 | Experiment repeatability | Repeated runs on the frozen replay corpus yield identical results. Distinct from NFR-01 (rebuild vs. same-input determinism). |
| NFR-05 | Modularity | CPES separable from infrastructure adapters (§3.9). Enables clean attribution of results. |
| NFR-06 | Extensibility | Adding a technique/signal needs no redesign. |
| NFR-07 | Maintainability | Clean structure, consistent naming (§3.9), documented decisions. |
| NFR-08 | Performance (measured, not optimized) | Resource use and detection latency measured under conditions defined in Evaluation; not productionized (§2.3). Numeric targets deferred. |
| NFR-09 | Reliability | Pipeline processes the corpus without run-invalidating event loss; failures detectable; runs restartable. |
| NFR-10 | Scalability (within scope only) | Handles single-endpoint corpus volume; enterprise/multi-host scale not required (§2.3). |
| NFR-11 | Documentation quality | Sufficient for NFR-01; first-class deliverable. |

## 5.3 System Constraints

| ID | Constraint | Source |
|---|---|---|
| CON-01 | Windows-only endpoint. | §2.3 |
| CON-02 | Sysmon host telemetry as source. | §2.2 |
| CON-03 | Elastic infrastructure only; replaceable; not a contribution. | §2.2, §3.8 |
| CON-04 | Single-endpoint scope. | §2.3 |
| CON-05 | Near-real-time streaming. | §2.5 |
| CON-06 | Bounded sliding-window processing. | §2.5, §3.5 |
| CON-07 | Detection only; no prevention/response. | §2.3 |
| CON-08 | Deep black-box models excluded; CPES interpretable. | §2.3, §8 |
| CON-09 | ~5–6 selected ATT&CK PrivEsc techniques. | §2.2 |
| CON-10 | Constrained B.Tech timeline; optional items yield first. | §1.5 |
| CON-11 | Primary scored unit is the process-lineage chain. | §2.6 |
| CON-12 | No automatic ATT&CK technique attribution (future work). | §2.3 v1.2, FR-09 |

## 5.4 External Dependencies *(versions deferred to Technology Stack)*
Sysmon (telemetry generation); Winlogbeat or equivalent shipper (transport — replaceable, not contribution-relevant); Elasticsearch (index/storage); Kibana (visualization, supports FR-11/Optional); Atomic Red Team (controlled technique execution); Python (analysis/tooling, §3.9); MITRE ATT&CK (taxonomy + manual ground-truth vocabulary); Public datasets (*conditional* — only if a suitable PrivEsc-labeled Sysmon dataset exists; the secondary-contribution corpus exists because this may not be satisfiable).

## 5.5 Assumptions

| ID | Assumption |
|---|---|
| ASM-01 | Controlled, dedicated lab endpoint (physical/VM), isolated enough to execute techniques safely (§2.4). |
| ASM-02 | OS build and Sysmon config fixed and versioned across all experiments (§2.4). |
| ASM-03 | Configured Sysmon emits the event types the selected techniques exercise, with reasonable completeness and correct timestamps (risk R-01 if violated). |
| ASM-04 | Attack activity generated via Atomic Red Team; benign activity generated/sourced under defined conditions (§2.4). |
| ASM-05 | Operator has privileges to install Sysmon, run Atomic tests, and produce integrity-level transitions on the lab endpoint. |
| ASM-06 | Evaluation uses the frozen replay corpus; runtime nondeterminism does not affect reported metrics (§2.5). |
| ASM-07 | Each lineage chain can be labeled attack/benign + technique-ID with acceptable confidence (controlled execution). |

## 5.6 Risks & Mitigations

| ID | Risk | Mitigation |
|---|---|---|
| R-01 | Missing/incomplete telemetry. | Validate per-technique coverage before reliance; version Sysmon config; drop/replace an unobservable technique (Datasets). |
| R-02 | Dataset limitations. | Secondary-contribution corpus; document benign generation; report composition honestly; state small-n as a limitation. |
| R-03 | False positives from benign elevations. | Include realistic benign elevations; measure FP rather than avoid it — this is CPES's raison d'être. |
| R-04 | Reproducibility failure. | Freeze configs/corpus; script pipeline; document environment; internally acceptance-test NFR-01/04 before submission. |
| R-05 | Performance/measurement noise. | Performance measured, not required production-fast (NFR-08); replay makes latency deterministic. |
| R-06 | Second-baseline overrun. | Optional (FR-13); hard go/no-go in Experimental Setup; single-event baseline alone satisfies core claim. |
| R-07 | Scope creep. | §2.7 protocol: flag against Section 2 before work. |
| R-08 | Interpretability vs. accuracy tension. | Accepted deliberately; interpretability is a claimed strength; addressed in scoring-derivation work (dep. #7); honest reporting if accuracy suffers. |

## 5.7 Reviewer #2 Resolutions (recorded)
Added FR-14/15/16 (result export, replay-as-capability, corpus construction) — without them NFR-01/04 and the secondary contribution were unverifiable. Resolved FR-11↔NFR-02 tension by making Kibana Optional and detection-independent. Reframed Performance and Scalability to be verifiable and bounded (NFR-08/10). Kept event correlation as internal mechanism, not a headline requirement, to avoid re-inflating the demoted claim (§4). Deferred all how/how-much (windows, formulas, schemas, thresholds, metrics, versions) to §6/§8/§9/§11.

---

# Section 6 — System Architecture
*(LOCKED v1.0)*

## 6.1 High-level architecture
A two-zone pipeline. The **Infrastructure Zone** (Sysmon → shipper → Elasticsearch → Kibana) generates, transports, indexes, stores, and optionally visualizes telemetry. The **Contribution Zone** (CPES) reads telemetry through a single adapter and performs all analysis. The zones meet at exactly one interface — the Retrieval Adapter (C5) — the only CPES component aware of Elastic. This realizes CON-03 and NFR-02 structurally: the contribution is portable because only one component is backend-coupled. (Architecture figure: `fig-06-infrastructure-contribution-boundary`.)

## 6.2 Major system components
Infrastructure Zone: Sysmon (C1), Log Shipper (C2), Elasticsearch (C3), Kibana (C4, optional). Contribution Zone: Retrieval Adapter (C5), Lineage Reconstructor (C6), Context Builder (C7), Window Manager (C8), CPES Scorer (C9), Detection & Explanation Emitter (C10), Result Exporter (C11). Cross-cutting: Baseline Harness (C12), Replay Driver (C13), Corpus Builder (C14).

## 6.3 Component responsibilities

| ID | Component | Responsibility | Serves |
|---|---|---|---|
| C1 | Sysmon | Emit host telemetry for events the selected techniques exercise. | FR-01, CON-02 |
| C2 | Log Shipper | Transport telemetry to Elasticsearch. | FR-01 |
| C3 | Elasticsearch | Index and store telemetry. | FR-01 |
| C4 | Kibana | Visualize telemetry/detections; no detection logic. | FR-11 (O) |
| C5 | Retrieval Adapter | Read telemetry from Elastic; hand CPES a backend-neutral event stream. **Sole Elastic-coupled component.** | FR-02, NFR-02 |
| C6 | Lineage Reconstructor | Build process-lineage chains from the event stream. | FR-03, CON-11 |
| C7 | Context Builder | Derive runtime context per chain (integrity transitions, command line, registry, lineage relations). | FR-04 |
| C8 | Window Manager | Maintain bounded sliding windows; assemble the event group per chain per detection window. | FR-05, CON-06 |
| C9 | CPES Scorer | Compute the interpretable chain-level CPES Score, retaining per-signal contributions. | FR-06, NFR-03, CON-08 |
| C10 | Detection & Explanation Emitter | Apply threshold; emit detection + signal-decomposed explanation + logging. | FR-07, FR-08, FR-10 |
| C11 | Result Exporter | Export detections/scores/labels/metric inputs, UI-independent. | FR-14 |
| C12 | Baseline Harness | Run single-event baseline (and optional second baseline) over identical input. | FR-12, FR-13 (O) |
| C13 | Replay Driver | Feed frozen replay corpus through identical C5-downstream path for deterministic runs. | FR-15, NFR-04 |
| C14 | Corpus Builder | Construct and manually label the PrivEsc Sysmon corpus (attack/benign + technique ground truth). | FR-16, FR-09 |

C9 is the novel core; C5–C8, C10–C14 are supporting machinery around it.

## 6.4 Data flow
Live path: C1 → C2 → C3 → **C5** → C6 → C7 → C8 → C9 → C10 → C11; C4 reads from C3, and C10 may optionally feed C4. No component after C5 references Elastic. Evaluation path: **C13** replays the frozen corpus into C5's downstream interface (bypassing live C1–C3), driving identical C6–C10 code — operational and experimental paths differ only in *source*, not *analysis* (§2.5). C12 consumes the same input as C9 (see §6.7) for like-for-like comparison.

## 6.5 Infrastructure vs contribution boundary
The boundary is the C5 seam: C5 depends on Elastic; C6–C14 do not. **Invariant:** backend independence (NFR-02) holds iff replacing C5 with an adapter for another backend requires no change to C6–C11. This is the architecture's central invariant and the paper's portability argument. Any future request pushing detection logic into C3/C4 violates CON-03 and is rejected under §2.7.

## 6.6 Runtime pipeline
Per cycle: C5 pulls new events → C6 attaches/extends lineage chains → C7 enriches with runtime context → C8 windows the chain's events (evicting out-of-bound) → C9 scores, recording each signal's contribution → C10 thresholds and, on a crossing, emits detection + explanation + log. Window parameters are specified in §8 and tuned later; the architecture fixes only *that* windowing occurs at C8.

## 6.7 Component interactions
One-directional flow, no back-edges into infrastructure. C9↔C10 share the per-signal contribution record, making the explanation (FR-08) a first-class output rather than a post-hoc reconstruction. **C12 attaches at C8's output** (identical windowed input as C9) ensuring fair baseline comparison. C13 substitutes for C1–C3 at C5's downstream boundary. C14 produces the artifact C13 consumes.

## 6.8 Deployment architecture *(LOCKED: All-in-One)*
Single controlled lab endpoint/VM hosting Sysmon, Elastic Stack, and CPES together. Environment (OS build, Sysmon config, stack versions) fixed and versioned across experiments (ASM-02). Backend independence preserved via C5, so this topology choice does not touch the contribution. Rationale of record: the objective is to develop, evaluate, and publish CPES, not to build production infrastructure; co-location maximizes reproducibility, minimizes moving parts, simplifies deployment and debugging, enables deterministic experimentation, and reduces environmental variability. Consistent with single-endpoint scope (CON-04) and reproducibility-first philosophy (NFR-01).

## 6.9 Trust boundaries
**T1 (Endpoint ↔ analysis):** telemetry crossing C2→C3 is trusted within the controlled lab (ASM-01); no claim of resistance to a telemetry-tampering adversary — out of scope, stated explicitly. **T2 (Infrastructure ↔ contribution at C5):** CPES trusts C5 delivers faithful telemetry; it does not validate Elastic integrity. Both are acceptable under the controlled-lab assumption and must be named as scope limits in the paper.

## 6.10 Failure points

| Point | Failure | Consequence | Handling |
|---|---|---|---|
| C1 | Sysmon misses needed events | Incomplete chain; FN | R-01: validate per-technique coverage in C14 first |
| C2/C3 | Transport/index drops or latency | Missing events in window | Live: tolerated (measured, not productionized). Eval: C13 replay bypasses → deterministic |
| C5 | Adapter mis-maps telemetry | Corrupted analysis | Only backend-coupled unit → contract-test in isolation |
| C6 | Lineage misassembled (PID reuse, missing parent) | Wrong scored unit | §8 correctness obligation (see §6.11) |
| C8 | Window mis-sized | FN or FP | Tuning deferred to Experimental Setup (dep. #6) |
| C9 | Unsound score derivation | Weak/uninterpretable detection | Top open dependency (#7); CON-08 guards interpretability |

## 6.11 Reviewer #2 architectural resolutions (recorded)
Single backend-coupled component (C5) is the cleanest defense of NFR-02 — foregrounded in the architecture figure. Identical eval/runtime path via C13 pre-empts the "streaming isn't reproducible" criticism at the architectural level. Baseline attachment fixed at C8's output so C9 and C12 see identical input (fair comparison). Explanation made a shared C9↔C10 artifact so scoring and explanation cannot drift. **Logged as a §8 correctness obligation:** C6 lineage reconstruction must handle PID reuse and missing-parent cases, which can silently corrupt the scored unit. All window values, scoring internals, schemas, thresholds deferred to §8/§9/§11. No scope creep — every component maps to a locked FR/NFR/CON.

---

# Section 7 — Technology Stack
*(PERMANENTLY LOCKED v1.1)*

## 7.0 Technology philosophy *(governing rule, LOCKED)*
Every technology, framework, or library in the project must satisfy **all four** conditions: (1) directly supports a functional requirement, (2) maps to a specific architectural component, (3) contributes to reproducibility, (4) does not dilute the CPES research contribution. Any dependency failing any condition is excluded. This rule governs all future technology decisions, including §8.

## 7.1 Programming language
**Python**, single implementation language for the Contribution Zone (C5–C14). Chosen for the first-party Elasticsearch client, mature data libraries, readability (serving CON-08 and NFR-01), and reproducibility. Performance is measured not optimized (NFR-08), so compiled-language speed is not decisive. Rejected: Go, Rust, Java/Scala — all trade reproducibility/readability for unneeded performance.

## 7.2 Operating system *(LOCKED: Windows 11)*
Windows 11, one frozen build documented for the project's duration (ASM-02). Mandatory per CON-01 (integrity levels, UAC, Windows lineage are OS-specific). No Linux, macOS, cloud, or multi-platform support. Deployed on a dedicated snapshot-able VM (§6.8 all-in-one, ASM-01). Microsoft's 2026 productization of Sysmon into Windows 11 uses the same config files and event log and does not disturb the stack (recorded for awareness).

## 7.3 Telemetry collection
**Sysmon**, chosen over native auditing for ProcessGUID (lineage across PID reuse, dep. #9), integrity levels, full command line, parent lineage, image loads, and registry detail in one schema. Custom versioned config `sysmon-config-v1.xml`, scoped to selected-technique EIDs (finalized §9), pinned to prevent drift.

## 7.4 Log collection
**Winlogbeat**, native ECS-compliant shipper (C2), version-matched to the stack. Rejected: Elastic Agent, Logstash, Fluent Bit/Fluentd. Recorded caveat: Beats' Elastic-license lock does not affect NFR-02, which is defended at C5 downstream of storage. Infrastructure only (CON-03), replaceable, Contribution-Zone-independent.

## 7.5 Storage & search
**Elasticsearch** (C3), indexed retrieval for C5's windowed pulls. Infrastructure only — per Decision 3, no detection, scoring, correlation, analytics, or CPES logic executes in Elasticsearch or Kibana. NFR-02 preserved by the §6.5 invariant; only C5 is backend-dependent.

## 7.6 Visualization
**Kibana** (C4, optional, FR-11). Custom dashboard rejected (timeline cost, "engineering not research" risk). No detection logic depends on Kibana; evaluation flows through C11's UI-independent export (FR-14).

## 7.7 Development frameworks
Included: `elasticsearch` client (C5 only, quarantined), pandas (C7/C11/eval), NumPy (numerical support). **Conditionally deferred (Decision 5):** NetworkX (only if C6 lineage needs graph algorithms) and scikit-learn (only if the interpretable scoring derivation requires a simple interpretable learned model, never violating CON-08) — introduced in §8 only if genuinely required, never speculatively. matplotlib/plotting deferred to §13.

## 7.8 Experimental tools
Atomic Red Team (C14 attack generation), MITRE ATT&CK (FR-09 manual labeling vocabulary), VM software (§6.8 host, snapshot/reset), Git (local VC), GitHub (remote + artifact release). All serve reproducibility (NFR-01).

## 7.9 Development environment
IDE unprescribed (VS Code recommended). Git + GitHub. Exact-pinned dependency spec (no ranges). Organization per §3.9 with the `cpes` top-level package (NFR-05).

## 7.10 Version table *(PERMANENT reproducibility artifact — LOCKED; verified live, July 2026)*

| Component | Pinned version | Notes |
|---|---|---|
| Windows 11 | One frozen build (exact build recorded at setup) | Held constant (ASM-02) |
| Sysmon | 15.20 | Sysinternals, Jun 18 2026 |
| Sysmon config | `sysmon-config-v1.xml` (project-versioned) | Scoped to selected-technique EIDs (§9) |
| Elasticsearch | 9.4.3 | Current supported release (Jun 30 2026) |
| Kibana | 9.4.3 | Version-matched (required) |
| Winlogbeat | 9.4.3 | Version-matched |
| Python | 3.12.x (latest 3.12 patch) | Client requires ≥3.10; 3.15 alpha excluded |
| Elasticsearch Python client (`elasticsearch`) | 9.4.1 | Matches ES 9.4 minor |
| pandas | 2.2.x (latest 2.2 patch) | Not 3.0 — breaking changes avoided for stability |
| NumPy | 1.26.x | pandas 2.2-compatible; avoids NumPy 2.0 ABI churn |

Policy (LOCKED): exact-pin everything reproducibility depends on; match Elastic minor across Elasticsearch/Kibana/Winlogbeat; record the exact Windows build at setup; prioritize stability/support over novelty. Recorded caveats: Elastic 9.x EOL cadence is aggressive, mitigated by environment freezing/snapshotting; pandas 2.2/NumPy 1.26 pins trade currency for stability deliberately. **Any library introduced in §8 must be added here with its exact version before §8 locks.**

## 7.11 Technology interaction
Bound to the §6 figure (`fig-06-infrastructure-contribution-boundary`): C1=Sysmon 15.20, C2=Winlogbeat 9.4.3, C3=Elasticsearch 9.4.3, C4=Kibana 9.4.3, C5=`elasticsearch` 9.4.1, C6–C11=Python 3.12 + pandas 2.2 + NumPy 1.26 (+ conditional §8 libraries).

## 7.12 Research contribution boundary *(LOCKED)*
The research contribution is exclusively the CPES methodology. Sysmon, Winlogbeat, Elasticsearch, Kibana, Python, and every supporting library exist only to enable CPES. The paper must never imply the infrastructure is the contribution.

## 7.13 Final consistency review (recorded)
All six checks passed: every technology maps to a component and ≥1 requirement; no unnecessary dependency (Decision 1 test applied); backend independence preserved (client quarantined in C5); reproducibility strengthened (exact pins, stable-not-newest, versioned config, snapshot VM); full consistency with §1–6; no new scope.

---

# Section 8 — CPES Algorithm
*(Methodology Specification — LOCKED v1.0)*

## 8.1 Purpose
CPES consumes runtime host telemetry, reconstructs process-lineage chains, and assigns each chain a single interpretable score expressing how strongly its runtime context indicates privilege escalation. Objective: **detect privilege escalation at the process-lineage-chain level with fewer false positives than single-event detection, via an interpretable, deterministic aggregation of contextual evidence whose every detection is traceable to the signals that produced it.** It is deliberately not single-event detection, not rule aggregation, not graph-representation learning, not a black-box classifier, and not vendor risk scoring (§3.7). The claimed novelty is the privilege-escalation-specific runtime context model plus chain-level, interpretable, benchmarked scoring — not the aggregation family, which is intentionally simple.

## 8.2 Detection philosophy
Privilege escalation is relational: its constituent events are individually common in benign operation; what distinguishes escalation is their combination and context (an integrity elevation without a legitimate consent path, within an anomalous lineage, co-occurring with privilege-relevant activity, in a tight temporal span). The process-lineage chain is the primary detection unit (CON-11) because escalation is intrinsically a lineage crossing a privilege boundary. Scoring the chain lets benign context actively suppress false alarms a single-event detector would raise.

## 8.3 Processing pipeline (logical stages)
Ingest (C5→C6) → lineage reconstruction (C6) → context derivation (C7) → windowed grouping (C8) → evidence extraction → scoring (C9) → decision & explanation (C10). No stage after C5 references the backend.

## 8.4 Runtime context model
Categories (qualitative; no weights/thresholds): parent–child relationship; lineage relationship (ancestry, depth, coherence); integrity-level transition (with/without legitimate elevation path); privilege inheritance along lineage; command-line context (auto-elevation invocation, obfuscation indicators — as signals, not signatures); registry context (privilege-relevant modifications in chain context); image/module context; temporal proximity. A category is active only if at least one selected technique exercises it (dep. #4).

## 8.5 Event correlation model
Lineage grouping (structural, by stable process identity + parent references); windowed association (bounded sliding window, dep. #6, governing the context-completeness vs. latency/memory trade-off; size/overlap/eviction deferred to Experimental Setup); contextual grouping / chain construction (windowed events + derived context = event group, the input unit; chain remains the scored unit).

## 8.6 Scoring framework — Approach B (Additive Signed-Evidence Model) *(LOCKED)*
Each present contextual signal contributes a **signed evidence term** (log-likelihood ratio of the signal under escalation vs. benign); the chain's score is the prior log-odds plus the sum of present signals' evidence terms. Positive terms push toward escalation, negative (benign) terms pull away; detection occurs on threshold crossing. Form (specification, no values): *CPES Score(chain) = prior log-odds + Σ signed evidence contribution over present signals.* Continuous signals are represented as binned evidence features. **All evidence contributions, bin boundaries, and the detection threshold are derived from corpus statistics and deferred (§9/§10/§11); the additive signed-log-evidence form is fixed, deterministic, and interpretable by construction.** Approaches A (hand-tuned) and D (black box) rejected; **Approach C (logistic regression / shallow tree, requiring scikit-learn) recorded as a contingency only** — considered in Evaluation iff B's independence assumption materially degrades results, and adoptable by swapping only C9's internal fitting since the additive log-odds form is identical. **scikit-learn is not adopted** (dep. #7 resolved; §7.10 unchanged).

## 8.7 Explainability model
Intrinsic to Approach B. Per detection, CPES emits: which signals contributed (present signals with signed contributions); why the score increased (ranked positive contributions, plus outweighed benign contributions); which chain elements were responsible (the specific processes/events producing each signal). The score is literally the sum of these contributions, so the explanation is a faithful decomposition, not a surrogate — the property differentiating CPES from Stratum-B black boxes.

## 8.8 Correctness obligations (dependency #9 resolved)
Process identity anchored to **Sysmon ProcessGUID** (not reusable PID), structurally preventing PID-reuse identity collisions. Missing parents → chain treated as **truncated**, scored on available evidence, incompleteness recorded; ancestry never fabricated. Incomplete telemetry → chain flagged **incomplete** (per-technique validation, R-01), scored with caveat. Broken chains → the reconstructable connected fragment is scored, fragmentation recorded; joins never guessed. A lineage chain is a rooted tree keyed by ProcessGUID→parent-ProcessGUID; a dict adjacency map suffices. **NetworkX is not adopted** (dep. #9 stack question resolved; §7.10 unchanged).

## 8.9 Assumptions
Reliable ProcessGUID for lineage (ASM-03); selected-technique context expressible via §8.4 over Sysmon; attack/benign separable to a useful (not perfect) degree; corpus statistics representative enough to generalize within scope (limitation, §8.10); controlled-lab telemetry faithful (T2, §6.9) — no tampering defense.

## 8.10 Limitations
No technique attribution (CON-12); no zero-day generality claim; no adversarial/mimicry robustness; no multi-host correlation (CON-04); independence assumption may mis-weight correlated signals (Approach C is the documented mitigation); no prevention/response (CON-07); truncated/incomplete chains scored with caveats, not perfectly.

## 8.11 Reviewer #2 review (recorded)
Sharpest attack: Approach B is mathematically a weight-of-evidence/Naive-Bayes classifier over engineered features — the aggregation is old and this is not disputed; the paper must locate novelty in the PrivEsc-specific context model, chain-level unit, interpretability-by-construction, and benchmarked FP reduction, and must frame simplicity as a deliberate interpretability choice, not an innovation. Independence assumption is a real weakness (mitigate via non-redundant signals; report honestly; hold C in reserve). Novelty depends on corpus soundness (dep. #8) — raises stakes on §9. Circularity risk — evidence derivation must be disjoint from evaluation data (binding on §10/§11). Signal engineering is where hidden complexity/brittleness could enter — each signal definition must be justified and reproducible. Baseline must be fair and literature-grounded, not a strawman. ProcessGUID reliance sound but validate per technique (R-01).

## 8.12 Lock status
Locked, conditional on three binding obligations carried forward: (1) no circularity between evidence derivation and evaluation; (2) corpus soundness; (3) fair, literature-grounded single-event baseline.

---

# Section 9 — Datasets
*(LOCKED v1.0)*

## 9.1 Selected techniques
Six ATT&CK PrivEsc techniques: **T1548.002** (Bypass UAC), **T1134.001** (Token Theft), **T1134.002** (Create Process with Token), **T1543.003** (Windows Service), **T1546.003** (WMI Event Subscription — contingency drop), **T1055.001** (DLL Injection). **T1068 deliberately excluded** (reproducibility, complexity, weak contextual telemetry, poor CPES suitability, inconsistent dataset support). Active §8.4 categories are exactly those in the coverage matrix; nothing outside it is in scope.

## 9.2 Technique × context-category coverage matrix

Rows are the eight §8.4 context categories; columns are the six locked techniques. ● = primary signal for that technique; ○ = secondary/situational.

| §8.4 context category | T1548.002 UAC Bypass | T1134.001 Token Theft | T1134.002 Process w/ Token | T1543.003 Windows Service | T1546.003 WMI Sub. | T1055.001 DLL Injection | Coverage |
|---|---|---|---|---|---|---|---|
| Integrity-level transition | ● | ● | ● | ○ | ○ | ● | 6 |
| Parent–child relationship | ● | ● | ● | ● | ● | ● | 6 |
| Lineage relationship | ● | ● | ○ | ● | ● | ● | 6 |
| Privilege inheritance | ○ | ● | ● | ● | ● | ● | 6 |
| Command-line context | ● | ○ | ○ | ● | ● | ○ | 6 |
| Registry context | ● | — | — | ● | ● | — | 3 |
| Image/module context | ○ | — | — | ● | — | ● | 3 |
| Temporal context | ● | ● | ● | ● | ● | ● | 6 |

Every §8.4 category exercised by ≥3 techniques; six of eight by all six. Registry (T1548.002, T1543.003, T1546.003) and image/module (T1543.003, T1055.001) survive the T1546.003 contingency drop with ≥2 techniques each. Matrix confirms no orphaned category and validates the slate against the evidence model.

## 9.3 Corpus overview
Primary source: **PrivEsc Sysmon Corpus** (secondary contribution, dep. #8, built by C14), with an **attack partition** (Atomic-executed, technique-labeled) and a **benign partition** including mandatory hard negatives (§9.4). Public datasets are supplementary cross-check only (§9.7).

## 9.4 Benign data generation *(BINDING requirement)*
The benign partition **must** include hard negatives resembling escalation: legitimate UAC elevations, software installation, Windows service management, administrator PowerShell usage, legitimate WMI activity, and ordinary Windows background activity. This is mandatory throughout the project because the false-positive-reduction claim depends on it. A benign partition of idle noise is non-compliant.

## 9.5 Attack data generation
Atomic Red Team execution on the frozen Windows 11 VM with `sysmon-config-v1.xml`; executions bracketed (timestamps, technique ID, atomic number) for deterministic segmentation/labeling; multiple runs/variants per technique (R-02 mitigation); prerequisites fetched, cleanup run, snapshot-restore between batches where feasible; per-technique telemetry-coverage validation (R-01) before admission, else §8.8 completeness handling applies.

## 9.6 Sysmon configuration `sysmon-config-v1.xml` *(LOCKED, technique-scoped)*
Frozen to exactly the technique-justified EID set — collect only telemetry required to evaluate CPES (reproducibility-first):

- **EID 1** — Process creation (all techniques)
- **EID 10** — Process access (T1134.001, T1055.001)
- **EID 8** — CreateRemoteThread (T1055.001)
- **EID 7** — Image/module load (T1543.003, T1055.001)
- **EID 12/13** — Registry object create/modify (T1548.002, T1543.003, T1546.003)
- **EID 11** — File create (T1543.003)
- **EID 19/20/21** — WMI event filter/consumer/binding (T1546.003 only)
- **EID 6** — Driver load (optional, T1543.003 BYOVD only)

Added to version-controlled artifacts and the §7.10 table. If T1546.003 is dropped, EIDs 19/20/21 are removed → `sysmon-config-v2.xml` (§3.11).

## 9.7 Public-dataset cross-check
Reputable public Sysmon datasets used only to sanity-check representativeness of the self-built corpus — never blended into evidence derivation without provenance. Each source recorded with origin/version. Validation aid supporting O2, not a primary source.

## 9.8 No-circularity data split *(O1 — binding)*
Evidence contributions (§8.6) derived on a **derivation set** disjoint from a **held-out evaluation set**; no chain in both. Exact protocol (hold-out vs. k-fold, ratios) specified in §10/§11; §9 fixes the requirement. Violation inflates results and voids the contribution.

## 9.9 Corpus versioning & reproducibility
`cpes-telemetry-corpus-v1`; frozen replay snapshot `cpes-replay-v1` (C13, §2.5). Scripted, documented generation (VM build, Sysmon config version, Atomic test list+versions, benign-generation procedure, labeling brackets) for third-party reconstruction (NFR-01) — what makes the corpus a contribution.

## 9.10 Assumptions
Atomic reliably executes the six techniques (ASM-04); hard-negative benign activity generatable and correctly labelable (ASM-07); per-technique coverage validated pre-admission (R-01); corpus representative enough for derived evidence to generalize within scope (§8.9).

## 9.11 Risks
R-02 (small-n; multiple runs/variants + honest reporting), R-09 (weak benign partition; §9.4 binding requirement + pre-eval review), R-10 (labeling error; controlled brackets + provenance + spot-audit), R-11 (circularity; §9.8 disjoint split enforced in §11).

## 9.12 Reviewer #2 obligations (recorded)
Benign partition is the sharpest attack surface and must contain real hard negatives, described explicitly in the paper. Corpus soundness (O2) is the project's critical path; derivation/eval split (O1) and label integrity are load-bearing. Small-n reported transparently, generalization scoped (§8.10). Public data confined to cross-check. No scope creep; T1068 stays excluded.

---

# Section 10 — Experimental Setup
*(LOCKED v1.0)*

## 10.1 Evaluation protocol *(LOCKED)*
**k-fold cross-validation** with **stratified folds** (by technique and attack/benign), **chain-level partitioning** (folds split lineage chains — the scored unit — never an individual chain's events, enforcing O1), a **fixed random seed**, and **reproducible, recorded fold assignments**. This is the official evaluation protocol. Chosen over single hold-out because it wins on fairness, statistical validity, small-corpus suitability, and publication quality, ties on reproducibility, and loses only marginally on implementation simplicity (a low, one-time cost, no new dependency). **Shipped-vs-evaluated distinction (binding §11 obligation):** k-fold produces k per-fold evidence models used to *estimate* generalization; the final deliverable CPES model is derived on the full corpus. The paper must report k-fold estimates and separately state the shipped model is full-corpus-derived — reporting the shipped model's numbers as if cross-validated would be circular.

## 10.2 Experimental environment
Frozen all-in-one Windows 11 VM (§6.8, §7.2), `sysmon-config-v1.xml`, Elastic 9.4.3, CPES engine (Python 3.12 / pandas 2.2 / NumPy 1.26), snapshot-versioned. Every experiment records VM build, config version, corpus version (`cpes-telemetry-corpus-v1`), and code commit (NFR-01).

## 10.3 Replay mechanics *(dependency #5, C13)*
Evaluation replays the frozen `cpes-replay-v1` corpus through the identical C5-downstream pipeline (C6–C10) via the Replay Driver (C13) — same code path, frozen deterministic input (§2.5, NFR-04). Original event timestamps preserved so temporal signals and latency measurement behave as live. Determinism verified by re-running a fold and confirming bit-identical detections/scores.

## 10.4 Sliding-window tuning *(dependency #6 — procedure; values are §11 results)*
Window form fixed (§8.5); parameters (size, overlap, eviction) tuned **only on derivation data within each fold** (O1). Procedure: sweep a pre-declared candidate set, select per a pre-declared derivation-set objective, apply to that fold's evaluation. Guardrails: candidate set and selection rule declared before seeing evaluation data; tuning inside folds prevents evaluation leakage. Chosen values are results, reported in §11, not fixed here.

## 10.5 Single-event baseline *(O3 — mandatory, fair)*
A **single-event integrity-transition rule** modeled on the real Splunk/Elastic-style analytics from §4 (flags a chain on an individual qualifying event — e.g., higher-integrity child than parent, or system-integrity process with non-system parent — without cross-event correlation). Runs over the **identical windowed input** as CPES (C12 at C8 output, §6.7) for like-for-like comparison. Literature-grounded so it is recognizably fair, not a strawman. Not a contribution — its sole role is to quantify what CPES's context adds.

## 10.6 Optional second-baseline go/no-go gate *(dependency #3 — mechanism locked, decision deferred)*
A second baseline is implemented **only if** it can be built and validated within a bounded pre-agreed time budget using the existing corpus and stack **without** significant additional complexity or project delay. Approach-C (interpretable learned model reusing the §8.6 additive form, adding only scikit-learn → then entering §7.10) is preferred over a graph baseline. If the gate is not met, the single-event baseline alone satisfies the core claim (§2.2) and the second baseline becomes documented future work. The go/no-go decision is made and recorded at implementation time — not pre-committed.

## 10.7 Experiment matrix
Per fold: (1) derive evidence terms + tune window on derivation data; (2) run CPES over evaluation data → detections/scores/explanations; (3) run single-event baseline over identical evaluation data; (4) if gate met, run second baseline likewise; (5) export all via C11 (FR-14). Aggregate across folds. Latency/CPU/memory observations are *captured* under replay here but *defined and interpreted* in §11.

## 10.8 Controlled conditions & reproducibility
Frozen VM, deterministic replay, seeded fold assignment, versioned corpus, recorded commit; full matrix scripted end-to-end for third-party reproduction (NFR-01). Deviations (e.g., R-01 incomplete technique) logged and carried into §11 interpretation.

## 10.9 Boundary discipline
Section 10 defines how experiments are conducted and how parameters are chosen. Metrics, final threshold values, and result interpretation are §11. Window values, detection-threshold values, and metric definitions are explicitly deferred to §11.

## 10.10 Reviewer #2 obligations (recorded)
k-fold + chain-level stratified folds answer the small-corpus statistical-thinness critique and enforce O1 structurally. Shipped-vs-evaluated distinction must be stated (binding §11 obligation) to avoid circularity. Baseline grounded in real analytics (O3) held. Window tuning confined to folds on derivation data with pre-declared candidates prevents tuning-to-the-test. Second-baseline gate prevents scope explosion (R-06). Boundary held — no metric definitions leaked. No scope creep.

---

# Section 11 — Evaluation
*(LOCKED v1.0)*

## 11.1 Research claim *(stated throughout Evaluation)*
**"CPES reduces false positives while maintaining comparable recall relative to a literature-grounded single-event baseline."** Every metric earns its place by how directly it substantiates this comparative claim. False Positive Rate, Precision, and Recall are therefore primary; Accuracy is reported only for completeness and comparability with prior work.

## 11.2 Metric hierarchy *(LOCKED)*
**Primary:** False Positive Rate (headline), Precision, Recall (guardrail — proves FPR reduction was not bought by missing attacks; always reported jointly with FPR). **Secondary:** F1 Score, Detection Latency (measured, not optimized, NFR-08). **Supporting:** Accuracy (completeness/comparability only, explicitly de-emphasized), CPU Usage, Memory Usage, Throughput, Explainability. Accuracy is demoted because on a benign-heavy corpus it is dominated by true negatives and can look high while the detector is useless; it is always shown next to FPR/Precision/Recall.

## 11.3 Chain-level counting
All counting at lineage-chain granularity (CON-11) using §9.5 ground truth, per detector at its operating threshold. **TP:** attack chain, flagged. **FP:** benign chain, flagged. **TN:** benign chain, not flagged. **FN:** attack chain, not flagged.

```
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
FPR       = FP / (FP + TN)
F1        = 2 · Precision · Recall / (Precision + Recall)
Accuracy  = (TP + TN) / (TP + TN + FP + FN)
```

Truncated/incomplete chains (§8.8) are labeled, decided, and counted normally, with incomplete status tracked so §11.10 reports results with and without them.

## 11.4 Detection-threshold selection *(O1-preserving)*
The continuous CPES Score is thresholded to a decision (FR-07). The threshold is selected **only on derivation data within each fold**, per a pre-declared selection rule declared before evaluation, then applied unchanged to that fold's evaluation set — a derivation-set artifact like evidence terms and window parameters; evaluation never informs it. The fixed baseline (§10.5) has no tunable threshold. Threshold-independent characterization (§11.5) is computed on evaluation data to show score separability without selecting an operating point from it, so it does not violate O1. Threshold numeric value is a result, not fixed here.

## 11.5 k-fold aggregation & reporting
Per §10.1, each fold yields a full metric set on held-out chains. Report mean + standard deviation/variance across folds (spread as important as mean on a small corpus); confidence intervals where appropriate, honestly caveated for small k — if CIs would be uninformative, report per-fold values directly rather than implying false precision. Include a threshold-independent precision–recall characterization. Aggregation is over folds, not pooled predictions, preserving per-fold derive/evaluate independence (O1).

## 11.6 Shipped-vs-evaluated reporting *(binding, from §10.1)*
All headline numbers are cross-validated estimates. The final full-corpus shipped model's own numbers are never reported as performance (circular). Stated explicitly wherever results appear.

## 11.7 CPES vs. single-event baseline *(headline comparison, O3)*
Both detectors run over identical windowed evaluation input (C12 at C8 output) in every fold. Reported as **paired per-fold differences** (CPES − baseline per fold) to control fold variance and show consistency. Primary statement: **FPR reduction at comparable recall** — CPES vs. baseline FPR *and* recall always reported together; reporting FPR improvement while hiding a recall drop is prohibited. A paired statistical check across folds supports consistency, caveated for small k, presented as evidence, not overclaimed significance.

## 11.8 Latency, CPU, memory, throughput
Measured under deterministic replay (§10.3, NFR-08). Detection Latency: elapsed processing time from the replayed pattern-completing event to the crossing detection (§3.7), reported as a distribution (tails matter). CPU/Memory: engine consumption during corpus replay under fixed VM conditions, method stated. Throughput: events/chains per unit time. All measured not optimized, compared to the baseline's profile for context; repeatable via replay (NFR-04) but absolute figures are VM-dependent and reported as such.

## 11.9 Explainability evaluation *(measurable, LOCKED)*
Because Approach B's explanation is the signed score decomposition (§8.7): **Faithfulness** — verify contributing signals sum to the CPES Score for every detection (exact check; 100% by construction; a mismatch is a bug). **Attribution Alignment** — for attack chains, verify the top contributing signals match the technique's known exercised signals per the §9.2 coverage matrix; report the alignment rate. **Chain-element Localization** — verify the explanation points to the specific responsible chain elements (FR-08), checked against known execution. Reported as three concrete measures. **Recorded caveat (retained):** attribution alignment is evaluated against a *design-informed* reference (the coverage matrix), not an independent oracle; the paper must state this so the claim is not overstated.

## 11.10 Reviewer #2 obligations *(binding honesty)*
Class imbalance: Accuracy demoted, FPR/Precision/Recall lead, imbalance ratio reported. Shipped-vs-evaluated: only cross-validated numbers reported as performance. Small corpus: sizes/per-technique counts, fold spread, honest CIs; generalization scoped to six techniques on one endpoint (§8.10). FPR/recall coupling: always joint (§11.7). Statistical validity: fold aggregation with spread, paired comparison, significance caveated for small k. Baseline fairness (O3): identical input, literature-grounded, paired. Incomplete-chain transparency: results with and without incomplete chains (§11.3).

## 11.11 Boundary discipline
Section 11 defines what is measured, how counted, how honestly reported — not experimental procedure (§10) or methodology (§8). Numeric results are produced by running the §10 matrix; §11 defines their meaning and reporting form, not their values.

## 11.12 Reviewer #2 resolutions (recorded)
Comparative-first hierarchy defends the actual claim and avoids the accuracy-on-imbalanced-data trap. Explainability made measurable (faithfulness + attribution-alignment + localization). Threshold circularity prevented (derivation-only selection; sweep curves for characterization only). FPR/recall gaming prevented (joint reporting). Attribution-alignment reference caveated as design-informed. Small-k CIs must not imply false precision. No scope creep; O1–O3 carried unchanged.

---

# Section 12 — Implementation Roadmap
*(LOCKED v1.0)*

## 12.1 Philosophy
Sequential, timeline-agnostic milestones honoring the project's build discipline: complete one module before the next; every milestone has explicit prerequisites, deliverables, completion criteria, and named dependents. Order is dependencies-first, risk-second, deliberately risk-front-loaded. Planning only — no code.

## 12.2 Milestone sequence

**M0 — Environment.** *Prereqs:* none. *Deliverables:* frozen Windows 11 VM (build recorded, ASM-02), Elastic 9.4.3 running, Git/GitHub repo + `cpes` skeleton (§3.9), pinned deps (§7.10). *Completion:* end-to-end test event ingested; snapshot versioned. *Dependents:* all. **MANUAL:** VM/Elastic/Sysmon-prep. **CLAUDE:** scaffold, dep spec, templates, docs.

**M1 — Sysmon config.** *Prereqs:* M0. *Deliverables:* `sysmon-config-v1.xml` frozen to §9.6 EID set, version-controlled. *Completion:* deployed; each targeted EID confirmed emitting. *Dependents:* M2, M3. **CLAUDE:** author config, EID→technique justification. **MANUAL:** deploy, confirm operational.

**M2 — Corpus generation.** ⚠️ *Risk-critical (O2).* *Prereqs:* M1. *Deliverables:* `cpes-telemetry-corpus-v1` — attack partition (six techniques, bracketed/labeled §9.3/§9.5) + mandatory hard-negative benign partition (§9.4). *Completion:* all six executed and captured; all hard-negative benign categories present; versioned/frozen. *Dependents:* M3, M8, M9, M10. **MANUAL:** run Atomics, generate benign activity, snapshot. **CLAUDE:** bracketing/segmentation/labeling scaffolding, docs.

**M3 — Telemetry validation.** ⚠️ *Risk gate (R-01, O2).* *Prereqs:* M2. *Deliverables:* per-technique coverage report; label-integrity spot-audit (R-10); benign hard-negative review (R-09). *Completion:* every technique passes coverage or is flagged/handled (§8.8); benign partition confirmed to contain real hard negatives. *Dependents:* M4, M8. **CLAUDE:** validation/audit scripts, coverage report. **MANUAL:** sign-off on hard-negative adequacy. **Gate DG-1 here.**

**M4 — Lineage reconstruction (C6).** ⚠️ *Risk-critical (§8.8).* *Prereqs:* M3. *Deliverables:* ProcessGUID-keyed chains handling PID reuse, truncated, incomplete, fragmented cases (§8.8); dict tree, no NetworkX. *Completion:* chains correct on corpus; four hard cases handled; spot-checked vs. known executions. *Dependents:* M5, M7. **CLAUDE:** module + correctness tests.

**M5 — Context + windowing (C7, C8).** *Prereqs:* M4. *Deliverables:* context derivation for active §8.4 categories (§9.2 matrix); bounded window/event-group assembly (§8.5, form). *Completion:* each active signal extractable; windowed groups deterministic. *Dependents:* M6, M10. **CLAUDE:** modules + tests.

**M6 — CPES scorer + explainability (C9, C10).** *Prereqs:* M5. *Deliverables:* additive signed-evidence scoring (§8.6, form only), per-signal contribution record, detection + explanation (§8.7, FR-08). *Completion:* chain-level score with faithful decomposition (faithfulness passes by construction, §11.9); explanation localizes chain elements. *Dependents:* M8. **CLAUDE:** scorer + explanation modules, faithfulness test.

**M7 — Retrieval adapter + replay (C5, C13).** *Prereqs:* M4. *Deliverables:* sole Elastic-coupled adapter (quarantined) → backend-neutral stream; Replay Driver feeding `cpes-replay-v1` through identical downstream path (§10.3). *Completion:* live and replay produce identical downstream input; determinism verified (NFR-04). *Dependents:* M9. **CLAUDE:** modules + determinism test. *Parallel, off critical path.*

**M8 — Evidence derivation (k-fold, O1).** *Prereqs:* M3, M6. *Deliverables:* per-fold derivation of evidence terms, bins, window params, threshold — strictly on derivation data within each fold (O1, §10.4, §11.4); stratified chain-level folds, fixed seed, recorded assignments (§10.1). *Completion:* k evidence models, no leakage, reproducible folds. *Dependents:* M9. **CLAUDE:** derivation + fold modules, O1-leakage test.

**M9 — Evaluation.** *Prereqs:* M6, M7, M8, M10. *Deliverables:* full §10.7 matrix under replay; metric hierarchy (§11.2) at chain level; CPES-vs-baseline paired per-fold (§11.7); explainability measures (§11.9); latency/CPU/memory/throughput (§11.8); k-fold aggregation with honest spread (§11.5); shipped-vs-evaluated separation (§11.6). *Completion:* research claim (§11.1) evaluated, all obligations honored (§11.10). *Dependents:* §13. **CLAUDE:** harness, aggregation, reporting. **MANUAL:** honesty-obligation review. **Gate DG-2 after core.**

**M10 — Single-event baseline (C12).** *Mandatory (O3).* *Prereqs:* M2, M5 (windowed-input contract, attaches at C8 output). *Deliverables:* literature-grounded single-event integrity-transition detector (§10.5), identical windowed input. *Completion:* runs on corpus, chain-level decisions comparable to CPES. *Dependents:* M9. **CLAUDE:** baseline module, fairness docs. *Parallel.*

**M11 — Optional second baseline.** *Gated (dep. #3, §10.6).* *Prereqs:* M9 core, DG-2 passed. *Deliverables:* Approach-C learned baseline (adds scikit-learn to §7.10 if built) or documented deferral. *Completion:* built+evaluated within budget, or formally deferred. *Dependents:* none (strengthens M9). **MANUAL:** DG-2 decision. **CLAUDE:** module if built.

## 12.3 Critical path
**M0 → M1 → M2 → M3 → M4 → M5 → M6 → M8 → M9.** M7 branches off M4, rejoins at M9 (parallel, off path). M10 branches off M2/M5, rejoins at M9. M11 gated off M9. Corpus (M2) and validation (M3) sit early on the critical path by design so the highest risk surfaces with maximum recovery time.

## 12.4 Dependency graph
`M0→M1→M2→M3→M4→{M5→M6→M8, M7}; M5→M10; {M6,M7,M8,M10}→M9; M9→M11(gated).` Every arrow is a hard prerequisite; no milestone starts before predecessors' completion criteria are met.

## 12.5 Risk checkpoints
RC-1 (M3): coverage + label integrity + hard-negative adequacy (R-01/09/10, O2) — the key early gate. RC-2 (M4): lineage correctness on the four hard cases (§8.8); unreliable technique flagged before the scorer depends on it. RC-3 (M8): O1 leakage check — no chain in both derivation and evaluation of any fold. RC-4 (M9): honest-reporting obligations (§11.10) reviewed before results are final.

## 12.6 Decision gates
**DG-1 (M3) — WMI contingency:** if T1546.003 telemetry/corpus proves disproportionately costly, drop it here → remove EIDs 19/20/21 → `sysmon-config-v2.xml`; re-verify §9.2 matrix (registry and image/module survive at ≥2 techniques); scope reduces to five. **DG-2 (after M9 core) — second baseline go/no-go:** implement M11 only if it fits the bounded budget on existing corpus/stack without significant added complexity; else defer to future work. Both decisions recorded at decision time.

## 12.7 Recommended order (LOCKED)
Environment → Sysmon → Corpus → Telemetry Validation → Lineage Reconstruction → Context Builder → CPES Scorer → Evidence Derivation → Evaluation, with Retrieval Adapter/Replay (M7) and Single-Event Baseline (M10) implemented in parallel as defined. The scorer is never built before the corpus is validated — that inversion is forbidden.

## 12.8 Reviewer #2 resolutions (recorded)
Risk-front-loading places O2 at M2/M3 early on the critical path. M7 parallelism keeps replay off the critical path without violating dependencies. M8 O1 discipline enforced at RC-3 before M9 trusts any number. M10 attaches at C8 output (prereq M5, not M2 alone). M3 hard-negative sign-off is MANUAL human judgment, recorded so it isn't skipped. No scope creep, no re-opened locks; every milestone maps to C1–C14 and the six techniques; O1–O3 and shipped-vs-evaluated enforced at named checkpoints.

---

# Section 13 — Paper Outline
*(LOCKED v1.0)*

## 13.1 Target venue & framing constraint
IEEE/Scopus conference (§1.5). **Governing framing rule for all sections below (from §4, §8.11):** novelty is located in the privilege-escalation-specific runtime context model, the chain-level unit, interpretability-by-construction, benchmarked FP-reduction, and the reproducible corpus — **never** in the additive-evidence math, which is presented as a deliberate interpretability choice, not an innovation. Overselling the aggregation is the primary rejection risk and every framing annotation below enforces avoiding it.

## 13.2 Paper structure *(pointers to locked Bible sections — no prose)*

**Title** — from §1.1 (CPES: A Context-Aware Multi-Event Correlation Methodology for Runtime Privilege Escalation Detection on Windows Endpoints).

**Abstract** — *[to be written on request only]* — structure: problem (§1.4) → gap (§4.2) → CPES one-line (§8.1) → primary result FPR reduction at comparable recall (§11.1) → reproducibility + corpus (§9). Framing rule applies.

**Keywords** — sourced from §3 terminology: privilege escalation, Windows endpoint detection, Sysmon telemetry, process-lineage chain, context-aware detection, interpretable scoring, MITRE ATT&CK, reproducibility.

**I. Introduction** — problem (§1.3/§1.4), motivation (§1.5), single-endpoint scope framed as a practicality feature (§4.7 point 6), contribution statement (§1.6 v1.1 + secondary corpus contribution §1.7), CPES-detects-only-not-attributes scope (CON-12). Framing rule applies.

**II. Related Work** — three strata (§4.1): commercial (Splunk/Elastic/Log360), provenance-graph HIDS (KAIROS/MAGIC/FLASH/NodLink), scoring/correlation. Primary anchor Bhardwaj 2025 (§4.5 threat #1); motivation anchor Virkud 2024 (technique-label ambiguity, §4.7 point 5). Must explicitly distinguish CPES from each stratum (§4.2).

**III. Research Gap** — the four-way gap (§4.2, §4.4 table): PrivEsc-specific + automated chain-level scoring + interpretable + benchmarked-vs-single-event — the unoccupied intersection.

**IV. Proposed Methodology (CPES)** — purpose (§8.1), detection philosophy (§8.2), runtime context model (§8.4), correlation model (§8.5), additive signed-evidence scoring (§8.6, form), explainability (§8.7), correctness obligations (§8.8). Framing rule central here.

**V. System Architecture** — two-zone design and the C5 backend-independence invariant (§6.1/§6.5), components (§6.3), data flow (§6.4), all-in-one deployment (§6.8), trust boundaries (§6.9). Figure: `fig-06-infrastructure-contribution-boundary`.

**VI. Implementation** — technology stack (§7, version table §7.10), lineage reconstruction via ProcessGUID (§8.8), interpretability-preserving design (CON-08), no-black-box/no-unnecessary-deps philosophy (§7.0). *Structure/roadmap from §12; no code.*

**VII. Experimental Setup** — k-fold stratified chain-level protocol (§10.1), frozen VM + replay (§10.2/§10.3), window tuning in-fold (§10.4), single-event baseline definition (§10.5), second-baseline gate (§10.6), experiment matrix (§10.7).

**VIII. Evaluation** — research claim stated (§11.1), metric hierarchy (§11.2), chain-level counting (§11.3), threshold selection O1-preserving (§11.4), aggregation (§11.5), CPES-vs-baseline paired comparison (§11.7), resource/latency (§11.8), explainability measures (§11.9).

**IX. Results & Discussion** — *[values produced by M9]* — primary FPR/Precision/Recall results and paired baseline comparison, secondary F1/latency, supporting accuracy (de-emphasized, §11.2)/resources/explainability, all with honest spread (§11.5) and shipped-vs-evaluated separation (§11.6). Honesty obligations §11.10.

**X. Limitations** — directly from §8.10: no technique attribution, no zero-day generality, no adversarial robustness, single-endpoint, independence assumption, small corpus. Plus corpus-representativeness (§9.10) and design-informed explainability reference (§11.9 caveat).

**XI. Future Work** — deferred items: automatic ATT&CK technique attribution (CON-12), second baseline if gated out (§10.6/DG-2), streaming productionization, multi-host, Approach-C learned scoring, additional techniques.

**XII. Conclusion** — restate claim (§11.1) and contribution (§1.6) within evidenced bounds; no overclaim.

**References** — §4.9 sources + technology/tool citations; formalized in a reference manager, verified against publisher of record before submission (§4.9).

## 13.3 Claim → Evidence Traceability Matrix
Every paper claim mapped to its supporting Bible section, validating experiment (M-milestone), measuring metric, and supporting figure/table. Figure/table IDs follow §3.9 naming; those marked *[from M9]* are populated by evaluation results.

| # | Claim | Bible section | Validating experiment | Measuring metric | Figure/Table |
|---|---|---|---|---|---|
| C1 | Single-event PrivEsc detection produces high false positives on hard-negative benign activity | §1.4, §4.1, §9.4 | M9 (baseline on hard-negative benign) | Baseline FPR, Precision | tbl-fpr-comparison *[M9]* |
| C2 | CPES reduces false positives vs. the single-event baseline | §1.6, §8.1, §11.1 | M9 (paired CPES-vs-baseline) | FPR (primary, headline) | tbl-fpr-comparison, fig-pr-curve *[M9]* |
| C3 | The FPR reduction does not sacrifice recall (comparable recall) | §11.1, §11.7 | M9 (joint FPR+Recall reporting) | Recall (guardrail primary) | tbl-primary-metrics *[M9]* |
| C4 | CPES improves precision over the baseline | §11.2 | M9 | Precision (primary) | tbl-primary-metrics *[M9]* |
| C5 | CPES detection is interpretable — every detection decomposes into contributing signals | §8.7, NFR-03, FR-08 | M6, M9 | Faithfulness (100% by construction) | tbl-explainability *[M9]* |
| C6 | CPES's contributing signals align with the techniques' known exercised signals | §9.2, §11.9 | M9 | Attribution-alignment rate | tbl-explainability, tbl-technique-coverage-matrix |
| C7 | CPES localizes the responsible chain elements | §8.7, FR-08, §11.9 | M9 | Chain-element localization | tbl-explainability *[M9]* |
| C8 | Lineage reconstruction is robust to PID reuse, missing parents, incomplete/broken chains | §8.8 | M4 (RC-2) | Reconstruction correctness (spot-check) | fig-lineage-cases |
| C9 | The contribution is backend-independent (only C5 is Elastic-coupled) | §3.8, §6.5, NFR-02 | M7 (adapter isolation) | Architectural invariant (design demonstration) | fig-06-infrastructure-contribution-boundary |
| C10 | Results are reproducible and repeatable (deterministic replay) | §1.8, NFR-01, NFR-04, §10.3 | M7 (determinism check), M9 | Replay determinism (bit-identical re-run) | tbl-version-table (§7.10) |
| C11 | Evaluation is free of derivation/evaluation circularity | O1, §9.8, §10.1, §11.4 | M8 (RC-3 leakage check) | O1 leakage check (pass/fail) | fig-kfold-protocol |
| C12 | The benign corpus contains genuine hard negatives | §9.4 (binding), R-09 | M3 (RC-1 sign-off) | Hard-negative coverage review | tbl-corpus-composition |
| C13 | The PrivEsc Sysmon corpus is a reproducible secondary contribution | §1.7, §9.9 | M2, M3 | Corpus versioning + documentation completeness | tbl-corpus-composition |
| C14 | Every CPES context category is exercised by ≥1 selected technique | §9.2 | M3 | Coverage matrix | tbl-technique-coverage-matrix |
| C15 | CPES is practical on a single endpoint (measured resource cost) | §11.8, NFR-08/NFR-10 | M9 | Latency, CPU, Memory, Throughput (supporting) | tbl-resource-metrics *[M9]* |
| C16 | Reported performance is the cross-validated estimate, not the shipped model | §10.1, §11.6 | M9 | Shipped-vs-evaluated separation (reporting) | (stated in Results text) |

**Traceability completeness note:** every primary and secondary metric in §11.2 maps to at least one claim; every claim maps to a locked section, a validating milestone, and an evidence artifact. Claims C2–C4 (the core FP-reduction-at-comparable-recall claim) are backed by the headline paired comparison; C5–C7 substantiate interpretability; C11/C16 encode the anti-circularity and honesty obligations directly as auditable claims. No claim in the outline lacks objective backing.

## 13.4 Reviewer #2 review (final, outline-level)
Structure maps cleanly to a standard IEEE/Scopus layout with no orphaned section. The framing rule (§13.1) is embedded at every framing-sensitive section (Abstract, I, II, IV) to pre-empt the primary rejection risk. Limitations (§X) is honest by construction — sourced directly from §8.10 rather than softened. The traceability matrix ensures no claim outruns its evidence, which is the specific failure mode that sinks under-supported detection papers. No new scope, techniques, datasets, metrics, architecture, or CPES changes introduced — the outline is purely a mapping of locked content. Two carried cautions for the eventual writing phase: (1) Related Work must confront Bhardwaj 2025 head-on, not bury it; (2) Results must state the shipped-vs-evaluated distinction wherever numbers appear (C16). Both are recorded, not deferred silently.

---

# Document Status

**This Project Bible is FROZEN at v1.0.**

All thirteen sections are locked and constitute the single source of truth for the CPES project. All implementation must conform to this Bible exactly.

**Frozen scope summary:**

```
✓ Project Bible Complete      — Sections 1–13 locked
✓ Scope Frozen                — §1, §2 (six techniques, single Windows endpoint, detection-only)
✓ Architecture Frozen         — §6 (two-zone, C1–C14, C5 backend-independence invariant)
✓ Technology Stack Frozen     — §7 (version table §7.10; no scikit-learn, no NetworkX)
✓ CPES Frozen                 — §8 (additive signed-evidence, interpretable, ProcessGUID lineage)
✓ Dataset Plan Frozen         — §9 (PrivEsc Sysmon corpus, sysmon-config-v1.xml, hard negatives)
✓ Evaluation Plan Frozen      — §10, §11 (k-fold, FPR-primary hierarchy, O1-preserving)
✓ Roadmap Frozen              — §12 (risk-front-loaded M0→M9, M7/M10 parallel, DG-1/DG-2)
```

**Standing state carried into the build:**

- *One open dependency:* #3 optional second baseline — gated at DG-2, decided at implementation time.
- *Four binding obligations:* O1 (no circularity, RC-3), O2 (corpus soundness, RC-1), O3 (fair baseline, M10), shipped-vs-evaluated reporting (RC-4).
- *One contingency:* T1546.003 (WMI) drop at DG-1 if telemetry/corpus cost is disproportionate.

**Change-control rule:** Any future request that conflicts with a frozen decision triggers a conflict flag before proceeding. Changes to a frozen section require an explicit unlock, recorded under the §3.11 maintenance rule. No section may be redesigned, rewritten, summarized, or optimized without explicit unlock.

*End of Project Bible v1.0 (Frozen).*
