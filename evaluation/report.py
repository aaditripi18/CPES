"""Generate docs/RESULTS.md from results/*.json. Every number in that file comes from here.

    python -m evaluation.report
"""

from __future__ import annotations

import json

from .data import ROOT

RESULTS = ROOT / "results"
OUT = ROOT / "docs" / "RESULTS.md"
NAMES = {
    "cpes": "CPES",
    "single_event_research": "Single-event (research rule)",
    "single_event_package": "Single-event (package C12, windowed)",
    "ioc_signature_research": "IOC / signature (research rule)",
    "cpes_research_signals": "CPES (research signals)",
    "cpes_package_with_evidence": "CPES (package engine, evidence channels)",
}


def _load(name: str) -> dict | None:
    path = RESULTS / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _cv_table(record: dict) -> list[str]:
    r = record["result"]
    lines = [
        f"Units {r['units']:,} ({r['attack']} attack, {r['benign']:,} benign) · {r['folds']} folds · folds skipped (no attack): {len(r['skipped_folds_without_attack'])} · execution `{record['id']}`, code `{record['code_sha256'][:12]}`",
        "",
        "| Detector | P (mean ± sd) | R (mean ± sd) | F1 (mean ± sd) | Pooled TP / FP / FN | Pooled F1 | Recall by technique |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, v in r["detectors"].items():
        m, c = v["fold_mean"], v["pooled"]
        techniques = ", ".join(f"{t} {x}" for t, x in v["recall_by_technique"].items())
        lines.append(f"| {NAMES.get(name, name)} | {m['precision']:.3f} ± {m['precision_std']:.3f} | {m['recall']:.3f} ± {m['recall_std']:.3f} | **{m['f1']:.3f}** ± {m['f1_std']:.3f} | {c['tp']} / {c['fp']} / {c['fn']} | {c['f1']:.3f} | {techniques} |")
    return lines


CATEGORY_NAMES = {
    "uac_listed_lolbin": "UAC via a listed auto-elevating binary",
    "uac_other_method": "UAC via other methods (UACME etc.)",
    "token_impersonation": "Token impersonation (Potato family, PrintSpoofer, getsystem, RogueWinRM)",
    "service_abuse": "Service abuse (unquoted path, PsExec)",
    "other_exploit": "Other exploits (CVE, spooler, registry, handle inheritance)",
    "not_applicable_no_sysmon": "No Sysmon events (Security/System only) — not applicable",
}
DETECTOR_NAMES = {
    "cpes_research_signals": "CPES (research signals)",
    "cpes_package": "CPES (package engine)",
    "generic_unexplained_gain_package": "Generic 'unexplained privilege gain' (package, unweighted)",
    "ioc_signature_research": "IOC / signature rule",
    "single_event_research": "Single-event integrity rule",
}


def _external_section() -> list[str]:
    record = _load("ext-evtx-privesc")
    out = ["", "## 6. External generalisation — EVTX-ATTACK-SAMPLES (never seen by CPES)", "",
           "Shipped package engine with frozen weights from the lab corpus (held out). Unit = published sample file; every file is an attack, so precision is not estimated. Pre-registered in [design/external-and-evasion-evaluation.md](design/external-and-evasion-evaluation.md).", ""]
    if not record:
        return out + ["_Not run yet._"]
    r = record["result"]
    out += [f"{r['dataset']} · execution `{record['id']}`", "",
            "| Category | Files | CPES detected | Generic test fired | Single-event rule fired | CPES or generic |", "|---|---|---|---|---|---|"]
    for key, row in r["summary_by_category"].items():
        out.append(f"| {CATEGORY_NAMES.get(key, key)} | {row['files']} | {row['cpes_detected']} | {row['generic_fired']} | {row['single_event_fired']} | {row['cpes_or_generic']} |")
    detected = [f for f in r["files"] if f.get("outcome") == "detected"]
    out += ["", "Every CPES alert and the process it is anchored on:", ""]
    out += [f"- `{f['file']}` — " + ", ".join(f["cpes_anchors"]) for f in detected]
    skipped = sum(f.get("evidence", {}).get("skipped", {}).get("pipe_missing_field", 0) for f in r["files"])
    out += ["", f"Pipe evidence records skipped because the capture has no `User` field on EID 17/18: {skipped}. The token signal therefore cannot fire on this dataset."]
    return out


def _evasion_section() -> list[str]:
    record = _load("evasion-v3")
    out = ["", "## 7. Evasion robustness — corpus-v3 with attacker-controlled changes", "",
           "Each variant rewrites only attack-process records; labels unchanged. Cells: attack units detected (of 87) and recall for the technique the variant targets.", ""]
    if not record:
        return out + ["_Not run yet._"]
    variants = record["result"]["variants"]
    target = {"V0": None, "V1": "T1055.001", "V2": "T1543.003", "V3": "T1548.002", "V4": "T1134.001", "V5": None}
    detectors = list(next(iter(variants.values()))["detectors"])
    out += ["| Variant | " + " | ".join(DETECTOR_NAMES.get(d, d) for d in detectors) + " |", "|---|" + "---|" * len(detectors)]
    for name, body in variants.items():
        cells = []
        for d in detectors:
            s = body["detectors"][d]
            technique = target[name]
            cells.append(s["attack_detected"] + (f" · {technique} {s['recall_by_technique'][technique]}" if technique else ""))
        out.append(f"| **{name}** {body['transform']} | " + " | ".join(cells) + " |")
    out += ["", "Benign units flagged are unchanged across variants (benign records are never modified)."]
    return out


def _streaming_section() -> list[str]:
    record = _load("stream-replay-v3")
    out = ["", "## 8. Live scoring — corpus-v3 replayed as a stream", "",
           "`cpes.streaming.StreamingScorer` scores each window once, when the event-time watermark passes its end, using only what has arrived. Package engine with evidence channels, frozen weights.", ""]
    if not record:
        return out + ["_Not run yet._"]
    r = record["result"]
    a, t, c, s = r["agreement"], r["time_to_alert_seconds"], r["cost"], r["settings"]
    out += [
        f"Replay of {s['events']:,} events · window {s['span_seconds']:.0f} s / advance {s['advance_seconds']:.0f} s · watermark tick {s['tick_seconds']:.0f} s · execution `{record['id']}`",
        "",
        "| Measure | Value |",
        "|---|---|",
        f"| Alerts raised live (window, signal, anchored process) | {a['live']} |",
        f"| Alerts in the batch (hindsight) result | {a['batch']} |",
        f"| Identical in both | {a['both']} |",
        f"| Live-only / batch-only | {len(a['live_only'])} / {len(a['batch_only'])} |",
        f"| Attack processes alerted live | {t['attack_units_alerted']} |",
        f"| Time to alert, median / p95 / max (event time) | {t['median']:.0f} s / {t['p95']:.0f} s / {t['max']:.0f} s |",
        f"| Scoring cost per tick, median / max (wall time) | {c['median_tick_seconds'] * 1000:.1f} ms / {c['max_tick_seconds'] * 1000:.0f} ms over {c['ticks']} ticks |",
        "",
        f"Chain IDs differ between live and batch for {a['chain_keyed_counts']['live_windows'] - a['chain_keyed_counts']['same_chain_id']} live window(s): a chain's root changes when an earlier ancestor's events arrive, so alerts are compared on what they point at, not on chain names. {t['note']}",
    ]
    return out


def _sigma_section() -> list[str]:
    lab, ext, eva = _load("sigma-lab-v3"), _load("sigma-ext-evtx"), _load("sigma-evasion")
    out = ["", "## 9. CPES vs SigmaHQ rules (release r2026-07-01)", "",
           "Every Sysmon-category Windows rule in the *core* (curated) and *all* packs, evaluated by `evaluation/sigma.py` (unit-tested Sigma semantics; unsupported features skipped and counted). Pre-registered in [design/external-and-evasion-evaluation.md](design/external-and-evasion-evaluation.md) Part C.", ""]
    if lab:
        r = lab["result"]
        ref = r.get("cpes_reference", {})
        out += ["### 9.1 Lab corpus — run level (labels from the execution ledger only)", "",
                "| Detector | Rules evaluated | Runs, technique-consistent | Alerts outside any run | Processes alerted outside runs |", "|---|---|---|---|---|"]
        for key, label in (("cpes_research_signals", "CPES (research signals)"), ("cpes_package_with_evidence", "CPES (package engine)")):
            if key in ref:
                out.append(f"| {label} | 4 signals | {ref[key]['modelled_runs_detected_consistent']} | — | {ref[key]['false_alarm_processes']} |")
        for pack, body in r["packs"].items():
            for level in ("high_or_critical", "any_level"):
                rl = body[level]["run_level"]
                out.append(f"| Sigma {pack}, {level.replace('_', ' ')} | {body['rules_evaluated']} | {rl['runs_consistent']} | {rl['outside_runs']['alerts']} | {rl['outside_runs']['processes']} |")
        core = r["packs"]["core"]["high_or_critical"]
        out += ["", f"Rules that test registry `Details` are excluded on this corpus because Winlogbeat re-encodes that field ({r['packs']['core']['rules_dropped_details']} core, {r['packs']['all']['rules_dropped_details']} all).",
                "", "Which process gets flagged (attack *outcome* processes, i.e. the process that ended up elevated):", "",
                "| Detector | Injection | Token | Service binary | UAC elevated process |", "|---|---|---|---|---|"]
        out.append("| Sigma core, high+ | " + " | ".join(core["unit_level"]["by_technique"].get(t, "—") for t in ("T1055.001", "T1134", "T1543.003", "T1548.002")) + " |")
        rg = _load("research-grouped")
        if rg:
            rt = rg["result"]["detectors"]["cpes"]["recall_by_technique"]
            out.append("| CPES (research signals) | " + " | ".join(rt.get(t, "—") for t in ("T1055.001", "T1134.001", "T1543.003", "T1548.002")) + " |")
        out += ["", "Sigma mostly alerts on the actor (`reg.exe` writing the hijack key, `sc.exe` creating the service); CPES attributes the alert to the process that gained privilege and states how. The CPES row is in-sample against labels its own signals helped define (§1), so this table shows *which process* each approach points at, not detection quality — the run-level table above is the fair comparison."]
    if ext:
        r = ext["result"]
        out += ["", "### 9.2 EVTX-ATTACK-SAMPLES — files with at least one alert", "",
                "| Category | Files | CPES | CPES or generic test | Sigma core, high+ | Sigma all, any level |", "|---|---|---|---|---|---|"]
        for key in CATEGORY_NAMES:
            row = r["summary_by_category"].get(key)
            if row:
                out.append(f"| {CATEGORY_NAMES[key]} | {row['files']} | {row.get('cpes_detected', '—')} | {row.get('cpes_or_generic', '—')} | {row['core_high']} | {row['all_any']} |")
        out += ["", "Caveat: some SigmaHQ rules were written with this public dataset in view (3 of the 46 core rules that fired here cite the dataset or its author). The overlap is limited but cannot be excluded."]
    if eva:
        v = eva["result"]["variants"]
        out += ["", "### 9.3 Evasion — Sigma on the same variants", "",
                "| Variant | Sigma core high+: runs consistent | Sigma core high+: outcome processes flagged |", "|---|---|---|"]
        for name, body in v.items():
            h = body["packs"]["core"]["high_or_critical"]
            out.append(f"| {name} | {h['runs_consistent']} | {h['unit_level']['attack_units']} |")
        out += ["", "V1: Sigma's injection rules match the PE `OriginalFileName`, which a renamed copy keeps, so renaming does not evade them (the CPES research injection signal and the image-name IOC drop to 0/18). V3: WSReset is itself a documented UAC-bypass binary with a dedicated Sigma rule, so Sigma's per-binary coverage catches the substitution; CPES's four-name list does not, and CPES's generic test does (§7)."]
    return out


HELDOUT_CATEGORIES = {
    "uac_listed_binary": "UAC, listed binary",
    "uac_other_method": "UAC, other method",
    "code_injection": "Code injection",
    "service_as_system": "Service-based execution as SYSTEM",
    "token_runas": "RunAs (no Sysmon) — not applicable",
    "control_not_privesc": "Controls (persistence, log tampering, LSASS dump)",
}


def _heldout_section() -> list[str]:
    record = _load("heldout-otrf-v2")
    out = ["", "## 10. CPES v2 on held-out data — OTRF Security-Datasets", "",
           "Pre-registered (with one amendment made before any result) in [design/cpes-v2-heldout.md](design/cpes-v2-heldout.md). v2 = v1 + the generic test, weighted from the lab corpus only. Unit = capture file.", ""]
    if not record:
        return out + ["_Not run yet._"]
    r = record["result"]
    names = [("research-v3-full-table", "CPES v1"), ("cpes-v2", "CPES v2"), ("generic_alone", "Generic test"), ("single_event", "Single-event rule"), ("sigma_core_high", "Sigma core high+")]
    out += [f"{r['dataset']} · execution `{record['id']}`", "",
            "| Detector | Privilege-escalation files detected | Control files with an alert |", "|---|---|---|"]
    for key, label in names:
        p = r["primary"][key]
        out.append(f"| {label} | {p['privesc_files_detected']} | {p['control_files_alerted']} |")
    v = r["v2_verdict"]
    out += ["", f"**Pre-registered verdict for v2: {v['verdict']}** ({v['rule']}).", "",
            "| Category | Files | " + " | ".join(label for _, label in names) + " |", "|---|---|" + "---|" * len(names)]
    for key, label in HELDOUT_CATEGORIES.items():
        row = r["summary_by_category"].get(key)
        if row:
            out.append(f"| {label} | {row['files']} | " + " | ".join(str(row[k]) for k, _ in names) + " |")
    out += ["", "Every CPES v1 alert and the process it is anchored on:", ""]
    for f in r["files"]:
        anchors = (f.get("detectors") or {}).get("research-v3-full-table", {})
        if anchors.get("refused"):
            out.append(f"- `{f['file']}` — pipeline refused: {anchors['refused']}")
        elif anchors.get("anchors"):
            out.append(f"- `{f['file']}` ({HELDOUT_CATEGORIES[f['category']]}) — " + ", ".join(anchors["anchors"]))
    return out


def _incidents_section() -> list[str]:
    record = _load("incidents-lab-v3")
    out = ["", "## 11. Incidents — joining Sigma actor alerts and CPES outcome alerts", "",
           "`cpes.correlation.correlate`: same process; parent/grandparent within 300 s; or a CPES alert's resolver actor is the other alert's process. Pre-registered in [design/incident-correlation.md](design/incident-correlation.md). Lab corpus, Sigma core high+ and the CPES package engine.", ""]
    if not record:
        return out + ["_Not run yet._"]
    r = record["result"]
    out += [f"execution `{record['id']}`", "", "| Configuration | Alerts | Incidents | Runs whose incident names the elevated process | Incidents outside any run | Incidents with both sources |", "|---|---|---|---|---|---|"]
    for key, label in (("sigma_alone", "Sigma alone"), ("cpes_alone", "CPES alone"), ("fused", "Fused")):
        c = r["configurations"][key]
        out.append(f"| {label} | {c['alerts']} | {c['incidents']} | {c['runs_whose_incident_names_the_elevated_process']} | {c['noise_incidents_outside_runs']} | {c['incidents_with_both_sources']} |")
    items = r["items_to_open"]
    out += ["", f"Items an analyst opens: {items['sigma_and_cpes_separately']} with both tools separately, {items['fused']} fused ({items['reduction'] * 100:.1f}% fewer). Attribution comes from CPES's alerts themselves; the join connects actor and outcome in only {r['configurations']['fused']['incidents_with_both_sources']} incidents (the resolver records no actor for service escalations). {r['note']}"]
    if r.get("fused_examples"):
        e = r["fused_examples"][-1]
        out += ["", f"Example fused incident `{e['id']}`: " + "; ".join(e["alerts"])]
    return out


def _service_signature_section() -> list[str]:
    record = _load("service-signature-v1")
    out = ["", "## 12. Service rule + signature suppressor (S1) on 100 unused OTRF captures", "",
           "S1 skips the service-location anchor when Sysmon recorded the process's own image as validly signed (EID 7). Pre-registered in [design/service-signature-suppressor.md](design/service-signature-suppressor.md); test set = every OTRF Windows host archive at `d9d40ef` not used before.", ""]
    if not record:
        return out + ["_Not run yet._"]
    r = record["result"]
    t, n = r["test_set"], r["non_regression"]
    out += [f"execution `{record['id']}`", "", "| | S0 (current) | S1 |", "|---|---|---|",
            f"| Service anchors on T | {t['s0_anchors']} | {t['s1_anchors']} |",
            f"| … vendor (Defender / Azure paths) | {t['s0_vendor']} | {t['s1_vendor']} |",
            f"| … other | {t['s0_other']} | {t['s1_other']} |", "",
            f"Archives: {t['archives']} ({', '.join(f'{k} {v}' for k, v in t['outcomes'].items())}); {t['archives_with_own_image_signature_records']} contain own-image signature records. "
            f"Non-regression: EVTX files changed {len(n['evtx_files_changed'])}/{n['evtx_files']}; lab corpus changed: {n['lab_changed']}. "
            f"Verdict: **{'adopted' if r['verdict']['adopt_s1'] else 'not adopted'}** (safety held: {r['verdict']['safety_held']}; rule: {r['verdict']['rule']})."]
    return out


def _vm_live_section() -> list[str]:
    record = _load("vm-live-v1")
    out = ["", "## 13. Second corpus — live VM session (vm-live-v1)", "",
           "A new session on a Windows 11 VM with every detector frozen: 30 min benign use, then the ten corpus-v3 Atomic tests × 5 (50 runs), "
           "Microsoft Defender on, System 7045 / Security 4697 collected alongside Sysmon. E-c labels (±150 s). Pre-registered in "
           "[design/vm-live-v1.md](design/vm-live-v1.md); session record in [../lab/vm-session/SESSION-NOTES.md](../lab/vm-session/SESSION-NOTES.md). "
           "The corpus holds host and account identifiers and is not published.", ""]
    if not record:
        return out + ["_Not run yet._"]
    r = record["result"]
    c, runs = r["corpus"], r["runs"]
    out += [f"execution `{record['id']}` · {c['unique']:,} documents ({c['duplicates_removed']} duplicates) · {runs['total']} runs · "
            f"Defender reported a detection with a successful action in {runs['defender_detected']} runs (all T1548.002)", "",
            "| Detector | Runs, any flag | Runs, consistent | False-alarm processes | Consistent by technique |", "|---|---|---|---|---|"]
    for name, v in r["detectors"].items():
        by = ", ".join(f"{t} {x}" for t, x in v.get("by_technique_consistent", {}).items()) or "—"
        out.append(f"| {name} | {v['runs_any']}/{v['runs']} | {str(v['runs_consistent']) + '/' + str(v['runs']) if 'runs_consistent' in v else '—'} | {v['false_alarm_processes']} | {by} |")
    sg = r["sigma_core_high"]
    out.append(f"| SigmaHQ core, high/critical | {sg['runs_any']}/{sg['runs']} | {sg['runs_consistent']}/{sg['runs']} | {sg['outside_runs']['processes']} | "
               + ", ".join(f"{t} {x}" for t, x in sg["by_technique_consistent"].items()) + " |")
    n, s2 = r["outcome_process_named"], r["service_install_corroboration"]
    excl = r["detectors_excluding_defender_runs"]["R_research_signals"]
    out += ["", f"Runs whose privileged process actually appeared (elevated auto-elevating binary, SYSTEM service binary): {n['runs_with_outcome_process']}; "
            f"named by R {n['R']}, P {n['P']}, Sigma {n['Sigma']}. R or Sigma, any flag: {r['r_or_sigma_runs_any']}/{runs['total']}. "
            f"Excluding the {runs['defender_detected']} runs with a Defender detection, R detects {excl['runs_consistent']}/{excl['runs']} consistently.", "",
            "Service-install corroboration (S2): " + "; ".join(f"{k} service runs {v['s0_service_runs_detected']} → {v['s2_service_runs_detected']}, false-alarm processes {v['s0_false_alarm_processes']} → {v['s2_false_alarm_processes']}" for k, v in s2["by_engine"].items())
            + f". Adoption criteria **{'met' if s2['adopted'] else 'not met'}**" + (" — to become an optional package setting, off by default; not yet implemented in `cpes`." if s2["adopted"] else "."), "",
            "| | Expectation | Observed | Verdict |", "|---|---|---|---|"]
    for key, h in r["hypotheses"].items():
        observed = h["observed"] if not isinstance(h["observed"], dict) else ", ".join(f"{k} {v}" for k, v in h["observed"].items())
        verdict = "untestable" if h["supported"] is None else ("supported" if h["supported"] else "**not supported**")
        out.append(f"| {key} | {h['expected']} | {observed} | {verdict} |")
    return out


def _package_v3_section() -> list[str]:
    record = _load("package-v3-dev")
    out = ["", "## 14. Package v3 modes — development checks (seen data)", "",
           "research-v3 replicates the published research rules inside the package, including their two name rules (`mavinject.exe`, `atomicservice`). "
           "structural-v3 adds the `services.exe` parent check (B1) and, where install records exist, service-install corroboration (B2). "
           "These run on data already seen during development, so they show what each mode does, not how it generalises; VM2 is the test. "
           "Pre-registered in [design/package-v3-and-vm2.md](design/package-v3-and-vm2.md).", ""]
    if not record:
        return out + ["_Not run yet._"]
    r = record["result"]
    lab, vm, ev = r["corpus_v3"], r["vm_live_v1"], r["evtx_attack_samples"]
    grouped = _load("package-grouped")
    current_f1 = f"{grouped['result']['detectors']['cpes']['fold_mean']['f1']:.3f}" if grouped else "—"
    out += [f"execution `{record['id']}`", "", "| | package-v2 (current) | research-v3 | structural-v3 |", "|---|---|---|---|",
            f"| corpus-v3 grouped-CV F1 | {current_f1} | {lab['research-v3']['cv']['f1_mean']:.3f} | {lab['structural-v3']['cv']['f1_mean']:.3f} |",
            f"| corpus-v3 benign units with a service flag | {lab['package-v2_benign_units_with_service_flag']} | {lab['research-v3']['benign_units_with_service_flag']} | {lab['structural-v3']['benign_units_with_service_flag']} |"]
    rl = vm["run_level"]
    out.append("| vm-live-v1 runs, consistent | " + " | ".join(f"{rl[m]['runs_consistent']}/{rl[m]['runs']}" for m in ("package-v2", "research-v3", "structural-v3")) + " |")
    out.append("| vm-live-v1 false-alarm processes | " + " | ".join(str(rl[m]["false_alarm_processes"]) for m in ("package-v2", "research-v3", "structural-v3")) + " |")
    out.append(f"| EVTX-ATTACK-SAMPLES files detected | {ev['package-v2']['files_detected']} | — | {ev['structural-v3']['files_detected']} |")
    out += ["", f"research-v3 equals the research rules per process: corpus-v3 **{lab['research_identical']}**, vm-live-v1 **{vm['research_identical']}**. "
            f"B1 loses the service signal on {len(ev['service_files_lost_by_B1'])} EVTX files ({', '.join(f'`{f}`' for f in ev['service_files_lost_by_B1'])}). "
            f"B2 alone on vm-live-v1: service runs {vm['service']['service-install-only']['service_runs_detected']}/10, false-alarm processes {vm['service']['service-install-only']['false_alarm_processes']}."]
    return out


def build() -> str:
    out = [
        "# CPES results (generated)",
        "",
        "Generated by `python -m evaluation.report` from `results/*.json`; do not edit by hand.",
        "Protocols and pre-registered expectations: [design/evidence-channels-and-package-evaluation.md](design/evidence-channels-and-package-evaluation.md).",
        "Unless a section says otherwise, figures are on corpus-v3 (single Windows 11 lab endpoint). Inputs are pinned by SHA-256 in each results file.",
        "",
    ]
    sections = [
        ("research-grouped", "1. Research protocol, replicated (grouped 5-fold CV)", "Research signal flags from the labelled table; replication of `analysis/corpus_eval_grouped.py`. It reproduces that script's printed means and standard deviations exactly, which validates the fold code used below."),
        ("ea-chain-grouped", "2. E-a — benign units grouped by lineage chain", "Same as §1 but each benign lineage chain is one CV group, so related benign processes never straddle folds."),
        ("package-grouped", "3. Package engine with evidence channels (grouped 5-fold CV)", "Signals observed by `cpes.CpesPipeline` with pipe and remote-thread evidence attached to windows; weights re-derived per fold with `cpes.derivation`."),
        ("package-grouped-noevidence", "4. Package engine without evidence channels", "As §3 without evidence: the package before this change."),
    ]
    for name, title, text in sections:
        record = _load(name)
        out += [f"## {title}", "", text, ""]
        out += _cv_table(record) if record else ["_Not run yet._"]
        if record and "signal_firings_on_units" in record["result"]:
            firings = record["result"]["signal_firings_on_units"]
            out += ["", "Signal firings on units: " + "; ".join(f"`{s}` {v['attack']} attack / {v['benign']} benign" for s, v in firings.items())]
        outside = record["result"].get("flags_outside_units") if record else None
        if outside is not None:
            windows = outside["windows_with_signal_anchored_only_outside_units"]
            images = "; ".join(f"`{s}` on " + ", ".join(f"{img} ×{n}" for img, n in v.items()) for s, v in outside["by_signal_and_image"].items()) or "none"
            out += ["", f"Alerts the unit metrics cannot see (anchored only on processes without a ProcessCreate in the capture): {sum(windows.values())} window(s) — " + (", ".join(f"`{s}` {n}" for s, n in windows.items()) or "none") + f"; processes: {images}."]
        if record and record["result"].get("benign_groups"):
            out += ["", f"Benign CV groups: {record['result']['benign_groups']}."]
        out.append("")
    record = _load("ec-ledger-time")
    out += ["## 5. E-c — run-level, labels from the execution ledger only", "", "Unit = logged Atomic run; a run is detected if a flagged process was created within ±150 s of it. *Consistent* = the flag's signal belongs to the run's technique (not defined for rules without mechanism semantics). No fitting.", ""]
    if record:
        r = record["result"]
        out += [f"{r['runs']} logged runs: " + ", ".join(f"{t} {n}" for t, n in r["runs_by_technique"].items()) + f" · execution `{record['id']}`", "", "| Detector | Runs, any flag | Runs, technique-consistent | Flagged processes | False-alarm processes | Consistent by technique |", "|---|---|---|---|---|---|"]
        for name, v in r["detectors"].items():
            by = ", ".join(f"{t} {x}" for t, x in (v["by_technique_consistent"] or {}).items()) or "—"
            alarms = f"{v['false_alarm_processes']}" + (f" ({', '.join(f'{k} {n}' for k, n in v['false_alarm_images'].items())})" if v["false_alarm_images"] else "")
            out.append(f"| {NAMES.get(name, name)} | {v['modelled_runs_detected_any']} | {v['modelled_runs_detected_consistent'] or '—'} | {v['flagged_processes']} | {alarms} | {by} |")
    else:
        out.append("_Not run yet._")
    out += _external_section() + _evasion_section() + _streaming_section() + _sigma_section() + _heldout_section() + _incidents_section() + _service_signature_section() + _vm_live_section() + _package_v3_section()
    out += ["", "## Reading these results", "", "See [dashboard/EVALUATION-NOTES.md](dashboard/EVALUATION-NOTES.md) for interpretation and open decisions.", ""]
    return "\n".join(out)


def main() -> None:
    OUT.write_text(build(), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
