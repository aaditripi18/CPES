# Stitch prompts for the CPES dashboard

No Stitch integration is available from this coding environment, so no Stitch
design has been generated or inspected for CPES. These prompts are for you to
paste into Google Stitch (Web mode). Paste prompt 0 first, then each page prompt
as a refinement of the same project. Export the HTML/Tailwind and drop it in
`dashboard/design/stitch/` — it will be treated as **visual design only** and
re-wired to the real API, exactly as was done for Stowaway and leakcheck (in both
projects Stitch invented features and numbers that had to be removed).

The current React build already follows the system below, so Stitch output can be
adopted screen by screen without changing behaviour.

---

## Prompt 0 — the visual system (paste first)

Design a desktop web application called "CPES — Contextual Privilege Escalation
Scoring", an investigation and research workbench for Windows endpoint telemetry.
It is a sibling of two existing projects: Stowaway (near-black, cyan signal colour)
and leakcheck (warm off-white, amber signal colour). CPES gets its own identity:

Feel: a forensic investigation console crossed with a research notebook. Calm,
dense but readable, every number traceable. Think Linear's precision and an
intelligence analyst's timeline tool. No gradients, no glow, no 3D, no stock art,
no "AI" sparkles, no hacker green-on-black.

Look: graphite background #0b0e13, panels #11151c and #161b24, hairline borders
#222a36, text #e4e8ef, muted text #8a94a6. Hanken Grotesk for UI and prose,
JetBrains Mono for identifiers, GUIDs, timestamps, scores and code. One
interactive accent, violet #a78bfa, used for selection, focus and links only.
Severity: detected = coral #ff7b6b, below threshold = slate, baseline-only =
amber #f2b84b, clean = sage #7fd1a8. Evidence styling: observed telemetry is a
solid chip; derived context is an outlined chip; resolver-inferred association is
a dashed outline chip. Radius 4–6 px. 14 px base text. Left sidebar navigation
(Overview, Datasets, Explorer, Runs, Detections, Lineage, Scoring, Evaluation,
Experiments, System), a slim top bar showing the active dataset and active run as
mono chips, and a persistent "SYNTHETIC" or "PRIVATE LAB DATA" badge whenever such
data is on screen.

## Prompt 1 — Overview

The landing screen. A one-sentence product statement at the top: "CPES scores the
mechanism of a privilege escalation — not the symptom — and shows the evidence
behind every score." Below, a row of five compact metric tiles (records accepted,
process nodes, lineage chains, scored windows, detected windows) for the latest
run, each with a mono value and a muted caption naming the run id. Then a two-column
area: left, a score distribution histogram (log-odds bins, a vertical dashed line
at the 0.50 threshold, bars right of the line in coral, bars clickable); right, an
event-code distribution as horizontal bars (Sysmon EID labels like "1 ProcessCreate",
"13 RegistryValueSet"). Below, a "Recent detections" list (chain GUID, window time,
score, fired signals as chips) and a "Recent runs" table (run id, dataset, status
pill, detected windows, started). A right-hand panel "Research claims" lists each
published figure with a status pill: "matches", "differs", or "not reproduced yet".
A first-time visitor strip at the very top, dismissible: "New here? Take the
90-second tour" with three steps.

## Prompt 2 — Datasets (upload + inventory)

A drag-and-drop upload zone (dashed border, accepts .csv .json .jsonl .ndjson,
256 MB limit shown), with optional fields "Name", "Where does this data come
from?", and a checkbox "This file is synthetic". After upload, a validation report
card: status pill (Valid / Valid with rejections / Invalid), counts (read, accepted,
rejected, parse errors), a mapping table with 11 canonical fields (source path
column editable as a mono text input, required fields marked), warnings list
(amber), rejection list (coral) with line numbers and the exact error, a "time
range" line and a lineage preview line ("2,219 process nodes · 96 chains · 38
truncated"). A primary button "Run CPES on this dataset" with window span,
advance and threshold inputs. Below, the inventory: a table of datasets with name,
category badge (Research telemetry / Synthetic / User upload), format, records,
SHA-256 (truncated mono, copy button), ground truth (yes/no + unit), validation
status, run count. A second table "Other artifacts" for label tables, execution
ledgers and zip archives.

## Prompt 3 — Explorer

A data grid for raw telemetry: a search box, facet filter chips on the left
(event code, host, user, integrity level, process name) each with counts, a time
range filter, a column picker, sortable columns, pagination with total count, and
missing values shown as a muted "∅". Clicking a row opens a right drawer with three
tabs: "Original" (pretty JSON), "Canonical mapping" (11 rows: canonical field ·
source path · value · present/absent), "Unmapped fields" (field list). Export
filtered records button.

## Prompt 4 — Detections and the explainable score

Left: a list of scored windows (detected first) with score bars. Right: the
selected detection. Header: chain GUID, window start–end, decision pill
"DETECTED (≥ 0.50)". A horizontal waterfall: prior 0 → each fired signal's weight
as a coral segment → final score, with the threshold drawn as a dashed line.
A table of all four signals: present/absent, weight, contribution, wiring status
("not wired in pipeline" for two of them, muted). An evidence section with three
grouped lists: Observed telemetry (event chips linking to the raw record),
Derived context (integrity transitions parent → child), Resolver association
(the sentence explaining how the elevated process was re-associated with the
registry write). A small "Single-event baseline" verdict card for the same window.

## Prompt 5 — Lineage

A full-height process tree canvas (top-to-bottom), nodes as compact cards: image
basename in mono, PID, integrity badge, event count, coral ring if referenced by a
detection. Unresolved parents drawn as a dashed ghost node labelled "parent not in
telemetry". A left list of chains (root image, process count, detected windows,
truncated badge). A right drawer for the selected process: GUID, parent, children,
first/last seen, command line, event list with links into Explorer, detections.

## Prompt 6 — Evaluation and experiments

Two clearly separated bands. Band 1 "Recorded research experiments": cards for
each analysis script with a role badge (Canonical, Supporting, Validity check,
Ablation, Adverse result, Unavailable), protocol line in mono, "Run again" button,
last run time, script SHA-256. The canonical card shows a grouped bar chart of
precision / recall / F1 for three detectors with ± std whiskers. Band 2 "This
detection run (dashboard protocol)": a protocol banner stating "in-sample, chain
level — not the paper's protocol", two confusion matrices side by side (CPES vs
single-event baseline), and a per-technique table.

## Prompt 7 — System & limitations

A sober page: supported inputs, canonical schema table, signal table with wiring
status, known unsupported techniques, numbered limitations, data availability,
versions (cpes, dashboard, Python, git commit).
