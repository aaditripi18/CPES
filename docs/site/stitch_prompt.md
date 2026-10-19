# Stitch prompts for the CPES project site

Use Stitch in **Web** mode. Paste prompt 1 and generate. Then paste prompts 2–5
one at a time as refinements of the same design. Export the HTML/Tailwind at the
end and put it in `site/stitch/` (or paste it into the session).

Every number below comes from `docs/RESULTS.md` (generated from `results/`).
After export, the numbers are re-wired to `results/` and any feature, figure or
claim Stitch invents is removed — the same process used for Stowaway and
leakcheck. Don't worry if Stitch rounds a number or adds a decorative widget;
it will be checked.

The look matches the dashboard (`docs/dashboard/stitch_prompts.md`, prompt 0),
so the site and the tool feel like one product.

---

## Prompt 1 — the page (paste first)

A one-page website for "CPES — Contextual Privilege Escalation Scoring", a
security research tool that detects Windows privilege escalation by its
*mechanism* rather than its symptom, names the process that actually gained
privilege, and shows the evidence behind every alert.

Feel: a forensic investigation console crossed with an editorial research
report. Calm, precise, technical, trustworthy — a well-designed security
write-up, not a startup landing page. No gradients, no glow, no 3D blobs, no
stock imagery, no hacker green-on-black, no hype words.

Look: graphite background #0b0e13, panels #11151c, hairline dividers #222a36,
off-white text #e4e8ef, muted text #8a94a6. Hanken Grotesk for headings and
prose, JetBrains Mono for numbers, process names, GUIDs and code. One
interaction colour, violet #a78bfa, for links and buttons only. Coral #ff7b6b
only for "elevated / detected". 1100 px content width. Dark only.

Hero, the centrepiece: on the left, a large headline "Which process actually
gained SYSTEM — and how?" and a short line under it: "CPES rebuilds the process
tree from Sysmon telemetry, re-associates every privilege gain with the evidence
of how it happened, and scores it — live, explainable, and tested against the
rules defenders already run." Three buttons: "See the evidence chain", "Open the
dashboard" (primary, violet) and "Reproduce it". On the right, a custom
illustration built from UI elements: a small top-to-bottom process tree drawn
as mono cards (explorer.exe → cmd.exe → fodhelper.exe), the last card outlined
in coral with a small "High" integrity badge. A separate card on the side,
"reg.exe — HKCU\…\ms-settings\shell\open\command", is joined to the coral card
by a dashed violet line labelled "re-associated". Under it a mono score line:
"score = 0 + 7.37 (autoelevation) ≥ 0.50 → detected".

Below the hero, a slim row of three stats separated by hairlines:
"4 mechanism signals · every alert explained",
"160 / 160 live alerts identical to hindsight · median 83 s to alert",
"tested on 53 public attack captures it never saw".

Then sections, each with a small mono section number (01, 02, …) and a short
title: The problem · How it works · The evidence chain · Results in the lab ·
Beyond the lab · Against Sigma · Try it · Reproduce · Limitations.
Sticky top bar with the "CPES" wordmark in mono and links Results, How it works,
Dashboard, Reproduce, GitHub.

---

## Prompt 2 — the problem, how it works, the evidence chain (paste second)

**The problem.** Two-column section. Left: a short paragraph: "A common rule
flags privilege escalation when a process's integrity level rises above its
parent's. That symptom misses escalations that cause no jump — a service binary
started by services.exe, injected code, a stolen token — and fires on legitimate
software that elevates. Windows also re-parents the elevated process away from
the attacker, so the actor and the outcome sit in different branches." Right: a
small diagram of two separate process branches — one ending in a coral
"atomicservice.exe [System]" under services.exe, one with "cmd.exe → sc.exe
create" — with a dashed line between them labelled "no parent link: re-parented
by the OS".

**How it works.** A horizontal pipeline of six small mono-labelled boxes joined
by thin arrows: "Sysmon / Winlogbeat / .evtx" → "Lineage" → "Context" →
"Windows" → "Signals + resolver" → "Score + decision", with a thin branch from
"Signals" to "Evidence channels (named pipes, remote threads)". Under it, one
line per box in muted text. A small note: "Every stage is deterministic and
tested; nothing is inferred that the telemetry does not contain."

**The evidence chain.** A large card that looks like a real detection detail:
header "chain 678A-6A96-7D00 · DETECTED ≥ 0.5"; a horizontal waterfall bar
(prior 0 → +7.3651 autoelevation_lolbin → score 7.3651) with a dashed amber
threshold line at 0.5; a table of four signals with present/absent and weight;
three grouped evidence lists labelled "observed" (two mono event chips),
"derived" (an integrity transition "powershell.exe [Medium] → sdclt.exe
[High]"), and "inferred" (a dashed-outline sentence "auto-elevating 'sdclt.exe'
at 'high' re-associated with hijack registry write …"). Caption: "Each alert
decomposes into exact weights and the records that produced them."

---

## Prompt 3 — results in the lab, beyond the lab (paste third)

**Results in the lab.** A clean full-width table with hairline row dividers,
right-aligned mono numbers, no zebra stripes. Title "Grouped 5-fold
cross-validation on a lab Sysmon corpus (2,161 process instances, 87 attack)".
Columns: Detector, Precision, Recall, F1. Rows:
CPES · 0.986 ± 0.029 · 1.000 ± 0.000 · 0.993 ± 0.015 (row in bold);
Single-event integrity rule · 0.982 ± 0.036 · 0.404 ± 0.163 · 0.551 ± 0.136;
IOC / signature rule · 1.000 ± 0.000 · 0.567 ± 0.194 · 0.705 ± 0.151.
Under the table, a muted note box: "Recall is favourable by construction —
attack outcomes are labelled partly by their own mechanism. With labels taken
only from the execution log, CPES flags the right mechanism in 98 of 126 runs
with one false alarm."

**Beyond the lab.** Three side-by-side cards, each with a mono label, one large
number and two lines:
1. "NEVER-SEEN ATTACKS" — "26 / 53" — "public Sysmon captures flagged by CPES with
   its generic 'unexplained privilege gain' test (9 by the specific signals
   alone). The structural service signal caught 5 of 7 Potato-style token
   attacks it was not built for."
2. "EVASION" — a tiny two-row before/after: "renamed injector 18 → 0",
   "renamed service binary 28 → 28"; caption "Signals that read names break;
   signals that read structure don't. Swapping to an unlisted auto-elevating
   binary drops the UAC signal 33 → 0 while the generic test rises 18 → 32."
3. "LIVE" — "83 s" — "median time from elevation to alert while streaming;
   live alerts identical to the hindsight result (160 / 160)."

---

## Prompt 4 — against Sigma, try it (paste fourth)

**Against Sigma.** Title "How it compares with SigmaHQ (850 core rules)". A
compact table: columns Measure, CPES, Sigma core (high+). Rows:
"Lab runs, right technique flagged" · 98 / 126 · 106 / 126;
"Public captures flagged" · 26 / 53 (with generic test) · 42 / 53;
"Alerts outside attack runs" · 1 process · 8 alerts;
"Flags the process that gained privilege (UAC / service)" · 33 / 33 · 28 / 28 ·
0 / 33 · 0 / 28 — show this last row as two small inline pairs, with a tiny
footnote marker on the CPES cell: "in-sample: these lab labels were partly
defined by CPES's own signals".
Above the table, a large plain sentence: "Sigma finds more. CPES tells you which
process ended up elevated, how, and why — they are complementary." Below it, a
muted line: "Sigma alerts on the actor (reg.exe writing the key, sc.exe creating
the service); CPES attributes the outcome."

**Try it.** A wide screenshot-style mock of the dashboard's Live page: a left
control panel (source "Replay", dataset select, speed "600×", Start/Stop) and a
right alert feed of three cards, each with a coral score "+6.10", a signal pill
"service_dropped_binary", a mono process name, and a one-line explanation. A
REPLAY badge in amber at the top so it is clearly a replay. Under it two buttons:
"Upload your own .evtx" and "Run the 90-second demo".

---

## Prompt 5 — reproduce, limitations, footer (paste fifth)

**Reproduce.** A dark terminal-style code block with a copy button containing:
```
python scripts/fetch_external.py
python -m evaluation.run all
python -m evaluation.report
python dashboard/run_server.py
```
Beside it a short list: "Every protocol was written down with its expected
outcome before it ran", "Every number on this page is generated from
results/", "Inputs pinned by SHA-256".

**Limitations.** A numbered list in plain text, no icons:
1. One lab endpoint; no multi-host or enterprise traffic yet.
2. Four mechanisms; techniques without a signal are not detected.
3. The auto-elevation signal names four binaries and does not generalise to
   other UAC methods; the generic test covers part of that gap.
4. On this corpus the injection signal is an image-name rule.
5. SigmaHQ detects more attacks; CPES is a complement, not a replacement.

**Footer.** Wordmark, one line "Research code by <your name>", links GitHub,
Dashboard, Results, and a muted line "Public samples: EVTX-ATTACK-SAMPLES
(GPL-3.0). Rules: SigmaHQ (DRL 1.1)."
