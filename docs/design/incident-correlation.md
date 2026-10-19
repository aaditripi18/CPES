# Incident correlation: Sigma actor alerts + CPES outcome alerts — pre-registration

Written 2026-10-19 before the correlation was run on any data.

## Problem

SigmaHQ rules alert on what the attacker's tools do (`reg.exe` writes a hijack
key, `sc.exe` creates a service, PowerShell runs an encoded command). CPES
alerts on the process that ends up elevated, and its resolver records the actor
it re-associated with. An analyst today opens each alert separately. The
question: does joining them into incidents (a) reduce what must be opened and
(b) make each incident state which process gained privilege?

## Correlation rule (`cpes/correlation/incidents.py`, fixed now)

An alert has a time, a process, optional related processes (for CPES: the
resolver's actor and anchors), a source (`sigma` / `cpes`), a title and
technique tags. Two alerts belong to the same incident when **any** holds:

1. they concern the same process;
2. one process is the parent, child or grandparent/grandchild of the other
   (lineage within two generations) and they are at most `gap` seconds apart;
3. a CPES alert's resolver actor is the other alert's process (cross-channel
   link) — no time limit beyond the alert's own window.

Incidents are the connected components (union-find). `gap` = 300 s, the CPES
window span. An incident's **outcome** is the set of processes CPES flagged in
it; incidents without a CPES alert have no outcome. Severity = highest member
level (CPES alerts count as high).

## Measured on the lab corpus (ledger-time labels, as E-c)

Alerts: Sigma core high+ (same 773 rules as §9) and CPES package engine with
evidence channels. Three configurations: Sigma alone, CPES alone, fused.

* alerts and incidents (compression = alerts / incidents);
* per logged run (±150 s): number of incidents touching the run
  (fragmentation), and whether one of them names an elevated outcome
  (attribution);
* incidents entirely outside any run (noise incidents).

**Expectations.** Fused incidents < Sigma-alone alerts (compression > 1); fused
attribution > Sigma-alone attribution (which is 0 by construction: Sigma has no
outcome concept); fused noise incidents ≤ Sigma noise + CPES false alarms. The
lab attacks run from one PowerShell session, so rule 2 may chain consecutive
runs; we report how many incidents span more than one run (purity) rather than
tune `gap` after seeing it.

## Outcome (recorded 2026-10-19 after the run; ../RESULTS.md §11)

| Expectation | Outcome |
|---|---|
| Fused incidents < Sigma-alone alerts | **Held, but weakly informative:** 146 fused incidents vs 209 Sigma alerts. Sigma alone already groups its 209 alerts into 101 incidents. Against opening both tools' incidents separately (101 + 66 = 167), fusion saves 21 items (12.6%). |
| Fused attribution > Sigma attribution (0) | **Held** (90/126 runs vs 0/126) — but this equals CPES alone (90/126): the attribution comes from CPES's own alerts, not from joining. |
| Fused noise ≤ Sigma noise + CPES false alarms | **Held** (16 = 8 + 8). |

Descriptive, added after the first run: only **7** fused incidents contain both
a Sigma and a CPES alert (13 CPES alerts joined). The conservative rules rarely
connect the attacker's tool to the elevated process: for service escalations
the resolver records no actor, and the elevated binary sits under
`services.exe`, outside the attacker's process tree. Per-run fragmentation and
purity are not informative here (runs ~75 s apart, overlapping ±150 s windows).

Next hypothesis (needs its own pre-registration): record an actor for service
escalations (the process whose service-registry write or service-creation
command precedes the SYSTEM binary) so correlation can cross that tree boundary.
