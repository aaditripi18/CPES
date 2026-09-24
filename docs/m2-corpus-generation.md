# M2 corpus-generation preparation

M2 prepares the repository to record the reproducible PrivEsc Sysmon corpus
`cpes-telemetry-corpus-v1`. This document does not authorize execution,
collection, or corpus publication. Those actions occur only after explicit
laboratory approval.

## Frozen scope

The attack partition is limited to these six selected techniques:

- T1548.002 Bypass UAC
- T1134.001 Token Theft
- T1134.002 Create Process with Token
- T1543.003 Windows Service
- T1546.003 WMI Event Subscription
- T1055.001 DLL Injection

T1068 and every technique outside this list are excluded. T1546.003 remains in
scope unless the M3 DG-1 decision is later made; M2 does not make that decision.

## Preconditions for later laboratory collection

- Start from the approved M1 post-validation snapshot of the controlled Windows
  11 endpoint.
- Keep `configs/sysmon-config-v1.xml` deployed and unchanged.
- Use the approved M0 telemetry collection path.
- Record the exact VM build, Sysmon version/configuration hash, Atomic Red Team
  revision, operator, and UTC offset before each batch.

## Manual bracket recording

Before any future controlled activity, populate the execution-plan template
with verified Atomic identifiers, prerequisites, variants, and cleanup notes.
For every attack or benign activity, record a start timestamp, end timestamp,
activity type, variant, operator, cleanup status, and evidence reference in
`execution-ledger.csv`. Attack records additionally require a technique ID and
Atomic test identifier.

`cpes.corpus.recording` creates only deterministic metadata from these manually
provided values. It does not interact with the endpoint or telemetry.

## Required benign partition categories

Future benign collection must include all of the following, not merely idle
system activity:

- legitimate UAC elevations;
- software installation;
- Windows service management;
- administrator PowerShell usage;
- legitimate WMI activity;
- ordinary Windows background activity.

## M2-to-M3 boundary

M2 records capture provenance and bracketed ground truth. M3, not M2, performs
the per-technique coverage report, label-integrity spot audit, and hard-negative
adequacy review.
