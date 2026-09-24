# CPES — Context Resolver: design for load-bearing cross-channel re-association (patent core)

**Date:** 2026-09-06
**Purpose:** make the context re-association the thing that actually does the detection, so the novelty is real and the patent claims are defensible. Today the signals barely use context (510 ignores the registry; 530 collapsed to an image-name match because its EID 8 channel was empty). This document specifies the resolver, how every signal consumes it, how it generalises to techniques with no bespoke signal, and how it avoids the labels-vs-signals circularity.

---

## 1. The problem the resolver solves

Windows **re-parents the escalation outcome out of the attacker's process tree** (verified in the corpus): an abused auto-elevating LOLBin is spawned by `svchost`/`consent`, a malicious service binary by `services.exe` (the SCM), an impersonated SYSTEM shell by the SCM, and an injected thread appears inside an unrelated victim. So the *actor*, the *mechanism*, and the *elevated outcome* land in **different process subtrees and different Sysmon channels**. Naive process-lineage or single-event rules therefore cannot connect them — which is why single-event and signature baselines miss 2/4 mechanisms. **Re-association across channels, bridging the OS mediation, is the necessary step**; the resolver is that step.

## 2. What the resolver produces

For each **privilege-relevant anchor** event, the resolver emits one **Resolved Context** object:

```
ResolvedContext {
  anchor           : the privilege-relevant event (see 3)
  actor            : the initiating non-privileged process (re-associated across re-parenting)
  mediator         : the OS component that performed the re-parenting (services.exe / consent.exe|AppInfo / SCM / RPC), if any
  privilege_delta  : effective privilege before -> after (e.g. Medium -> High, User -> SYSTEM)
  evidence         : cross-channel events tied to this escalation:
                       process_create(s) [EID1], registry writes [EID12/13],
                       pipe create/connect [EID17/18], remote thread [EID8], image loads [EID7]
  resolution_path  : the explicit links used to re-associate (for interpretability + the patent)
}
```

The `resolution_path` is the audit trail: it records *why* the resolver believes these cross-channel events belong to one escalation. That trail is both the interpretability story for the paper and the concrete mechanism for the patent.

## 3. Anchors (what starts a resolution)

Any event indicating a possible privilege change:
- a process observed at **High/System** integrity;
- an **integrity-elevation edge** (child > parent);
- a **service creation / registration** (SCM registry write or `sc`/`CreateService`);
- a **named-pipe connection by a SYSTEM process**;
- a **remote thread / injection** event;
- a process whose **effective user/token** differs from its logon context.

## 4. Re-association rules (the bridges over OS mediation)

The resolver links an anchor to its true actor and evidence across the re-parenting boundary:

1. **SCM mediation (service technique).** A SYSTEM service binary spawned by `services.exe` is re-associated with (a) the `Services\<name>` registry write [EID13] and (b) the `sc`/`CreateService`/PowerShell caller that created that service, matched by service name + time. Actor = the caller; mediator = SCM; evidence = {service binary create, service registry write, creator process}.
2. **Consent/AppInfo mediation (UAC bypass).** A High-integrity auto-elevating LOLBin spawned by `consent.exe`/AppInfo/`svchost` is re-associated with the **hijack registry write** (`ms-settings`/`mscfile`/`shell\open\command`) and the medium-integrity user process that performed it, matched by session + time window. Actor = that user process; mediator = AppInfo; evidence = {hijack write, LOLBin create}.
3. **Impersonation mediation (token theft).** A SYSTEM interactive shell is re-associated with a **named-pipe create by a non-SYSTEM user** and the subsequent **pipe connect by SYSTEM** [EID17/18], plus the transient service used to trigger it, matched by pipe name + time. Actor = the pipe creator; mediator = SCM/impersonation; evidence = {pipe create, pipe connect, service registry write}.
4. **Injection mediation.** An injector process is re-associated with its **CreateRemoteThread** [EID8] and the victim target; where the injection primitive emits no EID 8 (e.g., `mavinject /INJECTRUNNING` on some builds), the resolver falls back to the injector invocation + image-load [EID7] evidence and records the reduced-evidence state in `resolution_path` (honest degradation, not a silent name match).

All links are recorded in `resolution_path` with the join key used (guid / service name / pipe name / time delta), so every association is auditable.

## 5. Signals become predicates over the resolved context

Each signal stops reading a single event and instead reads the `ResolvedContext` — this is what makes re-association load-bearing:

- **510 autoelevation_lolbin** := anchor is a High LOLBin **AND** `evidence` contains the hijack registry write **by the resolved actor** (not merely "fodhelper ran at High"). This is what removes the Elastic/Splunk IOC overlap — the signal now requires the *mechanism* (actor-performed hijack write re-associated to the elevated LOLBin), not the image.
- **520 service_dropped_binary** := anchor is a SYSTEM service binary **AND** `evidence` shows it was created by a non-service actor pointing at a binary outside system directories (structural, no basename).
- **530 remote_thread_injection** := anchor is an injection **AND** `evidence` contains the CreateRemoteThread / target link (with the honest reduced-evidence fallback recorded).
- **540 token_impersonation** := anchor is a SYSTEM shell **AND** `evidence` contains the user-created pipe + SYSTEM connect re-association.

Each signal's weight is still a log-likelihood ratio; the score is still additive; but the *feature* each signal tests is now a re-associated cross-channel condition.

## 6. Generalisation to techniques with no bespoke signal (the key patent claim)

Because the resolver builds a `ResolvedContext` for **any** privilege-relevant anchor — not only the four known mechanisms — a **generic escalation test** can run over the resolved context:

> **Unexplained privilege gain**: the anchor reached higher effective privilege than its resolved actor's context, and the `resolution_path` contains **no legitimate mediating path** (no consented UAC via `consent.exe` with user interaction, no signed-service install, no OS-initiated SYSTEM spawn).

This flags escalations for which no per-technique signal exists. It is the answer to "does the resolver generalise?" — yes, because the resolution + the generic test are technique-agnostic; the per-mechanism signals (510–540) are interpretable specialisations that add precision and explanation. **This must be demonstrated on the unsignalled detonations** (see the paper track) before it is claimed — architecture alone is not a result.

## 7. Circularity resolution (so signals may consume every channel)

Once signals read the resolved context (registry, pipe, remote-thread, image-load), those channels can no longer *also* be the independent validation labels. Fix: **labels come from provenance / ground truth** — the Atomic-runner command-line fingerprint (`\atomicredteam\atomics\Txxxx`) and the atomic execution log — which the resolver does **not** consume as a feature. Then signals may use every telemetry channel and recall is still non-circular, because the label channel (provenance) is disjoint from the signal channels (telemetry).

## 8. Patent claim skeleton (for the attorney / IP cell — not legal text)

- **Independent claim:** a method for detecting privilege escalation on an endpoint by (i) ingesting multi-channel host telemetry, (ii) for a privilege-relevant anchor, **resolving a cross-channel context that re-associates the elevated outcome with its initiating actor across operating-system re-parenting mediation**, and (iii) scoring the resolved context to decide escalation, with the resolution path retained as an explanation.
- **Dependent claims:** the SCM / consent-AppInfo / impersonation / injection re-association rules (Section 4); per-mechanism predicates over the resolved context (Section 5); additive weight-of-evidence scoring; the generic unexplained-privilege-gain test over the resolved context (Section 6); provenance-disjoint labelling (Section 7).
- **Novelty position:** prior art (single-event integrity rules; IOC/signature rules; SIEM threat-hunting such as Bhardwaj 2025) operates per-event or per-channel and cannot bridge OS re-parenting; the resolver's cross-channel re-association across mediation is the distinguishing step. **File a provisional before public disclosure of the paper.**

## 9. Implementation plan (in the `cpes` package)

1. `context/resolver.py` — anchors + the four re-association rules + `ResolvedContext` emission (+ `resolution_path`). **DONE** (2026-09-06). All four mechanisms implemented; token/injection handled via optional `PipeEvidence`/`RemoteThreadEvidence` params, so **no change to the frozen `ContextEvent` model was required**.
2. `orchestration/resolved_observations.py` — signals as predicates over `ResolvedContext` (`ResolvedSignalObservationGenerator`). **DONE** — pipeline seam unchanged.
3. Unit tests per re-association rule. **DONE** — full suite 115 green (incl. mechanism-conditioning, benign VBox-pipe and legit-system-binary negatives).
4. `detection/generic.py` — the unexplained-privilege-gain test. **DEFERRED until the VM data exists**: it must be calibrated against the unsignalled detonations + benign diversity, or it will false-positive on legitimate elevations (installers, taskmgr self-elevation). Building it blind would be guessing; build + validate after the expansion collection.
5. End-to-end wiring: carry pipe/remote-thread evidence through the windowing pipeline so the resolver runs in the live path (currently the resolver accepts them directly; the analysis harness already exercises this). Integration step, no model change.
6. Move labelling to provenance (Section 7) in the evaluation harness — enables signals to consume every channel without circularity.
7. Re-run evaluation; **demonstrate generalisation on the unsignalled detonations** (needs the VM data).

**Status:** the patentable substance (1–3) is built and tested. Steps 4, 6, 7 need the expansion VM session's data to be done honestly (calibrate the generic test, demonstrate generalisation); step 5 is integration. Nothing further is blocked on frozen-model approval.
