# Can the service rule's vendor false alarms be fixed? — exploratory check

Written 2026-10-19. **Exploratory, not a test:** it uses only data already
seen (lab corpus-v3, EVTX-ATTACK-SAMPLES, the 21 OTRF captures of the held-out
run), so nothing here is a performance claim. Script:
`scripts/explore_service_rule.py`.

## The defect

`service_dropped_binary` fires on any SYSTEM-integrity process whose image is
outside `\Windows\` and `\Program Files`. On the OTRF captures it alerted on
Defender (`MsMpEng.exe`, `MpCmdRun.exe` under `ProgramData`) and Azure agents
(`WaAppAgent.exe`, `WindowsAzureGuestAgent.exe`, `CollectGuestLogs.exe` and
others under `WindowsAzure` / `Packages`) — 19 vendor binaries, 0 attacks
([cpes-v2-heldout.md](cpes-v2-heldout.md)). The rule's true detections are
`AtomicService.exe` (lab, 28/28 runs) and, outside its design, Potato-style
token tools (EVTX-ATTACK-SAMPLES, 5/7).

## Candidate discriminators, checked against the telemetry

| Candidate | Vendor false alarms (19) | True detections | Usable? |
|---|---|---|---|
| Image is **signed** (Sysmon EID 7 for the process's own image) | signature recorded for **2** (Defender, signed); the 17 Azure agents have **no** image-load records (filtered by that capture's Sysmon config) | lab `AtomicService.exe`: recorded **unsigned**; Potato tools: no record | Only as a *suppressor* when a valid signature is positively observed: removes 2/19, keeps every attack |
| Binary was **written in the capture** (EID 11 to the image path) | 0/19 written | 0 of AtomicService / Potato tools written (staged before recording); only `program.exe` (unquoted path) | No — removes all true detections |
| `\Services\` registry writes ≤ 300 s before start | 18–1,496 writes before vendor services | 409 before AtomicService; 0 before Potato tools | No — background registry churn, no separation |
| **Service-installed** event (System 7045 / Security 4697) naming the binary | none name a vendor binary | lab corpus collected **Sysmon only** (no 7045); EVTX samples: none | Not testable on the lab data; would need a new evidence channel and new data |
| Vendor **path allow-list** (`ProgramData\Microsoft\Windows Defender`, `WindowsAzure`, `Packages\Plugins`) | removes 19/19 | keeps all | Fitted to what we saw; an administrator (which service creation already requires) can place a binary there — evadable by construction |

## Conclusion

With Sysmon-only telemetry there is no structural feature that separates these
vendor services from attacker binaries. The two honest options are a
**signature suppressor** (small, safe gain) and a **service-install evidence
channel** (principled, but needs System/Security logs, which the lab corpus
did not collect). Either must be pre-registered and evaluated on captures not
used here.
