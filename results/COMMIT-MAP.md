# Commit map (history rewrite, 2026-10-19)

Before the repository was made public, one lab process GUID was removed from an
early version of `dashboard/web/src/lib/format.test.ts` by rewriting the
unpublished commits. No other file changed (the final tree is identical), but
every commit hash after that point changed. Results and ledger entries recorded
before the rewrite name the **old** hashes; this table maps them. Code
fingerprints (`code_sha256`) are unaffected.

| Old commit | New commit | Subject |
|---|---|---|
| `4b1b721c9b32` | `62d51273df0c` | Add local research dashboard around the unchanged cpes package |
| `48352f6ed905` | `50aeb1693e79` | Wire pipe and remote-thread evidence through the pipeline; add versioned evaluation |
| `0bea13fbaa31` | `3966276897e8` | Record evaluation results at 48352f6 and generate docs/RESULTS.md |
| `76895b4bc73a` | `f622aea849f9` | Add detection-lab scaffold: health check and Phase 0 guide |
| `d6b2f0b0039a` | `9ae17b293648` | Add external, evasion, live and Sigma evaluations; streaming scorer; EVTX support |
| `63742a394418` | `b19a9c9244c2` | Record all eleven evaluation protocols at d6b2f0b and regenerate docs/RESULTS.md |
| `b8dda97dfc3c` | `50bc9fbfa51f` | Add Stitch prompts for the CPES project site; update dashboard prompts |
| `bb09551ea7a1` | `c11100d16cab` | Pre-register CPES v2 and the OTRF held-out test; freeze the v2 model |
| `1e821862e303` | `ca6ae4f02f1a` | Amend OTRF held-out mapping before any result: UtcTime as event time, position ids |
| `1fe1a156f685` | `0641e422b134` | Run CPES v2 held-out test on OTRF; v2 not adopted (pre-registered verdict) |
| `97ad943a0ef7` | `48a63c8bfb28` | Add incident correlation (cpes.correlation) and the incidents-lab-v3 protocol |
| `1941bd50877b` | `d6a63fb17619` | Add dashboard incidents view and analyst outputs |
| `999337f8f2f5` | `52efc6d01c3e` | Add CI and ATT&CK badges, incident results, and a public-data demo script |
| `69e95aeadc8e` | `64959cb9515c` | Record all protocols at clean commit 999337f (no figure changed) |
| `de21cc50b456` | `a69758def3a8` | Add light/dark theme, a new Overview hero, and trim dashboard chrome |
| `5cf87be39847` | `9fe87dca41b0` | Record exploratory check: no structural fix for service-rule vendor false alarms in Sysmon-only data |
| `29c291ab4b10` | `e7785cf0af3e` | Pre-register signature suppressor for the service rule (S1) on 100 unused OTRF captures |
| `364218047477` | `e7acead71ff4` | Implement the S1 signature suppressor and the service-signature-v1 protocol |
| `c947e5dfd93a` | `e42e659c2f5b` | Record service-signature-v1: suppressor removed 0 of 7 vendor false alarms, not adopted |
