# vm-live-v1 session notes

Operational events during the session, recorded as they happened. None changes
the pre-registered procedure in [docs/design/vm-live-v1.md](../../docs/design/vm-live-v1.md).

- **Benign period**: 30 min, as scripted (`benign-period.csv`).
- **Part 1 (uac)**: 20 runs logged, 15:47:17Z–16:48:33Z on 2026-10-23. All five
  Fodhelper runs (T1548.002 #3) failed to start with "Access is denied" and have
  an empty exit code; the other 15 report exit code 0. Cause to be checked against
  Defender's detection history after the session, not assumed.
- **After part 1**: Elasticsearch in the VM stopped answering and the guest froze
  (screen clock stopped at 01:54 local). An ACPI shutdown was ignored; the VM was
  powered off from the host and restarted **without** reverting the snapshot, so
  telemetry still in the guest's event logs could be shipped by Winlogbeat.
  Elasticsearch's heap was then capped at 2 GB (`config/jvm.options.d/heap.options`)
  because the default (half of the VM's 8 GB) plus the Defender scan is the likely
  cause. Infrastructure only; detectors, labels and runs unchanged.
