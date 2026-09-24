# CPES — live demo

Runs the full CPES detection pipeline on the collected Sysmon telemetry and prints
a professional report to the terminal: telemetry ingest → evidence model →
per-instance scoring (with interpretable per-signal breakdown) → evaluation vs.
baselines → summary.

Pure Python 3 standard library — **no packages, no network, no VM** needed.

## Run

From the repository root:

```
python demo\cpes_demo.py
```

or from inside the folder:

```
cd demo
python cpes_demo.py
```

Options:
- `--no-color`  plain text (use if your terminal shows raw escape codes, or when redirecting to a file)
- `--corpus <path>` / `--log <path>`  point at a different corpus / atomic log

By default it reads `../analysis/corpus-v3.ndjson` and `../analysis/cpes-atomic-log-v3.csv`.

## Notes for the demo
- Colours render in Windows Terminal and PowerShell 5.1+. In legacy `cmd.exe` use `--no-color`.
- The numbers printed are computed live from the telemetry every run — nothing is hard-coded.
- The evaluation figures match the analysis in `docs/CPES-Corpus-v3-Evaluation-2026-09-01.md`.
