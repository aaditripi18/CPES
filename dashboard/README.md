# CPES research dashboard

A local web application around the unchanged `cpes` package: upload telemetry,
validate it record by record, explore the raw records, run `CpesPipeline`,
inspect every detection down to the records behind it, walk the reconstructed
process lineage, and re-run the research evaluation scripts with full provenance.

The dashboard computes no scores, signals or metrics of its own:

| What you see | Where it comes from |
|---|---|
| Validation results | `CanonicalEventMapper.map_document` + `CanonicalEventTranslator.translate`, called per record |
| Detections, scores, contributions | `cpes.orchestration.CpesPipeline` → `cpes.exporting.ResultExporter` (stored verbatim as `export.json`) |
| Resolver explanations | `cpes.context.ContextResolver.resolve` on the window's recorded event group |
| Baseline on a run | `cpes.baseline.SingleEventBaselineDetector` on the identical windows |
| Metrics on a run | `cpes.evaluation.EvaluationHarness`, only when the dataset has ground truth |
| Published figures | `analysis/*.py` and `demo/cpes_demo.py`, executed unchanged; stdout stored with script and input SHA-256 |
| Evidence weights | `dashboard/models/research-v3-full-table.json`, derived with `cpes.derivation.derive_evidence_model` by `dashboard/scripts/derive_evidence_model.py` |

## Run it

From the repository root, with the project venv active (Python 3.12):

```powershell
pip install -r requirements.txt -r dashboard/requirements.txt
cd dashboard/web; npm ci; npm run build; cd ../..
python dashboard/run_server.py
```

Open http://127.0.0.1:8790. The server binds to localhost only, because the lab
corpora contain the lab host and account names.

Frontend development with hot reload (API still on 8790):

```powershell
python dashboard/run_server.py --reload
cd dashboard/web; npm run dev     # http://localhost:5173, proxies /api
```

Tests:

```powershell
pytest dashboard/tests     # 29 tests; two skip without the private corpus
pytest tests               # the package's own suite, unchanged
```

## Where things are stored

`dashboard/data/` (git-ignored; override with `CPES_DASHBOARD_DATA`):

```
datasets/<upload-id>/original.<ext>, meta.json, validation/<mapping-key>.json
builtin/<dataset-id>/meta-cache.json, validation/…
runs/<run-id>/status.json, config.json, export.json, baseline.json,
              evaluation.json, rejections.json, chains.json, structure.json,
              processes.json, windows.json, audit.json, event_index.json
experiments/<exec-id>/record.json   (stdout, stderr, exit code, hashes)
```

A run or experiment is never overwritten; each start creates a new directory.
An upload that has runs cannot be deleted.

## Built-in datasets

| id | file | kind |
|---|---|---|
| `lab-corpus-v3` | `analysis/corpus-v3.ndjson` | research telemetry, private, process-level labels |
| `lab-corpus-combined` | `analysis/corpus-combined.ndjson` | research telemetry, private |
| `synthetic-format-preview` | `docs/sample-telemetry-SYNTHETIC.ndjson` | synthetic; needs position-derived event ids |
| `synthetic-legacy-sample` | `examples/synthetic-telemetry-sample.json` | synthetic; legacy schema, custom mapping suggested |

The `analysis/` corpora are git-ignored. On a fresh clone only the synthetic
datasets exist and the private-data experiments show as not runnable.

## Design

Visual system and page structure: `docs/dashboard/stitch_prompts.md`. The
assessment that led to this design: `docs/dashboard/ASSESSMENT.md`. Concerns
about the evaluation method: `docs/dashboard/EVALUATION-NOTES.md`.
