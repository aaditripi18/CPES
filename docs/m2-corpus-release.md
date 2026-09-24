# M2 corpus release metadata procedure

This document specifies how a future, manually generated corpus will be
identified reproducibly. It creates no archive, checksum, release asset, or
corpus data.

After approved laboratory collection is complete, the operator will:

1. Create the attack and benign corpus archive outside the normal Git working
   tree.
2. Record the archive filename, cryptographic checksum, and release reference
   in `corpus/cpes-telemetry-corpus-v1/manifest.json`.
3. Retain the completed `execution-ledger.csv` alongside the manifest.
4. Freeze the archive and metadata under the corpus version
   `cpes-telemetry-corpus-v1`.

Until those manual actions are explicitly authorized and complete, the manifest
must retain `"status": "template"`, the ledger must have no data rows, and no
raw telemetry belongs in this repository.
