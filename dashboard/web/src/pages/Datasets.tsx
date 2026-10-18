import { FileUp, UploadCloud } from "lucide-react";
import { DragEvent, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { upload } from "../api";
import { CategoryBadge, ErrorBox, Hash, Loading, PageHeader, Panel, Pill, StatusPill } from "../components/ui";
import { bytes, int } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { DatasetMeta, ValidationReport } from "../types";
import { useWorkspace } from "../Workspace";

const ACCEPTED = [".csv", ".json", ".jsonl", ".ndjson", ".evtx"];
const MAX_BYTES = 256 * 1024 * 1024;

interface Inventory {
  datasets: DatasetMeta[];
  artifacts: { name: string; path: string; category: string; description: string; available: boolean; size_bytes: number | null }[];
}

export function Datasets() {
  const inventory = useApi<Inventory>("/api/inventory");
  return (
    <>
      <PageHeader eyebrow="data" title="Datasets">
        Upload telemetry, check it against the C5 field mapping record by record, then run the real CPES pipeline on it. Built-in datasets are registered by reference to files in the repository; uploads are stored byte-for-byte with their SHA-256.
      </PageHeader>
      <UploadPanel onUploaded={inventory.reload} />
      <div className="h-5" />
      {inventory.error && <ErrorBox error={inventory.error} onRetry={inventory.reload} />}
      {inventory.loading && !inventory.data && <Loading label="Reading inventory" />}
      {inventory.data && <InventoryTables inventory={inventory.data} />}
    </>
  );
}

function UploadPanel({ onUploaded }: { onUploaded: () => void }) {
  const navigate = useNavigate();
  const { setDatasetId } = useWorkspace();
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const [source, setSource] = useState("");
  const [synthetic, setSynthetic] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const choose = (candidate: File | undefined | null) => {
    setError(null);
    if (!candidate) return;
    const extension = candidate.name.slice(candidate.name.lastIndexOf(".")).toLowerCase();
    if (!ACCEPTED.includes(extension)) {
      setError(`"${candidate.name}" is not a supported file type. Use ${ACCEPTED.join(", ")}.`);
      return;
    }
    if (candidate.size > MAX_BYTES) {
      setError(`"${candidate.name}" is ${bytes(candidate.size)}; the limit is ${bytes(MAX_BYTES)}.`);
      return;
    }
    if (candidate.size === 0) {
      setError(`"${candidate.name}" is empty.`);
      return;
    }
    setFile(candidate);
    if (!name) setName(candidate.name);
  };

  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    setDragging(false);
    choose(event.dataTransfer.files?.[0]);
  };

  const submit = async () => {
    if (!file) return;
    const form = new FormData();
    form.append("file", file);
    form.append("name", name || file.name);
    if (source.trim()) form.append("declared_source", source.trim());
    form.append("declared_synthetic", String(synthetic));
    setProgress(0);
    setError(null);
    try {
      const meta = await upload<DatasetMeta & { validation_report: ValidationReport }>(form, setProgress);
      setDatasetId(meta.id);
      onUploaded();
      navigate(`/datasets/${meta.id}`);
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setProgress(null);
    }
  };

  return (
    <Panel title="Upload a dataset" eyebrow="evtx · csv · json · jsonl / ndjson · ≤ 256 MB">
      <div className="grid lg:grid-cols-[1fr_360px] gap-5">
        <div
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => input.current?.click()}
          role="button"
          tabIndex={0}
          onKeyDown={(event) => (event.key === "Enter" || event.key === " ") && input.current?.click()}
          className={`rounded-md border-2 border-dashed px-6 py-8 flex flex-col items-center justify-center text-center cursor-pointer transition-colors ${dragging ? "border-accent bg-accent-dim/40" : "border-line-strong hover:border-accent/60 hover:bg-hover/50"}`}
        >
          <UploadCloud size={28} className={dragging ? "text-accent" : "text-muted"} />
          {file ? (
            <div className="mt-3">
              <div className="font-mono text-[13px]">{file.name}</div>
              <div className="text-2xs text-muted mt-0.5">
                {bytes(file.size)} · {file.type || "unknown MIME type"} · modified {new Date(file.lastModified).toISOString().slice(0, 10)}
              </div>
            </div>
          ) : (
            <>
              <div className="mt-3 text-ink">Drop a telemetry file here, or click to choose</div>
              <div className="text-2xs text-muted mt-1 max-w-md leading-relaxed">
                Windows event-log exports (.evtx, e.g. Sysmon saved from Event Viewer) and Winlogbeat/ECS exports map automatically. Other schemas can be mapped field by field after upload. Nothing is changed in the file; records that fail validation are listed, never silently dropped.
              </div>
            </>
          )}
          <input ref={input} type="file" accept={ACCEPTED.join(",")} className="hidden" onChange={(event) => choose(event.target.files?.[0])} />
        </div>
        <div className="space-y-3">
          <label className="block">
            <span className="eyebrow">name</span>
            <input className="input w-full mt-1" value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. lab session 2026-10-18" />
          </label>
          <label className="block">
            <span className="eyebrow">where does this data come from?</span>
            <textarea className="input w-full mt-1 h-16 resize-none" value={source} onChange={(event) => setSource(event.target.value)} placeholder="Host, collector, time span — recorded with the dataset" />
          </label>
          <label className="flex items-start gap-2 text-[13px]">
            <input type="checkbox" className="mt-0.5 accent-[#a78bfa]" checked={synthetic} onChange={(event) => setSynthetic(event.target.checked)} />
            <span>
              This file is <b>synthetic</b> (hand-written or generated). It will carry a SYNTHETIC badge everywhere it appears.
            </span>
          </label>
          <button className="btn btn-primary w-full justify-center" disabled={!file || progress !== null} onClick={submit}>
            <FileUp size={15} /> {progress !== null ? `Uploading ${Math.round(progress * 100)}%` : "Upload and validate"}
          </button>
          {progress !== null && (
            <div className="h-1 bg-raised rounded">
              <div className="h-full bg-accent rounded" style={{ width: `${progress * 100}%` }} />
            </div>
          )}
          {error && <ErrorBox error={error} />}
        </div>
      </div>
    </Panel>
  );
}

function InventoryTables({ inventory }: { inventory: Inventory }) {
  const navigate = useNavigate();
  return (
    <>
      <Panel title="Dataset inventory" eyebrow={`${inventory.datasets.length} datasets`} bodyClass="overflow-x-auto">
        <table className="tbl">
          <thead>
            <tr>
              <th>Dataset</th>
              <th>Category</th>
              <th>Format</th>
              <th className="text-right">Records</th>
              <th className="text-right">Size</th>
              <th>SHA-256</th>
              <th>Ground truth</th>
              <th>Validation</th>
              <th className="text-right">Runs</th>
            </tr>
          </thead>
          <tbody>
            {inventory.datasets.map((dataset) => (
              <tr key={dataset.id} className="row-link" onClick={() => navigate(`/datasets/${dataset.id}`)}>
                <td>
                  <div className="font-medium">{dataset.name}</div>
                  <div className="font-mono text-2xs text-muted">{dataset.path ?? dataset.original_filename}</div>
                  {!dataset.available && <Pill tone="detect">file not present locally</Pill>}
                </td>
                <td>
                  <CategoryBadge category={dataset.category} isPrivate={dataset.private} />
                </td>
                <td className="font-mono text-2xs">{dataset.format}</td>
                <td className="text-right font-mono">{dataset.records !== undefined ? int(dataset.records) : <span className="text-faint" title="counted when first opened">—</span>}</td>
                <td className="text-right font-mono text-2xs">{bytes(dataset.size_bytes)}</td>
                <td onClick={(event) => event.stopPropagation()}>
                  <Hash value={dataset.sha256} />
                </td>
                <td className="text-2xs">{dataset.ground_truth.available ? <Pill tone="ok">yes · {dataset.ground_truth.unit}</Pill> : <Pill tone="faint">none</Pill>}</td>
                <td>
                  <StatusPill status={dataset.validation?.status} />
                </td>
                <td className="text-right font-mono">{dataset.runs ?? 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
      <div className="h-5" />
      <Panel title="Other research artifacts" eyebrow="labels, execution ledgers, archives — listed, not loaded" bodyClass="overflow-x-auto">
        <table className="tbl">
          <thead>
            <tr>
              <th>Artifact</th>
              <th>Kind</th>
              <th>Description</th>
              <th className="text-right">Size</th>
              <th>Present</th>
            </tr>
          </thead>
          <tbody>
            {inventory.artifacts.map((artifact) => (
              <tr key={artifact.path}>
                <td>
                  <div>{artifact.name}</div>
                  <div className="font-mono text-2xs text-muted">{artifact.path}</div>
                </td>
                <td className="font-mono text-2xs text-muted">{artifact.category.replace(/_/g, " ")}</td>
                <td className="text-[12px] text-muted max-w-xl">{artifact.description}</td>
                <td className="text-right font-mono text-2xs">{bytes(artifact.size_bytes)}</td>
                <td>{artifact.available ? <Pill tone="ok">yes</Pill> : <Pill tone="detect">missing</Pill>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
      <p className="text-2xs text-muted mt-3">
        Not shown because they do not exist in this repository: any multi-host corpus, organic enterprise traffic, or the corpus-v4 records outside its zip. See <Link className="link" to="/system">System &amp; limits</Link>.
      </p>
    </>
  );
}
