import { Play, RefreshCw, Search, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { del, post } from "../api";
import { BarList } from "../components/charts";
import { CategoryBadge, Empty, ErrorBox, Hash, KV, Loading, Notice, PageHeader, Panel, Pill, StatusPill, Tabs } from "../components/ui";
import { bytes, duration, eventCodeLabel, int, time } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { DatasetDetail as Detail, EvidenceModelInfo, MappingField, MappingSpec, RunStatus, SchemaEntry, ValidationReport } from "../types";
import { useWorkspace } from "../Workspace";

const CANONICAL_HELP: Record<string, string> = {
  source_timestamp: "ISO 8601 with an offset (e.g. …Z). Orders the stream.",
  source_event_id: "Unique per record. Ties with the timestamp break ordering.",
  event_code: "Sysmon event ID (1, 8, 13, 17, 18 …).",
  process_guid: "Sysmon ProcessGuid — the only identity key for lineage.",
  parent_process_guid: "ParentProcessGuid; never inferred when missing.",
  process_id: "PID (informational).",
  integrity_level: "Untrusted / Low / Medium / High / System.",
  command_line: "Process command line.",
  registry_object: "Registry path for EID 12/13.",
  image_path: "Executable path.",
  module_path: "Loaded module path (EID 7).",
};

export function DatasetDetail() {
  const { id = "" } = useParams();
  const { setDatasetId } = useWorkspace();
  const dataset = useApi<Detail>(`/api/datasets/${id}`);
  const [tab, setTab] = useState<"validation" | "schema" | "metadata">("validation");
  useEffect(() => {
    if (dataset.data) setDatasetId(dataset.data.id);
  }, [dataset.data, setDatasetId]);

  if (dataset.error) return <ErrorBox error={dataset.error} onRetry={dataset.reload} />;
  if (!dataset.data) return <Loading label="Parsing dataset" />;
  const data = dataset.data;
  return (
    <>
      <PageHeader
        eyebrow={`dataset · ${data.origin}`}
        title={
          <span className="flex flex-wrap items-center gap-3">
            {data.name} <CategoryBadge category={data.category} isPrivate={data.private} />
          </span>
        }
        actions={
          <Link className="btn" to={`/explore/${data.id}`}>
            <Search size={15} /> Explore {int(data.records)} records
          </Link>
        }
      >
        {data.source}
      </PageHeader>
      {data.category === "synthetic" && (
        <div className="mb-4">
          <Notice tone="warn" title="Synthetic data">
            These records were written by hand to illustrate the format. Any detection on them demonstrates how the pipeline works; it says nothing about detection performance on real activity.
          </Notice>
        </div>
      )}
      <div className="grid xl:grid-cols-[1fr_340px] gap-5 items-start">
        <div className="panel min-w-0">
          <Tabs
            value={tab}
            onChange={setTab}
            items={[
              { id: "validation", label: "Validation & mapping" },
              { id: "schema", label: "Schema" },
              { id: "metadata", label: "Metadata" },
            ]}
          />
          <div className="p-4">
            {tab === "validation" && <ValidationSection dataset={data} />}
            {tab === "schema" && <SchemaSection datasetId={data.id} />}
            {tab === "metadata" && <MetadataSection dataset={data} />}
          </div>
        </div>
        <SideFacts dataset={data} />
      </div>
    </>
  );
}

function SideFacts({ dataset }: { dataset: Detail }) {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  return (
    <div className="space-y-4">
      <Panel title="File">
        <KV
          rows={[
            ["format", <span className="font-mono">{dataset.format}</span>],
            ["records read", <span className="font-mono">{int(dataset.records)}</span>],
            ["parse errors", <span className={`font-mono ${dataset.parse_error_count ? "text-detect" : ""}`}>{int(dataset.parse_error_count)}</span>],
            ["blank lines", <span className="font-mono">{int(dataset.blank_lines)}</span>],
            ["size", bytes(dataset.size_bytes)],
            ["SHA-256", <Hash value={dataset.sha256} length={16} />],
            ["timestamp field", <span className="font-mono">{dataset.timestamp_field ?? "none found"}</span>],
          ]}
        />
      </Panel>
      <Panel title="Ground truth">
        {dataset.ground_truth.available ? (
          <div className="space-y-2 text-[13px]">
            <Pill tone="ok">available · unit: {dataset.ground_truth.unit}</Pill>
            <div className="font-mono text-2xs text-muted break-all">{dataset.ground_truth.source}</div>
            <p className="text-muted leading-relaxed">{dataset.ground_truth.how}</p>
          </div>
        ) : (
          <div className="text-[13px] text-muted leading-relaxed">
            <Pill tone="faint">none</Pill>
            <p className="mt-2">{dataset.ground_truth.how}</p>
          </div>
        )}
      </Panel>
      {dataset.origin === "upload" && (
        <Panel title="Manage">
          <button
            className="btn w-full justify-center text-detect"
            onClick={async () => {
              if (!window.confirm(`Delete upload "${dataset.name}"? The stored file is removed. Refused if any run used it.`)) return;
              try {
                await del(`/api/datasets/${dataset.id}`);
                navigate("/datasets");
              } catch (reason) {
                setError((reason as Error).message);
              }
            }}
          >
            <Trash2 size={14} /> Delete upload
          </button>
          {error && <div className="mt-2"><ErrorBox error={error} /></div>}
        </Panel>
      )}
    </div>
  );
}

function MetadataSection({ dataset }: { dataset: Detail }) {
  return (
    <KV
      rows={[
        ["id", <span className="font-mono">{dataset.id}</span>],
        ["origin", dataset.origin === "builtin" ? "registered by reference (not copied)" : `uploaded ${time(dataset.uploaded_at)}`],
        ["path / file", <span className="font-mono text-2xs">{dataset.path ?? dataset.original_filename}</span>],
        ["source", dataset.source],
        ["contents", dataset.contents ?? "—"],
        ["notes", dataset.notes ?? "—"],
        ["privacy", dataset.private ? "Private: contains identifiers from the collection environment. Local use only." : "Safe to show publicly."],
        ["associated experiments", dataset.experiments.length ? dataset.experiments.map((e) => <Link key={e} className="link font-mono mr-2" to={`/evaluation#${e}`}>{e}</Link>) : "none"],
      ]}
    />
  );
}

function SchemaSection({ datasetId }: { datasetId: string }) {
  const schema = useApi<SchemaEntry[]>(`/api/datasets/${datasetId}/schema`);
  const [filter, setFilter] = useState("");
  if (schema.error) return <ErrorBox error={schema.error} />;
  if (!schema.data) return <Loading label="Inspecting fields" />;
  const rows = schema.data.filter((entry) => entry.path.toLowerCase().includes(filter.toLowerCase()));
  return (
    <>
      <div className="flex items-center justify-between gap-3 mb-3">
        <div className="text-[13px] text-muted">{schema.data.length} distinct field paths. Coverage = share of records where the path is present.</div>
        <input className="input w-64" placeholder="filter fields" value={filter} onChange={(event) => setFilter(event.target.value)} />
      </div>
      <div className="overflow-x-auto max-h-[560px] overflow-y-auto">
        <table className="tbl">
          <thead className="sticky top-0 bg-panel">
            <tr>
              <th>Field path</th>
              <th className="text-right">Present</th>
              <th className="w-40">Coverage</th>
              <th>Types</th>
              <th>Examples</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((entry) => (
              <tr key={entry.path}>
                <td className="font-mono text-[12px] break-all">{entry.path}</td>
                <td className="text-right font-mono text-[12px]">{int(entry.present)}</td>
                <td>
                  <div className="h-1.5 bg-raised rounded">
                    <div className="h-full bg-info/70 rounded" style={{ width: `${entry.coverage * 100}%` }} />
                  </div>
                  {entry.missing > 0 && (
                    <Link className="text-2xs link" to={`/explore/${datasetId}?missing=${encodeURIComponent(entry.path)}`}>
                      {int(entry.missing)} missing
                    </Link>
                  )}
                </td>
                <td className="font-mono text-2xs text-muted">{Object.entries(entry.types).map(([type, count]) => `${type} ${int(count)}`).join(" · ")}</td>
                <td className="font-mono text-2xs text-muted max-w-xs truncate" title={entry.examples.join(" | ")}>
                  {entry.examples.join(" | ")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function ValidationSection({ dataset }: { dataset: Detail }) {
  const initial: MappingSpec = dataset.suggested_mapping ?? { preset: "elastic-sysmon-field-mapping-v1", overrides: {}, event_id_from_position: false };
  const [spec, setSpec] = useState<MappingSpec>(initial);
  const [report, setReport] = useState<ValidationReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const schema = useApi<SchemaEntry[]>(`/api/datasets/${dataset.id}/schema`);

  const run = async (next: MappingSpec) => {
    setBusy(true);
    setError(null);
    try {
      setReport(await post<ValidationReport>(`/api/datasets/${dataset.id}/validate`, next));
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    run(initial);
    // run once per dataset with its suggested mapping
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dataset.id]);

  return (
    <div className="space-y-5">
      {dataset.structure_errors.length > 0 && (
        <Notice tone="detect" title="The file could not be read as records">
          {dataset.structure_errors.map((message) => (
            <div key={message}>{message}</div>
          ))}
        </Notice>
      )}
      <MappingEditor spec={spec} onChange={setSpec} fields={report?.mapping?.fields} schema={schema.data ?? []} presence={report?.field_presence} />
      <div className="flex items-center gap-3">
        <button className="btn" disabled={busy} onClick={() => run(spec)}>
          <RefreshCw size={14} className={busy ? "animate-spin" : ""} /> Validate with this mapping
        </button>
        {busy && <span className="text-2xs text-muted">mapping every record through CanonicalEventMapper + CanonicalEventTranslator…</span>}
      </div>
      {error && <ErrorBox error={error} />}
      {report && <ValidationReportView report={report} datasetId={dataset.id} />}
      {report && <RunLauncher datasetId={dataset.id} report={report} spec={spec} />}
    </div>
  );
}

function MappingEditor({ spec, onChange, fields, schema, presence }: { spec: MappingSpec; onChange: (spec: MappingSpec) => void; fields?: MappingField[]; schema: SchemaEntry[]; presence?: Record<string, number> }) {
  const paths = useMemo(() => schema.map((entry) => entry.path), [schema]);
  const coverage = useMemo(() => Object.fromEntries(schema.map((entry) => [entry.path, entry.coverage])), [schema]);
  const overrides = spec.overrides ?? {};
  const effective = (destination: string) => {
    if (destination in overrides) return overrides[destination] ?? "";
    return fields?.find((field) => field.destination === destination)?.source ?? "";
  };
  const canonical = ["source_timestamp", "source_event_id", "event_code", "process_guid", "parent_process_guid", "process_id", "integrity_level", "command_line", "registry_object", "image_path", "module_path"];
  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
        <div>
          <div className="font-semibold">Field mapping</div>
          <div className="text-2xs text-muted">Source path → canonical field. Values are copied as-is: no parsing, normalisation or enrichment (C5 contract).</div>
        </div>
        <div className="flex items-center gap-3 text-[13px]">
          <label className="flex items-center gap-1.5">
            <span className="text-muted">base</span>
            <select className="input py-1" value={spec.preset ?? ""} onChange={(event) => onChange({ ...spec, preset: event.target.value || null })}>
              <option value="elastic-sysmon-field-mapping-v1">elastic-sysmon-field-mapping-v1</option>
              <option value="">none (map every field)</option>
            </select>
          </label>
          <label className="flex items-center gap-1.5" title="For files without a record id. The id is derived from the record's position (rec-0000001…) and shown as derived everywhere.">
            <input type="checkbox" className="accent-[#a78bfa]" checked={!!spec.event_id_from_position} onChange={(event) => onChange({ ...spec, event_id_from_position: event.target.checked })} />
            <span>derive event id from record position</span>
          </label>
        </div>
      </div>
      <datalist id="schema-paths">
        {paths.map((path) => (
          <option key={path} value={path} />
        ))}
      </datalist>
      <div className="overflow-x-auto">
        <table className="tbl">
          <thead>
            <tr>
              <th>Canonical field</th>
              <th>Source path</th>
              <th className="text-right">Present after mapping</th>
              <th>Meaning</th>
            </tr>
          </thead>
          <tbody>
            {canonical.map((destination) => {
              const required = destination === "source_timestamp" || destination === "source_event_id";
              const fromPosition = destination === "source_event_id" && spec.event_id_from_position;
              const value = effective(destination);
              const inSchema = value && paths.includes(value);
              return (
                <tr key={destination}>
                  <td className="font-mono text-[12px] whitespace-nowrap">
                    {destination} {required && <Pill tone="accent">required</Pill>}
                  </td>
                  <td>
                    {fromPosition ? (
                      <Pill tone="warn" dashed>derived: record position</Pill>
                    ) : (
                      <div className="flex items-center gap-2">
                        <input
                          list="schema-paths"
                          className={`input w-80 font-mono text-[12px] ${value && !inSchema ? "border-warn/70" : ""}`}
                          value={value}
                          placeholder="unmapped"
                          onChange={(event) => onChange({ ...spec, overrides: { ...overrides, [destination]: event.target.value || null } })}
                        />
                        {value && !inSchema && <span className="text-2xs text-warn">not in this file</span>}
                        {value && inSchema && <span className="text-2xs text-muted font-mono">{Math.round((coverage[value] ?? 0) * 100)}% of records</span>}
                      </div>
                    )}
                  </td>
                  <td className="text-right font-mono text-[12px]">{presence ? int(presence[destination]) : "—"}</td>
                  <td className="text-2xs text-muted">{CANONICAL_HELP[destination]}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ValidationReportView({ report, datasetId }: { report: ValidationReport; datasetId: string }) {
  const [showAll, setShowAll] = useState(false);
  if (report.mapping_error) return <ErrorBox error={`Mapping is not usable: ${report.mapping_error}`} />;
  const codes = Object.entries(report.event_codes ?? {}).map(([code, count]) => ({ key: code, label: eventCodeLabel(code), value: count }));
  const rejections = report.rejections ?? [];
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <StatusPill status={report.status} />
        <span className="text-2xs text-muted font-mono">mapping {report.mapping?.version} · computed {time(report.computed_at)}</span>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
        {[
          ["read", report.records_read],
          ["accepted", report.accepted],
          ["rejected", report.rejected],
          ["parse errors", report.parse_error_count],
          ["no process_guid", report.without_process_guid ?? 0],
        ].map(([label, value]) => (
          <div key={label as string} className="rounded border border-line px-3 py-2 bg-raised/50">
            <div className="eyebrow">{label}</div>
            <div className={`font-mono text-[17px] ${(label === "rejected" || label === "parse errors") && Number(value) > 0 ? "text-detect" : ""}`}>{int(value as number)}</div>
          </div>
        ))}
      </div>
      {report.time_range && (
        <div className="text-[13px]">
          <span className="text-muted">time range </span>
          <span className="font-mono">
            {time(report.time_range.start)} → {time(report.time_range.end)}
          </span>
          <span className="text-muted"> ({duration(report.time_range.seconds)})</span>
          {report.lineage_preview && (
            <span className="text-muted">
              {" "}
              · lineage preview: <span className="font-mono text-ink">{int(report.lineage_preview.process_nodes)}</span> process nodes, <span className="font-mono text-ink">{int(report.lineage_preview.chains)}</span> chains, <span className="font-mono text-ink">{int(report.lineage_preview.truncated_chains)}</span> truncated
            </span>
          )}
        </div>
      )}
      {report.cross_record_errors.length > 0 && (
        <Notice tone="detect" title="Dataset-level errors (the pipeline would refuse this input)">
          {report.cross_record_errors.slice(0, 20).map((item, index) => (
            <div key={index} className="font-mono text-2xs">{item.message}</div>
          ))}
        </Notice>
      )}
      {report.warnings.length > 0 && (
        <Notice tone="warn" title={`${report.warnings.length} warning${report.warnings.length > 1 ? "s" : ""}`}>
          <ul className="list-disc pl-4 space-y-0.5">
            {report.warnings.map((warning) => (
              <li key={warning.code + warning.message}>{warning.message}</li>
            ))}
          </ul>
        </Notice>
      )}
      {(report.rejection_summary?.length ?? 0) > 0 && (
        <div>
          <div className="font-semibold mb-1.5">Rejected records — grouped by reason</div>
          <table className="tbl">
            <thead>
              <tr>
                <th>Stage</th>
                <th>Error (verbatim from the package)</th>
                <th className="text-right">Records</th>
              </tr>
            </thead>
            <tbody>
              {report.rejection_summary!.map((row) => (
                <tr key={row.stage + row.error}>
                  <td className="font-mono text-2xs">{row.stage}</td>
                  <td className="font-mono text-[12px] text-detect">{row.error}</td>
                  <td className="text-right font-mono">{int(row.count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <button className="link text-2xs mt-2" onClick={() => setShowAll(!showAll)}>
            {showAll ? "hide" : "show"} individual rejections ({int(report.rejected)}{report.rejected > rejections.length ? `, first ${rejections.length} listed` : ""})
          </button>
          {showAll && (
            <div className="max-h-72 overflow-y-auto mt-2">
              <table className="tbl">
                <tbody>
                  {rejections.map((row) => (
                    <tr key={row.index}>
                      <td className="font-mono text-2xs whitespace-nowrap">
                        <Link className="link" to={`/explore/${datasetId}?record=${row.index}`}>
                          {report.format === "json" ? `item ${row.location}` : `line ${row.location}`}
                        </Link>
                      </td>
                      <td className="font-mono text-2xs">{row.stage}</td>
                      <td className="font-mono text-2xs text-detect">{row.error}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
      {report.parse_error_count > 0 && (
        <div>
          <div className="font-semibold mb-1.5">Unparseable lines ({int(report.parse_error_count)})</div>
          <div className="max-h-56 overflow-y-auto">
            <table className="tbl">
              <tbody>
                {report.parse_errors.map((row) => (
                  <tr key={row.location}>
                    <td className="font-mono text-2xs whitespace-nowrap">line {row.location}</td>
                    <td className="font-mono text-2xs text-detect">{row.error}</td>
                    <td className="font-mono text-2xs text-muted truncate max-w-md">{row.excerpt}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {codes.length > 0 && (
        <div>
          <div className="font-semibold mb-1.5">Accepted records by event code</div>
          <BarList items={codes} tone="info" onSelect={undefined} />
        </div>
      )}
    </div>
  );
}

function RunLauncher({ datasetId, report, spec }: { datasetId: string; report: ValidationReport; spec: MappingSpec }) {
  const navigate = useNavigate();
  const { setRunId } = useWorkspace();
  const models = useApi<EvidenceModelInfo[]>("/api/evidence-models");
  const model = models.data?.[0];
  const [span, setSpan] = useState("300");
  const [advance, setAdvance] = useState("150");
  const [threshold, setThreshold] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [evidenceChannels, setEvidenceChannels] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const invalid = report.status === "invalid";
  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      const run = await post<RunStatus>("/api/runs", { dataset_id: datasetId, mapping: spec, span_seconds: Number(span), advance_seconds: Number(advance), threshold: threshold ?? model?.default_threshold, evidence_model_id: model?.id, note, evidence_channels: evidenceChannels });
      setRunId(run.id);
      navigate(`/runs/${run.id}`);
    } catch (reason) {
      setError((reason as Error).message);
      setBusy(false);
    }
  };
  return (
    <div className="rounded-md border border-accent/30 bg-accent-dim/20 p-4">
      <div className="flex items-center justify-between gap-3 mb-3">
        <div>
          <div className="font-semibold">Run CPES on this dataset</div>
          <div className="text-2xs text-muted">Executes cpes.orchestration.CpesPipeline on the {int(report.accepted)} accepted records. A new run directory is created; earlier runs are never overwritten.</div>
        </div>
        <button className="btn btn-primary" disabled={invalid || busy || !model} onClick={start}>
          <Play size={14} /> {busy ? "Starting…" : "Start run"}
        </button>
      </div>
      {invalid && <Notice tone="detect">Validation status is invalid, so a run is not allowed. Fix the mapping or the file first.</Notice>}
      <div className="grid md:grid-cols-4 gap-3">
        <label className="block">
          <span className="eyebrow">window span (s)</span>
          <input className="input w-full mt-1 font-mono" value={span} onChange={(event) => setSpan(event.target.value)} />
        </label>
        <label className="block">
          <span className="eyebrow">advance (s) ≤ span</span>
          <input className="input w-full mt-1 font-mono" value={advance} onChange={(event) => setAdvance(event.target.value)} />
        </label>
        <label className="block">
          <span className="eyebrow">threshold (log-odds)</span>
          <input className="input w-full mt-1 font-mono" value={threshold ?? model?.default_threshold ?? ""} onChange={(event) => setThreshold(event.target.value)} />
        </label>
        <label className="block">
          <span className="eyebrow">note (recorded with the run)</span>
          <input className="input w-full mt-1" value={note} onChange={(event) => setNote(event.target.value)} placeholder="optional" />
        </label>
      </div>
      <label className="flex items-start gap-2 text-[13px] mt-3">
        <input type="checkbox" className="mt-0.5 accent-[#a78bfa]" checked={evidenceChannels} onChange={(event) => setEvidenceChannels(event.target.checked)} />
        <span>
          Attach cross-channel evidence (named pipes EID 17/18, remote threads EID 8) so the token-impersonation and injection signals can fire. Untick to reproduce the package as it was before evidence channels.
        </span>
      </label>
      {model && (
        <div className="mt-3 text-2xs text-muted leading-relaxed">
          Evidence model <span className="font-mono text-ink">{model.id}</span>: weights {model.terms.map((t) => `${t.signal_id} ${Number(t.signed_log_likelihood).toFixed(2)}`).join(", ")}; prior applied {model.prior_applied} (derived prior {Number(model.prior_log_odds_derived).toFixed(3)} recorded, not applied — {model.prior_note}) {model.scope_note}
        </div>
      )}
      {!model && !models.loading && <Empty title="No evidence model found">dashboard/models/ is empty. Run dashboard/scripts/derive_evidence_model.py.</Empty>}
      {error && <div className="mt-3"><ErrorBox error={error} /></div>}
    </div>
  );
}
