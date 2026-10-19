import { Activity, BarChart3, Download, GitBranch, Loader2, Siren } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { CategoryBadge, Empty, ErrorBox, Hash, KV, Loading, Notice, PageHeader, Panel, Pill, Stat, StatusPill } from "../components/ui";
import { ago, int, SIGNAL_LABELS, time } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { RunStatus } from "../types";
import { useWorkspace } from "../Workspace";

export function Runs() {
  const runs = useApi<RunStatus[]>("/api/runs", 3000, (list) => list.some((run) => run.state === "running" || run.state === "queued"));
  const navigate = useNavigate();
  const [filter, setFilter] = useState("");
  const rows = (runs.data ?? []).filter((run) => !filter || `${run.id} ${run.dataset_id} ${run.dataset_name} ${run.note} ${run.state}`.toLowerCase().includes(filter.toLowerCase()));
  return (
    <>
      <PageHeader eyebrow="history" title="Runs" actions={<input className="input w-72" placeholder="search runs (id, dataset, note, state)" value={filter} onChange={(event) => setFilter(event.target.value)} />}>
        Every detection run is a fresh execution with its own directory: configuration, dataset checksum, the package exporter's output, baseline decisions and evaluation. Reopening a run shows what was recorded then; it is not re-executed.
      </PageHeader>
      {runs.error && <ErrorBox error={runs.error} onRetry={runs.reload} />}
      {!runs.data && !runs.error && <Loading />}
      {runs.data && runs.data.length === 0 && (
        <Panel>
          <Empty title="No runs yet" action={<Link className="btn btn-primary" to="/datasets">Choose a dataset</Link>}>
            Start a run from a dataset page after validation.
          </Empty>
        </Panel>
      )}
      {rows.length > 0 && (
        <Panel bodyClass="overflow-x-auto">
          <table className="tbl">
            <thead>
              <tr>
                <th>Run</th>
                <th>Dataset</th>
                <th>Status</th>
                <th className="text-right">Accepted</th>
                <th className="text-right">Rejected</th>
                <th className="text-right">Chains</th>
                <th className="text-right">Windows</th>
                <th className="text-right">Detected</th>
                <th>Threshold</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((run) => (
                <tr key={run.id} className="row-link" onClick={() => navigate(`/runs/${run.id}`)}>
                  <td>
                    <div className="font-mono text-[12px]">{run.id}</div>
                    {run.note && <div className="text-2xs text-muted truncate max-w-xs">{run.note}</div>}
                  </td>
                  <td>
                    <div className="text-[12px]">{run.dataset_name}</div>
                    <CategoryBadge category={run.dataset_category} />
                  </td>
                  <td>
                    <StatusPill status={run.state} />
                    {run.state === "running" && <div className="text-2xs text-muted mt-0.5">{run.stage}</div>}
                  </td>
                  <td className="text-right font-mono">{int(run.summary?.records_accepted)}</td>
                  <td className="text-right font-mono">{int(run.summary?.records_rejected)}</td>
                  <td className="text-right font-mono">{int(run.summary?.lineage_chains)}</td>
                  <td className="text-right font-mono">{int(run.summary?.nonempty_windows)}</td>
                  <td className={`text-right font-mono ${run.summary?.detected_windows ? "text-detect" : ""}`}>{int(run.summary?.detected_windows)}</td>
                  <td className="font-mono text-2xs">{run.summary?.threshold ?? "—"}</td>
                  <td className="text-2xs text-muted whitespace-nowrap">{ago(run.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </>
  );
}

export function RunDetail() {
  const { id = "" } = useParams();
  const { setRunId, setDatasetId } = useWorkspace();
  const run = useApi<RunStatus>(`/api/runs/${id}`, 800, (value) => value.state === "running" || value.state === "queued");
  useEffect(() => {
    setRunId(id);
  }, [id, setRunId]);
  useEffect(() => {
    if (run.data) setDatasetId(run.data.dataset_id);
  }, [run.data, setDatasetId]);
  if (run.error) return <ErrorBox error={run.error} onRetry={run.reload} />;
  if (!run.data) return <Loading />;
  const data = run.data;
  const config = data.config;
  const summary = data.summary;
  const active = data.state === "running" || data.state === "queued";
  return (
    <>
      <PageHeader
        eyebrow={`detection run · ${data.state === "completed" ? "recorded output" : data.state}`}
        title={<span className="font-mono text-[19px]">{data.id}</span>}
        actions={
          data.state === "completed" && (
            <>
              <Link className="btn btn-primary" to={`/runs/${id}/detections`}>
                <Activity size={14} /> Detections
              </Link>
              <Link className="btn" to={`/runs/${id}/incidents`}>
                <Siren size={14} /> Incidents{summary?.incidents !== undefined ? ` (${summary.incidents})` : ""}
              </Link>
              <Link className="btn" to={`/runs/${id}/lineage`}>
                <GitBranch size={14} /> Lineage
              </Link>
              <Link className="btn" to={`/evaluation?run=${id}`}>
                <BarChart3 size={14} /> Evaluation
              </Link>
            </>
          )
        }
      >
        <span>
          {data.dataset_name} · <Link className="link font-mono" to={`/datasets/${data.dataset_id}`}>{data.dataset_id}</Link> · started {time(data.created_at)}
          {data.completed_at ? ` · completed ${time(data.completed_at)}` : ""}
        </span>
        {data.note && <div className="mt-1 italic">“{data.note}”</div>}
      </PageHeader>
      <StageProgress run={data} />
      {data.state === "failed" && (
        <div className="my-4 space-y-2">
          <ErrorBox error={`${data.error_type}: ${data.error}`} />
          {data.traceback && (
            <details className="panel p-3">
              <summary className="cursor-pointer text-2xs text-muted">traceback (recorded with the run)</summary>
              <pre className="font-mono text-2xs whitespace-pre-wrap mt-2 text-muted">{data.traceback}</pre>
            </details>
          )}
        </div>
      )}
      {active && <div className="text-muted text-[13px] my-4 flex items-center gap-2"><Loader2 size={14} className="animate-spin" /> Running stage “{data.stage}”…</div>}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3 my-5">
          <Stat label="records accepted" value={int(summary.records_accepted)} sub={`${int(summary.records_rejected)} rejected`} />
          <Stat label="process nodes" value={int(summary.process_nodes)} />
          <Stat label="lineage chains" value={int(summary.lineage_chains)} />
          <Stat label="scored windows" value={int(summary.scored_windows)} sub={`${int(summary.nonempty_windows)} contain events`} />
          <Stat label="detected windows" value={int(summary.detected_windows)} tone={summary.detected_windows ? "detect" : undefined} sub={`in ${int(summary.detected_chains)} chains`} />
          <Stat label="signals fired" value={Object.values(summary.signals_fired).reduce((a, b) => a + b, 0)} sub={Object.entries(summary.signals_fired).map(([s, n]) => `${s} ${n}`).join(" · ") || "none"} />
        </div>
      )}
      {config && (
        <div className="grid xl:grid-cols-2 gap-5">
          <Panel title="Configuration (as recorded)" eyebrow="reproduce with these values">
            <KV
              rows={[
                ["engine", <span className="font-mono text-2xs">{config.engine}</span>],
                ["dataset", <span>{config.dataset.name} <CategoryBadge category={config.dataset.category} /></span>],
                ["dataset SHA-256", <Hash value={config.dataset.sha256} length={20} />],
                ["records", `${int(config.dataset.records_read)} read · ${int(config.dataset.records_accepted)} accepted · ${int(config.dataset.records_rejected)} rejected · ${int(config.dataset.parse_errors)} unparseable`],
                ["mapping", <span className="font-mono text-2xs">{config.mapping.version}{config.mapping.spec.event_id_from_position ? " · event id derived from position" : ""}</span>],
                ["window", <span className="font-mono text-2xs">span {config.window.span_seconds}s · advance {config.window.advance_seconds}s · {time(config.window.start_at)} → {time(config.window.horizon_end_at)}</span>],
                ["threshold", <span className="font-mono">{config.threshold}</span>],
                [
                  "evidence channels",
                  config.evidence_channels?.enabled ? (
                    <span className="font-mono text-2xs">
                      on · {config.evidence_channels.pipe_evidence} pipe, {config.evidence_channels.remote_thread_evidence} remote-thread records · {config.evidence_channels.mapping}
                    </span>
                  ) : (
                    <span className="text-2xs text-muted">off{config.evidence_channels?.reason ? ` — ${config.evidence_channels.reason}` : " (run predates evidence channels)"}</span>
                  ),
                ],
                ["evidence model", <span className="font-mono text-2xs">{config.evidence_model.id} (prior applied {config.evidence_model.prior_applied})</span>],
                ["versions", <span className="font-mono text-2xs">cpes {String(config.versions.cpes)} · dashboard {String(config.versions.dashboard)} · python {String(config.versions.python)}</span>],
                ["git commit", <span className="font-mono text-2xs">{String(config.versions.commit ?? "unknown").slice(0, 12)}{config.versions.cpes_package_modified ? " · cpes/ had uncommitted changes" : ""}</span>],
              ]}
            />
          </Panel>
          <div className="space-y-5">
            <Panel title="Signals in this run">
              <table className="tbl">
                <tbody>
                  {Object.entries(config.signals).map(([signal, wiring]) => (
                    <tr key={signal}>
                      <td>
                        <div className="font-mono text-[12px]">{signal}</div>
                        <div className="text-2xs text-muted">{SIGNAL_LABELS[signal]}</div>
                      </td>
                      <td className="font-mono text-[12px] text-right">{Number(config.evidence_model.terms.find((t) => t.signal_id === signal)?.signed_log_likelihood ?? 0).toFixed(3)}</td>
                      <td>{wiring.wired ? <Pill tone="ok">wired</Pill> : <Pill tone="warn" title={wiring.note}>not wired in pipeline</Pill>}</td>
                      <td className="text-right font-mono text-[12px]">{summary?.signals_fired[signal] ?? 0}×</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="text-2xs text-muted mt-2">Weight · wiring status in CpesPipeline · detected windows where the signal fired.</p>
            </Panel>
            <Panel title="Artifacts" eyebrow="files written by this run">
              <div className="grid sm:grid-cols-2 gap-2">
                {[
                  ["detections.csv", "detected windows, one row each"],
                  ["export.json", "cpes.exporting.ResultExporter output, verbatim"],
                  ["config.json", "everything needed to reproduce"],
                  ["evaluation.json", "metrics (only if labels exist)"],
                  ["baseline.json", "single-event baseline per window"],
                  ["rejections.json", "records excluded, with reasons"],
                  ["incidents.json", "CPES (+ Sigma) alerts joined into incidents"],
                  ["attack-layer.json", "MITRE ATT&CK Navigator layer"],
                  ["alerts.ecs.ndjson", "CPES alerts as ECS documents for a SIEM"],
                ].map(([name, description]) => (
                  <a key={name} className="flex items-start gap-2 rounded border border-line px-3 py-2 hover:bg-hover" href={`/api/runs/${id}/download/${name}`}>
                    <Download size={14} className="mt-0.5 text-accent" />
                    <span>
                      <span className="font-mono text-[12px]">{name}</span>
                      <span className="block text-2xs text-muted">{description}</span>
                    </span>
                  </a>
                ))}
              </div>
            </Panel>
          </div>
        </div>
      )}
      {config?.dataset.category === "synthetic" && (
        <div className="mt-5">
          <Notice tone="warn" title="Synthetic input">This run used hand-written records. Its output demonstrates the mechanics only.</Notice>
        </div>
      )}
    </>
  );
}

function StageProgress({ run }: { run: RunStatus }) {
  const stages = run.stages.filter((stage) => stage !== "queued");
  const current = stages.indexOf(run.stage);
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {stages.map((stage, index) => {
        const done = run.state === "completed" || index < current;
        const isCurrent = index === current && run.state !== "completed";
        const failed = run.state === "failed" && isCurrent;
        const tone = failed ? "detect" : done ? "ok" : isCurrent ? "accent" : "faint";
        return (
          <span key={stage} className="flex items-center gap-1.5">
            <Pill tone={tone}>
              {stage}
              {run.timings?.[stage] !== undefined ? ` · ${run.timings[stage].toFixed(2)}s` : ""}
            </Pill>
            {index < stages.length - 1 && <span className="text-faint">→</span>}
          </span>
        );
      })}
    </div>
  );
}
