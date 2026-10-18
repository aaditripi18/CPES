import { FileText, Play } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { post } from "../api";
import { Confusion, MetricBars } from "../components/charts";
import { Empty, ErrorBox, Hash, KV, Loading, Notice, PageHeader, Panel, Pill, StatusPill } from "../components/ui";
import { ago, bytes, int, ratio, time } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { CatalogEntry, Claim, DetectorRow, ExperimentRecord, Metrics, RunEvaluation, RunStatus } from "../types";
import { useWorkspace } from "../Workspace";

const ROLE_TONES: Record<string, "ok" | "info" | "accent" | "warn" | "detect" | "faint" | "neutral"> = {
  canonical: "ok",
  supporting: "info",
  validity_check: "accent",
  ablation: "neutral",
  robustness: "neutral",
  adverse_result: "detect",
  unavailable: "faint",
  demo: "warn",
};

interface Note {
  topic: string;
  severity: string;
  where: string;
  finding: string;
  mitigation_in_repo: string;
}

export function Evaluation() {
  const [params, setParams] = useSearchParams();
  const { runId } = useWorkspace();
  const selectedRun = params.get("run") ?? runId;
  const catalog = useApi<CatalogEntry[]>("/api/experiments/catalog", 1500, (items) => items.some((item) => item.latest?.state === "running"));
  const claims = useApi<Claim[]>("/api/experiments/claims");
  const notes = useApi<Note[]>("/api/experiments/notes");
  const runs = useApi<RunStatus[]>("/api/runs");
  const [error, setError] = useState<string | null>(null);
  const start = async (id: string) => {
    setError(null);
    try {
      await post<ExperimentRecord>("/api/experiments", { experiment_id: id });
      catalog.reload();
    } catch (reason) {
      setError((reason as Error).message);
    }
  };
  const latestIds = (catalog.data ?? []).map((item) => `${item.latest?.id}:${item.latest?.state}`).join(",");
  const reloadClaims = claims.reload;
  useEffect(() => {
    reloadClaims();
  }, [latestIds, reloadClaims]);
  useEffect(() => {
    if (window.location.hash && catalog.data) document.getElementById(window.location.hash.slice(1))?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [catalog.data]);
  const canonical = catalog.data?.find((item) => item.id === "grouped_cv");

  return (
    <>
      <PageHeader eyebrow="research" title="Evaluation workbench">
        Four different things are kept apart here: a <b>detection run</b> (no labels needed), <b>evaluation with labels</b> of a run, <b>cross-validation</b> as the paper reports it, and <b>recorded experiments</b> re-executed from the unchanged analysis scripts. Numbers from different protocols are never placed in one table.
      </PageHeader>
      <div className="grid md:grid-cols-4 gap-3 mb-5">
        {[
          ["Detection run", "CpesPipeline on any validated dataset. Scores and decisions only.", "Runs page"],
          ["Evaluation with labels", "Run decisions vs ground truth, via cpes.evaluation. Only for datasets with labels.", "Band 3 below"],
          ["Cross-validation", "Weights re-derived per training fold (analysis scripts). The paper's protocol.", "Band 2 below"],
          ["Recorded experiment", "A stored execution of a script: stdout, exit code, script and input SHA-256.", "Band 2 below"],
        ].map(([title, text, where]) => (
          <div key={title} className="panel px-4 py-3">
            <div className="font-semibold text-[13px]">{title}</div>
            <div className="text-2xs text-muted mt-1 leading-relaxed">{text}</div>
            <div className="eyebrow mt-2">{where}</div>
          </div>
        ))}
      </div>

      <Panel title="1 · Published figures, checked against fresh executions" eyebrow="README & paper hand-off ↔ analysis scripts" className="mb-5" bodyClass="overflow-x-auto">
        {claims.error && <ErrorBox error={claims.error} />}
        {claims.data && (
          <table className="tbl">
            <thead>
              <tr>
                <th>Claim</th>
                <th className="text-right">Stated</th>
                <th className="text-right">Latest execution</th>
                <th>Status</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {claims.data.map((claim) => (
                <tr key={claim.claim}>
                  <td>{claim.claim}</td>
                  <td className="text-right font-mono">{claim.expected.toFixed(3)}</td>
                  <td className="text-right font-mono">{claim.observed === null ? "—" : claim.observed.toFixed(3)}</td>
                  <td><StatusPill status={claim.status} /></td>
                  <td className="text-2xs">
                    {claim.execution_id ? <Link className="link font-mono" to={`/experiments/${claim.execution_id}`}>{claim.experiment}</Link> : <a className="link font-mono" href={`#${claim.experiment}`}>{claim.experiment}</a>}
                    <span className="text-muted"> · {claim.detector} · {claim.metric}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="text-2xs text-muted mt-2">“Matches” means the script printed the same value to three decimals in an execution recorded on this machine. Run the experiments below to check.</p>
      </Panel>

      <Panel title="2 · Recorded research experiments" eyebrow="analysis/ scripts, executed unchanged" className="mb-5">
        {error && <div className="mb-3"><ErrorBox error={error} /></div>}
        {catalog.error && <ErrorBox error={catalog.error} />}
        {!catalog.data && !catalog.error && <Loading />}
        {canonical?.latest?.parsed && (
          <div className="mb-5 rounded-md border border-ok/30 bg-ok-dim/20 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <div>
                <div className="font-semibold">Canonical comparison — grouped 5-fold CV</div>
                <div className="text-2xs text-muted font-mono">{canonical.protocol}</div>
              </div>
              <Link className="link text-2xs" to={`/experiments/${canonical.latest.id}`}>execution {canonical.latest.id} · {ago(canonical.latest.completed_at)}</Link>
            </div>
            <DetectorBars detectors={canonical.latest.parsed.detectors} highlight="CPES (context WoE)" />
            {canonical.latest.parsed.units && (
              <div className="text-2xs text-muted mt-3">
                {int(canonical.latest.parsed.units.units)} process units · {int(canonical.latest.parsed.units.attack)} attack · {int(canonical.latest.parsed.units.benign)} benign · {canonical.latest.parsed.aggregation} · whiskers = ±1 std
              </div>
            )}
          </div>
        )}
        <div className="grid xl:grid-cols-2 gap-3">
          {catalog.data?.map((entry) => (
            <div key={entry.id} id={entry.id} className="rounded-md border border-line bg-raised/40 p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Pill tone={ROLE_TONES[entry.role] ?? "neutral"}>{entry.role.replace(/_/g, " ")}</Pill>
                    <span className="font-semibold text-[13px]">{entry.title}</span>
                  </div>
                  <div className="font-mono text-2xs text-muted mt-1">{entry.script}</div>
                </div>
                <button className="btn shrink-0" disabled={!entry.runnable || entry.latest?.state === "running"} onClick={() => start(entry.id)} title={entry.runnable ? "Execute the script now and record the output" : `missing: ${entry.missing_inputs.join(", ")}`}>
                  <Play size={13} /> {entry.latest?.state === "running" ? "running…" : entry.latest ? "Run again" : "Run"}
                </button>
              </div>
              <div className="text-2xs font-mono text-ink/80 mt-2">{entry.protocol}</div>
              {entry.role_note && <div className="text-2xs text-muted mt-1.5 leading-relaxed">{entry.role_note}</div>}
              {!entry.runnable && <div className="mt-2"><Notice tone="warn">Cannot run here: {entry.missing_inputs.join(", ")} not present.</Notice></div>}
              {entry.latest && (
                <div className="mt-3 pt-3 border-t border-line">
                  <div className="flex flex-wrap items-center gap-2 text-2xs">
                    <StatusPill status={entry.latest.state} />
                    <Link className="link font-mono" to={`/experiments/${entry.latest.id}`}><FileText size={11} className="inline" /> {entry.latest.id}</Link>
                    <span className="text-muted">{entry.latest.duration_seconds !== undefined ? `${entry.latest.duration_seconds}s · ` : ""}{ago(entry.latest.started_at)}</span>
                  </div>
                  {entry.latest.parsed && entry.id !== "grouped_cv" && Object.keys(entry.latest.parsed.detectors).length > 0 && (
                    <div className="mt-3">
                      <DetectorBars detectors={entry.latest.parsed.detectors} compact />
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </Panel>

      <Panel
        title="3 · Labelled evaluation of a detection run"
        eyebrow="cpes.evaluation.EvaluationHarness on dashboard runs"
        className="mb-5"
        actions={
          <select className="input py-1" value={selectedRun ?? ""} onChange={(event) => setParams(event.target.value ? { run: event.target.value } : {})}>
            <option value="">choose a run</option>
            {runs.data?.filter((r) => r.state === "completed").map((r) => (
              <option key={r.id} value={r.id}>{r.id} · {r.dataset_id}</option>
            ))}
          </select>
        }
      >
        {selectedRun ? <RunEvaluationView runId={selectedRun} /> : <Empty title="No run selected">Choose a completed run.</Empty>}
      </Panel>

      <Panel title="4 · Review of the evaluation method" eyebrow="concerns only — the published method is not changed" bodyClass="overflow-x-auto">
        {notes.data && (
          <table className="tbl">
            <thead>
              <tr>
                <th>Topic</th>
                <th>Finding</th>
                <th>Already addressed in the repository?</th>
              </tr>
            </thead>
            <tbody>
              {notes.data.map((note) => (
                <tr key={note.topic}>
                  <td className="whitespace-nowrap">
                    <div className="font-medium">{note.topic}</div>
                    <Pill tone={note.severity === "high" ? "detect" : note.severity === "medium" ? "warn" : note.severity === "info" ? "info" : "faint"}>{note.severity}</Pill>
                    <div className="font-mono text-2xs text-muted mt-1">{note.where}</div>
                  </td>
                  <td className="text-[12px] leading-relaxed max-w-xl">{note.finding}</td>
                  <td className="text-[12px] text-muted leading-relaxed max-w-md">{note.mitigation_in_repo}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="text-2xs text-muted mt-2">Proposed corrective experiments: docs/dashboard/EVALUATION-NOTES.md.</p>
      </Panel>
    </>
  );
}

function DetectorBars({ detectors, highlight, compact }: { detectors: Record<string, DetectorRow>; highlight?: string; compact?: boolean }) {
  const rows = Object.entries(detectors).map(([name, row]) => ({
    name,
    values: { precision: row.precision, recall: row.recall, f1: row.f1 },
    errors: { precision: row.precision_std ?? null, recall: row.recall_std ?? null, f1: row.f1_std ?? null },
    highlight: highlight ? name === highlight : name.startsWith("CPES"),
  }));
  const metrics = compact ? [{ key: "f1", label: "F1" }] : [{ key: "precision", label: "precision" }, { key: "recall", label: "recall" }, { key: "f1", label: "F1" }];
  return <MetricBars rows={rows} metrics={metrics} />;
}

function metricRow(metrics: Metrics) {
  return { precision: metrics.precision, recall: metrics.recall, fpr: metrics.false_positive_rate, f1: metrics.f1_score };
}

function RunEvaluationView({ runId }: { runId: string }) {
  const evaluation = useApi<RunEvaluation>(`/api/runs/${runId}/evaluation`);
  if (evaluation.error) return <ErrorBox error={evaluation.error} />;
  if (!evaluation.data) return <Loading />;
  const data = evaluation.data;
  if (!data.available)
    return (
      <Notice tone="info" title="No metrics for this run">
        {data.reason}
      </Notice>
    );
  const chain = data.chain_level!;
  const process = data.process_level_diagnostic!;
  return (
    <div className="space-y-5">
      <Notice tone="warn" title="Not the paper's protocol">
        {data.in_sample_warning}
      </Notice>
      <div className="grid xl:grid-cols-2 gap-5">
        <div className="rounded-md border border-line p-4">
          <div className="font-semibold">Chain level (harness)</div>
          <div className="text-2xs text-muted mt-0.5 mb-3 leading-relaxed">{chain.protocol} {int(chain.labelled_chains)} labelled chains; {int(chain.excluded_unlabelled_chains)} chains without any labelled process excluded.</div>
          <div className="grid sm:grid-cols-2 gap-4">
            <Confusion title="CPES" tp={chain.comparison.cpes.confusion.true_positives} fp={chain.comparison.cpes.confusion.false_positives} tn={chain.comparison.cpes.confusion.true_negatives} fn={chain.comparison.cpes.confusion.false_negatives} />
            <Confusion title="Single-event baseline" tp={chain.comparison.baseline.confusion.true_positives} fp={chain.comparison.baseline.confusion.false_positives} tn={chain.comparison.baseline.confusion.true_negatives} fn={chain.comparison.baseline.confusion.false_negatives} />
          </div>
          <MetricTable rows={[["CPES", metricRow(chain.comparison.cpes)], ["Single-event baseline", metricRow(chain.comparison.baseline)]]} />
          <div className="mt-3"><Notice tone="warn">{chain.caveat} Largest chain: {int(chain.largest_chains[0]?.processes)} processes.</Notice></div>
        </div>
        <div className="rounded-md border border-line p-4">
          <div className="font-semibold">Process level (diagnostic)</div>
          <div className="text-2xs text-muted mt-0.5 mb-3 leading-relaxed">{process.protocol}</div>
          <div className="grid sm:grid-cols-2 gap-4">
            <Confusion title="CPES" tp={process.cpes.confusion.true_positives} fp={process.cpes.confusion.false_positives} tn={process.cpes.confusion.true_negatives} fn={process.cpes.confusion.false_negatives} />
            <Confusion title="Single-event baseline" tp={process.single_event_baseline.confusion.true_positives} fp={process.single_event_baseline.confusion.false_positives} tn={process.single_event_baseline.confusion.true_negatives} fn={process.single_event_baseline.confusion.false_negatives} />
          </div>
          <MetricTable rows={[["CPES", metricRow(process.cpes)], ["Single-event baseline", metricRow(process.single_event_baseline)]]} />
          <table className="tbl mt-3">
            <thead>
              <tr>
                <th>Technique</th>
                <th className="text-right">Attack processes</th>
                <th className="text-right">CPES flagged</th>
                <th className="text-right">Baseline flagged</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(process.per_technique).map(([technique, row]) => (
                <tr key={technique}>
                  <td className="font-mono text-[12px]">{technique}</td>
                  <td className="text-right font-mono">{row.attack_processes}</td>
                  <td className={`text-right font-mono ${row.cpes_flagged === 0 ? "text-detect" : ""}`}>{row.cpes_flagged}</td>
                  <td className="text-right font-mono">{row.baseline_flagged}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="text-2xs text-muted mt-2 leading-relaxed">{process.explanation}</p>
          {(process.false_positive_processes?.length ?? 0) > 0 && (
            <details className="mt-3">
              <summary className="cursor-pointer text-[12px]">Benign-labelled processes this engine flagged ({process.false_positive_processes!.length})</summary>
              <ul className="mt-2 space-y-0.5 font-mono text-2xs">
                {process.false_positive_processes!.map((item) => (
                  <li key={item.process_guid}>
                    <Link className="link" to={`/runs/${runId}/lineage?focus=${encodeURIComponent(item.process_guid)}&process=${encodeURIComponent(item.process_guid)}`}>{item.image_path ?? item.process_guid}</Link> <span className="text-faint">{item.process_guid}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      </div>
    </div>
  );
}

function MetricTable({ rows }: { rows: [string, { precision: string | null; recall: string | null; fpr: string | null; f1: string | null }][] }) {
  return (
    <table className="tbl mt-3">
      <thead>
        <tr>
          <th>Detector</th>
          <th className="text-right">Precision</th>
          <th className="text-right">Recall</th>
          <th className="text-right">FPR</th>
          <th className="text-right">F1</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(([name, row]) => (
          <tr key={name}>
            <td>{name}</td>
            <td className="text-right font-mono">{ratio(row.precision)}</td>
            <td className="text-right font-mono">{ratio(row.recall)}</td>
            <td className="text-right font-mono">{ratio(row.fpr, 4)}</td>
            <td className="text-right font-mono">{ratio(row.f1)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function ExperimentPage() {
  const { id = "" } = useParams();
  const record = useApi<ExperimentRecord>(`/api/experiments/${id}`, 1000, (r) => r.state === "running");
  if (record.error) return <ErrorBox error={record.error} />;
  if (!record.data) return <Loading />;
  const data = record.data;
  return (
    <>
      <PageHeader eyebrow={`recorded experiment · ${data.experiment_id}`} title={data.title} actions={<Link className="btn" to={`/evaluation#${data.experiment_id}`}>back to workbench</Link>}>
        <span className="font-mono text-[12px]">{data.protocol}</span>
      </PageHeader>
      <div className="grid xl:grid-cols-[380px_1fr] gap-5 items-start">
        <div className="space-y-4">
          <Panel title="Provenance">
            <KV
              rows={[
                ["execution", <span className="font-mono text-2xs">{data.id}</span>],
                ["state", <StatusPill status={data.state} />],
                ["exit code", <span className="font-mono">{data.exit_code ?? "—"}</span>],
                ["started", time(data.started_at)],
                ["duration", data.duration_seconds !== undefined ? `${data.duration_seconds} s` : "—"],
                ["script", <span className="font-mono text-2xs">{data.script}</span>],
                ["script SHA-256", <Hash value={data.script_sha256} length={16} />],
                ["python", <span className="font-mono text-2xs">{String(data.versions.python)}</span>],
                ["git commit", <span className="font-mono text-2xs">{String(data.versions.commit ?? "unknown").slice(0, 12)}</span>],
              ]}
            />
          </Panel>
          <Panel title="Inputs">
            <ul className="space-y-2">
              {data.inputs.map((input) => (
                <li key={input.path}>
                  <div className="font-mono text-[12px]">{input.path}</div>
                  <div className="flex items-center gap-2 text-2xs text-muted">
                    {bytes(input.bytes)} <Hash value={input.sha256} length={16} />
                  </div>
                </li>
              ))}
            </ul>
          </Panel>
          {data.parsed && Object.keys(data.parsed.detectors).length > 0 && (
            <Panel title="Numbers parsed from the output" eyebrow={data.parsed.aggregation}>
              <DetectorBars detectors={data.parsed.detectors} />
            </Panel>
          )}
        </div>
        <Panel title="Standard output (verbatim)" eyebrow="nothing below is recomputed by the dashboard">
          <pre className="font-mono text-[12px] leading-5 whitespace-pre-wrap text-ink/90 overflow-x-auto">{data.stdout || (data.state === "running" ? "running…" : "(empty)")}</pre>
          {data.stderr && (
            <details className="mt-3">
              <summary className="cursor-pointer text-2xs text-muted">stderr</summary>
              <pre className="font-mono text-2xs whitespace-pre-wrap text-detect/90 mt-2">{data.stderr}</pre>
            </details>
          )}
        </Panel>
      </div>
    </>
  );
}
