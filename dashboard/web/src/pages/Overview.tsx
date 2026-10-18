import { ArrowRight, X } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { BarList, ScoreHistogram } from "../components/charts";
import { CategoryBadge, Empty, ErrorBox, Loading, PageHeader, Panel, Pill, Stat, StatusPill } from "../components/ui";
import { ago, eventCodeLabel, int, score, shortGuid, SIGNAL_LABELS, time } from "../lib/format";
import { useApi, useLocalState } from "../lib/hooks";
import type { DatasetMeta, Overview as OverviewData } from "../types";
import { useWorkspace } from "../Workspace";

export function Overview() {
  const overview = useApi<OverviewData>("/api/overview", 4000, (data) => data.runs.some((run) => run.state === "running" || run.state === "queued"));
  const [introHidden, setIntroHidden] = useLocalState("cpes.intro.hidden", false);
  const navigate = useNavigate();
  const { setRunId } = useWorkspace();
  if (overview.error) return <ErrorBox error={`${overview.error} — is the API server running? (python dashboard/run_server.py)`} onRetry={overview.reload} />;
  if (!overview.data) return <Loading label="Loading overview" />;
  const data = overview.data;
  const latest = data.latest;
  const runId = latest?.run.id;
  const summary = latest?.run.summary;
  const threshold = Number(summary?.threshold ?? 0.5);

  return (
    <>
      <PageHeader eyebrow="overview" title="CPES scores the mechanism of a privilege escalation — not the symptom — and shows the evidence behind every score." />
      {!introHidden && <Intro onHide={() => setIntroHidden(true)} />}
      {!latest && (
        <Panel className="mb-5">
          <Empty title="No completed run yet" action={<Link className="btn btn-primary" to="/datasets">Choose a dataset and run CPES</Link>}>
            Everything on this page is computed from a recorded run. Nothing is shown until one exists.
          </Empty>
        </Panel>
      )}
      {latest && summary && runId && (
        <>
          <div className="flex flex-wrap items-center gap-2 mb-3 text-[13px]">
            <span className="text-muted">Latest completed run</span>
            <Link className="link font-mono" to={`/runs/${runId}`} onClick={() => setRunId(runId)}>{runId}</Link>
            <span className="text-muted">on</span>
            <Link className="link" to={`/datasets/${latest.run.dataset_id}`}>{latest.run.dataset_name}</Link>
            {latest.dataset && <CategoryBadge category={latest.dataset.category} isPrivate={latest.dataset.private} />}
            <span className="text-muted">· validation</span>
            <StatusPill status={latest.validation_status} />
            <span className="text-muted">· {ago(latest.run.completed_at)}</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3 mb-5">
            <Stat label="telemetry records" value={int(summary.records_accepted)} sub={`${int(summary.records_rejected)} rejected`} onClick={() => navigate(`/explore/${latest.run.dataset_id}`)} />
            <Stat label="process nodes" value={int(summary.process_nodes)} onClick={() => navigate(`/runs/${runId}/lineage`)} />
            <Stat label="lineage chains" value={int(summary.lineage_chains)} onClick={() => navigate(`/runs/${runId}/lineage`)} />
            <Stat label="evaluated units" value={int(summary.nonempty_windows)} sub={`chain × window with events (of ${int(summary.scored_windows)} scored)`} onClick={() => navigate(`/runs/${runId}/detections?detected=all`)} />
            <Stat label="detected windows" value={int(summary.detected_windows)} tone={summary.detected_windows ? "detect" : undefined} sub={`${int(summary.detected_chains)} chains · threshold ${summary.threshold}`} onClick={() => navigate(`/runs/${runId}/detections`)} />
            <Stat label="labelled evaluation" value={summary.evaluated ? "yes" : "no"} sub={summary.evaluated ? "in-sample, see Evaluation" : "dataset has no ground truth"} onClick={() => navigate(`/evaluation?run=${runId}`)} />
          </div>
          <div className="grid xl:grid-cols-[1.4fr_1fr] gap-5 mb-5">
            <Panel title="Score distribution" eyebrow={`${int(latest.nonempty_windows)} windows with events · click a bar to list its windows`}>
              <ScoreHistogram bins={latest.score_histogram} threshold={threshold} onSelect={(bin) => navigate(`/runs/${runId}/detections?detected=all&min_score=${bin}&max_score=${bin + 1}`)} />
            </Panel>
            <Panel title="Signals that fired in detections" eyebrow="click to filter detections">
              {Object.keys(latest.signals_fired).length === 0 ? (
                <Empty title="No signal fired">No window reached the threshold in this run.</Empty>
              ) : (
                <BarList tone="detect" items={Object.entries(latest.signals_fired).map(([signal, count]) => ({ key: signal, label: signal, value: count, hint: SIGNAL_LABELS[signal] }))} onSelect={(signal) => navigate(`/runs/${runId}/detections?signal=${signal}`)} />
              )}
              <div className="eyebrow mt-5 mb-2">accepted records by event code · click to explore</div>
              <BarList tone="info" items={Object.entries(latest.event_codes).slice(0, 10).map(([code, count]) => ({ key: code, label: eventCodeLabel(code), value: count }))} onSelect={(code) => navigate(`/explore/${latest.run.dataset_id}?f.event.code=${encodeURIComponent(code)}`)} />
            </Panel>
          </div>
          <div className="grid xl:grid-cols-[1.4fr_1fr] gap-5 mb-5">
            <Panel title="Highest-scoring detections" eyebrow="latest run" bodyClass="" actions={<Link className="link text-2xs" to={`/runs/${runId}/detections`}>all detections →</Link>}>
              {latest.recent_detections.length === 0 ? (
                <Empty title="No detections in the latest run" />
              ) : (
                <table className="tbl">
                  <tbody>
                    {latest.recent_detections.map((window) => (
                      <tr key={window.window_index} className="row-link" onClick={() => navigate(`/runs/${runId}/detections?w=${window.window_index}`)}>
                        <td className="font-mono text-[12px]">chain {shortGuid(window.lineage_chain_id)}</td>
                        <td className="font-mono text-2xs text-muted">{time(window.start)}</td>
                        <td>{window.signals.map((signal) => <Pill key={signal} tone="detect">{signal}</Pill>)}</td>
                        <td className="text-right font-mono text-detect">{score(window.cpes_score)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Panel>
            <Panel title="Research claims" eyebrow="stated figure vs latest recorded execution" bodyClass="" actions={<Link className="link text-2xs" to="/evaluation">workbench →</Link>}>
              <table className="tbl">
                <tbody>
                  {data.claims.map((claim) => (
                    <tr key={claim.claim}>
                      <td className="text-[12px]">{claim.claim}</td>
                      <td className="font-mono text-[12px] text-right">{claim.expected.toFixed(3)}</td>
                      <td className="text-right"><StatusPill status={claim.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          </div>
        </>
      )}
      <div className="grid xl:grid-cols-[1.4fr_1fr] gap-5">
        <Panel title="Recent runs" bodyClass="" actions={<Link className="link text-2xs" to="/runs">history →</Link>}>
          {data.runs.length === 0 ? (
            <Empty title="No runs" />
          ) : (
            <table className="tbl">
              <tbody>
                {data.runs.map((run) => (
                  <tr key={run.id} className="row-link" onClick={() => navigate(`/runs/${run.id}`)}>
                    <td className="font-mono text-[12px]">{run.id}</td>
                    <td className="text-[12px]">{run.dataset_name}</td>
                    <td><StatusPill status={run.state} /></td>
                    <td className="text-right font-mono text-[12px]">{run.summary ? `${run.summary.detected_windows} det` : run.stage}</td>
                    <td className="text-2xs text-muted text-right">{ago(run.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
        <Panel title="System" bodyClass="p-4" actions={<Link className="link text-2xs" to="/system">limits →</Link>}>
          <div className="space-y-1.5 text-[13px]">
            <div className="flex justify-between"><span className="text-muted">API</span><Pill tone="ok">{String(data.health.status)}</Pill></div>
            <div className="flex justify-between"><span className="text-muted">cpes package</span><span className="font-mono">{String(data.health.cpes)}</span></div>
            <div className="flex justify-between"><span className="text-muted">dashboard</span><span className="font-mono">{String(data.health.dashboard)}</span></div>
            <div className="flex justify-between"><span className="text-muted">python</span><span className="font-mono">{String(data.health.python)}</span></div>
            <div className="flex justify-between"><span className="text-muted">git commit</span><span className="font-mono">{String(data.health.commit ?? "—").slice(0, 10)}</span></div>
            <div className="flex justify-between"><span className="text-muted">datasets registered</span><span className="font-mono">{data.datasets}</span></div>
            <div className="flex justify-between"><span className="text-muted">recorded experiments</span><span className="font-mono">{data.experiments.length}</span></div>
          </div>
        </Panel>
      </div>
    </>
  );
}

function Intro({ onHide }: { onHide: () => void }) {
  const inventory = useApi<{ datasets: DatasetMeta[] }>("/api/inventory");
  const lab = inventory.data?.datasets.find((d) => d.id === "lab-corpus-v3");
  const demoDataset = lab?.available ? lab : inventory.data?.datasets.find((d) => d.id === "synthetic-format-preview");
  return (
    <section className="panel mb-5 overflow-hidden">
      <div className="grid lg:grid-cols-[1.2fr_1fr]">
        <div className="p-5">
          <div className="flex items-start justify-between gap-3">
            <div className="eyebrow">new here · what CPES does</div>
            <button className="text-muted hover:text-ink" onClick={onHide} aria-label="hide introduction"><X size={15} /></button>
          </div>
          <p className="mt-2 leading-relaxed text-ink/90">
            Single-event rules flag a privilege escalation when a process's integrity level rises above its parent's. That symptom misses escalations that never cause a jump — a service binary started by <span className="font-mono">services.exe</span>, injected code, a stolen token — and fires on legitimate software that elevates. CPES reconstructs process lineage from Sysmon telemetry, re-associates the elevated outcome with the evidence of <i>how</i> it happened (a hijack registry write, a dropped service binary…), and adds up signed weights of evidence into a score with a threshold. Every score can be decomposed into the signals and records that produced it.
          </p>
          <p className="mt-2 text-[13px] text-muted leading-relaxed">
            Scope, stated plainly: one Windows 11 lab endpoint, four escalation techniques, four mechanism signals. Techniques without a signal are not detected. See <Link className="link" to="/system">System &amp; limits</Link>.
          </p>
        </div>
        <div className="p-5 bg-raised/50 border-l border-line">
          <div className="eyebrow mb-2">demonstration path</div>
          <ol className="space-y-2 text-[13px]">
            {[
              [demoDataset ? `Open “${demoDataset.name}”` : "Open a dataset", demoDataset ? `/datasets/${demoDataset.id}` : "/datasets", demoDataset?.category === "synthetic" ? "synthetic — mechanics only" : demoDataset ? "real lab telemetry (private)" : ""],
              ["Validate it and start a run", demoDataset ? `/datasets/${demoDataset.id}` : "/datasets", "the real CpesPipeline"],
              ["Open the top detection", "/runs", "score → signals → records"],
              ["Walk the process tree", "/runs", "lineage around the detection"],
              ["Check the published numbers", "/evaluation", "re-run the analysis scripts"],
            ].map(([label, to, hint], index) => (
              <li key={label} className="flex items-start gap-2.5">
                <span className="font-mono text-2xs w-5 h-5 shrink-0 rounded-full border border-accent/50 text-accent flex items-center justify-center">{index + 1}</span>
                <span>
                  <Link className="hover:text-accent" to={to}>{label} <ArrowRight size={12} className="inline" /></Link>
                  {hint && <span className="block text-2xs text-muted">{hint}</span>}
                </span>
              </li>
            ))}
          </ol>
          {lab && !lab.available && <p className="text-2xs text-warn mt-3">The private lab corpus is not on this machine, so the demo uses the synthetic sample.</p>}
        </div>
      </div>
    </section>
  );
}
