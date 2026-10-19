import { ArrowDown, ArrowRight, Link2, Upload } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { BarList, ScoreHistogram } from "../components/charts";
import { CategoryBadge, Empty, ErrorBox, Loading, Panel, Pill, Stat, StatusPill } from "../components/ui";
import { ago, eventCodeLabel, int, score, shortGuid, SIGNAL_LABELS, time } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { ChainNode, FeaturedChain, HeadlineResult, Overview as OverviewData } from "../types";
import { useWorkspace } from "../Workspace";

export function Overview() {
  const overview = useApi<OverviewData>("/api/overview", 4000, (data) => data.runs.some((run) => run.state === "running" || run.state === "queued"));
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
      <Hero featured={data.featured} />
      {data.headline.length > 0 && <HeadlineStrip items={data.headline} />}
      <PipelineStrip />
      {!latest && (
        <Panel className="mb-5">
          <Empty title="No completed run yet" action={<Link className="btn btn-primary" to="/datasets">Choose a dataset and run CPES</Link>}>
            Everything on this page is computed from a recorded run. Nothing is shown until one exists.
          </Empty>
        </Panel>
      )}
      {latest && summary && runId && (
        <>
          <div id="latest" className="flex flex-wrap items-center gap-2 mb-3 text-[13px] scroll-mt-16">
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
          </div>
        </>
      )}
    </>
  );
}

function Hero({ featured }: { featured: FeaturedChain | null }) {
  return (
    <section className="grid lg:grid-cols-12 gap-8 items-start pb-8 mb-6 border-b border-line">
      <div className="lg:col-span-7 flex flex-col gap-4 pt-2">
        <div className="eyebrow flex items-center gap-2">
          <span className="w-1.5 h-1.5 bg-accent" /> privilege-escalation detection for Windows
        </div>
        <h1 className="text-[32px] leading-10 font-semibold tracking-tight">Which process actually gained privilege — and how?</h1>
        <p className="text-[15px] leading-relaxed text-muted max-w-xl">
          CPES rebuilds the process tree from Sysmon telemetry, traces each privilege gain back to the evidence of how it happened, and scores it. Every alert is explained, and the results are tested against the SigmaHQ rules defenders already run.
        </p>
        <div className="flex flex-wrap gap-2 pt-1">
          <Link className="btn btn-primary" to="/datasets">
            <Upload size={14} /> Upload telemetry
          </Link>
          {featured && (
            <Link className="btn" to={`/runs/${featured.run_id}/incidents?i=${featured.incident_id}`}>
              See this incident <ArrowRight size={14} />
            </Link>
          )}
          <Link className="btn btn-ghost" to="/evaluation">
            How it was evaluated
          </Link>
        </div>
      </div>
      <div className="lg:col-span-5">{featured ? <EvidenceChainCard featured={featured} /> : <EmptyChainCard />}</div>
    </section>
  );
}

function ChainRow({ node, index, outcome, actor }: { node: ChainNode; index: number; outcome?: boolean; actor?: boolean }) {
  return (
    <div className={`flex items-center justify-between gap-2 rounded-sm border px-2.5 py-1.5 bg-raised ${outcome ? "border-detect" : "border-line"}`}>
      <div className="flex items-center gap-2 min-w-0 font-mono text-[12px]">
        <span className={outcome ? "text-detect font-bold" : "text-faint"}>{outcome ? "!" : String(index + 1).padStart(2, "0")}</span>
        <span className="font-medium truncate">{node.image ?? "unknown"}</span>
        {node.pid !== null && <span className="text-2xs text-muted">PID {node.pid}</span>}
        {actor && <span className="chip border-accent/50 text-accent">actor</span>}
      </div>
      {node.integrity_level && <span className={`chip uppercase ${outcome ? "border-detect text-detect bg-detect-dim" : "border-line text-muted"}`}>{node.integrity_level}</span>}
    </div>
  );
}

function EvidenceChainCard({ featured }: { featured: FeaturedChain }) {
  const outcomeIndex = featured.chain.length - 1;
  const actor = featured.actor;
  const actorOutsideChain = actor && !featured.chain.some((node) => node.process_guid === actor.process_guid);
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between pb-2.5 mb-3 border-b border-line">
        <span className="eyebrow">evidence chain · recorded run</span>
        <CategoryBadge category={featured.dataset_category} />
      </div>
      <div className="flex flex-col">
        {featured.chain.map((node, index) => (
          <div key={node.process_guid}>
            <ChainRow node={node} index={index} outcome={index === outcomeIndex} actor={node.process_guid === actor?.process_guid} />
            {index < outcomeIndex && <div className="pl-6 text-faint text-[12px] leading-none py-1">↓</div>}
          </div>
        ))}
      </div>
      {featured.explanation && (
        <div className="mt-3 pt-2 border-t border-dashed border-accent/70">
          <div className="flex items-center justify-between text-2xs mb-1.5">
            <span className="font-mono uppercase tracking-[0.06em] text-accent flex items-center gap-1">
              <Link2 size={12} /> re-associated
            </span>
            {actorOutsideChain && actor && (
              <span className="text-muted">
                actor <span className="font-mono text-ink">{actor.image}</span>
                {actor.pid !== null && <span> · PID {actor.pid}</span>}
              </span>
            )}
          </div>
          <div className="rounded-sm border border-accent/40 bg-bg px-2.5 py-1.5 font-mono text-2xs leading-relaxed break-all">{featured.explanation}</div>
        </div>
      )}
      <div className="mt-3 flex items-center justify-between gap-2 rounded-sm border border-line bg-bg px-2.5 py-1.5 text-2xs font-mono">
        <span className="text-muted">
          {featured.signal_id} <span className="text-ink">{score(featured.weight)}</span> ≥ threshold {featured.threshold ?? "—"}
        </span>
        <span className="chip border-detect text-detect bg-detect-dim uppercase">detected</span>
      </div>
      <div className="mt-2.5 flex items-center justify-between text-2xs text-muted">
        <span className="truncate">
          {featured.dataset_name}
          {featured.sigma_alerts ? ` · ${featured.sigma_alerts} Sigma alert${featured.sigma_alerts > 1 ? "s" : ""} in the same incident` : ""}
        </span>
        <Link className="link shrink-0 ml-2" to={`/runs/${featured.run_id}/detections?w=${featured.window_index}`}>
          score breakdown →
        </Link>
      </div>
    </div>
  );
}

function EmptyChainCard() {
  return (
    <div className="panel p-6 text-center">
      <div className="eyebrow mb-2">evidence chain</div>
      <p className="text-[13px] text-muted">Run CPES on a dataset with an escalation and its evidence chain appears here.</p>
      <Link className="btn btn-primary mt-3" to="/datasets">
        Choose a dataset
      </Link>
    </div>
  );
}

function HeadlineStrip({ items }: { items: HeadlineResult[] }) {
  return (
    <section className="panel mb-6 grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 divide-y sm:divide-y-0 xl:divide-x divide-line">
      {items.map((item) => (
        <Link key={item.protocol} to="/evaluation" className="px-4 py-3 hover:bg-hover transition-colors" title={`protocol ${item.protocol}`}>
          <div className="eyebrow">{item.label}</div>
          <div className="font-mono text-[20px] leading-7 mt-0.5">{item.value}</div>
          <div className="text-2xs text-muted">{item.detail}</div>
        </Link>
      ))}
    </section>
  );
}

const PIPELINE: [string, string, string][] = [
  ["ingest", "Telemetry", "Sysmon JSONL, CSV or raw .evtx, checked record by record"],
  ["lineage", "Process tree", "Parent links rebuilt; missing parents kept as gaps"],
  ["context", "Re-association", "Elevated process linked to the actor and evidence behind it"],
  ["windows", "Time windows", "Each process chain scored over sliding windows"],
  ["signals", "Mechanisms", "Four escalation signals, each with a learned weight"],
  ["decide", "Score", "Weights add up; at or above the threshold it alerts"],
];

function PipelineStrip() {
  return (
    <section className="mb-8">
      <div className="flex items-center justify-between mb-2.5">
        <span className="eyebrow">how it works</span>
        <a className="link text-2xs flex items-center gap-1" href="#latest">
          latest run <ArrowDown size={12} />
        </a>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2">
        {PIPELINE.map(([key, title, text], index) => (
          <div key={key} className="panel px-3 py-2.5">
            <div className="flex items-center justify-between font-mono text-2xs text-muted mb-1">
              <span>
                {String(index + 1).padStart(2, "0")} / {key}
              </span>
              <span className={index === PIPELINE.length - 1 ? "text-detect" : "text-accent"}>{index === PIPELINE.length - 1 ? "≥" : "→"}</span>
            </div>
            <div className="font-mono text-[12px] font-semibold mb-1">{title}</div>
            <p className="text-2xs text-muted leading-snug">{text}</p>
          </div>
        ))}
      </div>
      <div className="mt-2 text-2xs text-muted flex flex-wrap items-center gap-1.5">
        <span className="text-accent font-mono">evidence channels</span>
        {["named pipes · EID 17/18", "remote threads · EID 8", "registry writes · EID 12–14"].map((label) => (
          <span key={label} className="chip border-line text-ink bg-panel">
            {label}
          </span>
        ))}
      </div>
    </section>
  );
}
