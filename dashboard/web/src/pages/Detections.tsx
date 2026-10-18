import { ArrowRight, Download, GitBranch, Search } from "lucide-react";
import { useEffect } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { qs } from "../api";
import { Waterfall } from "../components/charts";
import { DecisionPill, Empty, ErrorBox, KV, Loading, Notice, PageHeader, Pager, Panel, Pill } from "../components/ui";
import { basename, int, score, shortGuid, SIGNAL_LABELS, time } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { RunStatus, WindowDetail, WindowRow } from "../types";
import { useWorkspace } from "../Workspace";

const LIMIT = 40;

export function NoRun({ what }: { what: string }) {
  return (
    <>
      <PageHeader eyebrow={what} title={what[0].toUpperCase() + what.slice(1)} />
      <Panel>
        <Empty title="No run selected" action={<Link className="btn btn-primary" to="/runs">Open a run</Link>}>
          {what[0].toUpperCase() + what.slice(1)} belong to a detection run. Open one from the run history, or start a run from a dataset.
        </Empty>
      </Panel>
    </>
  );
}

export function Detections() {
  const { id = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const { setRunId, setDatasetId } = useWorkspace();
  useEffect(() => setRunId(id), [id, setRunId]);
  const run = useApi<RunStatus>(`/api/runs/${id}`);
  useEffect(() => {
    if (run.data) setDatasetId(run.data.dataset_id);
  }, [run.data, setDatasetId]);
  const detected = params.get("detected") ?? "true";
  const offset = Number(params.get("offset") ?? 0);
  const query = {
    detected: detected === "all" ? undefined : detected,
    signal: params.get("signal") ?? undefined,
    chain: params.get("chain") ?? undefined,
    min_score: params.get("min_score") ?? undefined,
    max_score: params.get("max_score") ?? undefined,
    baseline: params.get("baseline") ?? undefined,
    sort: params.get("sort") ?? "score",
    order: params.get("order") ?? "desc",
    offset,
    limit: LIMIT,
  };
  const windows = useApi<{ total: number; rows: WindowRow[] }>(`/api/runs/${id}/windows${qs(query)}`);
  const selected = params.get("w");
  const set = (changes: Record<string, string | null>, keepOffset = false) => {
    const next = new URLSearchParams(params);
    Object.entries(changes).forEach(([key, value]) => (value === null ? next.delete(key) : next.set(key, value)));
    if (!keepOffset) next.delete("offset");
    setParams(next);
  };
  useEffect(() => {
    if (!selected && windows.data?.rows.length) set({ w: String(windows.data.rows[0].window_index) }, true);
    // select the first row once rows arrive
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [windows.data, selected]);

  if (run.error) return <ErrorBox error={run.error} />;
  const signals = Object.keys(run.data?.config?.signals ?? {});
  return (
    <>
      <PageHeader
        eyebrow={`detections · run ${id}`}
        title="Detection explorer"
        actions={
          <a className="btn" href={`/api/runs/${id}/download/detections.csv`}>
            <Download size={14} /> detections.csv
          </a>
        }
      >
        Each scored unit is one lineage chain inside one time window (the package's C8/C9 unit). Select a window to follow its decision back to the signals, the weights and the telemetry records behind them.
      </PageHeader>
      <div className="grid grid-cols-[400px_1fr] gap-4 items-start">
        <div className="space-y-3 sticky top-16">
          <div className="panel p-3 grid grid-cols-2 gap-2 text-[12px]">
            <label className="col-span-2 flex items-center gap-2">
              <span className="text-muted w-16">show</span>
              <select className="input py-1 flex-1" value={detected} onChange={(event) => set({ detected: event.target.value, w: null })}>
                <option value="true">detected windows</option>
                <option value="false">below threshold</option>
                <option value="all">all windows with events</option>
              </select>
            </label>
            <label className="col-span-2 flex items-center gap-2">
              <span className="text-muted w-16">signal</span>
              <select className="input py-1 flex-1" value={params.get("signal") ?? ""} onChange={(event) => set({ signal: event.target.value || null, w: null })}>
                <option value="">any</option>
                {signals.map((signal) => (
                  <option key={signal} value={signal}>{signal}</option>
                ))}
              </select>
            </label>
            <label className="col-span-2 flex items-center gap-2">
              <span className="text-muted w-16">baseline</span>
              <select className="input py-1 flex-1" value={params.get("baseline") ?? ""} onChange={(event) => set({ baseline: event.target.value || null, w: null })}>
                <option value="">any</option>
                <option value="true">baseline flagged</option>
                <option value="false">baseline silent</option>
              </select>
            </label>
            <label className="col-span-2 flex items-center gap-2">
              <span className="text-muted w-16">sort</span>
              <select className="input py-1 flex-1" value={`${query.sort}:${query.order}`} onChange={(event) => { const [sort, order] = event.target.value.split(":"); set({ sort, order }); }}>
                <option value="score:desc">score, high → low</option>
                <option value="score:asc">score, low → high</option>
                <option value="time:asc">time, earliest first</option>
                <option value="time:desc">time, latest first</option>
                <option value="events:desc">most events</option>
              </select>
            </label>
            {(params.get("chain") || params.get("min_score") || params.get("max_score")) && (
              <div className="col-span-2 flex flex-wrap gap-1">
                {params.get("chain") && <button className="chip border-accent/40 bg-accent-dim/60" onClick={() => set({ chain: null, w: null })}>chain {shortGuid(params.get("chain"))} ×</button>}
                {(params.get("min_score") || params.get("max_score")) && (
                  <button className="chip border-accent/40 bg-accent-dim/60" onClick={() => set({ min_score: null, max_score: null, w: null })}>
                    score in [{params.get("min_score") ?? "−∞"}, {params.get("max_score") ?? "∞"}) ×
                  </button>
                )}
              </div>
            )}
          </div>
          <Panel bodyClass="">
            {windows.error && <div className="p-3"><ErrorBox error={windows.error} /></div>}
            {!windows.data && !windows.error && <Loading />}
            {windows.data && windows.data.total === 0 && <Empty title="No windows match">{detected === "true" ? "No window reached the threshold in this run." : "Try another filter."}</Empty>}
            {windows.data && windows.data.total > 0 && (
              <>
                <ul className="divide-y divide-line max-h-[calc(100vh-360px)] overflow-y-auto">
                  {windows.data.rows.map((row) => (
                    <li key={row.window_index}>
                      <button onClick={() => set({ w: String(row.window_index) }, true)} className={`w-full text-left px-3 py-2.5 hover:bg-hover ${selected === String(row.window_index) ? "bg-accent-dim/60" : ""}`}>
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[12px] truncate" title={row.lineage_chain_id}>chain {shortGuid(row.lineage_chain_id)}</span>
                          <span className={`font-mono text-[13px] ${row.is_detected ? "text-detect" : "text-muted"}`}>{score(row.cpes_score)}</span>
                        </div>
                        <div className="flex items-center justify-between gap-2 mt-1">
                          <span className="font-mono text-2xs text-muted">{time(row.start)} · {int(row.event_count)} ev</span>
                          <span className="flex gap-1">
                            {row.signals.map((signal) => (
                              <Pill key={signal} tone="detect">{signal.split("_")[0]}</Pill>
                            ))}
                            {row.baseline_detected && <Pill tone="warn" title="single-event baseline flags this window">baseline</Pill>}
                          </span>
                        </div>
                      </button>
                    </li>
                  ))}
                </ul>
                <Pager offset={offset} limit={LIMIT} total={windows.data.total} onChange={(next) => set({ offset: String(next) }, true)} />
              </>
            )}
          </Panel>
        </div>
        <div className="min-w-0">{selected ? <DetectionDetail runId={id} windowIndex={Number(selected)} /> : <Panel><Empty title="Select a window" /></Panel>}</div>
      </div>
    </>
  );
}

export function DetectionDetail({ runId, windowIndex }: { runId: string; windowIndex: number }) {
  const detail = useApi<WindowDetail>(`/api/runs/${runId}/windows/${windowIndex}`);
  if (detail.error) return <ErrorBox error={detail.error} />;
  if (!detail.data) return <Loading label="Loading window" />;
  const data = detail.data;
  const record = data.record;
  const threshold = Number(record.detection_threshold);
  const prior = Number(data.prior_applied);
  const present = record.contributions;
  const processName = (guid: string | null) => (guid ? basename(data.processes[guid]?.image_path) : "—");
  const integrityTransitions = data.audit?.integrity_transitions ?? [];
  const resolved = data.audit?.resolved ?? [];
  const sum = present.reduce((total, c) => total + Number(c.signed_log_likelihood), prior);
  return (
    <div className="space-y-4">
      <Panel
        eyebrow={`window #${windowIndex}`}
        title={
          <span className="flex flex-wrap items-center gap-2">
            chain <span className="font-mono">{shortGuid(record.lineage_chain_id)}</span> <DecisionPill detected={record.is_detected} threshold={record.detection_threshold} />
            {record.is_truncated && <Pill tone="warn" title="the chain has a parent that is not in the telemetry">truncated chain</Pill>}
            {record.label && <Pill tone={record.label.is_attack ? "detect" : "ok"} title="chain label derived from research process labels">label: {record.label.is_attack ? `attack (${record.label.techniques?.join(", ")})` : "benign"}</Pill>}
          </span>
        }
        actions={
          <Link className="btn" to={`/runs/${runId}/lineage?chain=${encodeURIComponent(record.lineage_chain_id)}${resolved[0] ? `&focus=${encodeURIComponent(resolved[0].anchor_process_guid)}` : ""}`}>
            <GitBranch size={14} /> Lineage
          </Link>
        }
      >
        <KV
          rows={[
            ["window", <span className="font-mono text-[12px]">{time(record.window_start)} → {time(record.window_end)}</span>],
            ["chain id", <span className="font-mono text-2xs break-all">{record.lineage_chain_id}</span>],
            ["events in window", <span className="font-mono">{int(data.summary?.event_count)} events · {int(data.summary?.process_count)} processes</span>],
            ["raw records", <Link className="link" to={`/explore/${data.dataset_id}?time_from=${encodeURIComponent(record.window_start)}&time_to=${encodeURIComponent(record.window_end)}&sort=__time__`}>open this time window in Explorer (all chains) <ArrowRight size={12} className="inline" /></Link>],
          ]}
        />
      </Panel>

      <Panel title="How the score was reached" eyebrow="cpes.scoring.CpesScoringEngine — additive signed evidence">
        <Waterfall prior={prior} steps={present.map((c) => ({ label: c.signal_id, value: Number(c.signed_log_likelihood) }))} threshold={threshold} finalScore={Number(record.cpes_score)} />
        <div className="mt-4 font-mono text-[12px] text-ink/90 bg-raised/60 rounded px-3 py-2 leading-6">
          score = prior {data.prior_applied}
          {present.map((c) => ` + ${Number(c.signed_log_likelihood).toFixed(4)} (${c.signal_id})`)} = {Number(record.cpes_score).toFixed(4)} {record.is_detected ? "≥" : "<"} threshold {record.detection_threshold} → {record.is_detected ? "detected" : "not detected"}
          {Math.abs(sum - Number(record.cpes_score)) > 1e-9 && <span className="text-detect"> (display sum mismatch — report this)</span>}
        </div>
        <table className="tbl mt-4">
          <thead>
            <tr>
              <th>Signal</th>
              <th>Observed in window</th>
              <th className="text-right">Weight</th>
              <th className="text-right">Added</th>
              <th>Pipeline wiring</th>
            </tr>
          </thead>
          <tbody>
            {record.observations.map((observation) => {
              const wiring = data.signals[observation.signal_id];
              return (
                <tr key={observation.signal_id}>
                  <td>
                    <div className="font-mono text-[12px]">{observation.signal_id}</div>
                    <div className="text-2xs text-muted">{SIGNAL_LABELS[observation.signal_id]}</div>
                  </td>
                  <td>{observation.is_present ? <Pill tone="detect">present · {observation.source_references.length} ref</Pill> : <Pill tone="faint">absent</Pill>}</td>
                  <td className="text-right font-mono text-[12px]">{Number(data.weights[observation.signal_id]).toFixed(4)}</td>
                  <td className="text-right font-mono text-[12px]">{observation.is_present ? score(data.weights[observation.signal_id], 4) : "0 (absent signals add nothing)"}</td>
                  <td>{wiring?.wired ? <Pill tone="ok">wired</Pill> : <Pill tone="warn" title={wiring?.note}>not wired — cannot fire</Pill>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <p className="text-2xs text-muted mt-2 leading-relaxed">
          All four weights in this evidence model are positive, so no signal pushes a score down; the engine adds a term only for a present signal, and an absent signal contributes nothing (it is not evidence of benignity). The applied prior is 0 to match the research decision rule; the derived prior is recorded in the run configuration.
        </p>
      </Panel>

      <Panel title="Evidence behind the decision" eyebrow="observed · derived · inferred">
        <div className="space-y-5">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <Pill tone="neutral">observed</Pill>
              <span className="text-[13px] font-medium">Telemetry records cited by the resolver</span>
            </div>
            {data.evidence_events.length === 0 ? (
              <p className="text-2xs text-muted">No record-level evidence for this window (no signal fired).</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {data.evidence_events.map((event) => (
                  <Link key={event.event_id} className="chip border-line-strong bg-raised hover:border-accent" to={`/explore/${data.dataset_id}?indices=${event.record_indices.join(",")}&record=${event.record_indices[0] ?? ""}`}>
                    event {event.event_id} <Search size={10} />
                  </Link>
                ))}
              </div>
            )}
          </div>
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <Pill tone="info">derived</Pill>
              <span className="text-[13px] font-medium">Integrity transitions in the window (ContextBuilder, parent → child)</span>
            </div>
            {integrityTransitions.length === 0 ? (
              <p className="text-2xs text-muted">{data.audit ? "No parent → child integrity change inside this window." : "Not recorded for windows without a present signal."}</p>
            ) : (
              <table className="tbl">
                <tbody>
                  {integrityTransitions.map((t) => (
                    <tr key={t.parent_process_guid + t.child_process_guid}>
                      <td className="font-mono text-[12px]">{processName(t.parent_process_guid)} <span className="text-muted">[{t.parent_integrity_level}]</span></td>
                      <td className="text-muted">→</td>
                      <td className="font-mono text-[12px]">{processName(t.child_process_guid)} <span className="text-muted">[{t.child_integrity_level}]</span></td>
                      <td className="font-mono text-2xs text-muted">{shortGuid(t.child_process_guid)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <Pill tone="accent" dashed>inferred</Pill>
              <span className="text-[13px] font-medium">Cross-channel re-association (ContextResolver)</span>
            </div>
            {resolved.length === 0 ? (
              <p className="text-2xs text-muted">The resolver associated nothing in this window.</p>
            ) : (
              <ul className="space-y-2">
                {resolved.map((item, index) => (
                  <li key={index} className="rounded border border-dashed border-accent/40 px-3 py-2">
                    <div className="flex flex-wrap items-center gap-2 text-[12px]">
                      <Pill tone="detect">{item.anchor_kind}</Pill>
                      <span className="text-muted">anchor</span>
                      <Link className="link font-mono" to={`/runs/${runId}/lineage?chain=${encodeURIComponent(record.lineage_chain_id)}&focus=${encodeURIComponent(item.anchor_process_guid)}`}>
                        {processName(item.anchor_process_guid)} {shortGuid(item.anchor_process_guid)}
                      </Link>
                      {item.actor_process_guid && (
                        <>
                          <span className="text-muted">actor</span>
                          <span className="font-mono">{processName(item.actor_process_guid)} {shortGuid(item.actor_process_guid)}</span>
                        </>
                      )}
                      {item.mediator && <span className="text-muted">via <span className="font-mono text-ink">{item.mediator}</span></span>}
                      {item.privilege_level && <span className="text-muted">at <span className="font-mono text-ink">{item.privilege_level}</span></span>}
                    </div>
                    {item.resolution_path.map((line) => (
                      <div key={line} className="font-mono text-2xs text-ink/80 mt-1.5 break-all">{line}</div>
                    ))}
                  </li>
                ))}
              </ul>
            )}
            <p className="text-2xs text-muted mt-2">Recomputed by calling the same ContextResolver on this window's recorded event group. The association is an inference rule (same window, matching tokens), not an observed causal link.</p>
          </div>
        </div>
      </Panel>

      <div className="grid md:grid-cols-2 gap-4">
        <Panel title="Single-event baseline on the same window" eyebrow="cpes.baseline.SingleEventBaselineDetector">
          {data.baseline.is_detected ? (
            <>
              <Pill tone="warn">flags this window</Pill>
              <p className="text-[12px] text-muted mt-2">A child process has a higher integrity level than its parent:</p>
              <ul className="font-mono text-[12px] mt-1">
                {data.baseline.triggering_process_guids.map((guid) => (
                  <li key={guid}>{processName(guid)} {shortGuid(guid)}</li>
                ))}
              </ul>
            </>
          ) : (
            <>
              <Pill tone="faint">silent</Pill>
              <p className="text-[12px] text-muted mt-2">No parent → child integrity elevation in this window, so the single-event rule does not fire.</p>
            </>
          )}
        </Panel>
        <Panel title="Processes referenced">
          <ul className="space-y-2">
            {Object.entries(data.processes).map(([guid, info]) => (
              <li key={guid} className="text-[12px]">
                <div className="flex items-center gap-2">
                  <span className="font-mono">{basename(info?.image_path)}</span>
                  {info?.integrity_level && <Pill tone="neutral">{info.integrity_level}</Pill>}
                  {info?.label && <Pill tone={info.label.is_attack ? "detect" : "ok"}>{info.label.is_attack ? info.label.technique : "benign"}</Pill>}
                </div>
                <div className="font-mono text-2xs text-muted break-all">{guid} · pid {info?.process_id ?? "—"}</div>
                {info?.command_line && <div className="font-mono text-2xs text-ink/70 break-all mt-0.5">{info.command_line}</div>}
              </li>
            ))}
          </ul>
        </Panel>
      </div>
      {!record.is_detected && <Notice tone="info">This window is below the threshold. It is shown so the absence of a detection can be inspected too.</Notice>}
    </div>
  );
}
