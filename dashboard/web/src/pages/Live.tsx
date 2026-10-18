import { Pause, Play, Radio } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { get, post } from "../api";
import { CategoryBadge, Empty, ErrorBox, Loading, Notice, PageHeader, Panel, Pill, StatusPill } from "../components/ui";
import { int, score, shortGuid, SIGNAL_LABELS, time } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { DatasetMeta } from "../types";

interface LiveAlert {
  n: number;
  raised_at: string;
  watermark: string;
  window_start: string;
  window_end: string;
  lineage_chain_id: string;
  score: string;
  threshold: string;
  contributions: { signal_id: string; weight: string; anchors: { process_guid: string; image: string | null }[] }[];
  explanation: string[];
  events_known: number;
}

interface LiveSnapshot {
  id: string;
  source: "replay" | "elasticsearch";
  dataset_id: string | null;
  speed: number | null;
  state: "starting" | "running" | "completed" | "stopped" | "failed";
  error: string | null;
  started_at: string;
  finished_at: string | null;
  settings: { span_seconds: number; advance_seconds: number; threshold: string; evidence_model: string };
  event_start: string | null;
  event_end: string | null;
  watermark: string | null;
  events: number;
  windows_scored: number;
  signals: Record<string, number>;
  alert_count: number;
  alerts: LiveAlert[];
}

interface LiveIndex {
  sessions: Omit<LiveSnapshot, "alerts">[];
  elasticsearch: { configured: boolean; url: string | null; index: string; how: string };
}

const SPEEDS: { value: string; label: string }[] = [
  { value: "30", label: "30× (1 min of telemetry in 2 s)" },
  { value: "60", label: "60×" },
  { value: "120", label: "120×" },
  { value: "600", label: "600×" },
  { value: "max", label: "as fast as possible" },
];

export function Live() {
  const index = useApi<LiveIndex>("/api/live");
  const inventory = useApi<{ datasets: DatasetMeta[] }>("/api/inventory");
  const [source, setSource] = useState<"replay" | "elasticsearch">("replay");
  const [datasetId, setDatasetId] = useState<string>("");
  const [speed, setSpeed] = useState("60");
  const [session, setSession] = useState<LiveSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const alertsRef = useRef<LiveAlert[]>([]);
  const [alerts, setAlerts] = useState<LiveAlert[]>([]);

  const datasets = (inventory.data?.datasets ?? []).filter((d) => d.available);
  useEffect(() => {
    if (!datasetId && datasets.length) setDatasetId((datasets.find((d) => d.id === "lab-corpus-v3") ?? datasets[0]).id);
  }, [datasets, datasetId]);

  // Reattach to a session that is still running (e.g. after navigating away).
  useEffect(() => {
    const running = index.data?.sessions.find((s) => s.state === "running" || s.state === "starting");
    if (running && !session) get<LiveSnapshot>(`/api/live/${running.id}`).then((snap) => {
      alertsRef.current = snap.alerts;
      setAlerts(snap.alerts);
      setSession(snap);
    });
  }, [index.data, session]);

  useEffect(() => {
    if (!session || !(session.state === "running" || session.state === "starting")) return;
    const timer = setInterval(async () => {
      try {
        const snap = await get<LiveSnapshot>(`/api/live/${session.id}?since=${alertsRef.current.length}`);
        if (snap.alerts.length) {
          alertsRef.current = [...alertsRef.current, ...snap.alerts];
          setAlerts(alertsRef.current);
        }
        setSession(snap);
      } catch (reason) {
        setError((reason as Error).message);
      }
    }, 800);
    return () => clearInterval(timer);
  }, [session]);

  const start = async () => {
    setError(null);
    alertsRef.current = [];
    setAlerts([]);
    try {
      setSession(await post<LiveSnapshot>("/api/live", { source, dataset_id: datasetId, speed }));
      index.reload();
    } catch (reason) {
      setError((reason as Error).message);
    }
  };
  const stop = async () => {
    if (!session) return;
    setSession(await post<LiveSnapshot>(`/api/live/${session.id}/stop`, {}));
  };

  const running = session?.state === "running" || session?.state === "starting";
  const dataset = datasets.find((d) => d.id === (session?.dataset_id ?? datasetId));
  const progress = session?.event_start && session?.event_end && session.watermark ? Math.min(1, (new Date(session.watermark).getTime() - new Date(session.event_start).getTime()) / Math.max(1, new Date(session.event_end).getTime() - new Date(session.event_start).getTime())) : 0;

  return (
    <>
      <PageHeader eyebrow="detection" title="Live detection">
        CPES scoring telemetry as it arrives: each window is scored once, when it closes, using only the events received so far (<span className="font-mono">cpes.streaming.StreamingScorer</span>). Replay plays recorded telemetry at a chosen speed; Elasticsearch mode reads your lab's live index.
      </PageHeader>
      {index.error && <ErrorBox error={index.error} />}
      <div className="grid xl:grid-cols-[360px_1fr] gap-5 items-start">
        <div className="space-y-4">
          <Panel title="Source">
            <div className="space-y-3 text-[13px]">
              <label className="flex items-start gap-2">
                <input type="radio" className="mt-1 accent-[#a78bfa]" checked={source === "replay"} onChange={() => setSource("replay")} disabled={running} />
                <span>
                  <b>Replay</b> recorded telemetry
                  <span className="block text-2xs text-muted">Honest demo mode: the alerts are real CPES output, the arrival is simulated.</span>
                </span>
              </label>
              <label className="flex items-start gap-2">
                <input type="radio" className="mt-1 accent-[#a78bfa]" checked={source === "elasticsearch"} onChange={() => setSource("elasticsearch")} disabled={running || !index.data?.elasticsearch.configured} />
                <span>
                  <b>Elasticsearch</b> (live lab)
                  <span className="block text-2xs text-muted">{index.data?.elasticsearch.configured ? `${index.data.elasticsearch.url} · ${index.data.elasticsearch.index}` : `Not configured. ${index.data?.elasticsearch.how ?? ""}`}</span>
                </span>
              </label>
              {source === "replay" && (
                <>
                  <label className="block">
                    <span className="eyebrow">dataset</span>
                    <select className="input w-full mt-1" value={datasetId} onChange={(event) => setDatasetId(event.target.value)} disabled={running}>
                      {datasets.map((d) => (
                        <option key={d.id} value={d.id}>{d.name}</option>
                      ))}
                    </select>
                  </label>
                  <label className="block">
                    <span className="eyebrow">speed (event time per wall second)</span>
                    <select className="input w-full mt-1" value={speed} onChange={(event) => setSpeed(event.target.value)} disabled={running}>
                      {SPEEDS.map((s) => (
                        <option key={s.value} value={s.value}>{s.label}</option>
                      ))}
                    </select>
                  </label>
                </>
              )}
              {running ? (
                <button className="btn w-full justify-center" onClick={stop}><Pause size={14} /> Stop</button>
              ) : (
                <button className="btn btn-primary w-full justify-center" onClick={start} disabled={source === "replay" && !datasetId}><Play size={14} /> Start</button>
              )}
              {error && <ErrorBox error={error} />}
            </div>
          </Panel>
          {session && (
            <Panel title="Session" eyebrow={session.id}>
              <div className="space-y-2 text-[13px]">
                <div className="flex items-center gap-2">
                  <StatusPill status={session.state === "starting" ? "running" : session.state === "stopped" ? "queued" : session.state} />
                  {session.source === "replay" ? <Pill tone="warn">REPLAY {session.speed ? `${session.speed}×` : "max speed"}</Pill> : <Pill tone="detect"><Radio size={11} /> LIVE</Pill>}
                  {dataset && <CategoryBadge category={dataset.category} isPrivate={dataset.private} />}
                </div>
                <div className="h-1.5 bg-raised rounded overflow-hidden">
                  <div className="h-full bg-accent transition-all" style={{ width: `${progress * 100}%` }} />
                </div>
                <div className="font-mono text-2xs text-muted">event time {time(session.watermark)} {session.event_end && session.source === "replay" ? `of ${time(session.event_end, false)}` : ""}</div>
                <div className="grid grid-cols-3 gap-2 pt-1">
                  {[
                    ["events", int(session.events)],
                    ["windows", int(session.windows_scored)],
                    ["alerts", int(session.alert_count)],
                  ].map(([label, value]) => (
                    <div key={label} className="rounded border border-line px-2 py-1.5">
                      <div className="eyebrow">{label}</div>
                      <div className={`font-mono text-[16px] ${label === "alerts" && session.alert_count ? "text-detect" : ""}`}>{value}</div>
                    </div>
                  ))}
                </div>
                {Object.entries(session.signals).map(([signal, count]) => (
                  <div key={signal} className="flex justify-between text-2xs font-mono">
                    <span>{signal}</span>
                    <span className="text-detect">{count}</span>
                  </div>
                ))}
                {session.error && <ErrorBox error={session.error} />}
                <p className="text-2xs text-muted leading-relaxed">
                  window {session.settings.span_seconds}s / advance {session.settings.advance_seconds}s · threshold {session.settings.threshold} · weights {session.settings.evidence_model}. Measured on the lab corpus, live alerts match the hindsight result exactly; time-to-alert is at most advance + one tick (docs/RESULTS.md §8).
                </p>
                {session.dataset_id && !running && (
                  <Link className="link text-2xs" to={`/datasets/${session.dataset_id}`}>Run a full recorded analysis of this dataset →</Link>
                )}
              </div>
            </Panel>
          )}
        </div>
        <Panel title="Alert feed" eyebrow={session ? `${alerts.length} alerts · newest first` : "start a session"} bodyClass="">
          {!session && <Empty title="Nothing streaming">Choose a source and press Start. Alerts appear here the moment their window closes, with the evidence that produced them.</Empty>}
          {session && alerts.length === 0 && (running ? <Loading label="Waiting for the first window to close" /> : <Empty title="No alerts">No window reached the threshold.</Empty>)}
          <ul className="divide-y divide-line max-h-[calc(100vh-220px)] overflow-y-auto">
            {[...alerts].reverse().map((alert) => (
              <li key={alert.n} className="px-4 py-3 animate-[fadein_0.4s_ease-out]">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[13px] text-detect">{score(alert.score)}</span>
                  {alert.contributions.map((c) => (
                    <Pill key={c.signal_id} tone="detect" title={SIGNAL_LABELS[c.signal_id]}>{c.signal_id}</Pill>
                  ))}
                  <span className="font-mono text-2xs text-muted ml-auto">window {time(alert.window_start, false)}–{time(alert.window_end, false)}</span>
                </div>
                <div className="mt-1.5 text-[12px]">
                  {alert.contributions.flatMap((c) => c.anchors).map((anchor) => (
                    <span key={anchor.process_guid} className="mr-3">
                      <span className="font-mono">{anchor.image ?? "process"}</span> <span className="font-mono text-2xs text-faint">{shortGuid(anchor.process_guid)}</span>
                    </span>
                  ))}
                </div>
                {alert.explanation.map((line) => (
                  <div key={line} className="font-mono text-2xs text-ink/75 mt-1 break-all">{line}</div>
                ))}
                <div className="text-2xs text-faint mt-1">chain {shortGuid(alert.lineage_chain_id)} · {int(alert.events_known)} events known when scored · raised {time(alert.raised_at, false)}</div>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
      {session?.source === "replay" && (
        <div className="mt-4">
          <Notice tone="info">Replay mode re-plays recorded telemetry. To score a real Windows VM live, follow lab/README.md (Phase 0–1) and start the server with the CPES_ES_* settings.</Notice>
        </div>
      )}
    </>
  );
}
