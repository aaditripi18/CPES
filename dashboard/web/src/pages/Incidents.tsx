import { Download, FileText, GitBranch, Layers } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { Empty, ErrorBox, KV, Loading, Notice, PageHeader, Panel, Pill, Stat } from "../components/ui";
import { shortGuid, time } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { Incident, IncidentAlert, IncidentsFile, RunStatus } from "../types";
import { useWorkspace } from "../Workspace";

type Filter = "all" | "outcome" | "both";

const FILTERS: { id: Filter; label: string; test: (i: Incident) => boolean }[] = [
  { id: "all", label: "all", test: () => true },
  { id: "outcome", label: "names an elevated process", test: (i) => i.outcome.length > 0 },
  { id: "both", label: "CPES + Sigma", test: (i) => i.sources.length > 1 },
];

export function Incidents() {
  const { id = "" } = useParams();
  const { setRunId } = useWorkspace();
  const [params, setParams] = useSearchParams();
  const run = useApi<RunStatus>(`/api/runs/${id}`);
  const file = useApi<IncidentsFile>(`/api/runs/${id}/incidents`);
  const [filter, setFilter] = useState<Filter>("all");
  useEffect(() => setRunId(id), [id, setRunId]);

  if (run.error) return <ErrorBox error={run.error} />;
  if (file.error) return <ErrorBox error={file.error} onRetry={file.reload} />;
  if (!file.data || !run.data) return <Loading />;
  const data = file.data;
  const rows = data.incidents.filter(FILTERS.find((f) => f.id === filter)!.test);
  const selectedId = params.get("i") ?? rows[0]?.id;
  const selected = data.incidents.find((i) => i.id === selectedId);
  const both = data.incidents.filter((i) => i.sources.length > 1).length;

  return (
    <>
      <PageHeader
        eyebrow={`incidents · run ${id}`}
        title="Incidents"
        actions={
          <>
            <a className="btn" href={`/api/runs/${id}/download/attack-layer.json`} title="MITRE ATT&CK Navigator layer (format 4.5)">
              <Layers size={14} /> ATT&CK layer
            </a>
            <a className="btn" href={`/api/runs/${id}/download/alerts.ecs.ndjson`} title="CPES alerts as Elastic Common Schema documents, one per line">
              <Download size={14} /> ECS alerts
            </a>
          </>
        }
      >
        Alerts joined into incidents by three fixed rules: same process; parent, child or grandparent within {data.gap_seconds} s; or the CPES resolver's actor link. The rules were pre-registered in{" "}
        <span className="font-mono">docs/design/incident-correlation.md</span> and are not tuned per run.
      </PageHeader>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 my-5">
        <Stat label="incidents" value={data.incidents.length} sub={`from ${data.cpes_alerts + data.sigma_alerts} alerts`} />
        <Stat label="CPES alerts" value={data.cpes_alerts} tone={data.cpes_alerts ? "detect" : undefined} sub="elevated process × signal" />
        <Stat label="Sigma alerts" value={data.sigma.enabled ? data.sigma_alerts : "off"} sub={data.sigma.enabled ? `${data.sigma.rules} core rules · ${data.sigma.levels}` : "not run"} />
        <Stat label="CPES + Sigma joined" value={both} sub="incidents with both sources" tone={both ? "accent" : undefined} />
      </div>

      {!data.sigma.enabled && (
        <div className="mb-4">
          <Notice tone="info" title="Sigma was not run for this run">
            {data.sigma.reason}. Start a new run with “Also run SigmaHQ core rules” ticked to join attacker-tool alerts to CPES outcomes.
          </Notice>
        </div>
      )}

      {data.incidents.length === 0 ? (
        <Panel>
          <Empty title="No incidents">No CPES window crossed the threshold{data.sigma.enabled ? " and no high or critical Sigma rule matched" : ""} in this run.</Empty>
        </Panel>
      ) : (
        <div className="grid xl:grid-cols-[minmax(320px,420px)_1fr] gap-5">
          <Panel
            title="Incident queue"
            bodyClass="p-0"
            actions={
              <select className="input text-2xs py-1" value={filter} onChange={(event) => setFilter(event.target.value as Filter)}>
                {FILTERS.map((f) => (
                  <option key={f.id} value={f.id}>{f.label}</option>
                ))}
              </select>
            }
          >
            <ul className="divide-y divide-line max-h-[70vh] overflow-y-auto">
              {rows.map((incident) => (
                <li key={incident.id}>
                  <button
                    className={`w-full text-left px-4 py-3 hover:bg-hover ${incident.id === selectedId ? "bg-accent-dim/30" : ""}`}
                    onClick={() => setParams({ i: incident.id })}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-[12px]">{incident.id}</span>
                      <LevelPill level={incident.level} />
                    </div>
                    <div className="text-[13px] mt-1 leading-snug">{incident.headline}</div>
                    <div className="flex flex-wrap items-center gap-1 mt-1.5">
                      {incident.sources.map((s) => <SourcePill key={s} source={s} />)}
                      <span className="text-2xs text-muted ml-1">{incident.alerts.length} alerts · {time(incident.start)}</span>
                    </div>
                  </button>
                </li>
              ))}
              {rows.length === 0 && <li className="px-4 py-6 text-2xs text-muted">No incident matches this filter.</li>}
            </ul>
          </Panel>
          {selected ? <IncidentDetail runId={id} incident={selected} /> : <Panel><Empty title="Select an incident" /></Panel>}
        </div>
      )}
      <p className="text-2xs text-muted mt-4">{data.rule}</p>
    </>
  );
}

function IncidentDetail({ runId, incident }: { runId: string; incident: Incident }) {
  const explanations = incident.alerts.filter((a) => a.source === "cpes").flatMap((a) => a.explanation ?? []);
  const alerts = [...incident.alerts].sort((a, b) => a.time.localeCompare(b.time));
  return (
    <div className="space-y-5">
      <Panel
        title={incident.headline}
        eyebrow={`${incident.id} · ${incident.level}`}
        actions={
          <a className="btn btn-primary" href={`/api/runs/${runId}/incidents/${incident.id}/report.md`}>
            <FileText size={14} /> Report (.md)
          </a>
        }
      >
        <KV
          rows={[
            ["time", <span className="font-mono text-2xs">{time(incident.start)} → {time(incident.end)}</span>],
            ["sources", <span className="flex gap-1">{incident.sources.map((s) => <SourcePill key={s} source={s} />)}</span>],
            [
              "ATT&CK",
              <span className="flex flex-wrap gap-1">
                {incident.techniques.length ? incident.techniques.map((t) => <Pill key={t} tone="neutral">{t}</Pill>) : <span className="text-muted">—</span>}
              </span>,
            ],
            ["processes", `${incident.processes.length} involved`],
          ]}
        />
        <p className="text-2xs text-muted mt-3">
          A CPES technique is the one its signal was designed for, not a verified attribution (the service rule also fires on RoguePotato, a token-impersonation tool). Sigma techniques are the rule's own tags.
        </p>
      </Panel>

      <Panel title="Process that gained privilege" eyebrow="CPES outcome">
        {incident.outcome.length === 0 ? (
          <p className="text-[13px] text-muted">CPES did not flag an elevated process in this incident. It contains attacker-tool alerts only, so the outcome is unknown.</p>
        ) : (
          <ul className="space-y-2">
            {incident.outcome.map((o) => (
              <li key={o.process_guid} className="flex items-center justify-between gap-3 rounded border border-detect/30 bg-detect/5 px-3 py-2">
                <span>
                  <span className="font-mono text-[13px] text-detect">{o.image ?? "unknown image"}</span>
                  <span className="text-2xs text-muted ml-2">integrity {o.integrity_level ?? "unknown"} · {shortGuid(o.process_guid)}</span>
                </span>
                <Link className="btn text-2xs" to={`/runs/${runId}/lineage?focus=${encodeURIComponent(o.process_guid)}`}>
                  <GitBranch size={13} /> lineage
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Timeline" bodyClass="overflow-x-auto">
        <table className="tbl">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Alert</th>
              <th>Process</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <AlertRow key={a.id} runId={runId} alert={a} />
            ))}
          </tbody>
        </table>
      </Panel>

      {explanations.length > 0 && (
        <Panel title="Evidence chain" eyebrow="CPES resolver, as recorded">
          <ul className="space-y-1.5 text-[13px]">
            {explanations.map((line, n) => (
              <li key={n} className="font-mono text-2xs break-all">{line}</li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}

function AlertRow({ runId, alert }: { runId: string; alert: IncidentAlert }) {
  return (
    <tr>
      <td className="font-mono text-2xs whitespace-nowrap">{time(alert.time)}</td>
      <td><SourcePill source={alert.source} /></td>
      <td>
        <div className="text-[13px]">{alert.title}</div>
        <div className="text-2xs text-muted">
          {alert.level}
          {alert.source === "cpes" && alert.window_index !== undefined && (
            <>
              {" · "}weight {Number(alert.weight).toFixed(3)} ·{" "}
              <Link className="link" to={`/runs/${runId}/detections?w=${alert.window_index}`}>window #{alert.window_index}</Link>
            </>
          )}
          {alert.tags?.length ? ` · ${alert.tags.join(", ")}` : ""}
        </div>
      </td>
      <td>
        <div className="font-mono text-[12px]">{alert.image ?? "—"}</div>
        {alert.process_guid && <div className="text-2xs text-muted font-mono">{shortGuid(alert.process_guid)}</div>}
      </td>
    </tr>
  );
}

function SourcePill({ source }: { source: string }) {
  return <Pill tone={source === "cpes" ? "detect" : "info"}>{source === "cpes" ? "CPES" : "Sigma"}</Pill>;
}

function LevelPill({ level }: { level: string }) {
  return <Pill tone={level === "critical" ? "detect" : level === "high" ? "warn" : "neutral"}>{level}</Pill>;
}
