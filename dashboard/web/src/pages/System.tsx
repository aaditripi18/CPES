import { ErrorBox, Loading, PageHeader, Panel, Pill } from "../components/ui";
import { bytes, SIGNAL_LABELS } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { SystemInfo } from "../types";

export function System() {
  const info = useApi<SystemInfo>("/api/system");
  if (info.error) return <ErrorBox error={info.error} onRetry={info.reload} />;
  if (!info.data) return <Loading />;
  const data = info.data;
  return (
    <>
      <PageHeader eyebrow="system" title="System, inputs and limitations">
        What this installation can establish about itself. CPES detects four privilege-escalation mechanisms on Windows Sysmon telemetry; it does not claim to detect privilege escalation in general.
      </PageHeader>
      <div className="grid xl:grid-cols-2 gap-5">
        <Panel title="Detection mechanisms" eyebrow="signals and their status in cpes.CpesPipeline">
          <table className="tbl">
            <tbody>
              {data.signals.map((signal) => (
                <tr key={signal.signal_id}>
                  <td>
                    <div className="font-mono text-[12px]">{signal.signal_id}</div>
                    <div className="text-2xs text-muted">{SIGNAL_LABELS[signal.signal_id]}</div>
                  </td>
                  <td>{signal.wired ? <Pill tone="ok">wired</Pill> : <Pill tone="warn">not wired</Pill>}</td>
                  <td className="text-2xs text-muted leading-relaxed">
                    <div className="font-mono text-ink/80">reads: {signal.reads}</div>
                    {signal.note}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel title="Known unsupported techniques">
          <ul className="space-y-2 text-[13px]">
            {data.known_unsupported_techniques.map((item) => (
              <li key={item.technique}>
                <div className="font-medium">{item.technique}</div>
                <div className="text-2xs text-muted">{item.evidence}</div>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Limitations" className="xl:col-span-2">
          <ol className="list-decimal pl-5 space-y-1.5 text-[13px] leading-relaxed">
            {data.limitations.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ol>
        </Panel>
        <Panel title="Supported inputs" eyebrow={`upload limit ${bytes(data.max_upload_bytes)}`}>
          <table className="tbl">
            <tbody>
              {data.formats.map((format) => (
                <tr key={format.format}>
                  <td className="font-mono text-[12px]">{format.extensions.join(" ")}</td>
                  <td className="text-[12px] text-muted">{format.rule}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="eyebrow mt-4 mb-1.5">telemetry sources</div>
          <ul className="space-y-1.5 text-[13px]">
            {data.telemetry_sources.map((source) => (
              <li key={source.name}>
                {source.name} <Pill tone={source.status === "supported" ? "ok" : "faint"}>{source.status}</Pill>
                {source.note && <div className="text-2xs text-muted">{source.note}</div>}
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Input requirements" eyebrow="canonical event (C5) and default mapping">
          <table className="tbl">
            <thead>
              <tr>
                <th>Canonical field</th>
                <th>Default source (ECS)</th>
              </tr>
            </thead>
            <tbody>
              {data.default_mapping.map((field) => (
                <tr key={field.destination}>
                  <td className="font-mono text-[12px]">{field.destination} {field.required && <Pill tone="accent">required</Pill>}</td>
                  <td className="font-mono text-2xs text-muted">{field.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel title="Evaluation limitations and data availability">
          <ul className="space-y-2 text-[13px]">
            {data.data_availability.map((item) => (
              <li key={item.item}>
                <span className="font-medium">{item.item}</span> <Pill tone="faint">{item.state}</Pill>
                <div className="text-2xs text-muted">{item.note}</div>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Versions and resolver configuration">
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[12px] font-mono">
            {Object.entries(data.versions).map(([key, value]) => (
              <div key={key} className="contents">
                <span className="text-muted">{key}</span>
                <span className="truncate">{String(value)}</span>
              </div>
            ))}
          </div>
          <div className="eyebrow mt-4 mb-1.5">resolver discriminators (caller-supplied, as in the research scripts)</div>
          <div className="space-y-1 text-2xs font-mono">
            {Object.entries(data.resolver).map(([key, values]) => (
              <div key={key}>
                <span className="text-muted">{key}: </span>
                {values.join(", ")}
              </div>
            ))}
          </div>
          <div className="text-2xs text-muted mt-3 font-mono break-all">data root: {data.data_root}</div>
        </Panel>
      </div>
    </>
  );
}
