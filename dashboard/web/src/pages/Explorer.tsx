import { Columns3, Download, Filter, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { qs } from "../api";
import { CategoryBadge, Empty, ErrorBox, Loading, Missing, Notice, PageHeader, Pager, Panel, Pill, Tabs } from "../components/ui";
import { eventCodeLabel, int } from "../lib/format";
import { useApi, useLocalState } from "../lib/hooks";
import type { DatasetDetail, DatasetMeta, RecordInspection, RecordsPage, SchemaEntry } from "../types";
import { useWorkspace } from "../Workspace";

const LIMIT = 50;

export function ExplorerIndex() {
  const inventory = useApi<{ datasets: DatasetMeta[] }>("/api/inventory");
  const { datasetId } = useWorkspace();
  const navigate = useNavigate();
  useEffect(() => {
    if (datasetId) navigate(`/explore/${datasetId}`, { replace: true });
  }, [datasetId, navigate]);
  return (
    <>
      <PageHeader eyebrow="data" title="Dataset explorer">Choose a dataset to inspect its raw records.</PageHeader>
      {inventory.data && (
        <Panel>
          <ul className="divide-y divide-line">
            {inventory.data.datasets.filter((d) => d.available).map((d) => (
              <li key={d.id}>
                <Link to={`/explore/${d.id}`} className="flex items-center justify-between py-2.5 hover:text-accent">
                  <span>{d.name}</span>
                  <CategoryBadge category={d.category} isPrivate={d.private} />
                </Link>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </>
  );
}

export function Explorer() {
  const { id = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const { setDatasetId } = useWorkspace();
  const dataset = useApi<DatasetDetail>(`/api/datasets/${id}`);
  const schema = useApi<SchemaEntry[]>(`/api/datasets/${id}/schema`);
  const [savedColumns, setSavedColumns] = useLocalState<Record<string, string[]>>("cpes.explorer.columns", {});
  const [pickColumns, setPickColumns] = useState(false);
  const [draftQ, setDraftQ] = useState(params.get("q") ?? "");

  useEffect(() => setDatasetId(id), [id, setDatasetId]);
  const columns = savedColumns[id] ?? dataset.data?.default_columns ?? [];
  const filters = useMemo(() => {
    const out: Record<string, string[]> = {};
    params.forEach((value, key) => {
      if (key.startsWith("f.")) (out[key.slice(2)] ??= []).push(value);
    });
    return out;
  }, [params]);
  const offset = Number(params.get("offset") ?? 0);
  const sort = params.get("sort") ?? "__position__";
  const order = params.get("order") ?? "asc";
  const selected = params.get("record");

  const query: Record<string, string | number | string[] | undefined> = {
    q: params.get("q") ?? undefined,
    sort,
    order,
    offset,
    limit: LIMIT,
    columns: columns.join(","),
    missing: params.get("missing") ?? undefined,
    time_from: params.get("time_from") ?? undefined,
    time_to: params.get("time_to") ?? undefined,
    indices: params.get("indices") ?? undefined,
  };
  for (const [key, values] of Object.entries(filters)) query[`f.${key}`] = values;
  const page = useApi<RecordsPage>(dataset.data && columns.length ? `/api/datasets/${id}/records${qs(query)}` : null);

  const update = (changes: Record<string, string | null>, keepOffset = false) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value === null) next.delete(key);
      else next.set(key, value);
    }
    if (!keepOffset) next.delete("offset");
    setParams(next);
  };
  const toggleFilter = (field: string, value: string) => {
    const next = new URLSearchParams(params);
    const key = `f.${field}`;
    const current = next.getAll(key);
    next.delete(key);
    if (current.includes(value)) current.filter((v) => v !== value).forEach((v) => next.append(key, v));
    else [...current, value].forEach((v) => next.append(key, v));
    next.delete("offset");
    setParams(next);
  };
  const activeFilters = Object.entries(filters).flatMap(([field, values]) => values.map((value) => ({ field, value })));
  const exportHref = `/api/datasets/${id}/export${qs({ q: params.get("q") ?? undefined, missing: params.get("missing") ?? undefined, time_from: params.get("time_from") ?? undefined, time_to: params.get("time_to") ?? undefined, ...Object.fromEntries(Object.entries(filters).map(([k, v]) => [`f.${k}`, v])) })}`;

  if (dataset.error) return <ErrorBox error={dataset.error} onRetry={dataset.reload} />;
  if (!dataset.data) return <Loading label="Parsing dataset" />;
  const data = dataset.data;

  return (
    <>
      <PageHeader
        eyebrow="dataset explorer"
        title={
          <span className="flex flex-wrap items-center gap-3">
            <Link to={`/datasets/${id}`} className="hover:text-accent">{data.name}</Link> <CategoryBadge category={data.category} isPrivate={data.private} />
          </span>
        }
        actions={
          <>
            <button className="btn" onClick={() => setPickColumns(!pickColumns)}>
              <Columns3 size={14} /> Columns
            </button>
            <a className="btn" href={exportHref}>
              <Download size={14} /> Export {page.data ? int(page.data.total) : ""} as JSONL
            </a>
          </>
        }
      >
        Raw records exactly as read from the file{data.format === "csv" ? " (CSV rows; empty cells are absent fields)" : ""}. Search matches anywhere in the original record text.
      </PageHeader>
      {data.category === "synthetic" && (
        <div className="mb-4">
          <Notice tone="warn">Synthetic records — written to illustrate the format, not collected from a host.</Notice>
        </div>
      )}
      {pickColumns && schema.data && (
        <ColumnPicker
          schema={schema.data}
          columns={columns}
          onChange={(next) => setSavedColumns({ ...savedColumns, [id]: next })}
          onReset={() => {
            const copy = { ...savedColumns };
            delete copy[id];
            setSavedColumns(copy);
          }}
        />
      )}
      <div className="grid grid-cols-[240px_1fr] gap-4 items-start">
        <aside className="space-y-3 sticky top-16">
          <form
            onSubmit={(event) => {
              event.preventDefault();
              update({ q: draftQ.trim() || null });
            }}
          >
            <input className="input w-full" placeholder="search records…" value={draftQ} onChange={(event) => setDraftQ(event.target.value)} />
          </form>
          {data.timestamp_field && (
            <div className="panel p-3 space-y-1.5">
              <div className="eyebrow">time range ({data.timestamp_field})</div>
              <input className="input w-full font-mono text-2xs" placeholder="from, e.g. 2026-09-01T08:00:00Z" defaultValue={params.get("time_from") ?? ""} onBlur={(event) => update({ time_from: event.target.value.trim() || null })} />
              <input className="input w-full font-mono text-2xs" placeholder="to" defaultValue={params.get("time_to") ?? ""} onBlur={(event) => update({ time_to: event.target.value.trim() || null })} />
            </div>
          )}
          {page.data?.facets &&
            Object.entries(page.data.facets).map(([field, facet]) => (
              <div key={field} className="panel p-3">
                <div className="eyebrow mb-1.5 flex justify-between">
                  <span className="truncate" title={field}>{field}</span>
                  <span>{facet.distinct}</span>
                </div>
                <ul className="space-y-0.5 max-h-48 overflow-y-auto">
                  {facet.values.slice(0, 14).map(([value, count]) => {
                    const active = filters[field]?.includes(value);
                    return (
                      <li key={value}>
                        <button onClick={() => toggleFilter(field, value)} className={`w-full flex justify-between gap-2 rounded px-1.5 py-0.5 text-[12px] ${active ? "bg-accent-dim text-ink" : "hover:bg-hover text-ink/85"}`}>
                          <span className="font-mono truncate" title={value}>
                            {field === "event.code" ? eventCodeLabel(value) : value}
                          </span>
                          <span className="font-mono text-muted">{int(count)}</span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
        </aside>
        <div className="min-w-0 space-y-3">
          {(activeFilters.length > 0 || params.get("q") || params.get("missing") || params.get("time_from") || params.get("time_to") || params.get("indices")) && (
            <div className="flex flex-wrap items-center gap-1.5 text-[12px]">
              <Filter size={13} className="text-muted" />
              {params.get("q") && <FilterChip label={`text: ${params.get("q")}`} onRemove={() => { setDraftQ(""); update({ q: null }); }} />}
              {params.get("missing") && <FilterChip label={`missing: ${params.get("missing")}`} onRemove={() => update({ missing: null })} />}
              {params.get("time_from") && <FilterChip label={`from ${params.get("time_from")}`} onRemove={() => update({ time_from: null })} />}
              {params.get("time_to") && <FilterChip label={`to ${params.get("time_to")}`} onRemove={() => update({ time_to: null })} />}
              {params.get("indices") && <FilterChip label={`linked records (${params.get("indices")!.split(",").length})`} onRemove={() => update({ indices: null })} />}
              {activeFilters.map(({ field, value }) => (
                <FilterChip key={field + value} label={`${field} = ${value}`} onRemove={() => toggleFilter(field, value)} />
              ))}
              <button className="link text-2xs ml-1" onClick={() => setParams(new URLSearchParams())}>clear all</button>
            </div>
          )}
          <Panel bodyClass="">
            {page.error && <div className="p-4"><ErrorBox error={page.error} onRetry={page.reload} /></div>}
            {!page.data && !page.error && <Loading label="Querying records" />}
            {page.data && page.data.total === 0 && <Empty title="No records match">Remove a filter or change the search text.</Empty>}
            {page.data && page.data.total > 0 && (
              <>
                <div className="overflow-x-auto">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <SortHeader label={data.format === "json" ? "item" : "line"} field="__position__" sort={sort} order={order} onSort={(field, dir) => update({ sort: field, order: dir }, false)} />
                        {page.data.columns.map((column) => (
                          <SortHeader key={column} label={column} field={column} sort={sort} order={order} onSort={(field, dir) => update({ sort: field, order: dir }, false)} />
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {page.data.rows.map((row) => (
                        <tr key={row.index} className={`row-link ${selected === String(row.index) ? "row-active" : ""}`} onClick={() => update({ record: String(row.index) }, true)}>
                          <td className="font-mono text-2xs text-muted">{row.location}</td>
                          {page.data!.columns.map((column) => (
                            <td key={column} className="font-mono text-[12px] max-w-[280px] truncate" title={row.cells[column] ?? "absent"}>
                              {row.cells[column] === null ? <Missing /> : column === "event.code" ? eventCodeLabel(row.cells[column]) : row.cells[column]}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <Pager offset={offset} limit={LIMIT} total={page.data.total} onChange={(next) => update({ offset: String(next) }, true)} />
              </>
            )}
          </Panel>
        </div>
      </div>
      {selected !== null && <RecordDrawer datasetId={id} index={Number(selected)} format={data.format} onClose={() => update({ record: null }, true)} />}
    </>
  );
}

function FilterChip({ label, onRemove }: { label: string; onRemove: () => void }) {
  return (
    <span className="chip border-accent/40 bg-accent-dim/60 text-ink">
      <span className="max-w-[320px] truncate">{label}</span>
      <button onClick={onRemove} aria-label="remove filter">
        <X size={11} />
      </button>
    </span>
  );
}

function SortHeader({ label, field, sort, order, onSort }: { label: string; field: string; sort: string; order: string; onSort: (field: string, order: string) => void }) {
  const active = sort === field;
  return (
    <th>
      <button className={`inline-flex items-center gap-1 ${active ? "text-ink" : ""}`} onClick={() => onSort(field, active && order === "asc" ? "desc" : "asc")}>
        {label}
        {active && <span>{order === "asc" ? "↑" : "↓"}</span>}
      </button>
    </th>
  );
}

function ColumnPicker({ schema, columns, onChange, onReset }: { schema: SchemaEntry[]; columns: string[]; onChange: (columns: string[]) => void; onReset: () => void }) {
  const [filter, setFilter] = useState("");
  const rows = schema.filter((entry) => entry.path.toLowerCase().includes(filter.toLowerCase())).slice(0, 200);
  return (
    <Panel title="Columns" eyebrow={`${columns.length} shown · saved in this browser`} className="mb-4" actions={<button className="btn btn-ghost text-2xs" onClick={onReset}>reset to default</button>}>
      <input className="input w-72 mb-3" placeholder="filter fields" value={filter} onChange={(event) => setFilter(event.target.value)} />
      <div className="grid md:grid-cols-3 gap-x-4 gap-y-1 max-h-64 overflow-y-auto">
        {rows.map((entry) => (
          <label key={entry.path} className="flex items-center gap-2 text-[12px] font-mono">
            <input type="checkbox" className="accent-[#a78bfa]" checked={columns.includes(entry.path)} onChange={(event) => onChange(event.target.checked ? [...columns, entry.path] : columns.filter((c) => c !== entry.path))} />
            <span className="truncate" title={entry.path}>{entry.path}</span>
            <span className="text-faint ml-auto">{Math.round(entry.coverage * 100)}%</span>
          </label>
        ))}
      </div>
    </Panel>
  );
}

export function RecordDrawer({ datasetId, index, format, onClose }: { datasetId: string; index: number; format: string; onClose: () => void }) {
  const record = useApi<RecordInspection>(`/api/datasets/${datasetId}/records/${index}`);
  const [tab, setTab] = useState<"original" | "canonical" | "unmapped">("original");
  return (
    <div className="fixed inset-y-0 right-0 w-[560px] max-w-full bg-panel border-l border-line z-40 flex flex-col shadow-2xl">
      <div className="panel-head">
        <div>
          <div className="eyebrow">record {format === "json" ? `item ${record.data?.location ?? ""}` : `line ${record.data?.location ?? ""}`} · index {index}</div>
          <div className="mt-0.5">{record.data ? record.data.accepted ? <Pill tone="ok">accepted by mapping</Pill> : <Pill tone="detect">rejected</Pill> : null}</div>
        </div>
        <button className="btn btn-ghost" onClick={onClose} aria-label="close">
          <X size={16} />
        </button>
      </div>
      <Tabs
        value={tab}
        onChange={setTab}
        items={[
          { id: "original", label: "Original" },
          { id: "canonical", label: "Canonical mapping" },
          { id: "unmapped", label: `Unmapped fields${record.data ? ` (${record.data.unmapped_fields.length})` : ""}` },
        ]}
      />
      <div className="flex-1 overflow-y-auto p-4">
        {record.error && <ErrorBox error={record.error} />}
        {!record.data && !record.error && <Loading />}
        {record.data && tab === "original" && <pre className="font-mono text-[12px] leading-5 whitespace-pre-wrap break-all text-ink/90">{JSON.stringify(record.data.original, null, 2)}</pre>}
        {record.data && tab === "canonical" && (
          <>
            {record.data.issues.map((issue) => (
              <div key={issue} className="mb-3"><ErrorBox error={issue} /></div>
            ))}
            <table className="tbl">
              <thead>
                <tr>
                  <th>Canonical</th>
                  <th>Source</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                {record.data.canonical.map((row) => (
                  <tr key={row.destination}>
                    <td className="font-mono text-2xs">{row.destination}</td>
                    <td className="font-mono text-2xs text-muted break-all">{row.derived_from_position ? <Pill tone="warn" dashed>derived: position</Pill> : row.source ?? <span className="text-faint">unmapped</span>}</td>
                    <td className="font-mono text-2xs break-all">{row.present ? String(row.value) : <Missing />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
        {record.data && tab === "unmapped" && (
          <>
            <p className="text-2xs text-muted mb-2">Present in the record but not read by the mapping. CPES never sees these values.</p>
            <ul className="font-mono text-[12px] space-y-0.5">
              {record.data.unmapped_fields.map((field) => (
                <li key={field} className="break-all">{field}</li>
              ))}
            </ul>
          </>
        )}
      </div>
    </div>
  );
}
