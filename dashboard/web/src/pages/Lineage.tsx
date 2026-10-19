import dagre from "@dagrejs/dagre";
import { Background, Controls, Handle, MarkerType, MiniMap, Node, NodeProps, Position, ReactFlow, ReactFlowProvider, useReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Activity, Search, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { qs } from "../api";
import { Empty, ErrorBox, KV, Loading, PageHeader, Panel, Pill } from "../components/ui";
import { basename, eventCodeLabel, int, score, shortGuid, time } from "../lib/format";
import { useApi } from "../lib/hooks";
import { GRAPH_COLORS, type Theme, useTheme } from "../lib/theme";
import type { ChainGraph, ChainRow, GraphNode, ProcessInfo, RunStatus } from "../types";
import { useWorkspace } from "../Workspace";

const NODE_W = 200;
const NODE_H = 62;

type ProcessNodeData = GraphNode & { selected: boolean; focus: boolean } & Record<string, unknown>;
type GhostNodeData = { guid: string } & Record<string, unknown>;

function ProcessCard({ data }: NodeProps<Node<ProcessNodeData>>) {
  const detected = data.detected_windows.length > 0;
  const integrity = data.integrity_level ?? "";
  const integrityTone = integrity === "System" ? "text-detect" : integrity === "High" ? "text-warn" : "text-muted";
  return (
    <div
      className={`rounded-md border px-2.5 py-1.5 bg-panel text-left transition-colors ${data.selected ? "border-accent shadow-[0_0_0_2px_rgb(var(--c-accent)/0.35)]" : detected ? "border-detect" : "border-line-strong"} ${data.focus ? "ring-1 ring-accent/50" : ""}`}
      style={{ width: NODE_W, height: NODE_H }}
    >
      <Handle type="target" position={Position.Top} className="!bg-line-strong !border-0 !w-1.5 !h-1.5" />
      <div className="flex items-center justify-between gap-1">
        <span className="font-mono text-[12px] truncate text-ink" title={data.image_path ?? data.id}>
          {data.image_path ? basename(data.image_path) : <span className="text-faint">no image recorded</span>}
        </span>
        {detected && <span className="w-2 h-2 rounded-full bg-detect shrink-0" title="referenced by a detection" />}
      </div>
      <div className="flex items-center gap-2 font-mono text-2xs mt-0.5">
        <span className="text-muted">pid {data.process_id ?? "—"}</span>
        <span className={integrityTone}>{integrity || "—"}</span>
        <span className="text-faint ml-auto">{int(data.event_count)} ev</span>
      </div>
      <div className="flex items-center gap-1 mt-0.5 text-2xs">
        {data.label && <span className={data.label.is_attack ? "text-detect" : "text-ok/80"}>{data.label.is_attack ? data.label.technique : "benign"}</span>}
        {data.hidden_children > 0 && <span className="text-accent ml-auto">+{data.hidden_children} hidden</span>}
      </div>
      <Handle type="source" position={Position.Bottom} className="!bg-line-strong !border-0 !w-1.5 !h-1.5" />
    </div>
  );
}

function GhostCard({ data }: NodeProps<Node<GhostNodeData>>) {
  return (
    <div className="rounded-md border border-dashed border-faint px-2.5 py-1.5 bg-transparent text-left" style={{ width: NODE_W, height: NODE_H - 10 }} title={data.guid}>
      <div className="text-2xs text-muted">parent not in telemetry</div>
      <div className="font-mono text-2xs text-faint truncate">{data.guid}</div>
      <Handle type="source" position={Position.Bottom} className="!bg-faint !border-0 !w-1.5 !h-1.5" />
    </div>
  );
}

const nodeTypes = { process: ProcessCard, ghost: GhostCard };

function layout(graph: ChainGraph, selected: string | null, focus: string | null, colors: (typeof GRAPH_COLORS)[Theme]) {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "TB", nodesep: 24, ranksep: 46 });
  g.setDefaultEdgeLabel(() => ({}));
  const ghosts = new Set<string>();
  graph.nodes.forEach((node) => {
    g.setNode(node.id, { width: NODE_W, height: NODE_H });
    if (node.parent_unresolved && node.parent_process_guid) ghosts.add(node.parent_process_guid);
  });
  ghosts.forEach((guid) => g.setNode(`ghost:${guid}`, { width: NODE_W, height: NODE_H - 10 }));
  graph.edges.forEach((edge) => g.setEdge(edge.source, edge.target));
  graph.nodes.forEach((node) => {
    if (node.parent_unresolved && node.parent_process_guid) g.setEdge(`ghost:${node.parent_process_guid}`, node.id);
  });
  dagre.layout(g);
  const nodes: Node[] = [
    ...graph.nodes.map((node) => {
      const position = g.node(node.id);
      return { id: node.id, type: "process", position: { x: position.x - NODE_W / 2, y: position.y - NODE_H / 2 }, data: { ...node, selected: node.id === selected, focus: node.id === focus } };
    }),
    ...[...ghosts].map((guid) => {
      const position = g.node(`ghost:${guid}`);
      return { id: `ghost:${guid}`, type: "ghost", position: { x: position.x - NODE_W / 2, y: position.y - NODE_H / 2 }, data: { guid }, selectable: false };
    }),
  ];
  const edges = [
    ...graph.edges.map((edge) => ({ id: `${edge.source}->${edge.target}`, source: edge.source, target: edge.target, style: { stroke: colors.edge }, markerEnd: { type: MarkerType.ArrowClosed, color: colors.edge } })),
    ...graph.nodes.filter((n) => n.parent_unresolved && n.parent_process_guid).map((n) => ({ id: `ghost-${n.id}`, source: `ghost:${n.parent_process_guid}`, target: n.id, style: { stroke: colors.ghost, strokeDasharray: "4 4" } })),
  ];
  return { nodes, edges };
}

export function Lineage() {
  const { id = "" } = useParams();
  const { setRunId, setDatasetId } = useWorkspace();
  useEffect(() => setRunId(id), [id, setRunId]);
  const [params, setParams] = useSearchParams();
  const [chainFilter, setChainFilter] = useState("");
  const [detectedOnly, setDetectedOnly] = useState(false);
  const run = useApi<RunStatus>(`/api/runs/${id}`);
  useEffect(() => {
    if (run.data) setDatasetId(run.data.dataset_id);
  }, [run.data, setDatasetId]);
  const chains = useApi<ChainRow[]>(`/api/runs/${id}/chains${qs({ sort: "score" })}`);
  const focus = params.get("focus");
  // A link may name only a process; open the chain that process belongs to.
  const focusInfo = useApi<ProcessInfo>(focus && !params.get("chain") ? `/api/runs/${id}/processes/${encodeURIComponent(focus)}` : null);
  const chain = params.get("chain") ?? (focus ? focusInfo.data?.lineage_chain_id ?? null : chains.data?.[0]?.lineage_chain_id ?? null);
  const depth = params.get("depth") ?? "3";
  const selected = params.get("process");
  const graph = useApi<ChainGraph>(chain ? `/api/runs/${id}/chains/${encodeURIComponent(chain)}/graph${qs({ focus: focus ?? undefined, depth })}` : null);
  const set = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    Object.entries(changes).forEach(([key, value]) => (value === null ? next.delete(key) : next.set(key, value)));
    setParams(next);
  };
  const visibleChains = (chains.data ?? []).filter((c) => (!detectedOnly || c.detected_windows > 0) && (!chainFilter || `${c.lineage_chain_id} ${c.root_image ?? ""}`.toLowerCase().includes(chainFilter.toLowerCase())));
  const currentChain = chains.data?.find((c) => c.lineage_chain_id === chain);

  return (
    <>
      <PageHeader eyebrow={`lineage · run ${id}`} title="Process-lineage investigation">
        The process tree rebuilt from the telemetry. Parents missing from the data are drawn dashed, never guessed. Select a process to inspect it or expand its neighbourhood.
      </PageHeader>
      {run.data?.state && run.data.state !== "completed" && <ErrorBox error={`run is ${run.data.state}; lineage is available after it completes.`} />}
      <div className="grid grid-cols-[280px_1fr] gap-4 items-start">
        <Panel title="Chains" eyebrow={chains.data ? `${chains.data.length} reconstructed` : ""} bodyClass="">
          <div className="p-3 space-y-2 border-b border-line">
            <input className="input w-full" placeholder="filter by GUID or root image" value={chainFilter} onChange={(event) => setChainFilter(event.target.value)} />
            <label className="flex items-center gap-2 text-[12px]">
              <input type="checkbox" className="accent-accent" checked={detectedOnly} onChange={(event) => setDetectedOnly(event.target.checked)} /> only chains with detections
            </label>
          </div>
          {chains.error && <div className="p-3"><ErrorBox error={chains.error} /></div>}
          {!chains.data && !chains.error && <Loading />}
          <ul className="divide-y divide-line max-h-[calc(100vh-300px)] overflow-y-auto">
            {visibleChains.map((c) => (
              <li key={c.lineage_chain_id}>
                <button onClick={() => set({ chain: c.lineage_chain_id, focus: null, process: null })} className={`w-full text-left px-3 py-2 hover:bg-hover ${c.lineage_chain_id === chain ? "bg-accent-dim/60" : ""}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[12px] truncate">{c.root_image ? basename(c.root_image) : shortGuid(c.lineage_chain_id)}</span>
                    {c.detected_windows > 0 ? <span className="font-mono text-[12px] text-detect">{score(c.max_score)}</span> : <span className="font-mono text-2xs text-faint">{score(c.max_score)}</span>}
                  </div>
                  <div className="flex items-center gap-1.5 mt-0.5 text-2xs text-muted font-mono">
                    {int(c.process_count)} proc · {c.detected_windows} det
                    {c.is_truncated && <Pill tone="warn">truncated</Pill>}
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </Panel>
        <div className="min-w-0 space-y-3">
          {currentChain && (
            <div className="panel px-4 py-2.5 flex flex-wrap items-center gap-x-5 gap-y-1 text-[12px]">
              <span><span className="text-muted">chain </span><span className="font-mono">{currentChain.lineage_chain_id}</span></span>
              <span><span className="text-muted">processes </span><span className="font-mono">{int(currentChain.process_count)}</span></span>
              <span><span className="text-muted">shown </span><span className="font-mono">{graph.data ? `${graph.data.shown_nodes} of ${graph.data.total_nodes}` : "…"}</span></span>
              <span><span className="text-muted">unresolved parents </span><span className="font-mono">{currentChain.unresolved_parent_count}</span></span>
              {currentChain.detected_windows > 0 && (
                <Link className="link" to={`/runs/${id}/detections?chain=${encodeURIComponent(currentChain.lineage_chain_id)}&detected=true`}>
                  {currentChain.detected_windows} detected windows →
                </Link>
              )}
              {graph.data && graph.data.shown_nodes < graph.data.total_nodes && (
                <label className="flex items-center gap-1.5 ml-auto">
                  <span className="text-muted">descendant depth</span>
                  <select className="input py-0.5" value={depth} onChange={(event) => set({ depth: event.target.value })}>
                    {[1, 2, 3, 4, 6, 8, 12].map((d) => (
                      <option key={d} value={d}>{d}</option>
                    ))}
                  </select>
                </label>
              )}
            </div>
          )}
          <div className="panel h-[calc(100vh-250px)] min-h-[480px] relative overflow-hidden">
            {graph.error && <div className="p-4"><ErrorBox error={graph.error} /></div>}
            {!graph.data && !graph.error && chain && <Loading label="Laying out the chain" />}
            {!chain && <Empty title="No chain selected" />}
            {graph.data && (
              <ReactFlowProvider>
                <Graph graph={graph.data} selected={selected} focus={focus} onSelect={(guid) => set({ process: guid })} />
              </ReactFlowProvider>
            )}
            {selected && graph.data && <ProcessDrawer runId={id} guid={selected} onClose={() => set({ process: null })} onFocus={(guid) => set({ focus: guid, process: guid })} datasetId={run.data?.dataset_id ?? ""} />}
          </div>
        </div>
      </div>
    </>
  );
}

function Graph({ graph, selected, focus, onSelect }: { graph: ChainGraph; selected: string | null; focus: string | null; onSelect: (guid: string) => void }) {
  const { theme } = useTheme();
  const colors = GRAPH_COLORS[theme];
  const { nodes, edges } = useMemo(() => layout(graph, selected, focus, colors), [graph, selected, focus, colors]);
  const flow = useReactFlow();
  useEffect(() => {
    const target = focus ?? graph.nodes.find((n) => n.detected_windows.length)?.id;
    const timer = setTimeout(() => {
      if (target && graph.nodes.length > 40) {
        const node = nodes.find((n) => n.id === target);
        if (node) flow.setCenter(node.position.x + NODE_W / 2, node.position.y + NODE_H / 2, { zoom: 0.95, duration: 300 });
      } else {
        flow.fitView({ padding: 0.15, duration: 300 });
      }
    }, 30);
    return () => clearTimeout(timer);
    // recenter when the graph or the focus changes, not on selection
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, focus]);
  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      onNodeClick={(_, node) => node.type === "process" && onSelect(node.id)}
      nodesDraggable={false}
      nodesConnectable={false}
      minZoom={0.1}
      colorMode={theme}
      proOptions={{ hideAttribution: true }}
    >
      <Background color={colors.grid} gap={22} />
      <Controls showInteractive={false} />
      <MiniMap pannable zoomable nodeColor={(n) => (n.type === "ghost" ? colors.grid : (n.data as unknown as ProcessNodeData).detected_windows?.length ? colors.detect : colors.node)} maskColor={colors.mask} style={{ background: colors.panel }} />
    </ReactFlow>
  );
}

function ProcessDrawer({ runId, guid, onClose, onFocus, datasetId }: { runId: string; guid: string; onClose: () => void; onFocus: (guid: string) => void; datasetId: string }) {
  const process = useApi<ProcessInfo>(`/api/runs/${runId}/processes/${encodeURIComponent(guid)}`);
  const data = process.data;
  return (
    <div className="absolute inset-y-0 right-0 w-[420px] bg-panel border-l border-line z-10 flex flex-col">
      <div className="panel-head">
        <div className="min-w-0">
          <div className="eyebrow">process</div>
          <div className="font-mono text-[13px] truncate">{data ? basename(data.image_path) : shortGuid(guid)}</div>
        </div>
        <button className="btn btn-ghost" onClick={onClose} aria-label="close"><X size={16} /></button>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {process.error && <ErrorBox error={process.error} />}
        {!data && !process.error && <Loading />}
        {data && (
          <>
            <KV
              rows={[
                ["ProcessGuid", <span className="font-mono text-2xs break-all">{data.process_guid}</span>],
                ["PID", <span className="font-mono">{data.process_id ?? "—"}</span>],
                ["image", <span className="font-mono text-2xs break-all">{data.image_path ?? "not recorded"}</span>],
                ["integrity (first seen)", data.integrity_level ?? "—"],
                ["command line", <span className="font-mono text-2xs break-all">{data.command_line ?? "—"}</span>],
                ["first / last event", <span className="font-mono text-2xs">{time(data.first_seen)} → {time(data.last_seen, false)}</span>],
                ["research label", data.label ? (data.label.is_attack ? <Pill tone="detect">attack · {data.label.technique}</Pill> : <Pill tone="ok">benign</Pill>) : <span className="text-faint">none</span>],
              ]}
            />
            <div>
              <div className="eyebrow mb-1">parent</div>
              {data.parent_process_guid === null ? (
                <span className="text-2xs text-muted">no parent asserted in any record</span>
              ) : data.parent_in_telemetry ? (
                <button className="link font-mono text-[12px]" onClick={() => onFocus(data.parent_process_guid!)}>{basename(data.parent?.image_path)} {shortGuid(data.parent_process_guid)}</button>
              ) : (
                <span className="text-2xs text-warn">parent {data.parent_process_guid} is asserted but has no events in this dataset (unresolved)</span>
              )}
            </div>
            <div>
              <div className="eyebrow mb-1">children ({data.children?.length ?? 0})</div>
              <div className="flex flex-wrap gap-1">
                {(data.children ?? []).slice(0, 40).map((child) => (
                  <button key={child} className="chip border-line-strong hover:border-accent" onClick={() => onFocus(child)}>{shortGuid(child)}</button>
                ))}
                {(data.children?.length ?? 0) > 40 && <span className="text-2xs text-muted">+{(data.children?.length ?? 0) - 40} more</span>}
              </div>
              {(data.children?.length ?? 0) > 0 && <button className="btn mt-2 text-2xs" onClick={() => onFocus(guid)}>expand around this process</button>}
            </div>
            {data.detected_window_indices.length > 0 && (
              <div>
                <div className="eyebrow mb-1">detections referencing this process</div>
                <div className="flex flex-wrap gap-1">
                  {data.detected_window_indices.map((index) => (
                    <Link key={index} className="chip border-detect/50 text-detect bg-detect-dim" to={`/runs/${runId}/detections?w=${index}&detected=true`}>
                      <Activity size={10} /> window #{index}
                    </Link>
                  ))}
                </div>
              </div>
            )}
            <div>
              <div className="eyebrow mb-1 flex justify-between">
                <span>related telemetry ({int(data.event_count)} events)</span>
                {datasetId && data.events.length > 0 && (
                  <Link className="link normal-case tracking-normal" to={`/explore/${datasetId}?indices=${data.events.slice(0, 300).map((e) => e.record_index).join(",")}&sort=__time__`}>
                    open in Explorer <Search size={10} className="inline" />
                  </Link>
                )}
              </div>
              <div className="text-2xs text-muted mb-1">{Object.entries(data.event_codes).map(([code, count]) => `${eventCodeLabel(code)} ×${count}`).join(" · ")}</div>
              <ul className="font-mono text-2xs space-y-0.5 max-h-60 overflow-y-auto">
                {data.events.slice(0, 120).map((event) => (
                  <li key={event.event_id + event.record_index}>
                    <Link className="hover:text-accent" to={`/explore/${datasetId}?indices=${event.record_index}&record=${event.record_index}`}>
                      {time(event.timestamp, false)} · {eventCodeLabel(event.event_code)} · {event.event_id}
                    </Link>
                  </li>
                ))}
              </ul>
              {data.event_count > data.events.length && <div className="text-2xs text-faint mt-1">first {data.events.length} events listed</div>}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
