import { Activity, BarChart3, Siren, Database, FileSearch, GitBranch, Info, LayoutDashboard, ListTree, Play, Radio, Sigma } from "lucide-react";
import { ReactNode } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";
import { useApi } from "./lib/hooks";
import { useWorkspace } from "./Workspace";
import type { DatasetMeta, RunStatus } from "./types";
import { CategoryBadge, StatusPill } from "./components/ui";

export function Layout({ children }: { children: ReactNode }) {
  const { runId, datasetId } = useWorkspace();
  const location = useLocation();
  const run = useApi<RunStatus>(runId ? `/api/runs/${runId}` : null, 1500, (value) => value.state === "running" || value.state === "queued");
  const dataset = useApi<{ datasets: DatasetMeta[] }>("/api/inventory");
  const activeDataset = dataset.data?.datasets.find((d) => d.id === (datasetId ?? run.data?.dataset_id));
  const nav: { to: string; label: string; icon: ReactNode; needsRun?: boolean; needsDataset?: boolean }[] = [
    { to: "/", label: "Overview", icon: <LayoutDashboard size={16} /> },
    { to: "/datasets", label: "Datasets", icon: <Database size={16} /> },
    { to: datasetId ? `/explore/${datasetId}` : "/explore", label: "Explorer", icon: <FileSearch size={16} /> },
    { to: "/live", label: "Live", icon: <Radio size={16} /> },
    { to: "/runs", label: "Runs", icon: <Play size={16} /> },
    { to: runId ? `/runs/${runId}/detections` : "/detections", label: "Detections", icon: <Activity size={16} /> },
    { to: runId ? `/runs/${runId}/incidents` : "/incidents", label: "Incidents", icon: <Siren size={16} /> },
    { to: runId ? `/runs/${runId}/lineage` : "/lineage", label: "Lineage", icon: <GitBranch size={16} /> },
    { to: "/evaluation", label: "Evaluation", icon: <BarChart3 size={16} /> },
    { to: "/system", label: "System & limits", icon: <Info size={16} /> },
  ];
  return (
    <div className="min-h-screen flex">
      <aside className="w-[212px] shrink-0 border-r border-line bg-panel/60 flex flex-col sticky top-0 h-screen">
        <Link to="/" className="px-4 pt-4 pb-5 block">
          <div className="flex items-center gap-2">
            <svg width="22" height="22" viewBox="0 0 16 16" aria-hidden>
              <rect width="16" height="16" rx="3" fill="#161b24" stroke="#2e3747" />
              <path d="M4 11 L8 4 L12 11" stroke="#a78bfa" strokeWidth="1.6" fill="none" />
              <circle cx="8" cy="4" r="1.3" fill="#ff7b6b" />
            </svg>
            <span className="font-mono font-semibold tracking-[0.14em] text-[13px]">CPES</span>
          </div>
          <div className="text-2xs text-muted mt-1.5 leading-snug">Contextual privilege-escalation scoring</div>
        </Link>
        <nav className="flex-1 px-2 space-y-0.5">
          {nav.map((item) => (
            <NavLink
              key={item.label}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) => {
                const active = isActive || (item.label === "Detections" && location.pathname.includes("/detections")) || (item.label === "Lineage" && location.pathname.includes("/lineage")) || (item.label === "Incidents" && location.pathname.includes("/incidents")) || (item.label === "Explorer" && location.pathname.startsWith("/explore"));
                return `flex items-center gap-2.5 rounded px-2.5 py-1.5 text-[13px] ${active ? "bg-accent-dim text-ink" : "text-muted hover:text-ink hover:bg-hover"}`;
              }}
            >
              {item.icon}
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-3 border-t border-line text-2xs text-faint leading-relaxed">
          <ListTree size={12} className="inline mr-1" />
          Engine: unchanged <span className="font-mono">cpes</span> package. Research figures: <span className="font-mono">analysis/</span> scripts.
          <div className="mt-1 flex items-center gap-1">
            <Sigma size={12} /> No metric is computed without labels.
          </div>
        </div>
      </aside>
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-11 shrink-0 border-b border-line flex items-center gap-3 px-6 text-[12px] bg-bg/90 backdrop-blur sticky top-0 z-20">
          <span className="eyebrow">workspace</span>
          {activeDataset ? (
            <Link to={`/datasets/${activeDataset.id}`} className="flex items-center gap-2 hover:text-accent">
              <span className="text-muted">dataset</span>
              <span className="font-mono">{activeDataset.id}</span>
              <CategoryBadge category={activeDataset.category} isPrivate={activeDataset.private} />
            </Link>
          ) : (
            <Link to="/datasets" className="text-muted hover:text-ink">
              no dataset selected
            </Link>
          )}
          <span className="text-line-strong">/</span>
          {run.data ? (
            <Link to={`/runs/${run.data.id}`} className="flex items-center gap-2 hover:text-accent">
              <span className="text-muted">run</span>
              <span className="font-mono">{run.data.id}</span>
              <StatusPill status={run.data.state} />
            </Link>
          ) : (
            <Link to="/runs" className="text-muted hover:text-ink">
              no run selected
            </Link>
          )}
        </header>
        <main className="flex-1 px-6 py-6 min-w-0">{children}</main>
      </div>
    </div>
  );
}
