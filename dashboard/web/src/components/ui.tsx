import { AlertTriangle, Check, Copy, Loader2, Lock, FlaskConical } from "lucide-react";
import { ReactNode, useState } from "react";
import { CATEGORY_LABELS } from "../lib/format";
import type { Category, ValidationStatus } from "../types";

export function Panel({ title, eyebrow, actions, children, className = "", bodyClass = "p-4" }: { title?: ReactNode; eyebrow?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string }) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions || eyebrow) && (
        <header className="panel-head">
          <div className="min-w-0">
            {eyebrow && <div className="eyebrow mb-0.5">{eyebrow}</div>}
            {title && <h2 className="text-[14px] font-semibold text-ink truncate">{title}</h2>}
          </div>
          {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  );
}

export function PageHeader({ eyebrow, title, children, actions }: { eyebrow?: string; title: ReactNode; children?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4 mb-5">
      <div className="min-w-0 max-w-3xl">
        {eyebrow && <div className="eyebrow mb-1">{eyebrow}</div>}
        <h1 className="text-[22px] leading-7 font-semibold tracking-tight">{title}</h1>
        {children && <div className="text-muted mt-1.5 leading-relaxed">{children}</div>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

type Tone = "neutral" | "accent" | "detect" | "warn" | "ok" | "info" | "faint";
const TONES: Record<Tone, string> = {
  neutral: "border-line-strong text-ink bg-raised",
  accent: "border-accent/40 text-accent bg-accent-dim/60",
  detect: "border-detect/40 text-detect bg-detect-dim",
  warn: "border-warn/40 text-warn bg-warn-dim",
  ok: "border-ok/40 text-ok bg-ok-dim",
  info: "border-info/40 text-info bg-[#132235]",
  faint: "border-line text-muted bg-transparent",
};

export function Pill({ tone = "neutral", children, title, dashed }: { tone?: Tone; children: ReactNode; title?: string; dashed?: boolean }) {
  return (
    <span title={title} className={`chip ${TONES[tone]} ${dashed ? "border-dashed" : ""}`}>
      {children}
    </span>
  );
}

export function StatusPill({ status }: { status: ValidationStatus | string | null | undefined }) {
  if (!status) return <Pill tone="faint">not validated</Pill>;
  const map: Record<string, [Tone, string]> = {
    valid: ["ok", "valid"],
    valid_with_rejections: ["warn", "valid · rejections"],
    invalid: ["detect", "invalid"],
    completed: ["ok", "completed"],
    running: ["accent", "running"],
    queued: ["faint", "queued"],
    failed: ["detect", "failed"],
    matches: ["ok", "matches"],
    differs: ["detect", "differs"],
    not_reproduced_yet: ["faint", "not reproduced yet"],
    unparsed: ["warn", "unparsed"],
  };
  const [tone, label] = map[status] ?? ["neutral", status];
  return <Pill tone={tone}>{label}</Pill>;
}

export function CategoryBadge({ category, isPrivate }: { category: Category | string; isPrivate?: boolean }) {
  const tone: Tone = category === "synthetic" ? "warn" : category === "research_telemetry" ? "info" : category === "public_dataset" ? "ok" : "neutral";
  return (
    <span className="inline-flex items-center gap-1">
      <Pill tone={tone}>
        {category === "synthetic" ? <FlaskConical size={11} /> : null}
        {CATEGORY_LABELS[category] ?? category}
      </Pill>
      {isPrivate && (
        <Pill tone="faint" title="Contains lab host/account identifiers. Local use only; never publish.">
          <Lock size={10} /> private
        </Pill>
      )}
    </span>
  );
}

export function DecisionPill({ detected, threshold }: { detected: boolean; threshold?: string }) {
  return detected ? <Pill tone="detect">DETECTED{threshold ? ` ≥ ${threshold}` : ""}</Pill> : <Pill tone="faint">below threshold</Pill>;
}

export function Stat({ label, value, sub, onClick, tone }: { label: string; value: ReactNode; sub?: ReactNode; onClick?: () => void; tone?: "detect" | "ok" | "accent" }) {
  const color = tone === "detect" ? "text-detect" : tone === "ok" ? "text-ok" : tone === "accent" ? "text-accent" : "text-ink";
  const body = (
    <>
      <div className="eyebrow">{label}</div>
      <div className={`font-mono text-[22px] leading-8 mt-1 ${color}`}>{value}</div>
      {sub && <div className="text-2xs text-muted mt-0.5 truncate">{sub}</div>}
    </>
  );
  return onClick ? (
    <button onClick={onClick} className="panel px-4 py-3 text-left hover:border-accent/60 hover:bg-hover transition-colors">
      {body}
    </button>
  ) : (
    <div className="panel px-4 py-3">{body}</div>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-muted py-8 justify-center">
      <Loader2 size={16} className="animate-spin" /> {label}…
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="rounded-md border border-detect/40 bg-detect-dim px-4 py-3 text-[13px] flex items-start gap-2">
      <AlertTriangle size={16} className="text-detect mt-0.5 shrink-0" />
      <div className="flex-1">
        <div className="text-ink">{error}</div>
        {onRetry && (
          <button className="link text-2xs mt-1" onClick={onRetry}>
            retry
          </button>
        )}
      </div>
    </div>
  );
}

export function Notice({ tone = "warn", title, children }: { tone?: "warn" | "info" | "detect" | "ok"; title?: ReactNode; children: ReactNode }) {
  const styles = { warn: "border-warn/40 bg-warn-dim/60", info: "border-info/30 bg-[#101c2b]", detect: "border-detect/40 bg-detect-dim", ok: "border-ok/30 bg-ok-dim/60" }[tone];
  const text = { warn: "text-warn", info: "text-info", detect: "text-detect", ok: "text-ok" }[tone];
  return (
    <div className={`rounded-md border px-4 py-3 text-[13px] leading-relaxed ${styles}`}>
      {title && <div className={`font-semibold mb-0.5 ${text}`}>{title}</div>}
      <div className="text-ink/90">{children}</div>
    </div>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center text-center py-10 px-6">
      <div className="text-ink font-medium">{title}</div>
      {children && <div className="text-muted text-[13px] mt-1 max-w-md leading-relaxed">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function Copy_({ text, label }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="inline-flex items-center gap-1 text-muted hover:text-ink"
      title="Copy"
      onClick={(event) => {
        event.stopPropagation();
        navigator.clipboard?.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        });
      }}
    >
      {done ? <Check size={12} className="text-ok" /> : <Copy size={12} />}
      {label && <span className="text-2xs">{label}</span>}
    </button>
  );
}

export function Hash({ value, length = 12 }: { value?: string | null; length?: number }) {
  if (!value) return <span className="text-faint">—</span>;
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-2xs text-muted" title={value}>
      {value.slice(0, length)}… <Copy_ text={value} />
    </span>
  );
}

export function KV({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-4 gap-y-1.5 text-[13px]">
      {rows.map(([key, value], index) => (
        <div key={index} className="contents">
          <dt className="text-muted">{key}</dt>
          <dd className="min-w-0 break-words">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Missing() {
  return <span className="text-faint font-mono" title="field absent in this record">∅</span>;
}

export function Tabs<T extends string>({ value, onChange, items }: { value: T; onChange: (value: T) => void; items: { id: T; label: ReactNode }[] }) {
  return (
    <div className="flex gap-1 border-b border-line px-2">
      {items.map((item) => (
        <button
          key={item.id}
          onClick={() => onChange(item.id)}
          className={`px-3 py-2 text-[13px] -mb-px border-b-2 ${value === item.id ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink"}`}
        >
          {item.label}
        </button>
      ))}
    </div>
  );
}

export function Pager({ offset, limit, total, onChange }: { offset: number; limit: number; total: number; onChange: (offset: number) => void }) {
  const end = Math.min(offset + limit, total);
  return (
    <div className="flex items-center justify-between gap-3 px-3 py-2 text-2xs text-muted font-mono">
      <span>
        {total === 0 ? "0" : `${(offset + 1).toLocaleString()}–${end.toLocaleString()}`} of {total.toLocaleString()}
      </span>
      <span className="flex gap-1">
        <button className="btn btn-ghost px-2 py-0.5" disabled={offset === 0} onClick={() => onChange(0)}>
          «
        </button>
        <button className="btn btn-ghost px-2 py-0.5" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>
          prev
        </button>
        <button className="btn btn-ghost px-2 py-0.5" disabled={end >= total} onClick={() => onChange(offset + limit)}>
          next
        </button>
      </span>
    </div>
  );
}
