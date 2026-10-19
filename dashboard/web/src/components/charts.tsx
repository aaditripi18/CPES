// Small hand-built charts. Every mark is driven by API data; clickable marks
// navigate to the records they summarise.

export function BarList({ items, onSelect, format = (v) => v.toLocaleString(), tone = "accent", selected }: { items: { key: string; label: string; value: number; hint?: string }[]; onSelect?: (key: string) => void; format?: (value: number) => string; tone?: "accent" | "detect" | "info"; selected?: string | null }) {
  const max = Math.max(1, ...items.map((item) => item.value));
  const color = { accent: "bg-accent/70", detect: "bg-detect/80", info: "bg-info/70" }[tone];
  return (
    <ul className="space-y-1">
      {items.map((item) => {
        const body = (
          <>
            <div className="flex justify-between gap-3 text-[12px] mb-0.5">
              <span className="truncate font-mono text-ink/90" title={item.hint ?? item.label}>
                {item.label}
              </span>
              <span className="font-mono text-muted shrink-0">{format(item.value)}</span>
            </div>
            <div className="h-1.5 bg-raised rounded-sm overflow-hidden">
              <div className={`h-full ${color} rounded-sm`} style={{ width: `${(item.value / max) * 100}%` }} />
            </div>
          </>
        );
        return (
          <li key={item.key}>
            {onSelect ? (
              <button onClick={() => onSelect(item.key)} className={`w-full text-left rounded px-1.5 py-1 hover:bg-hover ${selected === item.key ? "bg-accent-dim/70" : ""}`}>
                {body}
              </button>
            ) : (
              <div className="px-1.5 py-1">{body}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/** Histogram of integer-floored score bins with the decision threshold marked. */
export function ScoreHistogram({ bins, threshold, onSelect }: { bins: { bin: number; count: number; detected: number }[]; threshold: number; onSelect?: (bin: number) => void }) {
  if (!bins.length) return null;
  const low = Math.min(...bins.map((b) => b.bin), Math.floor(threshold));
  const high = Math.max(...bins.map((b) => b.bin), Math.floor(threshold));
  const all = [] as { bin: number; count: number; detected: number }[];
  for (let bin = low; bin <= high; bin += 1) {
    const found = bins.find((b) => b.bin === bin);
    all.push({ bin, count: found?.count ?? 0, detected: found?.detected ?? 0 });
  }
  const max = Math.max(...all.map((b) => b.count));
  const width = 100 / all.length;
  const logScale = (value: number) => (value <= 0 ? 0 : Math.log10(value + 1) / Math.log10(max + 1));
  const thresholdX = ((threshold - low) / (high - low + 1)) * 100;
  return (
    <div>
      <div className="relative h-40 border-b border-line">
        {all.map((b, index) => {
          // Bar height is the log of the window count; the coral share is the
          // fraction of those windows the run actually marked detected.
          const share = b.count ? b.detected / b.count : 0;
          return (
            <button
              key={b.bin}
              disabled={!onSelect || b.count === 0}
              onClick={() => onSelect?.(b.bin)}
              title={`score in [${b.bin}, ${b.bin + 1}): ${b.count.toLocaleString()} windows, ${b.detected.toLocaleString()} detected`}
              className="absolute bottom-0 group"
              style={{ left: `${index * width}%`, width: `${width}%`, height: "100%" }}
            >
              <div className="absolute bottom-0 left-[12%] right-[12%] rounded-t-sm overflow-hidden flex flex-col-reverse bg-faint/70 group-hover:bg-muted" style={{ height: `${logScale(b.count) * 100}%`, minHeight: b.count ? 2 : 0 }}>
                <div className="bg-detect/85 group-hover:bg-detect" style={{ height: `${share * 100}%` }} />
              </div>
            </button>
          );
        })}
        <div className="absolute top-0 bottom-0 border-l border-dashed border-warn" style={{ left: `${thresholdX}%` }}>
          <span className="absolute -top-0.5 left-1 font-mono text-2xs text-warn whitespace-nowrap">threshold {threshold}</span>
        </div>
      </div>
      <div className="relative h-5 font-mono text-2xs text-muted">
        {all.map((b, index) => (
          <span key={b.bin} className="absolute text-center" style={{ left: `${index * width}%`, width: `${width}%` }}>
            {all.length <= 14 || index % 2 === 0 ? b.bin : ""}
          </span>
        ))}
      </div>
      <div className="text-2xs text-muted">x: CPES score bin [b, b+1) in log-odds · y: window count, log scale · coral share = windows the run marked detected</div>
    </div>
  );
}

/** Additive score: prior, then each present signal's exact weight, ending at the score. */
export function Waterfall({ prior, steps, threshold, finalScore }: { prior: number; steps: { label: string; value: number }[]; threshold: number; finalScore: number }) {
  const points = [prior];
  steps.forEach((step) => points.push(points[points.length - 1] + step.value));
  const low = Math.min(0, prior, threshold, ...points) - 0.5;
  const high = Math.max(threshold, ...points) + 0.8;
  const x = (value: number) => ((value - low) / (high - low)) * 100;
  const rows = [{ label: "prior (applied)", from: 0, to: prior, kind: "prior" as const }, ...steps.map((step, index) => ({ label: step.label, from: points[index], to: points[index + 1], kind: step.value >= 0 ? ("pos" as const) : ("neg" as const) }))];
  const marks = (
    <>
      <div className="absolute top-0 bottom-0 border-l border-faint/60" style={{ left: `${x(0)}%` }} />
      <div className="absolute -top-1 -bottom-1 border-l border-dashed border-warn" style={{ left: `${x(threshold)}%` }} />
    </>
  );
  return (
    <div className="space-y-1.5">
      <div className="grid grid-cols-[200px_1fr_88px] gap-3 text-2xs font-mono text-muted">
        <span />
        <div className="relative h-4">
          {Math.abs(x(threshold) - x(0)) > 8 && <span className="absolute -translate-x-1/2" style={{ left: `${x(0)}%` }}>0</span>}
          <span className="absolute -translate-x-1/2 text-warn whitespace-nowrap" style={{ left: `${x(threshold)}%` }}>
            threshold {threshold}
          </span>
        </div>
        <span className="text-right">contribution</span>
      </div>
      {rows.map((row, index) => {
        const left = Math.min(x(row.from), x(row.to));
        const width = Math.max(Math.abs(x(row.to) - x(row.from)), 0.4);
        const color = row.kind === "prior" ? "bg-muted/60" : row.kind === "pos" ? "bg-detect/80" : "bg-ok/80";
        return (
          <div key={index} className="grid grid-cols-[200px_1fr_88px] items-center gap-3">
            <div className="text-[12px] font-mono truncate text-ink/90" title={row.label}>
              {row.label}
            </div>
            <div className="relative h-5 bg-raised/60 rounded-sm">
              {marks}
              <div className={`absolute top-0.5 bottom-0.5 rounded-sm ${color}`} style={{ left: `${left}%`, width: `${width}%` }} />
            </div>
            <div className="font-mono text-[12px] text-right">{(row.to - row.from >= 0 ? "+" : "") + (row.to - row.from).toFixed(4)}</div>
          </div>
        );
      })}
      <div className="grid grid-cols-[200px_1fr_88px] items-center gap-3 pt-1.5 border-t border-line">
        <div className="text-[12px] font-semibold">CPES score</div>
        <div className="relative h-5">
          {marks}
          <div className="absolute top-0 bottom-0 w-[3px] -ml-px rounded bg-ink" style={{ left: `${x(finalScore)}%` }} />
        </div>
        <div className="font-mono text-[13px] text-right font-semibold">{finalScore.toFixed(4)}</div>
      </div>
    </div>
  );
}

export function MetricBars({ rows, metrics }: { rows: { name: string; values: Record<string, number | null>; errors?: Record<string, number | null>; highlight?: boolean }[]; metrics: { key: string; label: string }[] }) {
  return (
    <div className="space-y-4">
      {metrics.map((metric) => (
        <div key={metric.key}>
          <div className="eyebrow mb-1.5">{metric.label}</div>
          <div className="space-y-1">
            {rows.map((row) => {
              const value = row.values[metric.key];
              const error = row.errors?.[metric.key] ?? null;
              return (
                <div key={row.name} className="grid grid-cols-[180px_1fr_96px] items-center gap-3">
                  <div className={`text-[12px] truncate ${row.highlight ? "text-ink font-medium" : "text-muted"}`}>{row.name}</div>
                  <div className="relative h-3.5 bg-raised rounded-sm">
                    {value !== null && value !== undefined && (
                      <>
                        <div className={`absolute inset-y-0 left-0 rounded-sm ${row.highlight ? "bg-accent/80" : "bg-faint"}`} style={{ width: `${value * 100}%` }} />
                        {error !== null && error > 0 && (
                          <div className="absolute top-1/2 h-px bg-ink/80" style={{ left: `${Math.max(0, value - error) * 100}%`, width: `${(Math.min(1, value + error) - Math.max(0, value - error)) * 100}%` }} />
                        )}
                      </>
                    )}
                  </div>
                  <div className="font-mono text-[12px] text-right">
                    {value === null || value === undefined ? "—" : value.toFixed(3)}
                    {error !== null && error !== undefined ? <span className="text-muted"> ±{error.toFixed(3)}</span> : null}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

export function Confusion({ tp, fp, tn, fn, title }: { tp: number; fp: number; tn: number; fn: number; title?: string }) {
  const cell = (label: string, value: number, tone: string) => (
    <div className={`rounded px-3 py-2 border ${tone}`}>
      <div className="eyebrow">{label}</div>
      <div className="font-mono text-[18px]">{value.toLocaleString()}</div>
    </div>
  );
  return (
    <div>
      {title && <div className="text-[12px] text-muted mb-1.5">{title}</div>}
      <div className="grid grid-cols-[auto_1fr_1fr] gap-1.5 items-center text-2xs">
        <span />
        <span className="eyebrow text-center">predicted attack</span>
        <span className="eyebrow text-center">predicted benign</span>
        <span className="eyebrow [writing-mode:vertical-rl] rotate-180">attack</span>
        {cell("TP", tp, "border-ok/40 bg-ok-dim/50")}
        {cell("FN", fn, "border-detect/30 bg-detect-dim/50")}
        <span className="eyebrow [writing-mode:vertical-rl] rotate-180">benign</span>
        {cell("FP", fp, "border-detect/30 bg-detect-dim/50")}
        {cell("TN", tn, "border-line bg-raised")}
      </div>
    </div>
  );
}
