// Sysmon event IDs that occur in the CPES corpora (labels only; no logic depends on them).
export const EVENT_CODE_NAMES: Record<string, string> = {
  "1": "ProcessCreate",
  "3": "NetworkConnect",
  "5": "ProcessTerminate",
  "6": "DriverLoad",
  "7": "ImageLoad",
  "8": "CreateRemoteThread",
  "10": "ProcessAccess",
  "11": "FileCreate",
  "12": "RegistryObject",
  "13": "RegistryValueSet",
  "17": "PipeCreated",
  "18": "PipeConnected",
};

export const SIGNAL_LABELS: Record<string, string> = {
  autoelevation_lolbin: "Auto-elevating LOLBin + hijack write",
  service_dropped_binary: "SYSTEM service from dropped binary",
  remote_thread_injection: "Remote-thread injection",
  token_impersonation: "Named-pipe token impersonation",
};

export const CATEGORY_LABELS: Record<string, string> = {
  research_telemetry: "Research telemetry",
  synthetic: "Synthetic",
  user_upload: "User upload",
  public_dataset: "Public dataset",
};

export function eventCodeLabel(code: string | number | null | undefined): string {
  if (code === null || code === undefined || code === "None") return "no code";
  const name = EVENT_CODE_NAMES[String(code)];
  return name ? `${code} ${name}` : `EID ${code}`;
}

export function basename(path: string | null | undefined): string {
  if (!path) return "—";
  const parts = path.replace(/\//g, "\\").split("\\");
  return parts[parts.length - 1] || path;
}

export function shortGuid(guid: string | null | undefined): string {
  if (!guid) return "—";
  const clean = guid.replace(/[{}]/g, "");
  const parts = clean.split("-");
  // middle segments are a start timestamp in Sysmon GUIDs; the last segment's tail separates processes started in the same second
  return parts.length >= 5 ? `${parts[1]}-${parts[2]}…${parts[4].slice(-6)}` : clean.slice(0, 18);
}

export function score(value: string | number | null | undefined, digits = 2): string {
  if (value === null || value === undefined) return "—";
  const number = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(number)) return String(value);
  return `${number >= 0 ? "+" : ""}${number.toFixed(digits)}`;
}

export function ratio(value: string | number | null | undefined, digits = 3): string {
  if (value === null || value === undefined) return "undefined";
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) ? number.toFixed(digits) : String(value);
}

export function bytes(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 100 ? 0 : 1)} ${units[unit]}`;
}

export function int(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : value.toLocaleString("en-US");
}

export function time(value: string | null | undefined, withDate = true): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const iso = date.toISOString();
  return withDate ? `${iso.slice(0, 10)} ${iso.slice(11, 19)}Z` : `${iso.slice(11, 19)}Z`;
}

export function ago(value: string | null | undefined): string {
  if (!value) return "—";
  const seconds = (Date.now() - new Date(value).getTime()) / 1000;
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}

export function duration(seconds: number): string {
  if (seconds < 120) return `${Math.round(seconds)} s`;
  if (seconds < 7200) return `${Math.round(seconds / 60)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}
