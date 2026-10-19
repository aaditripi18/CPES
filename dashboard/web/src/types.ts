export type Category = "research_telemetry" | "synthetic" | "user_upload" | "public_dataset";

export interface GroundTruth {
  available: boolean;
  unit: string | null;
  source: string | null;
  how: string;
}

export interface ValidationSummary {
  status: ValidationStatus;
  accepted: number;
  rejected: number;
  parse_error_count: number;
  computed_at: string;
}

export type ValidationStatus = "valid" | "valid_with_rejections" | "invalid";

export interface MappingSpec {
  preset?: string | null;
  overrides?: Record<string, string | null>;
  event_id_from_position?: boolean;
}

export interface DatasetMeta {
  id: string;
  name: string;
  origin: "builtin" | "upload";
  path?: string;
  format: string;
  category: Category;
  source: string;
  contents?: string;
  ground_truth: GroundTruth;
  private: boolean;
  notes?: string;
  available: boolean;
  size_bytes: number | null;
  sha256?: string;
  records?: number;
  uploaded_at?: string;
  original_filename?: string;
  suggested_mapping?: MappingSpec;
  experiments: string[];
  validation?: ValidationSummary | null;
  runs?: number;
}

export interface DatasetDetail extends DatasetMeta {
  records: number;
  parse_errors: ParseError[];
  parse_error_count: number;
  structure_errors: string[];
  blank_lines: number;
  csv_columns: string[] | null;
  default_columns: string[];
  facet_fields: string[];
  timestamp_field: string | null;
}

export interface ParseError {
  location: number;
  error: string;
  excerpt: string;
}

export interface MappingField {
  destination: string;
  source: string | null;
  derived_from_position: boolean;
  optional: boolean;
  required: boolean;
}

export interface Rejection {
  index: number;
  location: number;
  stage: "mapping" | "translation";
  error: string;
}

export interface ValidationReport {
  status: ValidationStatus;
  computed_at: string;
  format: string;
  records_read: number;
  blank_lines: number;
  parse_errors: ParseError[];
  parse_error_count: number;
  structure_errors: string[];
  mapping_error?: string;
  mapping?: { spec: MappingSpec; key: string; version: string; fields: MappingField[] };
  accepted: number;
  rejected: number;
  rejections?: Rejection[];
  rejection_summary?: { stage: string; error: string; count: number }[];
  field_presence?: Record<string, number>;
  warnings: { code: string; message: string }[];
  cross_record_errors: { code: string; message: string }[];
  without_process_guid?: number;
  integrity_levels?: Record<string, number>;
  event_codes?: Record<string, number>;
  time_range?: { start: string; end: string; seconds: number };
  lineage_preview?: { process_nodes: number; chains: number; truncated_chains: number };
  dataset_sha256?: string;
}

export interface SchemaEntry {
  path: string;
  present: number;
  missing: number;
  coverage: number;
  types: Record<string, number>;
  examples: string[];
}

export interface RecordsPage {
  total: number;
  offset: number;
  limit: number;
  columns: string[];
  rows: { index: number; location: number; cells: Record<string, string | null> }[];
  facets?: Record<string, { distinct: number; values: [string, number][] }>;
}

export interface RecordInspection {
  index: number;
  location: number;
  format: string;
  original: Record<string, unknown>;
  canonical: { destination: string; source: string | null; present: boolean; value: unknown; derived_from_position: boolean; required: boolean }[];
  unmapped_fields: string[];
  accepted: boolean;
  issues: string[];
}

export type RunState = "queued" | "running" | "completed" | "failed";

export interface RunSummary {
  records_accepted: number;
  records_rejected: number;
  process_nodes: number;
  lineage_chains: number;
  scored_windows: number;
  nonempty_windows: number;
  detected_windows: number;
  detected_chains: number;
  signals_fired: Record<string, number>;
  threshold: string;
  evidence_model: string;
  evaluated: boolean;
  cpes_alerts?: number;
  sigma_alerts?: number;
  incidents?: number;
  sigma_enabled?: boolean;
}

export interface IncidentAlert {
  id: string;
  source: "cpes" | "sigma";
  time: string;
  process_guid: string | null;
  image: string | null;
  title: string;
  level: string;
  tags: string[];
  signal_id?: string;
  weight?: string;
  window_index?: number;
  score?: string;
  actor_process_guid?: string | null;
  explanation?: string[];
  rule_id?: string;
  record_index?: number;
}

export interface Incident {
  id: string;
  start: string;
  end: string;
  level: string;
  sources: string[];
  techniques: string[];
  outcome: { process_guid: string; image: string | null; integrity_level: string | null }[];
  processes: string[];
  alerts: IncidentAlert[];
  headline: string;
}

export interface IncidentsFile {
  rule: string;
  gap_seconds: number;
  sigma: { enabled: boolean; reason?: string; pack?: string; rules?: number; levels?: string; alerts?: number };
  cpes_alerts: number;
  sigma_alerts: number;
  incidents: Incident[];
}

export interface RunStatus {
  id: string;
  state: RunState;
  stage: string;
  stages: string[];
  created_at: string;
  completed_at?: string;
  failed_at?: string;
  dataset_id: string;
  dataset_name: string;
  dataset_category: Category;
  dataset_sha256?: string;
  note: string;
  kind: string;
  error?: string;
  error_type?: string;
  traceback?: string;
  timings?: Record<string, number>;
  summary?: RunSummary;
  config?: RunConfig | null;
}

export interface EvidenceModelInfo {
  id: string;
  title: string;
  derived_with: string;
  source_table: string;
  source_table_sha256: string;
  units: { total: number; attack: number; benign: number };
  signal_counts: Record<string, { attack_present: number; benign_present: number }>;
  prior_log_odds_derived: string;
  prior_applied: string;
  prior_note: string;
  default_threshold: string;
  terms: { signal_id: string; signed_log_likelihood: string }[];
  scope_note: string;
}

export interface SignalWiring {
  wired: boolean;
  reads: string;
  note: string;
}

export interface RunConfig {
  run_id: string;
  created_at: string;
  dataset: { id: string; name: string; category: Category; origin: string; sha256?: string; records_read: number; parse_errors: number; records_accepted: number; records_rejected: number; rejection_note: string };
  mapping: { spec: MappingSpec; version: string; fields: MappingField[] };
  window: { span_seconds: number; advance_seconds: number; start_at: string; horizon_end_at: string; rule: string };
  threshold: string;
  evidence_model: EvidenceModelInfo;
  signals: Record<string, SignalWiring>;
  resolver: Record<string, string[]>;
  versions: Record<string, string | boolean | null>;
  engine: string;
  evidence_channels?: { enabled: boolean; reason?: string; mapping?: string; pipe_evidence?: number; remote_thread_evidence?: number; skipped?: Record<string, number>; records_not_mappable?: number; attachment_rule?: string };
}

export interface WindowRow {
  window_index: number;
  lineage_chain_id: string;
  start: string;
  end: string;
  event_count: number;
  process_count: number;
  cpes_score: string;
  is_detected: boolean;
  signals: string[];
  baseline_detected: boolean;
  integrity_transitions: number;
  flags: { truncated: boolean; incomplete: boolean; fragmented: boolean };
}

export interface SourceRef {
  process_guid: string;
  event_id: string | null;
}

export interface ExportRecord {
  lineage_chain_id: string;
  window_start: string;
  window_end: string;
  prior_log_odds: string;
  cpes_score: string;
  detection_threshold: string;
  is_detected: boolean;
  is_truncated: boolean;
  is_incomplete: boolean;
  is_fragmented: boolean;
  contributions: { signal_id: string; signed_log_likelihood: string; source_references: SourceRef[] }[];
  observations: { signal_id: string; is_present: boolean; source_references: SourceRef[] }[];
  label: { is_attack: boolean; techniques?: string[] } | null;
}

export interface ProcessInfo {
  process_guid: string;
  parent_process_guid: string | null;
  process_id: number | string | null;
  image_path: string | null;
  integrity_level: string | null;
  command_line: string | null;
  first_seen: string;
  last_seen: string;
  event_count: number;
  event_codes: Record<string, number>;
  events: { event_id: string; timestamp: string; event_code: string | number | null; record_index: number }[];
  label: { is_attack: boolean; technique: string | null } | null;
  lineage_chain_id: string | null;
  is_incomplete: boolean | null;
  detected_window_indices: number[];
  children?: string[];
  parent?: ProcessInfo | null;
  parent_in_telemetry?: boolean | null;
}

export interface ResolvedContext {
  anchor_process_guid: string;
  anchor_kind: string;
  actor_process_guid: string | null;
  mediator: string | null;
  privilege_level: string | null;
  evidence_event_ids: string[];
  resolution_path: string[];
}

export interface WindowDetail {
  window_index: number;
  record: ExportRecord;
  summary: WindowRow | null;
  audit: {
    event_ids: string[];
    integrity_transitions: { parent_process_guid: string; child_process_guid: string; parent_integrity_level: string; child_integrity_level: string }[];
    resolved: ResolvedContext[];
    baseline_triggering_process_guids: string[];
  } | null;
  baseline: { window_index: number; lineage_chain_id: string; is_detected: boolean; triggering_process_guids: string[] };
  weights: Record<string, string>;
  prior_applied: string;
  processes: Record<string, ProcessInfo | null>;
  evidence_events: { event_id: string; record_indices: number[] }[];
  dataset_id: string;
  signals: Record<string, SignalWiring>;
}

export interface ChainRow {
  lineage_chain_id: string;
  root_process_guid: string;
  process_count: number;
  unresolved_parent_count: number;
  is_truncated: boolean;
  is_incomplete: boolean;
  is_fragmented: boolean;
  root_image: string | null;
  windows: number;
  nonempty_windows: number;
  detected_windows: number;
  max_score: string | null;
  signals: Record<string, number>;
  label: { is_attack: boolean; techniques?: string[]; labelled_processes?: number; attack_processes?: number } | null;
}

export interface GraphNode {
  id: string;
  image_path: string | null;
  process_id: number | string | null;
  integrity_level: string | null;
  first_seen: string | null;
  event_count: number;
  detected_windows: number[];
  label: { is_attack: boolean; technique: string | null } | null;
  parent_process_guid: string | null;
  parent_unresolved: boolean;
  hidden_children: number;
  is_root: boolean;
}

export interface ChainGraph {
  lineage_chain_id: string;
  total_nodes: number;
  shown_nodes: number;
  focus: string | null;
  unresolved_parent_process_guids: string[];
  nodes: GraphNode[];
  edges: { source: string; target: string }[];
}

export interface Metrics {
  detector: string;
  scored_chains: number;
  confusion: { true_positives: number; false_positives: number; true_negatives: number; false_negatives: number };
  precision: string | null;
  recall: string | null;
  false_positive_rate: string | null;
  false_negative_rate: string | null;
  accuracy: string | null;
  f1_score: string | null;
}

export interface RunEvaluation {
  available: boolean;
  reason?: string;
  ground_truth?: GroundTruth;
  in_sample_warning?: string;
  chain_level?: {
    protocol: string;
    labelled_chains: number;
    excluded_unlabelled_chains: number;
    largest_chains: { lineage_chain_id: string; processes: number; label: ChainRow["label"] }[];
    caveat: string;
    comparison: { scored_chains: number; cpes: Metrics; baseline: Metrics; comparison: Record<string, string | null> };
  };
  process_level_diagnostic?: {
    protocol: string;
    cpes: Metrics;
    single_event_baseline: Metrics;
    per_technique: Record<string, { attack_processes: number; cpes_flagged: number; baseline_flagged: number }>;
    flagged_but_unlabelled: number;
    false_positive_processes?: { process_guid: string; image_path: string | null }[];
    missed_by_technique?: Record<string, number>;
    explanation: string;
  };
}

export interface DetectorRow {
  precision: number;
  recall: number;
  fpr: number;
  f1: number;
  precision_std?: number;
  recall_std?: number;
  fpr_std?: number;
  f1_std?: number;
  tp?: number;
  fp?: number;
  fn?: number;
}

export interface ExperimentRecord {
  id: string;
  experiment_id: string;
  title: string;
  script: string;
  protocol: string;
  role: string;
  dataset: string | null;
  state: "running" | "completed" | "failed";
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  exit_code?: number | null;
  stdout?: string;
  stderr?: string;
  script_sha256: string;
  inputs: { path: string; sha256: string; bytes: number }[];
  versions: Record<string, string | boolean | null>;
  parsed?: {
    detectors: Record<string, DetectorRow>;
    units?: { units: number; attack: number; benign: number } | null;
    pooled_confusion?: Record<string, { tp: number; fp: number; tn: number; fn: number }> | null;
    weights?: Record<string, number>;
    aggregation: string;
    raw?: Record<string, unknown>;
    results_id?: string;
    code_sha256?: string;
  } | null;
}

export interface CatalogEntry {
  id: string;
  script: string;
  title: string;
  protocol: string;
  dataset: string | null;
  inputs: string[];
  role: string;
  role_note?: string;
  parser: string | null;
  runnable: boolean;
  missing_inputs: string[];
  latest: ExperimentRecord | null;
}

export interface Claim {
  claim: string;
  expected: number;
  experiment: string;
  detector: string;
  metric: string;
  observed: number | null;
  status: "matches" | "differs" | "not_reproduced_yet" | "unparsed";
  execution_id: string | null;
}

export interface ChainNode {
  process_guid: string;
  image: string | null;
  pid: number | null;
  integrity_level: string | null;
}

export interface FeaturedChain {
  run_id: string;
  dataset_name: string;
  dataset_category: string;
  incident_id: string;
  signal_id: string;
  weight: string;
  score: string;
  threshold: string | null;
  window_index: number;
  explanation: string | null;
  chain: ChainNode[];
  actor: ChainNode | null;
  sigma_alerts: number;
  sigma_titles: string[];
}

export interface HeadlineResult {
  label: string;
  value: string;
  detail: string;
  protocol: string;
}

export interface Overview {
  featured: FeaturedChain | null;
  headline: HeadlineResult[];
  runs: RunStatus[];
  run_counts: Record<string, number>;
  latest: {
    run: RunStatus;
    dataset: DatasetMeta | null;
    validation_status: ValidationStatus | null;
    score_histogram: { bin: number; count: number; detected: number }[];
    nonempty_windows: number;
    recent_detections: WindowRow[];
    event_codes: Record<string, number>;
    signals_fired: Record<string, number>;
  } | null;
  experiments: ExperimentRecord[];
  claims: Claim[];
  datasets: number;
  health: Record<string, string | boolean | null>;
}

export interface SystemInfo {
  versions: Record<string, string | boolean | null>;
  data_root: string;
  formats: { format: string; extensions: string[]; rule: string }[];
  max_upload_bytes: number;
  telemetry_sources: { name: string; status: string; mapping?: string; note?: string }[];
  canonical_fields: { name: string; required: boolean }[];
  default_mapping: MappingField[];
  signals: (SignalWiring & { signal_id: string })[];
  resolver: Record<string, string[]>;
  evidence_models: EvidenceModelInfo[];
  known_unsupported_techniques: { technique: string; evidence: string }[];
  limitations: string[];
  data_availability: { item: string; state: string; note: string }[];
}
