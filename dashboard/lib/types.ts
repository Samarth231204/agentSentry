// Shapes returned by the AgentGuard backend (agentguard/server/app.py).

export type Status = "confirmed" | "suspected" | "failed" | "error";

export interface CategoryScore {
  attempted: number;
  succeeded: number;
}

export interface Scorecard {
  total_attempts: number;
  total_successes: number;
  success_rate: number;
  by_category: Record<string, CategoryScore>;
}

export interface UsageRow {
  calls: number;
  prompt_tokens: number;
  completion_tokens: number;
}

export interface BudgetUsage {
  total: UsageRow;
  by_role: Record<string, UsageRow>;
}

export interface RunSummary {
  id: string;
  label: string;
  source: "agentguard_runs" | "project_root" | "run_dir";
  path: string;
  modified: number;
  modified_iso: string;
  files: string[];
  scorecard: Scorecard;
  statuses: Record<string, number>;
  generated_by: string | null;
  budget_usage: BudgetUsage | null;
  has_manifest: boolean;
  has_report: boolean;
  has_trace: boolean;
  warnings: string[];
}

export interface McpUsage {
  calls: { server: string; tool: string; count: number }[];
  total: number;
  errors: number;
  unavailable: string[];
}

export interface RunDetail extends RunSummary {
  llm_usage: BudgetUsage;
  mcp_usage: McpUsage;
  event_counts: Record<string, number>;
}

export interface ToolCall {
  name: string;
  args: Record<string, unknown>;
  timestamp: number;
}

export interface Turn {
  sent: string;
  received: string | null;
  tool_calls: ToolCall[];
  outcome: string;
  error: Record<string, string> | null;
}

export interface Finding {
  id: string;
  category: string;
  capability_targeted: string;
  turns: Turn[];
  oracle: string | null;
  oracle_detail: string | null;
  status: Status;
  confidence: number;
  success: boolean;
  severity: string | null;
  remediation: string | null;
  owasp: string | null;
  code_references: string[];
}

export interface ReportPayload {
  markdown: string | null;
  json: {
    generated_by?: string;
    scorecard?: Scorecard;
    severity?: Record<string, string>;
    remediation?: Record<string, string>;
    owasp?: Record<string, string>;
    code_references?: Record<string, string[]>;
  } | null;
}

export interface TraceEvent {
  timestamp: number;
  source: string;
  event_type: string;
  payload: Record<string, unknown>;
}

export interface TracePage {
  events: TraceEvent[];
  total: number;
  offset: number;
  next_offset: number;
}

export interface ProjectInfo {
  project_root: string;
  agentguard_version: string;
  run_count: number;
  run_dirs: string[];
}

export interface SettingsValues {
  attacker_model: string;
  reporter_model: string;
  chat_model: string;
  fallback_chain: string[];
  max_probes: number;
  category_cooldown_seconds: number;
  target_timeout: number;
  max_llm_calls: number | null;
  max_tokens: number | null;
  saved_to_file: boolean;
}

export interface ProviderStatus {
  id: string;
  label: string;
  configured: boolean;
  masked: string | null;
}

export interface SettingsResponse {
  settings: SettingsValues;
  providers: ProviderStatus[];
}

export interface KeyTestResult {
  ok: boolean;
  model: string;
  message: string;
}

export type RunState = "queued" | "running" | "done" | "failed" | "cancelled";

export interface RunStatus {
  run_id: string;
  state: RunState;
  phase: string | null;
  phases: Record<string, string>;
  error: string | null;
  started: number;
  finished: number | null;
  target_url: string | null;
  cancel_requested: boolean;
  awaiting_plan: boolean;
  automatic: boolean;
  mock: boolean;
}

export interface PlanItem {
  candidate_id: string;
  role: string;
  file: string;
  module: string;
  qualname: string;
  name: string;
  line: number;
  include: boolean;
  sandbox: boolean;
  destructive: boolean;
  confidence: number;
  source: "auto" | "agent" | "user" | "default";
  reason: string;
}

export interface DiscoveryCandidate {
  id: string;
  role: string;
  file: string;
  qualname: string;
  name: string;
  line: number;
  confidence: number;
  signals: string[];
  destructive: boolean;
  snippet: string;
}

export interface PlanResponse {
  plan: { project_root: string; created: number; items: PlanItem[] };
  candidates: DiscoveryCandidate[];
}
