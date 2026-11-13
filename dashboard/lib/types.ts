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

export interface RunDetail extends RunSummary {
  llm_usage: BudgetUsage;
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
