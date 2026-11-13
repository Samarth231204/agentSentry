"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { runPath } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { Finding, ReportPayload, RunDetail } from "@/lib/types";
import { formatNumber, formatTime, pct, titleCase } from "@/lib/format";
import { Bar, Panel, ErrorBox, Loading, Tile } from "@/components/ui";
import { FindingsTable } from "@/components/Findings";
import { TraceView } from "@/components/Trace";
import { ReportMarkdown } from "@/components/ReportMarkdown";
import { RunProgress } from "@/components/RunProgress";
import { PlanReview } from "@/components/PlanReview";

const TABS = ["overview", "plan", "findings", "report", "trace", "manifest"] as const;
type Tab = (typeof TABS)[number];

export function RunView() {
  const params = useSearchParams();
  const runId = params.get("id");
  const requestedTab = params.get("tab") as Tab | null;
  const tab: Tab = requestedTab && (TABS as readonly string[]).includes(requestedTab) ? requestedTab : "overview";

  const detail = useApi<RunDetail>(runId ? runPath(runId) : null);

  if (!runId) {
    return <ErrorBox message="No run selected. Go back to the runs list." />;
  }
  if (detail.loading) return <Loading what="Loading run" />;
  if (detail.error) return <ErrorBox message={detail.error} />;
  if (!detail.data) return null;

  const run = detail.data;
  return (
    <>
      <p className="small"><Link href="/">← All runs</Link></p>
      <h1>{run.label}</h1>
      <p className="muted small mono">{run.path} · modified {formatTime(run.modified)}</p>

      <RunProgress runId={runId} onFinished={detail.refetch} />

      <nav className="tabs" aria-label="Run sections">
        {TABS.map((t) => (
          <Link
            key={t}
            href={`/run?id=${encodeURIComponent(runId)}&tab=${t}`}
            className={t === tab ? "active" : undefined}
            aria-current={t === tab ? "page" : undefined}
          >
            {titleCase(t)}
          </Link>
        ))}
      </nav>

      {tab === "overview" ? <Overview run={run} /> : null}
      {tab === "plan" ? <PlanReview runId={runId} /> : null}
      {tab === "findings" ? <FindingsPanel runId={runId} /> : null}
      {tab === "report" ? <ReportPanel runId={runId} /> : null}
      {tab === "trace" ? <TraceView runId={runId} /> : null}
      {tab === "manifest" ? <ManifestPanel runId={runId} /> : null}
    </>
  );
}

function Overview({ run }: { run: RunDetail }) {
  const { scorecard } = run;
  const warnings = run.warnings ?? [];
  const categories = Object.entries(scorecard.by_category);
  const budget = run.budget_usage ?? run.llm_usage;
  const hasBudget = budget.total.calls > 0;
  const usedBudgetFile = run.budget_usage !== null;

  return (
    <>
      {warnings.map((w) => (
        <div className="banner" key={w}>
          {w}
        </div>
      ))}

      <div className="grid-tiles">
        <Tile label="Attempts" value={scorecard.total_attempts} />
        <Tile label="Successes" value={scorecard.total_successes} />
        <Tile label="Success rate" value={pct(scorecard.success_rate)} />
        <Tile label="LLM calls" value={formatNumber(budget.total.calls)} />
        <Tile
          label="LLM tokens"
          value={formatNumber(budget.total.prompt_tokens + budget.total.completion_tokens)}
        />
      </div>

      <Panel title="By attack category">
        {categories.length === 0 ? (
          <p className="muted">No attempts recorded.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Category</th>
                <th>Attempted</th>
                <th>Succeeded</th>
                <th>Success rate</th>
              </tr>
            </thead>
            <tbody>
              {categories.map(([name, row]) => (
                <tr key={name}>
                  <td>{titleCase(name)}</td>
                  <td>{row.attempted}</td>
                  <td>{row.succeeded}</td>
                  <td style={{ minWidth: 160 }}>
                    <Bar fraction={row.attempted ? row.succeeded / row.attempted : 0} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Attempt status">
        <div className="controls">
          {Object.entries(run.statuses).length === 0 ? <span className="muted">No attempts.</span> : null}
          {Object.entries(run.statuses).map(([status, count]) => (
            <span key={status} className={`badge ${status}`}>
              {status}: {count}
            </span>
          ))}
        </div>
      </Panel>

      <Panel title="LLM usage">
        {hasBudget ? (
          <table>
            <thead>
              <tr>
                <th>Role</th>
                <th>Calls</th>
                <th>Prompt tokens</th>
                <th>Completion tokens</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(budget.by_role).map(([role, row]) => (
                <tr key={role}>
                  <td>{titleCase(role)}</td>
                  <td>{formatNumber(row.calls)}</td>
                  <td>{formatNumber(row.prompt_tokens)}</td>
                  <td>{formatNumber(row.completion_tokens)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted">
            No LLM usage recorded for this run.
            {usedBudgetFile ? "" : " This run predates budget tracking (findings.json was not written)."}
          </p>
        )}
      </Panel>

      <Panel title="MCP calls">
        {run.mcp_usage.total === 0 && run.mcp_usage.unavailable.length === 0 ? (
          <p className="muted">No MCP calls recorded for this run.</p>
        ) : (
          <>
            {run.mcp_usage.total > 0 ? (
              <table>
                <thead>
                  <tr>
                    <th>Server</th>
                    <th>Tool</th>
                    <th>Calls</th>
                  </tr>
                </thead>
                <tbody>
                  {run.mcp_usage.calls.map((c) => (
                    <tr key={`${c.server}.${c.tool}`}>
                      <td className="mono small">{c.server}</td>
                      <td className="mono small">{c.tool}</td>
                      <td>{c.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : null}
            <p className="small muted">
              {run.mcp_usage.errors} error(s). Full request and response previews are in the Trace tab
              (mcp_tool_call, mcp_tool_result).
            </p>
            {run.mcp_usage.unavailable.map((u) => (
              <div className="banner" key={u}>
                Not used: {u}
              </div>
            ))}
          </>
        )}
      </Panel>

      <Panel title="Files in this run">
        <div className="controls small">
          {run.files.map((f) => (
            <code key={f}>{f}</code>
          ))}
        </div>
        <p className="small muted" style={{ marginBottom: 0 }}>
          Source: {run.source.replace(/_/g, " ")} · report: {run.generated_by ?? "not generated"}
        </p>
      </Panel>

      {Object.keys(run.event_counts).length > 0 ? (
        <Panel title="Trace events">
          <table>
            <tbody>
              {Object.entries(run.event_counts).map(([kind, count]) => (
                <tr key={kind}>
                  <td className="mono">{kind}</td>
                  <td>{formatNumber(count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      ) : null}
    </>
  );
}

function FindingsPanel({ runId }: { runId: string }) {
  const findings = useApi<Finding[]>(runPath(runId, "/findings"));
  if (findings.loading) return <Loading what="Loading findings" />;
  if (findings.error) return <ErrorBox message={findings.error} />;
  return (
    <Panel>
      <p className="small muted">Click a row to see the transcript, the oracle evidence and the fix.</p>
      <FindingsTable findings={findings.data ?? []} />
    </Panel>
  );
}

function ReportPanel({ runId }: { runId: string }) {
  const report = useApi<ReportPayload>(runPath(runId, "/report"));
  if (report.loading) return <Loading what="Loading report" />;
  if (report.error) return <ErrorBox message={report.error} />;
  if (!report.data?.markdown) {
    return (
      <Panel>
        <p className="muted">
          No report for this run. Generate one with <code>agentguard report PROJECT --findings findings.json</code>.
        </p>
      </Panel>
    );
  }
  const generatedBy = report.data.json?.generated_by;
  return (
    <Panel>
      {generatedBy === "deterministic_fallback" ? (
        <div className="banner">
          Generated without an LLM: severity and remediation are rule-based. OWASP mappings and code references are
          deterministic lookups.
        </div>
      ) : null}
      <ReportMarkdown markdown={report.data.markdown} />
    </Panel>
  );
}

function ManifestPanel({ runId }: { runId: string }) {
  const manifest = useApi<{ manifest: Record<string, unknown> | null }>(runPath(runId, "/manifest"));
  if (manifest.loading) return <Loading what="Loading manifest" />;
  if (manifest.error) return <ErrorBox message={manifest.error} />;
  if (!manifest.data?.manifest) {
    return (
      <Panel>
        <p className="muted">No manifest.yaml for this run. Create one with <code>agentguard init PROJECT</code>.</p>
      </Panel>
    );
  }
  return (
    <Panel title="Manifest">
      <pre>{JSON.stringify(manifest.data.manifest, null, 2)}</pre>
    </Panel>
  );
}
