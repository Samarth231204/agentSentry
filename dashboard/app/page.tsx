"use client";

import Link from "next/link";
import { useApi } from "@/lib/useApi";
import type { ProjectInfo, RunSummary } from "@/lib/types";
import { formatTime, pct } from "@/lib/format";
import { Bar, ErrorBox, Loading, Panel } from "@/components/ui";

export default function RunsPage() {
  const runs = useApi<RunSummary[]>("/api/runs");
  const project = useApi<ProjectInfo>("/api/project");

  return (
    <>
      <h1>Runs</h1>
      {project.data ? (
        <p className="muted small mono">
          project: {project.data.project_root} · AgentGuard {project.data.agentguard_version}
        </p>
      ) : null}

      {runs.loading ? <Loading what="Loading runs" /> : null}
      {runs.error ? <ErrorBox message={`Could not reach the backend: ${runs.error}`} /> : null}

      {runs.data && runs.data.length === 0 ? (
        <Panel title="No runs yet">
          <p>
            The dashboard reads results from this project. Create one with the CLI, for example
            <code> agentguard test</code>, or start the target and run it from the CLI, then reload.
            Runs in another folder can be shown with <code>agentguard up --run-dir PATH</code>.
          </p>
        </Panel>
      ) : null}

      {runs.data && runs.data.length > 0 ? (
        <Panel>
          <table>
            <thead>
              <tr>
                <th>Run</th>
                <th>Modified</th>
                <th>Attempts</th>
                <th>Successes</th>
                <th>Success rate</th>
                <th>Report</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.map((run) => (
                <tr key={run.id}>
                  <td>
                    <Link href={`/run?id=${encodeURIComponent(run.id)}`}>{run.label}</Link>
                    <div className="muted small mono">{run.source}</div>
                  </td>
                  <td className="small nowrap">{formatTime(run.modified)}</td>
                  <td>{run.scorecard.total_attempts}</td>
                  <td>{run.scorecard.total_successes}</td>
                  <td style={{ minWidth: 140 }}>
                    <div className="small">{pct(run.scorecard.success_rate)}</div>
                    <Bar fraction={run.scorecard.success_rate} />
                  </td>
                  <td className="small">
                    {run.generated_by === "deterministic_fallback" ? "rule-based" : run.has_report ? "LLM" : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      ) : null}
    </>
  );
}
