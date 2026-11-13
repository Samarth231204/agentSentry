"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useApi } from "@/lib/useApi";
import type { ProjectInfo, RunSummary, SettingsResponse } from "@/lib/types";
import { formatTime, pct } from "@/lib/format";
import { Bar, ErrorBox, Loading, Panel } from "@/components/ui";

/**
 * Home. Until the setup guide has been finished or skipped, opening the app goes to
 * the guide. After that, the page shows the user's runs.
 */
export default function HomePage() {
  const router = useRouter();
  const settings = useApi<SettingsResponse>("/api/settings");
  const runs = useApi<RunSummary[]>("/api/runs");
  const project = useApi<ProjectInfo>("/api/project");
  const onboarding = useApi<{ done: boolean }>("/api/onboarding");

  const backendDown = Boolean(settings.error || runs.error || onboarding.error);
  const hasKey = settings.data?.providers.some((p) => p.configured) ?? false;
  const noRuns = runs.data !== null && runs.data.length === 0;
  const firstVisit = onboarding.data !== null && !onboarding.data.done;

  useEffect(() => {
    if (firstVisit) router.replace("/onboarding");
  }, [firstVisit, router]);

  if (backendDown) {
    return (
      <Panel title="AgentGuard cannot reach its backend">
        <ErrorBox message={settings.error ?? runs.error ?? "Unknown error"} />
        <p>Start AgentGuard in your project folder, then reload this page:</p>
        <pre>agentguard up --project /path/to/your/project</pre>
      </Panel>
    );
  }
  if (firstVisit) return <Loading what="Opening setup" />;
  if (settings.loading || runs.loading) return <Loading what="Loading" />;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Your test runs</h1>
          {project.data ? (
            <p className="muted small">
              Testing <span className="mono">{project.data.project_root}</span>
            </p>
          ) : null}
        </div>
        <Link href="/new" className="btn">
          + New test
        </Link>
      </div>

      {noRuns ? (
        <Panel>
          <h2>No runs yet</h2>
          <p className="muted">
            {hasKey
              ? "Your model key is saved. Start a test to see what your agent can be tricked into doing."
              : "Start a test when you are ready."}
          </p>
          <div className="controls">
            <Link href="/new" className="btn">Start a test</Link>
            <Link href="/onboarding" className="btn secondary">Open setup guide</Link>
          </div>
        </Panel>
      ) : null}

      {runs.data && runs.data.length > 0 ? (
        <Panel>
          <table>
            <thead>
              <tr>
                <th>Run</th>
                <th>Started</th>
                <th>Attacks</th>
                <th>Successful</th>
                <th>Success rate</th>
                <th>Report</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.map((run) => (
                <tr key={run.id}>
                  <td>
                    <Link href={`/run?id=${encodeURIComponent(run.id)}`}>{run.label}</Link>
                    <div className="small">{run.mock ? <span className="badge info">demo check</span> : <span className="muted small">your agent</span>}</div>
                  </td>
                  <td className="small nowrap">{formatTime(run.modified)}</td>
                  <td>{run.scorecard.total_attempts}</td>
                  <td>{run.scorecard.total_successes}</td>
                  <td className="bar-cell">
                    <div className="small">{pct(run.scorecard.success_rate)}</div>
                    <Bar fraction={run.scorecard.success_rate} />
                  </td>
                  <td className="small">
                    {run.generated_by === "deterministic_fallback" ? "rule-based" : run.has_report ? "AI-written" : "—"}
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
