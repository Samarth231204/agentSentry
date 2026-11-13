"use client";

import { FormEvent, Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { postJSON, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { RunStatus, SettingsResponse } from "@/lib/types";
import { ErrorBox, Loading } from "@/components/ui";

type Mode = "auto" | "app" | "url";

export default function NewRunPage() {
  return (
    <Suspense fallback={<Loading what="Preparing" />}>
      <NewRunForm />
    </Suspense>
  );
}

function NewRunForm() {
  const router = useRouter();
  const params = useSearchParams();
  const settings = useApi<SettingsResponse>("/api/settings");

  const [demo, setDemo] = useState(false);
  const [mode, setMode] = useState<Mode>("auto");
  const [reviewPlan, setReviewPlan] = useState(true);
  const [targetApp, setTargetApp] = useState("app:app");
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:8000");
  const [canaries, setCanaries] = useState("");
  const [maxProbes, setMaxProbes] = useState("");
  const [maxCalls, setMaxCalls] = useState("");
  const [maxTokens, setMaxTokens] = useState("");
  const [replayRunId, setReplayRunId] = useState("");
  const [useA2a, setUseA2a] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Onboarding links here with ?mock=1 for the demo check.
  useEffect(() => {
    if (params.get("mock") === "1") setDemo(true);
  }, [params]);

  if (settings.loading) return <Loading what="Loading" />;
  if (settings.error) return <ErrorBox message={`Could not reach the backend: ${settings.error}`} />;

  const hasKey = settings.data?.providers.some((p) => p.configured) ?? false;
  const optionalInt = (value: string) => (value.trim() === "" ? undefined : Number(value));

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!demo && !hasKey) {
      setError("Connect a model key first (Get started → Model), or choose the demo check.");
      return;
    }
    setBusy(true);
    setError(null);
    const body = {
      target_app: mode === "app" ? targetApp.trim() : undefined,
      target_url: mode === "url" ? targetUrl.trim() : undefined,
      review_plan: reviewPlan,
      canaries: canaries.split(/[\n,]/).map((c) => c.trim()).filter(Boolean),
      max_probes: optionalInt(maxProbes),
      max_llm_calls: optionalInt(maxCalls),
      max_tokens: optionalInt(maxTokens),
      mock: demo,
      replay_run_id: replayRunId.trim() || undefined,
      use_a2a: useA2a,
    };
    try {
      const status = await postJSON<RunStatus>("/api/runs", body);
      await postJSON("/api/onboarding/complete").catch(() => undefined);
      router.push(`/run?id=${encodeURIComponent(status.run_id)}&tab=overview`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : (err as Error).message);
      setBusy(false);
    }
  }

  return (
    <div className="narrow" style={{ maxWidth: 860 }}>
      <div className="page-head">
        <div>
          <h1>New test</h1>
          <p className="muted">Choose what to test, then start. You can review the plan before any attack runs.</p>
        </div>
      </div>

      <form onSubmit={submit} className="stack">
        <section className="panel">
          <h2 style={{ marginTop: 0 }}>1. Choose the kind of test</h2>
          <div className="card-grid" style={{ marginTop: 0 }}>
            <label className={`card selectable ${!demo ? "selected" : ""} ${!hasKey ? "disabled" : ""}`}>
              <span className="form-row" style={{ alignItems: "center" }}>
                <input type="radio" name="kind" checked={!demo} onChange={() => setDemo(false)} />
                <strong>Real test</strong>
              </span>
              <p>Attacks your agent with your connected model. Takes a few minutes.</p>
              {!hasKey ? <p style={{ color: "var(--error)" }}>Needs a model key. Add one in Settings.</p> : null}
            </label>
            <label className={`card selectable ${demo ? "selected" : ""}`}>
              <span className="form-row" style={{ alignItems: "center" }}>
                <input type="radio" name="kind" checked={demo} onChange={() => setDemo(true)} />
                <strong>Demo check</strong>
              </span>
              <p>Runs the full pipeline with no model calls, in about 10 seconds. Proves the setup works. Says nothing about security.</p>
            </label>
          </div>
        </section>

        <section className="panel">
          <h2 style={{ marginTop: 0 }}>2. Your agent</h2>
          <p className="small muted">
            AgentGuard reads your project to find the functions that take user input and the tools the agent can
            call. It starts your agent with those points watched. Your files are not edited.
          </p>
          <div className="stack">
            <label className="check">
              <input type="checkbox" checked={reviewPlan} onChange={(e) => setReviewPlan(e.target.checked)} />
              <span>
                Let me review the plan before attacks start
                <small>Recommended. You approve or remove each watched function before anything runs.</small>
              </span>
            </label>
          </div>
        </section>

        <details className="advanced">
          <summary>Advanced options</summary>
          <div className="stack">
            <fieldset style={{ border: "none", padding: 0, margin: 0 }}>
              <legend className="small muted" style={{ marginBottom: 6 }}>Target</legend>
              <div className="controls">
                <label className="small"><input type="radio" name="mode" checked={mode === "auto"} onChange={() => setMode("auto")} /> Automatic (recommended)</label>
                <label className="small"><input type="radio" name="mode" checked={mode === "app"} onChange={() => setMode("app")} /> My ASGI app with <code>@expose</code></label>
                <label className="small"><input type="radio" name="mode" checked={mode === "url"} onChange={() => setMode("url")} /> Already running on localhost</label>
              </div>
              {mode === "app" ? (
                <label className="field">
                  ASGI app as <code>module:attribute</code>, relative to the project
                  <input type="text" value={targetApp} onChange={(e) => setTargetApp(e.target.value)} aria-label="ASGI app" />
                </label>
              ) : null}
              {mode === "url" ? (
                <label className="field">
                  URL of the running agent (localhost or 127.0.0.1 only)
                  <input type="text" value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} aria-label="Target URL" />
                </label>
              ) : null}
            </fieldset>

            <label className="field">
              Canary strings to look for (comma or new line separated)
              <textarea value={canaries} onChange={(e) => setCanaries(e.target.value)} rows={2} />
            </label>

            <div className="form-row">
              <label className="field">
                Attacks per category
                <input type="number" min={1} max={50} value={maxProbes} onChange={(e) => setMaxProbes(e.target.value)} placeholder="from settings" style={{ width: 160 }} />
              </label>
              <label className="field">
                Model call limit
                <input type="number" min={1} value={maxCalls} onChange={(e) => setMaxCalls(e.target.value)} placeholder="no limit" style={{ width: 160 }} />
              </label>
              <label className="field">
                Token limit
                <input type="number" min={1} value={maxTokens} onChange={(e) => setMaxTokens(e.target.value)} placeholder="no limit" style={{ width: 160 }} />
              </label>
            </div>

            <label className="field">
              Replay the attacks of an earlier run (run id)
              <input type="text" value={replayRunId} onChange={(e) => setReplayRunId(e.target.value)} placeholder="e.g. run-20261114-120000-ab12" style={{ maxWidth: 380 }} />
            </label>

            <label className="check">
              <input type="checkbox" checked={useA2a} onChange={(e) => setUseA2a(e.target.checked)} />
              <span>
                Run the steps as A2A agents
                <small>Agent cards and JSON-RPC calls, shown in the trace. For developers.</small>
              </span>
            </label>
          </div>
        </details>

        {error ? <div className="banner error">{error}</div> : null}
        <div className="controls">
          <button type="submit" disabled={busy || (!demo && !hasKey)}>
            {busy ? "Starting…" : demo ? "Start demo check" : "Start test"}
          </button>
          <Link href="/" className="btn secondary">Cancel</Link>
        </div>
      </form>
    </div>
  );
}
