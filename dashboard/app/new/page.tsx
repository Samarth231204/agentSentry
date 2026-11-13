"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { postJSON, ApiError } from "@/lib/api";
import type { RunStatus } from "@/lib/types";
import { Panel } from "@/components/ui";

type Mode = "auto" | "app" | "url";

export default function NewRunPage() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>("auto");
  const [reviewPlan, setReviewPlan] = useState(true);
  const [targetApp, setTargetApp] = useState("app:app");
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:8000");
  const [canaries, setCanaries] = useState("");
  const [maxProbes, setMaxProbes] = useState("");
  const [maxCalls, setMaxCalls] = useState("");
  const [maxTokens, setMaxTokens] = useState("");
  const [mock, setMock] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const optionalInt = (value: string) => (value.trim() === "" ? undefined : Number(value));

  async function submit(event: FormEvent) {
    event.preventDefault();
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
      mock,
    };
    try {
      const status = await postJSON<RunStatus>("/api/runs", body);
      router.push(`/run?id=${encodeURIComponent(status.run_id)}&tab=overview`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : (err as Error).message);
      setBusy(false);
    }
  }

  return (
    <>
      <h1>New run</h1>
      <form onSubmit={submit}>
        <Panel title="Target">
          <div className="controls">
            <label className="small">
              <input type="radio" name="mode" checked={mode === "auto"} onChange={() => setMode("auto")} /> Automatic
              (recommended): find my agent and watch it
            </label>
            <label className="small">
              <input type="radio" name="mode" checked={mode === "app"} onChange={() => setMode("app")} /> Advanced: my
              ASGI app with @expose
            </label>
            <label className="small">
              <input type="radio" name="mode" checked={mode === "url"} onChange={() => setMode("url")} /> Already running
              (localhost)
            </label>
          </div>
          {mode === "auto" ? (
            <p className="small muted">
              AgentGuard reads your code (it never runs it), proposes what to watch, and starts your agent with those
              wrappers applied. Your files are not edited.
            </p>
          ) : mode === "app" ? (
            <label className="small" style={{ display: "block" }}>
              ASGI app to start, as <code>module:attribute</code>, relative to the project folder
              <br />
              <input
                type="text"
                value={targetApp}
                onChange={(e) => setTargetApp(e.target.value)}
                style={{ width: 320, maxWidth: "100%" }}
                aria-label="ASGI app"
              />
              <p className="muted small">
                The app must use <code>@expose</code> on the function that handles user input. Phase 3 will find
                and wrap it automatically.
              </p>
            </label>
          ) : (
            <label className="small" style={{ display: "block" }}>
              URL of the running target (localhost or 127.0.0.1 only)
              <br />
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                style={{ width: 320, maxWidth: "100%" }}
                aria-label="Target URL"
              />
            </label>
          )}
        </Panel>

        <Panel title="Options">
          <label className="small" style={{ display: "block", marginBottom: 10 }}>
            <input type="checkbox" checked={reviewPlan} onChange={(e) => setReviewPlan(e.target.checked)} disabled={mode !== "auto"} />{" "}
            Review the plan before the attack starts (recommended)
          </label>
          <label className="small" style={{ display: "block", marginBottom: 10 }}>
            Canary strings to look for (comma or new line separated)
            <br />
            <textarea
              value={canaries}
              onChange={(e) => setCanaries(e.target.value)}
              rows={2}
              style={{ width: 360, maxWidth: "100%" }}
            />
          </label>
          <div className="controls">
            <label className="small">
              Probes per category
              <br />
              <input type="number" min={1} max={50} value={maxProbes} onChange={(e) => setMaxProbes(e.target.value)}
                placeholder="from settings" style={{ width: 150 }} />
            </label>
            <label className="small">
              LLM call limit
              <br />
              <input type="number" min={1} value={maxCalls} onChange={(e) => setMaxCalls(e.target.value)}
                placeholder="no limit" style={{ width: 150 }} />
            </label>
            <label className="small">
              Token limit
              <br />
              <input type="number" min={1} value={maxTokens} onChange={(e) => setMaxTokens(e.target.value)}
                placeholder="no limit" style={{ width: 150 }} />
            </label>
          </div>
          <label className="small" style={{ display: "block", marginTop: 10 }}>
            <input type="checkbox" checked={mock} onChange={(e) => setMock(e.target.checked)} />{" "}
            <strong>Mock mode</strong>: no provider calls. Checks that the pipeline runs end to end. It proves nothing
            about whether your app is vulnerable.
          </label>
        </Panel>

        <div className="controls">
          <button type="submit" disabled={busy}>
            {busy ? "Starting…" : "Run"}
          </button>
        </div>
        {error ? <div className="banner error">{error}</div> : null}
      </form>
    </>
  );
}
