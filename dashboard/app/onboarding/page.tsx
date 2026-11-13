"use client";

import Link from "next/link";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useApi } from "@/lib/useApi";
import type { ProjectInfo, SettingsResponse } from "@/lib/types";
import { KeyForm } from "@/components/KeyForm";
import { ErrorBox, Loading } from "@/components/ui";

const STEPS = ["Welcome", "Project", "Model", "First run"] as const;

export default function OnboardingPage() {
  return (
    <Suspense fallback={<Loading what="Loading setup" />}>
      <Onboarding />
    </Suspense>
  );
}

function Onboarding() {
  const params = useSearchParams();
  const [step, setStep] = useState(0);
  // Keep the step in the URL so a reload stays on the same step.
  useEffect(() => {
    const requested = Number(params.get("step"));
    if (Number.isInteger(requested) && requested >= 0 && requested < STEPS.length) setStep(requested);
  }, [params]);
  useEffect(() => {
    const url = new URL(window.location.href);
    url.searchParams.set("step", String(step));
    window.history.replaceState(null, "", url.toString());
  }, [step]);
  const settings = useApi<SettingsResponse>("/api/settings");
  const project = useApi<ProjectInfo>("/api/project");

  if (settings.loading || project.loading) return <Loading what="Checking AgentGuard" />;
  if (settings.error || project.error) {
    return (
      <div className="narrow">
        <ErrorBox message={`AgentGuard cannot reach its backend: ${settings.error ?? project.error}`} />
        <p>Start it in your project folder, then reload:</p>
        <pre>agentguard up --project /path/to/your/project</pre>
      </div>
    );
  }
  if (!settings.data) return null;

  const configured = settings.data.providers.filter((p) => p.configured);
  const hasKey = configured.length > 0;
  const next = () => setStep((s) => Math.min(s + 1, STEPS.length - 1));
  const back = () => setStep((s) => Math.max(s - 1, 0));

  return (
    <div className="narrow">
      <ol className="stepper" aria-label="Setup progress">
        {STEPS.map((label, i) => {
          const state = i < step ? "done" : i === step ? "current" : "";
          return (
            <li key={label} className={state}>
              <span className="dot">{i < step ? "✓" : i + 1}</span>
              {label}
            </li>
          );
        })}
      </ol>

      {step === 0 ? (
        <section className="panel">
          <h1>Welcome to AgentGuard</h1>
          <p className="lead">
            AgentGuard tests the AI agent in your project for security weaknesses: prompt injection, leaked
            secrets, unsafe tool use and data leaks. It then writes a report that explains each problem and how to
            fix it.
          </p>
          <div className="card-grid">
            <div className="card">
              <span className="icon">1</span>
              <h3>Your code is read, not changed</h3>
              <p>AgentGuard reads your code to find the parts that matter. It never edits your files.</p>
            </div>
            <div className="card">
              <span className="icon">2</span>
              <h3>Risky tools run in a sandbox</h3>
              <p>Tools that delete or send data are recorded, not executed, unless you allow them in the plan.</p>
            </div>
            <div className="card">
              <span className="icon">3</span>
              <h3>Everything stays on this machine</h3>
              <p>Runs, reports and API keys are stored locally. Keys never go into your browser storage.</p>
            </div>
          </div>
          <div className="controls">
            <button type="button" onClick={next}>Get started</button>
          </div>
        </section>
      ) : null}

      {step === 1 ? (
        <section className="panel">
          <h1>Which project should we test?</h1>
          <p className="lead">AgentGuard tests the project it was started for.</p>
          <p className="small muted" style={{ marginBottom: 6 }}>Project folder</p>
          <div className="key-block">{project.data?.project_root}</div>
          <p className="small muted" style={{ marginTop: 12 }}>
            To test a different project, stop AgentGuard and run <code>agentguard up --project PATH</code>.
          </p>
          <div className="controls" style={{ marginTop: 18 }}>
            <button type="button" className="secondary" onClick={back}>Back</button>
            <button type="button" onClick={next}>Continue</button>
          </div>
        </section>
      ) : null}

      {step === 2 ? (
        <section className="panel">
          <h1>Connect a model</h1>
          <p className="lead">
            AgentGuard uses a language model to plan the attacks and write the report. Paste one key to get
            started. Groq has a free tier and is a good first choice.
          </p>
          {hasKey ? (
            <div className="banner ok">
              Connected: {configured.map((p) => `${p.label} (${p.masked})`).join(", ")}. You can add more keys later
              in Settings.
            </div>
          ) : (
            <div className="banner warn">No model key yet. You can still run a demo check in the next step.</div>
          )}
          <KeyForm providers={settings.data.providers} onSaved={settings.refetch} />
          <div className="controls" style={{ marginTop: 18 }}>
            <button type="button" className="secondary" onClick={back}>Back</button>
            <button type="button" onClick={next}>{hasKey ? "Continue" : "Continue without a key"}</button>
          </div>
        </section>
      ) : null}

      {step === 3 ? (
        <section className="panel">
          <h1>Run your first check</h1>
          <p className="lead">Pick one. You can run both.</p>
          <div className="card-grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}>
            <div className="card">
              <span className="icon">▶</span>
              <h3>Demo check</h3>
              <p>
                Runs the whole pipeline in about 10 seconds with no model calls. Use it to see how a run looks. It
                says nothing about your agent's security.
              </p>
              <div className="controls" style={{ marginTop: 10, marginBottom: 0 }}>
                <Link href="/new?mock=1" className={hasKey ? "btn secondary" : "btn"}>Start demo check</Link>
              </div>
            </div>
            <div className={`card ${hasKey ? "" : "disabled"}`}>
              <span className="icon">🔍</span>
              <h3>Real test</h3>
              <p>
                Attacks your agent with the model you connected. Takes a few minutes and uses some of your model
                quota. You approve the watch plan before anything runs.
              </p>
              <div className="controls" style={{ marginTop: 10, marginBottom: 0 }}>
                {hasKey ? (
                  <Link href="/new" className="btn">Start real test</Link>
                ) : (
                  <span className="small muted">Connect a model in the previous step first.</span>
                )}
              </div>
            </div>
          </div>
          <div className="controls" style={{ marginTop: 10 }}>
            <button type="button" className="secondary" onClick={back}>Back</button>
            <Link href="/" className="btn secondary">Go to my runs</Link>
          </div>
        </section>
      ) : null}
    </div>
  );
}
