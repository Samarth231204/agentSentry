"use client";

import { useEffect, useRef, useState } from "react";
import { getJSON, postJSON, runPath } from "@/lib/api";
import type { RunStatus } from "@/lib/types";
import { formatTime, titleCase } from "@/lib/format";

const STEPS: Array<[string, string]> = [
  ["discover", "Read the code"],
  ["plan", "Plan what to watch"],
  ["instrument", "Apply watch points"],
  ["target", "Start your agent"],
  ["scan", "Scan for risks"],
  ["attack", "Attack"],
  ["report", "Write report"],
];

const TERMINAL = new Set(["done", "failed", "cancelled"]);

/**
 * Live progress for a run. Polls the backend while the run is active and shows
 * which step is running, plus which attack category is in progress. Runs
 * started by the CLI have no live status and render nothing.
 */
export function RunProgress({ runId, onFinished }: { runId: string; onFinished: () => void }) {
  const [status, setStatus] = useState<RunStatus | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const finishedRef = useRef(false);
  const onFinishedRef = useRef(onFinished);
  onFinishedRef.current = onFinished;

  useEffect(() => {
    finishedRef.current = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let cancelled = false;

    async function poll() {
      try {
        const next = await getJSON<RunStatus>(runPath(runId, "/status"));
        if (cancelled) return;
        setStatus(next);
        if (TERMINAL.has(next.state)) {
          if (!finishedRef.current) {
            finishedRef.current = true;
            onFinishedRef.current();
          }
        } else {
          timer = setTimeout(poll, 1000);
        }
      } catch {
        // 404: this run has no live status (started elsewhere). Show nothing.
        if (!cancelled) setStatus(null);
      }
    }

    poll();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [runId]);

  if (!status) return null;

  const active = status.state === "queued" || status.state === "running";
  const attack = status.progress?.attack;
  // Categories finished so far: the current one counts once it is done.
  const attackCompleted = attack ? (attack.index ?? 1) - (attack.state === "done" ? 0 : 1) : 0;
  const attackFraction = attack?.total ? attackCompleted / attack.total : 0;

  async function cancel() {
    setCancelling(true);
    setNote(null);
    try {
      await postJSON(runPath(runId, "/cancel"));
      setNote("Cancel requested. The run stops at the next safe point.");
    } catch (err) {
      setNote((err as Error).message);
    } finally {
      setCancelling(false);
    }
  }

  const title = active
    ? status.awaiting_plan
      ? "Waiting for your review"
      : "Test in progress"
    : status.state === "done"
      ? "Test finished"
      : status.state === "cancelled"
        ? "Test cancelled"
        : "Test failed";
  const pillClass = active ? "" : status.state;

  return (
    <section className="panel">
      <div className="page-head" style={{ marginBottom: 12 }}>
        <div className="controls" style={{ marginBottom: 0 }}>
          <h2 style={{ margin: 0 }}>{title}</h2>
          <span className={`pill ${pillClass}`}>{active ? (status.awaiting_plan ? "needs you" : "running") : status.state}</span>
        </div>
        <span className="small muted">Started {formatTime(status.started)}</span>
      </div>

      <ol className="stepper" aria-label="Progress">
        {STEPS.map(([key, label]) => {
          const state = status.phases[key] ?? "pending";
          const cls =
            state === "done" ? "done"
              : state === "running" ? "running current"
                : state === "awaiting_review" ? "current"
                  : state === "failed" ? "failed"
                    : state === "skipped" ? "skipped"
                      : "";
          return (
            <li key={key} className={cls}>
              <span className="dot">{state === "done" ? "✓" : state === "failed" ? "!" : ""}</span>
              <span>
                {label}
                {state === "running" ? "…" : ""}
              </span>
            </li>
          );
        })}
      </ol>

      {status.phase === "attack" && attack && attack.total ? (
        <div className="progress-line">
          <div className="label-row">
            <span>
              {attack.state === "done" ? "Finished" : "Testing"} <strong>{titleCase(attack.category ?? "")}</strong>
              {" "}({attack.index} of {attack.total})
            </span>
            <span className="muted small">{attack.attempts_so_far ?? 0} attempts recorded so far</span>
          </div>
          <div className="bar"><span style={{ width: `${Math.round(attackFraction * 100)}%` }} /></div>
        </div>
      ) : null}

      {status.mock ? (
        <div className="banner warn" style={{ marginTop: 14 }}>
          Demo check: no model was called, so the results say nothing about your agent's security. This only
          shows that the setup works.
        </div>
      ) : null}
      {status.transport === "a2a" ? <p className="small muted">Steps run as A2A agents.</p> : null}
      {status.error ? <div className="banner error">{status.error}</div> : null}
      {status.awaiting_plan ? (
        <div className="banner">
          Review what AgentGuard will watch, then approve it on the{" "}
          <a href={`?id=${encodeURIComponent(runId)}&tab=plan`}>Plan tab</a>.
        </div>
      ) : null}
      {active ? (
        <div className="controls" style={{ marginTop: 14, marginBottom: 0 }}>
          <button type="button" className="danger" onClick={cancel} disabled={cancelling || status.cancel_requested}>
            {status.cancel_requested ? "Cancelling…" : "Cancel test"}
          </button>
        </div>
      ) : null}
      {note ? <p className="small muted" style={{ marginTop: 10, marginBottom: 0 }}>{note}</p> : null}
    </section>
  );
}
