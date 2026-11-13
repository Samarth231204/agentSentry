"use client";

import { useEffect, useRef, useState } from "react";
import { getJSON, postJSON, runPath } from "@/lib/api";
import type { RunStatus } from "@/lib/types";
import { Panel } from "./ui";

const PHASE_LABELS: Record<string, string> = {
  discover: "Discover",
  plan: "Plan",
  instrument: "Instrument",
  target: "Start target",
  scan: "Scan",
  attack: "Attack",
  report: "Report",
};

const TERMINAL = new Set(["done", "failed", "cancelled"]);

/**
 * Live progress for a run started from the dashboard. Polls the backend's
 * status endpoint while the run is active. Runs that were started by the CLI
 * (or before this server started) have no live status and render nothing.
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
          timer = setTimeout(poll, 1500);
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

  return (
    <Panel title={active ? "Run in progress" : `Run ${status.state}`}>
      <div className="controls">
        {Object.entries(PHASE_LABELS)
          .filter(([key]) => key in status.phases)
          .map(([key, label]) => {
            const state = status.phases[key] ?? "pending";
            return (
              <span key={key} className={`phase ${state === "awaiting_review" ? "running" : state}`} title={state}>
                {label}: {state === "awaiting_review" ? "waiting for review" : state}
              </span>
            );
          })}
      </div>
      {status.mock ? (
        <p className="small muted">Mock mode: no provider calls were made, so no result says anything about your app.</p>
      ) : null}
      {status.error ? <div className="banner error">{status.error}</div> : null}
      {status.awaiting_plan ? (
        <div className="banner">
          Waiting for your review. Open the <a href={`?id=${encodeURIComponent(runId)}&tab=plan`}>Plan tab</a> to approve
          what AgentGuard will watch.
        </div>
      ) : null}
      {active ? (
        <div className="controls">
          <button type="button" onClick={cancel} disabled={cancelling || status.cancel_requested}>
            {status.cancel_requested ? "Cancelling…" : "Cancel run"}
          </button>
        </div>
      ) : null}
      {note ? <p className="small muted">{note}</p> : null}
    </Panel>
  );
}
