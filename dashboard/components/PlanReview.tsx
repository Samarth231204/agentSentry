"use client";

import { useEffect, useMemo, useState } from "react";
import { ApiError, postJSON, runPath } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { PlanResponse, PlanItem, DiscoveryCandidate, RunStatus } from "@/lib/types";
import { ErrorBox, Loading, Panel } from "./ui";

const ROLE_LABEL: Record<string, string> = {
  expose: "entrypoint",
  watch: "tool",
  watch_retrieval: "retrieval",
  watch_memory: "memory",
  watch_llm: "LLM call",
  watch_outbound: "outbound request",
};

/**
 * The plan that will be applied to the user's code. The user's files are not
 * edited: the plan is applied by an import hook when the target starts.
 * Approval is only possible while the run is waiting for review.
 */
export function PlanReview({ runId }: { runId: string }) {
  const plan = useApi<PlanResponse>(runPath(runId, "/plan"));
  const status = useApi<RunStatus>(runPath(runId, "/status"));
  const [include, setInclude] = useState<Record<string, boolean>>({});
  const [sandbox, setSandbox] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ kind: "ok" | "error"; text: string } | null>(null);

  useEffect(() => {
    if (!plan.data) return;
    const inc: Record<string, boolean> = {};
    const sb: Record<string, boolean> = {};
    for (const item of plan.data.plan.items) {
      inc[item.candidate_id] = item.include;
      sb[item.candidate_id] = item.sandbox;
    }
    setInclude(inc);
    setSandbox(sb);
  }, [plan.data]);

  const waiting = status.data?.awaiting_plan === true;
  const included = useMemo(() => plan.data?.plan.items.filter((i) => include[i.candidate_id]) ?? [], [plan.data, include]);
  const others = useMemo(() => {
    if (!plan.data) return [];
    const inPlan = new Set(plan.data.plan.items.map((i) => i.candidate_id));
    return plan.data.candidates.filter((c) => !inPlan.has(c.id));
  }, [plan.data]);

  if (plan.loading) return <Loading what="Loading plan" />;
  if (plan.error) {
    return (
      <Panel>
        <p className="muted">No plan for this run. Automatic runs create one; advanced runs skip planning.</p>
      </Panel>
    );
  }
  if (!plan.data) return null;

  async function approve() {
    setBusy(true);
    setNote(null);
    try {
      const edits = plan.data!.plan.items.map((i) => ({
        candidate_id: i.candidate_id,
        include: include[i.candidate_id],
        sandbox: sandbox[i.candidate_id],
      }));
      await postJSON(runPath(runId, "/plan/approve"), { edits });
      setNote({ kind: "ok", text: "Plan approved. The run continues." });
    } catch (err) {
      setNote({ kind: "error", text: err instanceof ApiError ? err.message : (err as Error).message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Panel title="What AgentGuard will watch">
        {waiting ? (
          <div className="banner">
            The run is waiting for your review. Untick anything that should not be watched. Tools that change state
            are sandboxed by default: they are recorded but not executed.
          </div>
        ) : (
          <p className="small muted">This plan is read-only: the run is not waiting for review.</p>
        )}
        {included.length === 0 ? <ErrorBox message="Nothing is included yet. Include exactly one entrypoint." /> : null}
        <table>
          <thead>
            <tr>
              <th>Include</th>
              <th>Role</th>
              <th>Function</th>
              <th>Where</th>
              <th>Sandbox</th>
              <th>Why</th>
            </tr>
          </thead>
          <tbody>
            {plan.data.plan.items.map((item) => (
              <PlanRow
                key={item.candidate_id}
                item={item}
                included={include[item.candidate_id] ?? false}
                sandboxed={sandbox[item.candidate_id] ?? false}
                editable={waiting}
                onInclude={(v) => setInclude((s) => ({ ...s, [item.candidate_id]: v }))}
                onSandbox={(v) => setSandbox((s) => ({ ...s, [item.candidate_id]: v }))}
              />
            ))}
          </tbody>
        </table>
        {waiting ? (
          <div className="controls" style={{ marginTop: 12 }}>
            <button type="button" onClick={approve} disabled={busy}>
              {busy ? "Approving…" : "Approve and continue"}
            </button>
          </div>
        ) : null}
        {note ? <div className={`banner ${note.kind === "error" ? "error" : ""}`}>{note.text}</div> : null}
      </Panel>

      {others.length > 0 ? (
        <Panel title="Found but not in the plan">
          <p className="small muted">
            These were found by discovery but were not included (low confidence, or the reviewer or agent excluded them).
          </p>
          <table>
            <tbody>
              {others.map((c) => (
                <CandidateRow key={c.id} candidate={c} />
              ))}
            </tbody>
          </table>
        </Panel>
      ) : null}
    </>
  );
}

function PlanRow({
  item,
  included,
  sandboxed,
  editable,
  onInclude,
  onSandbox,
}: {
  item: PlanItem;
  included: boolean;
  sandboxed: boolean;
  editable: boolean;
  onInclude: (v: boolean) => void;
  onSandbox: (v: boolean) => void;
}) {
  const isEntry = item.role === "expose";
  return (
    <tr>
      <td>
        <input
          type="checkbox"
          checked={included}
          disabled={!editable || isEntry}
          onChange={(e) => onInclude(e.target.checked)}
          aria-label={`include ${item.name}`}
          title={isEntry ? "The entrypoint is always included" : undefined}
        />
      </td>
      <td className="small">{ROLE_LABEL[item.role] ?? item.role}</td>
      <td className="mono small">{item.qualname}</td>
      <td className="mono small">{item.file}:{item.line}</td>
      <td>
        {item.destructive ? (
          <input
            type="checkbox"
            checked={sandboxed}
            disabled={!editable || !included}
            onChange={(e) => onSandbox(e.target.checked)}
            aria-label={`sandbox ${item.name}`}
          />
        ) : (
          <span className="muted small">n/a</span>
        )}
      </td>
      <td className="small">
        <span className="badge info">{item.source}</span> {item.reason}
        <div className="muted small">confidence {item.confidence.toFixed(2)}</div>
      </td>
    </tr>
  );
}

function CandidateRow({ candidate }: { candidate: DiscoveryCandidate }) {
  return (
    <tr>
      <td className="small">{ROLE_LABEL[candidate.role] ?? candidate.role}</td>
      <td className="mono small">{candidate.qualname}</td>
      <td className="mono small">{candidate.file}:{candidate.line}</td>
      <td className="small">
        <span className={`badge ${candidate.confidence >= 0.8 ? "info" : "failed"}`}>
          {candidate.confidence >= 0.8 ? "auto" : "ambiguous"}
        </span>{" "}
        {candidate.signals.join("; ")}
      </td>
    </tr>
  );
}
