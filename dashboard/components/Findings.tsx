"use client";

import { Fragment, useState } from "react";
import type { Finding } from "@/lib/types";
import { SeverityBadge, StatusBadge } from "./ui";

function outcomeLabel(outcome: string): string {
  return outcome.replace(/_/g, " ");
}

export function FindingDetail({ finding }: { finding: Finding }) {
  return (
    <div>
      <div className="controls small">
        <span><span className="label-inline">id</span> <code>{finding.id}</code></span>
        <span><span className="label-inline">target</span> {finding.capability_targeted}</span>
        <span><span className="label-inline">confidence</span> {finding.confidence.toFixed(2)}</span>
        {finding.oracle ? (
          <span><span className="label-inline">oracle</span> {finding.oracle}</span>
        ) : null}
        {finding.owasp ? <span><span className="label-inline">OWASP</span> {finding.owasp}</span> : null}
      </div>

      {finding.oracle_detail ? (
        <>
          <h3>Why this status</h3>
          <p>{finding.oracle_detail}</p>
        </>
      ) : null}

      {finding.remediation ? (
        <>
          <h3>Remediation</h3>
          <p>{finding.remediation}</p>
        </>
      ) : null}

      {finding.code_references.length > 0 ? (
        <>
          <h3>Code references</h3>
          <pre>{finding.code_references.join("\n")}</pre>
        </>
      ) : null}

      <h3>Transcript ({finding.turns.length} turn{finding.turns.length === 1 ? "" : "s"})</h3>
      {finding.turns.map((turn, i) => (
        <div className="turn" key={i}>
          <div className="label-inline">turn {i + 1} · {outcomeLabel(turn.outcome)}</div>
          <div className="label-inline">sent</div>
          <pre>{turn.sent}</pre>
          <div className="label-inline">received</div>
          <pre>{turn.received ?? "(no reply)"}</pre>
          {turn.tool_calls.length > 0 ? (
            <>
              <div className="label-inline">tool calls</div>
              <pre>
                {turn.tool_calls
                  .map((c) => `${c.name}(${JSON.stringify(c.args)})`)
                  .join("\n")}
              </pre>
            </>
          ) : null}
          {turn.error ? (
            <>
              <div className="label-inline">error</div>
              <pre>{JSON.stringify(turn.error)}</pre>
            </>
          ) : null}
        </div>
      ))}
    </div>
  );
}

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [open, setOpen] = useState<string | null>(null);
  if (findings.length === 0) {
    return <p className="muted">No findings recorded for this run.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Category</th>
          <th>Status</th>
          <th>Severity</th>
          <th>Oracle</th>
          <th>Turns</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f) => (
          <Fragment key={f.id}>
            <tr
              className="clickable"
              onClick={() => setOpen(open === f.id ? null : f.id)}
              aria-expanded={open === f.id}
            >
              <td>{f.category.replace(/_/g, " ")}</td>
              <td><StatusBadge status={f.status} /></td>
              <td><SeverityBadge severity={f.severity} /></td>
              <td className="small">{f.oracle ?? <span className="muted">none</span>}</td>
              <td className="small">{f.turns.length}</td>
            </tr>
            {open === f.id ? (
              <tr>
                <td colSpan={5}>
                  <FindingDetail finding={f} />
                </td>
              </tr>
            ) : null}
          </Fragment>
        ))}
      </tbody>
    </table>
  );
}
