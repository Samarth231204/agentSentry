"use client";

import type { CodeLocation, EvidenceFinding, EvidencePayload } from "@/lib/types";
import { titleCase } from "@/lib/format";
import { Panel, SeverityBadge } from "./ui";

/**
 * Evidence: for every attack that got through, which part of the user's agent was
 * vulnerable, the conversation that proves it, and the code behind that part.
 * Only successful (confirmed or suspected) attacks are shown; resisted ones stay in Findings.
 */
export function EvidenceView({ evidence }: { evidence: EvidencePayload }) {
  const categories = Object.entries(evidence.by_category);
  if (evidence.vulnerable === 0) {
    return (
      <Panel>
        <h2 style={{ marginTop: 0 }}>No vulnerabilities found in this run</h2>
        <p className="muted">
          {evidence.total_attempts === 0
            ? "This run has no attack attempts yet. Evidence appears here when the attack step finishes."
            : `Your agent resisted all ${evidence.total_attempts} attack attempts. Each attempt is listed in the Findings tab.`}
        </p>
      </Panel>
    );
  }

  return (
    <>
      <Panel title="Vulnerable parts of your agent">
        <p className="small muted">
          {evidence.vulnerable} of {evidence.total_attempts} attacks got through. Each row is an attack category and
          the parts of your agent it got through.
        </p>
        <table>
          <thead>
            <tr>
              <th>Attack</th>
              <th>Vulnerable part</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {categories.map(([category, row]) => (
              <tr key={category}>
                <td>
                  <a href={`#ev-${category}`}>{titleCase(category)}</a>
                </td>
                <td>
                  {row.parts.length > 0 ? (
                    row.parts.map((p) => <span className="part-chip" key={p}>{p}</span>)
                  ) : (
                    <span className="muted small">Not located in code</span>
                  )}
                </td>
                <td className="small nowrap">
                  {row.findings} attack{row.findings === 1 ? "" : "s"}
                  {row.confirmed < row.findings ? ` (${row.confirmed} confirmed)` : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      {categories.map(([category]) => (
        <section key={category} id={`ev-${category}`}>
          <h2>{titleCase(category)}</h2>
          {evidence.findings
            .filter((f) => f.category === category)
            .map((f) => (
              <EvidenceCard key={f.id} finding={f} />
            ))}
        </section>
      ))}
    </>
  );
}

function EvidenceCard({ finding }: { finding: EvidenceFinding }) {
  return (
    <div className="evidence-card">
      <div className="evidence-head">
        <span className="badge error">
          vulnerable · {finding.status === "confirmed" ? "confirmed" : "suspected by the AI judge"}
        </span>
        {finding.severity ? <SeverityBadge severity={finding.severity} /> : null}
        {finding.oracle ? <span className="small muted">detected by {finding.oracle.replace(/_/g, " ")}</span> : null}
        {finding.status === "suspected" && finding.confidence != null ? (
          <span className="small muted">· judge confidence {finding.confidence.toFixed(2)}</span>
        ) : null}
        {finding.owasp ? <span className="small muted">· {finding.owasp}</span> : null}
        <span className="small muted mono" style={{ marginLeft: "auto" }}>{finding.id}</span>
      </div>

      {finding.parts.length > 0 ? (
        <p style={{ marginBottom: 0 }}>
          <span className="small muted">Vulnerable: </span>
          {finding.parts.map((p) => <span className="part-chip" key={p}>{p}</span>)}
        </p>
      ) : null}

      {finding.oracle_detail ? (
        <>
          <h3>Why this counts as a vulnerability</h3>
          <p style={{ margin: 0 }}>{finding.oracle_detail}</p>
        </>
      ) : null}

      <h3>Attack log ({finding.turns.length} turn{finding.turns.length === 1 ? "" : "s"})</h3>
      {finding.turns.map((turn, i) => (
        <div className="turn attack-turn" key={i}>
          <div className="label-inline">turn {i + 1} · attacker sent</div>
          <pre>{turn.sent}</pre>
          <div className="label-inline">your agent replied</div>
          <pre>{turn.received ?? "(no reply)"}</pre>
          {turn.tool_calls.length > 0 ? (
            <>
              <div className="label-inline">tools your agent called</div>
              <pre className="tool-call">
                {turn.tool_calls.map((c) => `${c.name}(${JSON.stringify(c.args)})`).join("\n")}
              </pre>
            </>
          ) : null}
        </div>
      ))}

      <h3>Vulnerable code</h3>
      {finding.code.length === 0 ? (
        <p className="small muted">
          AgentGuard could not point to a specific line for this attack. The attack log above is the evidence.
        </p>
      ) : (
        finding.code.map((loc) => <CodeBlock key={`${loc.file}:${loc.start_line}`} loc={loc} />)
      )}

      {finding.remediation ? (
        <>
          <h3>How to fix it</h3>
          <p style={{ margin: 0 }}>{finding.remediation}</p>
        </>
      ) : null}
    </div>
  );
}

function CodeBlock({ loc }: { loc: CodeLocation }) {
  const hl = new Set(loc.highlight);
  return (
    <div className="code-block">
      <div className="code-title">
        <span className="mono">
          {loc.file}:{loc.highlight[0] ?? loc.start_line}
        </span>
        <span className="muted">
          {loc.part ?? ""}
          {loc.origin === "report" ? " · named by the AI report" : ""}
        </span>
      </div>
      <div className="code-body">
        {loc.lines.map((line) => (
          <div className={`code-line${hl.has(line.n) ? " hl" : ""}`} key={line.n}>
            <span className="ln">{line.n}</span>
            <span>{line.text || " "}</span>
          </div>
        ))}
      </div>
      <div className="code-why">{loc.why}</div>
    </div>
  );
}
