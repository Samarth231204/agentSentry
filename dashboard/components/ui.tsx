import type { ReactNode } from "react";

export function StatusBadge({ status }: { status: string }) {
  return <span className={`badge ${status}`}>{status}</span>;
}

export function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <span className="muted small">—</span>;
  return <span className={`badge ${severity.toLowerCase()}`}>{severity}</span>;
}

export function Tile({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="tile">
      <div className="value">{value}</div>
      <div className="label">{label}</div>
    </div>
  );
}

export function Bar({ fraction }: { fraction: number }) {
  const width = Math.max(0, Math.min(1, fraction)) * 100;
  return (
    <div className="bar" aria-label={`${Math.round(width)}%`}>
      <span style={{ width: `${width}%` }} />
    </div>
  );
}

export function Panel({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className="panel">
      {title ? <h2 style={{ marginTop: 0 }}>{title}</h2> : null}
      {children}
    </section>
  );
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return <p className="muted">{what}…</p>;
}

export function ErrorBox({ message }: { message: string }) {
  return <div className="banner error">{message}</div>;
}
