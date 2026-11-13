// The dashboard talks only to the local backend. Nothing is stored in the
// browser: no localStorage, no cookies, no API keys.

export const API_BASE: string =
  process.env.NEXT_PUBLIC_AGENTGUARD_API ?? "http://127.0.0.1:8787";

export async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { cache: "no-store" });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status} ${body}`);
  }
  return (await res.json()) as T;
}

export function runPath(runId: string, suffix = ""): string {
  return `/api/runs/${encodeURIComponent(runId)}${suffix}`;
}

export function traceStreamUrl(runId: string): string {
  return `${API_BASE}${runPath(runId, "/events")}`;
}
