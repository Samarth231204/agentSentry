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

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function send<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    cache: "no-store",
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!res.ok) {
    const detail = (data as { detail?: unknown } | null)?.detail;
    let message = text || `Request failed with status ${res.status}`;
    if (typeof detail === "string") {
      message = detail;
    } else if (Array.isArray(detail)) {
      message = detail.map((d: { msg?: string }) => d.msg ?? "invalid value").join("; ");
    }
    throw new ApiError(res.status, message);
  }
  return data as T;
}

export const postJSON = <T>(path: string, body?: unknown) => send<T>("POST", path, body ?? {});
export const putJSON = <T>(path: string, body: unknown) => send<T>("PUT", path, body);
export const deleteJSON = <T>(path: string) => send<T>("DELETE", path);
