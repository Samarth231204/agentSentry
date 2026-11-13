"use client";

import { useState } from "react";
import { postJSON, ApiError } from "@/lib/api";
import type { KeyTestResult, ProviderStatus } from "@/lib/types";

/**
 * Paste-once API key form. The key lives only in this component's state until
 * it is saved, then the field is cleared. Nothing is written to localStorage,
 * cookies, the URL or the console. The backend stores it in .agentguard/.env.
 */
export function KeyForm({
  providers,
  initialProvider,
  lockProvider = false,
  onSaved,
}: {
  providers: ProviderStatus[];
  initialProvider?: string;
  lockProvider?: boolean;
  onSaved?: () => void;
}) {
  const [provider, setProvider] = useState(initialProvider ?? providers[0]?.id ?? "groq");
  const [apiKey, setApiKey] = useState("");
  const [busy, setBusy] = useState<"test" | "save" | null>(null);
  const [note, setNote] = useState<{ kind: "ok" | "error"; text: string } | null>(null);

  async function test() {
    setBusy("test");
    setNote(null);
    try {
      const result = await postJSON<KeyTestResult>("/api/settings/keys/test", {
        provider,
        api_key: apiKey || undefined,
      });
      setNote({ kind: result.ok ? "ok" : "error", text: `${result.model}: ${result.message}` });
    } catch (err) {
      setNote({ kind: "error", text: (err as Error).message });
    } finally {
      setBusy(null);
    }
  }

  async function save() {
    setBusy("save");
    setNote(null);
    try {
      const saved = await postJSON<{ masked: string }>("/api/settings/keys", { provider, api_key: apiKey });
      setApiKey("");
      setNote({ kind: "ok", text: `Saved. Stored as ${saved.masked}.` });
      onSaved?.();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : (err as Error).message;
      setNote({ kind: "error", text: message });
    } finally {
      setBusy(null);
    }
  }

  const label = providers.find((p) => p.id === provider)?.label ?? provider;
  return (
    <div>
      <div className="controls">
        <label className="small">
          Provider{" "}
          <select
            value={provider}
            disabled={lockProvider}
            onChange={(e) => setProvider(e.target.value)}
          >
            {providers.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="controls">
        <input
          type="password"
          placeholder={`${label} API key`}
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          aria-label={`${label} API key`}
          style={{ minWidth: 340 }}
        />
        <button type="button" onClick={test} disabled={busy !== null}>
          {busy === "test" ? "Testing…" : "Test key"}
        </button>
        <button type="button" onClick={save} disabled={busy !== null || apiKey.trim().length === 0}>
          {busy === "save" ? "Saving…" : "Save key"}
        </button>
      </div>
      <p className="small muted">
        The key is sent to the local backend only. It is written to <code>.agentguard/.env</code> with
        permissions 600 and is never stored in this browser. Testing makes one tiny request to the provider.
      </p>
      {note ? <div className={`banner ${note.kind === "error" ? "error" : ""}`}>{note.text}</div> : null}
    </div>
  );
}
