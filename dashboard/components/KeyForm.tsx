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
  const [provider, setProvider] = useState(
    initialProvider ?? providers.find((p) => p.configured)?.id ?? providers[0]?.id ?? "anthropic",
  );
  const [apiKey, setApiKey] = useState("");
  const [extraValue, setExtraValue] = useState<string | null>(null); // null = unchanged
  const [busy, setBusy] = useState<"test" | "save" | null>(null);
  const [note, setNote] = useState<{ kind: "ok" | "error"; text: string } | null>(null);

  async function test() {
    setBusy("test");
    setNote(null);
    try {
      const result = await postJSON<KeyTestResult>("/api/settings/keys/test", {
        provider,
        api_key: apiKey || undefined,
        extra: extraValue?.trim() || undefined,
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
      const saved = await postJSON<{ masked: string | null }>("/api/settings/keys", {
        provider,
        api_key: apiKey || undefined,
        extra: extraValue === null ? undefined : extraValue.trim(),
      });
      setApiKey("");
      setExtraValue(null);
      setNote({ kind: "ok", text: saved.masked ? `Saved. Key stored as ${saved.masked}.` : "Saved." });
      onSaved?.();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : (err as Error).message;
      setNote({ kind: "error", text: message });
    } finally {
      setBusy(null);
    }
  }

  const current = providers.find((p) => p.id === provider);
  const label = current?.label ?? provider;
  const extra = current?.extra;
  const extraShown = extraValue ?? extra?.value ?? "";
  const canSave = apiKey.trim().length > 0 || (extra !== undefined && extraValue !== null && current?.configured);
  return (
    <div>
      <div className="controls">
        <label className="small">
          Provider{" "}
          <select
            value={provider}
            disabled={lockProvider}
            onChange={(e) => {
              setProvider(e.target.value);
              setExtraValue(null);
              setNote(null);
            }}
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
          style={{ flex: "1 1 240px", minWidth: 0, width: "100%", maxWidth: 420 }}
        />
        <button type="button" onClick={test} disabled={busy !== null}>
          {busy === "test" ? "Testing…" : "Test key"}
        </button>
        <button type="button" onClick={save} disabled={busy !== null || !canSave}>
          {busy === "save" ? "Saving…" : "Save key"}
        </button>
      </div>
      {extra ? (
        <div className="controls">
          <label className="small" style={{ flex: "1 1 240px", maxWidth: 420 }}>
            {extra.label} <span className="muted">(optional)</span>
            <input
              type="text"
              placeholder="wrkspc_…"
              value={extraShown}
              onChange={(e) => setExtraValue(e.target.value)}
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              aria-label={`${label} ${extra.label}`}
              style={{ display: "block", width: "100%", minWidth: 0, marginTop: 4 }}
            />
          </label>
          <p className="small muted" style={{ flexBasis: "100%", margin: 0 }}>{extra.help}</p>
        </div>
      ) : null}
      <p className="small muted">
        The key is sent to the local backend only. It is written to <code>.agentguard/.env</code> with
        permissions 600 and is never stored in this browser. Testing makes one tiny request to the provider.
      </p>
      {note ? <div className={`banner ${note.kind === "error" ? "error" : ""}`}>{note.text}</div> : null}
    </div>
  );
}
