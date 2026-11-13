"use client";

import { FormEvent, useEffect, useState } from "react";
import { ApiError, deleteJSON, putJSON } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { SettingsResponse, SettingsValues } from "@/lib/types";
import { KeyForm } from "@/components/KeyForm";
import { ErrorBox, Loading, Panel } from "@/components/ui";

type Draft = Omit<SettingsValues, "saved_to_file">;

export default function SettingsPage() {
  const settings = useApi<SettingsResponse>("/api/settings");
  const [draft, setDraft] = useState<Draft | null>(null);
  const [saveNote, setSaveNote] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [replacing, setReplacing] = useState<string | null>(null);

  useEffect(() => {
    if (settings.data && draft === null) {
      const { saved_to_file: _ignored, ...values } = settings.data.settings;
      setDraft(values);
    }
  }, [settings.data, draft]);

  if (settings.loading) return <Loading what="Loading settings" />;
  if (settings.error) return <ErrorBox message={`Could not reach the backend: ${settings.error}`} />;
  if (!settings.data || !draft) return null;

  function update<K extends keyof Draft>(key: K, value: Draft[K]) {
    setDraft((d) => (d ? { ...d, [key]: value } : d));
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    setSaveNote(null);
    try {
      await putJSON<{ settings: SettingsValues }>("/api/settings", draft);
      setSaveNote({ kind: "ok", text: "Settings saved to .agentguard/config.yaml. They apply to the next run." });
      settings.refetch();
    } catch (err) {
      setSaveNote({ kind: "error", text: err instanceof ApiError ? err.message : (err as Error).message });
    }
  }

  async function remove(provider: string, label: string) {
    if (!window.confirm(`Remove the saved ${label} key from this project?`)) return;
    try {
      await deleteJSON(`/api/settings/keys/${provider}`);
      settings.refetch();
    } catch (err) {
      setSaveNote({ kind: "error", text: (err as Error).message });
    }
  }

  const numberField = (
    key: keyof Draft,
    label: string,
    hint: string,
    min: number,
    max: number,
    step = 1,
    nullable = false,
  ) => (
    <label className="small" style={{ display: "block", marginBottom: 10 }}>
      {label}
      <br />
      <input
        type="number"
        min={min}
        max={max}
        step={step}
        value={(draft[key] as number | null) ?? ""}
        placeholder={nullable ? "no limit" : undefined}
        onChange={(e) => {
          const raw = e.target.value;
          update(key, (raw === "" && nullable ? null : Number(raw)) as Draft[typeof key]);
        }}
        style={{ width: 200 }}
      />
      <span className="muted"> {hint}</span>
    </label>
  );

  return (
    <>
      <h1>Settings</h1>

      <Panel title="API keys">
        {settings.data.providers.map((p) => (
          <div key={p.id} style={{ borderBottom: "1px solid var(--border)", padding: "10px 0" }}>
            <div className="controls" style={{ justifyContent: "space-between" }}>
              <strong>{p.label}</strong>
              <span className="mono small">{p.configured ? p.masked : "not set"}</span>
              <span className="controls" style={{ marginBottom: 0 }}>
                <button type="button" onClick={() => setReplacing(replacing === p.id ? null : p.id)}>
                  {p.configured ? "Replace" : "Add"}
                </button>
                {p.configured ? (
                  <button type="button" onClick={() => remove(p.id, p.label)}>
                    Remove
                  </button>
                ) : null}
              </span>
            </div>
            {replacing === p.id ? (
              <KeyForm
                providers={settings.data!.providers}
                initialProvider={p.id}
                lockProvider
                onSaved={() => {
                  setReplacing(null);
                  settings.refetch();
                }}
              />
            ) : null}
          </div>
        ))}
      </Panel>

      <Panel title="Models">
        <p className="small muted">
          Any LiteLLM model string. Use the same model across roles unless you know why not. Changing these does not
          affect a run that is already in progress.
        </p>
        <label className="small" style={{ display: "block", marginBottom: 10 }}>
          fallback chain
          <br />
          <input
            type="text"
            value={draft.fallback_chain.join(", ")}
            onChange={(e) =>
              update("fallback_chain", e.target.value.split(",").map((m) => m.trim()).filter(Boolean))
            }
            style={{ width: 360, maxWidth: "100%" }}
          />
          <span className="muted"> tried in order when a provider is rate-limited</span>
        </label>
        {(["attacker_model", "reporter_model", "chat_model"] as const).map((key) => (
          <label className="small" key={key} style={{ display: "block", marginBottom: 10 }}>
            {key.replace(/_/g, " ")}
            <br />
            <input
              type="text"
              value={draft[key]}
              onChange={(e) => update(key, e.target.value)}
              style={{ width: 360, maxWidth: "100%" }}
            />
          </label>
        ))}
      </Panel>

      <Panel title="Limits">
        <form onSubmit={save}>
          {numberField("max_probes", "Probes per category", "attack messages per category", 1, 50)}
          {numberField("category_cooldown_seconds", "Cooldown between categories", "seconds, eases rate limits", 0, 300, 0.5)}
          {numberField("target_timeout", "Target timeout", "seconds per request to your app", 5, 600)}
          {numberField("max_llm_calls", "Default LLM call limit", "for new runs; blank = no limit", 1, 100000, 1, true)}
          {numberField("max_tokens", "Default token limit", "for new runs; blank = no limit", 1, 100000000, 1, true)}
          <div className="controls">
            <button type="submit">Save settings</button>
          </div>
          {saveNote ? <div className={`banner ${saveNote.kind === "error" ? "error" : ""}`}>{saveNote.text}</div> : null}
        </form>
      </Panel>
    </>
  );
}
