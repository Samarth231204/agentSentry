"use client";

import Link from "next/link";
import { useApi } from "@/lib/useApi";
import type { SettingsResponse } from "@/lib/types";
import { KeyForm } from "@/components/KeyForm";
import { ErrorBox, Loading, Panel } from "@/components/ui";

export default function OnboardingPage() {
  const settings = useApi<SettingsResponse>("/api/settings");

  if (settings.loading) return <Loading what="Checking the backend" />;
  if (settings.error) return <ErrorBox message={`Could not reach the backend: ${settings.error}`} />;
  if (!settings.data) return null;

  const configured = settings.data.providers.filter((p) => p.configured);

  return (
    <>
      <h1>Set up AgentGuard</h1>
      <Panel title="1. Paste an API key">
        <p className="small muted">
          Pick the provider you want the attacker, judge and reporter to use. Only one key is needed to start.
        </p>
        <KeyForm providers={settings.data.providers} onSaved={settings.refetch} />
      </Panel>

      <Panel title="2. Keys on this machine">
        {configured.length === 0 ? (
          <p className="muted">No key saved yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Provider</th>
                <th>Stored as</th>
              </tr>
            </thead>
            <tbody>
              {configured.map((p) => (
                <tr key={p.id}>
                  <td>{p.label}</td>
                  <td className="mono">{p.masked}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="small muted">
          Keys can be replaced or removed on the <Link href="/settings">Settings</Link> page.
        </p>
      </Panel>

      <Panel title="3. Start a run">
        <p>
          Once a key is saved, <Link href="/new">start a run</Link>. To check the pipeline without spending
          quota, tick <strong>mock mode</strong> on that page first.
        </p>
      </Panel>
    </>
  );
}
