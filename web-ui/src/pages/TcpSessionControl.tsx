import { useEffect, useState } from "react";
import {
  fetchTcpTerminationSettings,
  updateTcpTerminationSettings,
  type TcpTerminationSettings,
} from "../api";

const MODES = [
  "disabled",
  "on_vpn_connect",
  "on_vpn_disconnect",
  "on_route_change",
  "always",
] as const;

export function TcpSessionControlPage() {
  const [settings, setSettings] = useState<TcpTerminationSettings | null>(null);
  const [mode, setMode] = useState<string>("disabled");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function load() {
    const data = await fetchTcpTerminationSettings();
    setSettings(data);
    setMode(data.mode);
  }

  useEffect(() => {
    load().catch((e: Error) => setError(e.message));
  }, []);

  async function save() {
    setSaving(true);
    setError(null);
    try {
      const updated = await updateTcpTerminationSettings(mode);
      setSettings(updated);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  if (error) return <p className="text-red-400">{error}</p>;
  if (!settings) return <p>Loading TCP session control…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">TCP Session Control</h1>
      <p className="text-sm text-slate-400">
        Configure when existing TCP sessions are terminated during VPN connect, disconnect, or route changes.
      </p>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4 space-y-4 max-w-lg">
        <label className="block text-sm text-slate-400">Termination mode</label>
        <select
          className="w-full rounded bg-slate-800 border border-slate-700 px-3 py-2 text-sm"
          value={mode}
          onChange={(e) => setMode(e.target.value)}
        >
          {MODES.map((m) => (
            <option key={m} value={m}>
              {m.replaceAll("_", " ")}
            </option>
          ))}
        </select>
        <button
          className="rounded bg-cyan-700 px-4 py-2 text-sm disabled:opacity-50"
          onClick={save}
          disabled={saving}
        >
          {saving ? "Saving…" : "Save settings"}
        </button>
        <p className="text-xs text-slate-500">Last updated: {settings.updated_at}</p>
      </div>
    </div>
  );
}
