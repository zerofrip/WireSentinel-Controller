import { useEffect, useState } from "react";
import {
  createTcpTerminationRule,
  deleteTcpTerminationRule,
  fetchTcpTerminationRules,
  updateTcpTerminationRule,
  type TcpTerminationRule,
  type TcpTerminationRulesSummary,
} from "../api";

export function TcpReconnectPoliciesPage() {
  const [summary, setSummary] = useState<TcpTerminationRulesSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [processName, setProcessName] = useState("");

  async function load() {
    setSummary(await fetchTcpTerminationRules());
  }

  useEffect(() => {
    load().catch((e: Error) => setError(e.message));
  }, []);

  async function addRule() {
    if (!processName.trim()) return;
    setError(null);
    try {
      await createTcpTerminationRule({
        process_name: processName.trim(),
        route: { type: "direct" },
        enabled: true,
      });
      setProcessName("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Create failed");
    }
  }

  async function toggleRule(rule: TcpTerminationRule) {
    setError(null);
    try {
      await updateTcpTerminationRule(rule.id, { enabled: !rule.enabled });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Update failed");
    }
  }

  async function removeRule(id: string) {
    setError(null);
    try {
      await deleteTcpTerminationRule(id);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed");
    }
  }

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading reconnect policies…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">TCP Reconnect Policies</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Stat label="Rules" value={summary.rule_count} />
        <Stat label="Enabled" value={summary.enabled_count} />
      </div>
      <div className="flex gap-2">
        <input
          className="flex-1 rounded bg-slate-800 border border-slate-700 px-3 py-2 text-sm"
          placeholder="Process name (e.g. chrome.exe)"
          value={processName}
          onChange={(e) => setProcessName(e.target.value)}
        />
        <button className="rounded bg-cyan-700 px-4 py-2 text-sm" onClick={addRule}>
          Add rule
        </button>
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <ul className="space-y-2 text-sm">
          {summary.rules.map((rule) => (
            <li key={rule.id} className="p-2 rounded bg-slate-800/50 flex items-center justify-between gap-4">
              <div>
                <div className="font-medium">{rule.process_name ?? rule.process_path ?? rule.id}</div>
                <div className="text-slate-400">
                  {rule.enabled ? "enabled" : "disabled"}
                  {rule.route ? ` · route: ${JSON.stringify(rule.route)}` : ""}
                </div>
              </div>
              <div className="flex gap-2 shrink-0">
                <button className="text-cyan-400 text-xs" onClick={() => toggleRule(rule)}>
                  {rule.enabled ? "Disable" : "Enable"}
                </button>
                <button className="text-red-400 text-xs" onClick={() => removeRule(rule.id)}>
                  Delete
                </button>
              </div>
            </li>
          ))}
          {summary.rules.length === 0 && (
            <li className="text-slate-500">No process-aware reconnect rules defined.</li>
          )}
        </ul>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="text-sm text-slate-400">{label}</div>
      <div className="text-3xl font-bold mt-2">{value}</div>
    </div>
  );
}
