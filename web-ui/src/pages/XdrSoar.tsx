import { useEffect, useState } from "react";
import { fetchXdrSoar, type SoarSummary } from "../api";

export function XdrSoarPage() {
  const [summary, setSummary] = useState<SoarSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchXdrSoar()
      .then(setSummary)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading SOAR playbooks…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">SOAR Playbooks</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Playbooks" value={summary.playbook_count} />
        <Stat label="Enabled" value={summary.enabled_playbooks} />
        <Stat label="Executions" value={summary.execution_count} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Playbooks</h2>
        {summary.playbooks.length === 0 ? (
          <p className="text-sm text-slate-500">No playbooks</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {summary.playbooks.map((p) => (
              <li key={p.id} className="p-2 rounded bg-slate-800/50">
                <div className="font-medium">{p.name}</div>
                <div className="text-slate-400">
                  {p.playbook_kind} · {p.enabled ? "enabled" : "disabled"}
                </div>
              </li>
            ))}
          </ul>
        )}
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
