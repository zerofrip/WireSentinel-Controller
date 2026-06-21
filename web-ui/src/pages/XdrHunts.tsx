import { useEffect, useState } from "react";
import { fetchXdrHunts, type HuntsSummary } from "../api";

export function XdrHuntsPage() {
  const [summary, setSummary] = useState<HuntsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchXdrHunts()
      .then(setSummary)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading threat hunts…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Threat Hunts</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Total hunts" value={summary.hunt_count} />
        <Stat label="Active" value={summary.active_hunts} />
        <Stat label="Results" value={summary.result_count} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Hunts</h2>
        {summary.hunts.length === 0 ? (
          <p className="text-sm text-slate-500">No hunts defined</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {summary.hunts.map((h) => (
              <li key={h.id} className="p-2 rounded bg-slate-800/50">
                <div className="font-medium">{h.name}</div>
                <div className="text-slate-400">
                  {h.query_kind} · {h.status}
                  {h.owner ? ` · ${h.owner}` : ""}
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
