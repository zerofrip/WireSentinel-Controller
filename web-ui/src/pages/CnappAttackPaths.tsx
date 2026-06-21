import { useEffect, useState } from "react";
import { fetchCnappAttackPaths, type AttackPathsSummary } from "../api";

export function CnappAttackPathsPage() {
  const [summary, setSummary] = useState<AttackPathsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCnappAttackPaths().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading attack paths…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">CNAPP Attack Paths</h1>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="Paths" value={summary.path_count} />
        <Stat label="Open" value={summary.open_paths} />
        <Stat label="Nodes" value={summary.node_count} />
        <Stat label="Edges" value={summary.edge_count} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Attack paths</h2>
        {summary.paths.length === 0 ? <p className="text-sm text-slate-500">No attack paths</p> : (
          <ul className="space-y-2 text-sm">{summary.paths.map((p) => (
            <li key={p.id} className="p-2 rounded bg-slate-800/50"><div className="font-medium">{p.name}</div><div className="text-slate-400">{p.severity} · {p.entry_asset ?? "—"} → {p.target_asset ?? "—"}</div></li>
          ))}</ul>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (<div className="rounded-lg border border-slate-800 bg-slate-900 p-4"><div className="text-sm text-slate-400">{label}</div><div className="text-3xl font-bold mt-2">{value}</div></div>);
}
