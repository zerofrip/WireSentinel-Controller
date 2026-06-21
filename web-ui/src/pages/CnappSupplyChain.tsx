import { useEffect, useState } from "react";
import { fetchCnappSupplyChain, type SupplyChainSummary } from "../api";

export function CnappSupplyChainPage() {
  const [summary, setSummary] = useState<SupplyChainSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCnappSupplyChain().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading supply chain…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">CNAPP Supply Chain</h1>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="Dependencies" value={summary.dependency_count} />
        <Stat label="Direct" value={summary.direct_dependencies} />
        <Stat label="Threats" value={summary.threat_count} />
        <Stat label="Open threats" value={summary.open_threats} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Supply chain threats</h2>
        {summary.threats.length === 0 ? <p className="text-sm text-slate-500">No threats</p> : (
          <ul className="space-y-2 text-sm">{summary.threats.map((t) => (
            <li key={t.id} className="p-2 rounded bg-slate-800/50"><div className="font-medium">{t.title}</div><div className="text-slate-400">{t.threat_kind} · {t.severity}</div></li>
          ))}</ul>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (<div className="rounded-lg border border-slate-800 bg-slate-900 p-4"><div className="text-sm text-slate-400">{label}</div><div className="text-3xl font-bold mt-2">{value}</div></div>);
}
