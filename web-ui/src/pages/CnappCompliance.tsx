import { useEffect, useState } from "react";
import { fetchCnappCompliance, type ComplianceSummary } from "../api";

export function CnappCompliancePage() {
  const [summary, setSummary] = useState<ComplianceSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCnappCompliance().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading compliance…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">CNAPP Compliance</h1>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="Controls" value={summary.control_count} />
        <Stat label="Violations" value={summary.violation_count} />
        <Stat label="Open violations" value={summary.open_violations} />
        <Stat label="Avg score" value={Math.round(summary.avg_score)} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Compliance controls</h2>
        <ul className="space-y-2 text-sm">{summary.controls.map((c) => (
          <li key={c.id} className="p-2 rounded bg-slate-800/50"><div className="font-medium">{c.framework} {c.control_id}</div><div className="text-slate-400">{c.title}</div></li>
        ))}</ul>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (<div className="rounded-lg border border-slate-800 bg-slate-900 p-4"><div className="text-sm text-slate-400">{label}</div><div className="text-3xl font-bold mt-2">{value}</div></div>);
}
