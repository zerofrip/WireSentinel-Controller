import { useEffect, useState } from "react";
import { fetchCnappIac, type IacSummary } from "../api";

export function CnappIacPage() {
  const [summary, setSummary] = useState<IacSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCnappIac().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading IaC…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">CNAPP IaC</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Scans" value={summary.scan_count} />
        <Stat label="Findings" value={summary.finding_count} />
        <Stat label="Open" value={summary.open_findings} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">IaC findings</h2>
        {summary.findings.length === 0 ? <p className="text-sm text-slate-500">No findings</p> : (
          <ul className="space-y-2 text-sm">{summary.findings.map((f) => (
            <li key={f.id} className="p-2 rounded bg-slate-800/50"><div className="font-medium">{f.title}</div><div className="text-slate-400">{f.severity} · {f.file_path ?? "—"}</div></li>
          ))}</ul>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (<div className="rounded-lg border border-slate-800 bg-slate-900 p-4"><div className="text-sm text-slate-400">{label}</div><div className="text-3xl font-bold mt-2">{value}</div></div>);
}
