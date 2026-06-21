import { useEffect, useState } from "react";
import { fetchCnappSbom, type SbomSummary } from "../api";

export function CnappSbomPage() {
  const [summary, setSummary] = useState<SbomSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCnappSbom().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading SBOM…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">CNAPP SBOM</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Stat label="Documents" value={summary.document_count} />
        <Stat label="Components" value={summary.component_count} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">SBOM documents</h2>
        {summary.documents.length === 0 ? <p className="text-sm text-slate-500">No SBOM documents</p> : (
          <ul className="space-y-2 text-sm">{summary.documents.map((d) => (
            <li key={d.id} className="p-2 rounded bg-slate-800/50"><div className="font-medium">{d.name}</div><div className="text-slate-400">{d.format} · {d.component_count} components</div></li>
          ))}</ul>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (<div className="rounded-lg border border-slate-800 bg-slate-900 p-4"><div className="text-sm text-slate-400">{label}</div><div className="text-3xl font-bold mt-2">{value}</div></div>);
}
