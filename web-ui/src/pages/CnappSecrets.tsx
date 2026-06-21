import { useEffect, useState } from "react";
import { fetchCnappSecrets, type SecretsSummary } from "../api";

export function CnappSecretsPage() {
  const [summary, setSummary] = useState<SecretsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCnappSecrets().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading secrets…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">CNAPP Secrets</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Findings" value={summary.finding_count} />
        <Stat label="Open" value={summary.open_findings} />
        <Stat label="High severity" value={summary.high_severity} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Secret findings</h2>
        {summary.findings.length === 0 ? <p className="text-sm text-slate-500">No secret findings</p> : (
          <ul className="space-y-2 text-sm">{summary.findings.map((f) => (
            <li key={f.id} className="p-2 rounded bg-slate-800/50"><div className="font-medium">{f.secret_kind}</div><div className="text-slate-400">{f.severity} · {f.file_path ?? f.source ?? "—"}</div></li>
          ))}</ul>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (<div className="rounded-lg border border-slate-800 bg-slate-900 p-4"><div className="text-sm text-slate-400">{label}</div><div className="text-3xl font-bold mt-2">{value}</div></div>);
}
