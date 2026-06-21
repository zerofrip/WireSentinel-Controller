import { useEffect, useState } from "react";
import { fetchCnappVulnerabilities, type VulnerabilitiesSummary } from "../api";

export function CnappVulnerabilitiesPage() {
  const [summary, setSummary] = useState<VulnerabilitiesSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCnappVulnerabilities().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading vulnerabilities…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">CNAPP Vulnerabilities</h1>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="CVEs" value={summary.vulnerability_count} />
        <Stat label="Critical" value={summary.critical_count} />
        <Stat label="Affected assets" value={summary.affected_asset_count} />
        <Stat label="Remediation plans" value={summary.remediation_count} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Vulnerabilities</h2>
        {summary.vulnerabilities.length === 0 ? <p className="text-sm text-slate-500">No vulnerabilities</p> : (
          <ul className="space-y-2 text-sm">{summary.vulnerabilities.map((v) => (
            <li key={v.id} className="p-2 rounded bg-slate-800/50"><div className="font-medium">{v.cve_id}: {v.title}</div><div className="text-slate-400">{v.severity} · score {v.score?.toFixed(1) ?? "—"}</div></li>
          ))}</ul>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (<div className="rounded-lg border border-slate-800 bg-slate-900 p-4"><div className="text-sm text-slate-400">{label}</div><div className="text-3xl font-bold mt-2">{value}</div></div>);
}
