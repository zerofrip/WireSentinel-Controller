import { useEffect, useState } from "react";
import { fetchCnappContainers, type ContainersSummary } from "../api";

export function CnappContainersPage() {
  const [summary, setSummary] = useState<ContainersSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCnappContainers().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading containers…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">CNAPP Containers</h1>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="Images" value={summary.image_count} />
        <Stat label="Scanned" value={summary.scanned_images} />
        <Stat label="Findings" value={summary.finding_count} />
        <Stat label="Critical" value={summary.critical_findings} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Container findings</h2>
        {summary.findings.length === 0 ? <p className="text-sm text-slate-500">No findings</p> : (
          <ul className="space-y-2 text-sm">{summary.findings.map((f) => (
            <li key={f.id} className="p-2 rounded bg-slate-800/50"><div className="font-medium">{f.title}</div><div className="text-slate-400">{f.severity} · {f.cve_id ?? "—"}</div></li>
          ))}</ul>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (<div className="rounded-lg border border-slate-800 bg-slate-900 p-4"><div className="text-sm text-slate-400">{label}</div><div className="text-3xl font-bold mt-2">{value}</div></div>);
}
