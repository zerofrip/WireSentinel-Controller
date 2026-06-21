import { useEffect, useState } from "react";
import { fetchCnappKubernetes, type KubernetesSummary } from "../api";

export function CnappKubernetesPage() {
  const [summary, setSummary] = useState<KubernetesSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCnappKubernetes().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading Kubernetes…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">CNAPP Kubernetes</h1>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="Clusters" value={summary.cluster_count} />
        <Stat label="Resources" value={summary.resource_count} />
        <Stat label="Findings" value={summary.finding_count} />
        <Stat label="Open findings" value={summary.open_findings} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Clusters</h2>
        <ul className="space-y-2 text-sm">
          {summary.clusters.map((c) => (
            <li key={c.id} className="p-2 rounded bg-slate-800/50">
              <div className="font-medium">{c.name}</div>
              <div className="text-slate-400">{c.provider} · {c.status} · {c.node_count} nodes</div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (<div className="rounded-lg border border-slate-800 bg-slate-900 p-4"><div className="text-sm text-slate-400">{label}</div><div className="text-3xl font-bold mt-2">{value}</div></div>);
}
