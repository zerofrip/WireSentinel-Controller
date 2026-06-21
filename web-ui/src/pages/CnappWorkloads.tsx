import { useEffect, useState } from "react";
import { fetchCnappWorkloads, type WorkloadsSummary } from "../api";

export function CnappWorkloadsPage() {
  const [summary, setSummary] = useState<WorkloadsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCnappWorkloads().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading workloads…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">CNAPP Workloads</h1>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="Workloads" value={summary.workload_count} />
        <Stat label="Active" value={summary.active_workloads} />
        <Stat label="Threats" value={summary.threat_count} />
        <Stat label="Open threats" value={summary.open_threats} />
      </div>
      <List title="Workloads" empty="No workloads" items={summary.workloads.map((w) => ({ id: w.id, title: w.name, meta: `${w.workload_kind} · ${w.namespace ?? "—"} · ${w.status}` }))} />
    </div>
  );
}

function List({ title, empty, items }: { title: string; empty: string; items: { id: string; title: string; meta: string }[] }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className="text-sm font-medium text-slate-400 mb-3">{title}</h2>
      {items.length === 0 ? <p className="text-sm text-slate-500">{empty}</p> : (
        <ul className="space-y-2 text-sm">{items.map((i) => (
          <li key={i.id} className="p-2 rounded bg-slate-800/50"><div className="font-medium">{i.title}</div><div className="text-slate-400">{i.meta}</div></li>
        ))}</ul>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (<div className="rounded-lg border border-slate-800 bg-slate-900 p-4"><div className="text-sm text-slate-400">{label}</div><div className="text-3xl font-bold mt-2">{value}</div></div>);
}
