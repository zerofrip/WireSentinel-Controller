import { useEffect, useState } from "react";
import { fetchAiInvestigations, type InvestigationsSummary } from "../api";

export function AiInvestigationsPage() {
  const [summary, setSummary] = useState<InvestigationsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAiInvestigations().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading investigations…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">AI Investigations</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Total" value={summary.investigation_count} />
        <Stat label="Open" value={summary.open_investigations} />
        <Stat label="High severity" value={summary.high_severity} />
      </div>
      <List title="Investigations" empty="No investigations" items={summary.investigations.map((i) => (
        <li key={i.id} className="p-2 rounded bg-slate-800/50 text-sm">
          <div className="font-medium">{i.title}</div>
          <div className="text-slate-400">{i.severity} · {i.status} · {i.priority}</div>
        </li>
      ))} />
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="text-sm text-slate-400">{label}</div>
      <div className="text-3xl font-bold mt-2">{value}</div>
    </div>
  );
}

function List({ title, empty, items }: { title: string; empty: string; items: React.ReactNode[] }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className="text-sm font-medium text-slate-400 mb-3">{title}</h2>
      {items.length === 0 ? <p className="text-sm text-slate-500">{empty}</p> : <ul className="space-y-2">{items}</ul>}
    </div>
  );
}
