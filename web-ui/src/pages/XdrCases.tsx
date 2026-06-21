import { useEffect, useState } from "react";
import { fetchXdrCases, type CasesSummary } from "../api";

export function XdrCasesPage() {
  const [summary, setSummary] = useState<CasesSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchXdrCases()
      .then(setSummary)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading XDR cases…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">XDR Cases</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Stat label="Total cases" value={summary.case_count} />
        <Stat label="Open" value={summary.open_cases} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Cases</h2>
        {summary.cases.length === 0 ? (
          <p className="text-sm text-slate-500">No investigation cases</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {summary.cases.map((c) => (
              <li key={c.id} className="p-2 rounded bg-slate-800/50">
                <div className="font-medium">{c.title}</div>
                <div className="text-slate-400">
                  {c.priority} · {c.status}
                  {c.assignee ? ` · ${c.assignee}` : ""}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
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
