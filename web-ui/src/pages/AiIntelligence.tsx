import { useEffect, useState } from "react";
import { fetchAiIntelligence, type IntelligenceSummary } from "../api";

export function AiIntelligencePage() {
  const [summary, setSummary] = useState<IntelligenceSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAiIntelligence().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading intelligence…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">AI Threat Intelligence</h1>
      <Stat label="Intel reports" value={summary.report_count} />
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <ul className="space-y-2 text-sm">
          {summary.reports.map((r) => (
            <li key={r.id} className="p-2 rounded bg-slate-800/50">
              <div className="font-medium">{r.title}</div>
              <div className="text-slate-400">{r.report_kind}</div>
              {r.summary && <div className="text-slate-500 mt-1">{r.summary}</div>}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4 max-w-xs">
      <div className="text-sm text-slate-400">{label}</div>
      <div className="text-3xl font-bold mt-2">{value}</div>
    </div>
  );
}
