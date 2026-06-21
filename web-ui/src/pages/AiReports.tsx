import { useEffect, useState } from "react";
import { fetchAiReports, type ReportsSummary } from "../api";

export function AiReportsPage() {
  const [summary, setSummary] = useState<ReportsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAiReports().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading reports…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">AI Reports</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Stat label="Intel reports" value={summary.intel_count} />
        <Stat label="Executive reports" value={summary.executive_count} />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Panel title="Intelligence">
          <ul className="space-y-2 text-sm">
            {summary.intel_reports.map((r) => (
              <li key={r.id} className="p-2 rounded bg-slate-800/50">
                <div className="font-medium">{r.title}</div>
                <div className="text-slate-400">{r.report_kind}</div>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Executive">
          <ul className="space-y-2 text-sm">
            {summary.executive_reports.map((r) => (
              <li key={r.id} className="p-2 rounded bg-slate-800/50">
                <div className="font-medium">{r.title}</div>
                <div className="text-slate-400">{r.report_kind}</div>
              </li>
            ))}
          </ul>
        </Panel>
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

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className="text-sm font-medium text-slate-400 mb-3">{title}</h2>
      {children}
    </div>
  );
}
