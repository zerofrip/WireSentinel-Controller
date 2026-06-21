import { useEffect, useState } from "react";
import { fetchSseDlp, type DlpSummary } from "../api";

export function SseDlpPage() {
  const [summary, setSummary] = useState<DlpSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchSseDlp()
      .then(setSummary)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading DLP incidents…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">DLP Incidents</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Total incidents" value={summary.incident_count} />
        <Stat label="Open" value={summary.open_incidents} />
        <Stat label="Blocked actions" value={summary.blocked_actions} />
      </div>
      <IncidentList incidents={summary.incidents} />
    </div>
  );
}

function IncidentList({ incidents }: { incidents: DlpSummary["incidents"] }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className="text-sm font-medium text-slate-400 mb-3">Recent incidents</h2>
      {incidents.length === 0 ? (
        <p className="text-sm text-slate-500">No DLP incidents</p>
      ) : (
        <ul className="space-y-2 text-sm">
          {incidents.map((i) => (
            <li key={i.id} className="p-2 rounded bg-slate-800/50">
              <div className="font-medium">{i.title}</div>
              <div className="text-slate-400">{i.resource ?? "—"} · {i.severity} · {i.action_taken}</div>
            </li>
          ))}
        </ul>
      )}
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
