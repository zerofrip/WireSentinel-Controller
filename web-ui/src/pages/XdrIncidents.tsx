import { useEffect, useState } from "react";
import { fetchXdrIncidents, type IncidentsSummary } from "../api";

export function XdrIncidentsPage() {
  const [summary, setSummary] = useState<IncidentsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchXdrIncidents()
      .then(setSummary)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading XDR incidents…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">XDR Incidents</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Total incidents" value={summary.incident_count} />
        <Stat label="Open" value={summary.open_incidents} />
        <Stat label="High severity" value={summary.high_severity} />
      </div>
      <List title="Recent incidents" empty="No XDR incidents">
        {summary.incidents.map((i) => (
          <li key={i.id} className="p-2 rounded bg-slate-800/50 text-sm">
            <div className="font-medium">{i.title}</div>
            <div className="text-slate-400">
              {i.severity} · {i.status} · {i.detected_at}
            </div>
          </li>
        ))}
      </List>
    </div>
  );
}

function List({
  title,
  empty,
  children,
}: {
  title: string;
  empty: string;
  children: React.ReactNode;
}) {
  const items = Array.isArray(children) ? children : [children];
  const hasItems = items.some(Boolean);
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className="text-sm font-medium text-slate-400 mb-3">{title}</h2>
      {!hasItems ? (
        <p className="text-sm text-slate-500">{empty}</p>
      ) : (
        <ul className="space-y-2">{children}</ul>
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
