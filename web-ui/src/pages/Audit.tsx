import { useEffect, useState } from "react";
import { fetchAudit } from "../api";

export function AuditPage() {
  const [events, setEvents] = useState<Array<Record<string, unknown>>>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAudit()
      .then(setEvents)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Audit</h1>
      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="min-w-full text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-4 py-2 text-left">Time</th>
              <th className="px-4 py-2 text-left">Source</th>
              <th className="px-4 py-2 text-left">Action</th>
              <th className="px-4 py-2 text-left">Actor</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={String(e.id)} className="border-t border-slate-800">
                <td className="px-4 py-2">{String(e.created_at)}</td>
                <td className="px-4 py-2">{String(e.source)}</td>
                <td className="px-4 py-2">{String(e.action)}</td>
                <td className="px-4 py-2">{String(e.actor ?? "-")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
