import { useEffect, useState } from "react";
import { fetchZtnaResources, type PublishedResourceRecord } from "../api";

export function ZtnaResourcesPage() {
  const [resources, setResources] = useState<PublishedResourceRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchZtnaResources()
      .then(setResources)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (resources.length === 0 && !error) return <p>Loading resources…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Published Resources</h1>
      <div className="rounded-lg border border-slate-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="text-left p-3">Name</th>
              <th className="text-left p-3">Host</th>
              <th className="text-left p-3">Type</th>
              <th className="text-left p-3">Published</th>
            </tr>
          </thead>
          <tbody>
            {resources.map((r) => (
              <tr key={r.id} className="border-t border-slate-800">
                <td className="p-3">{r.name}</td>
                <td className="p-3 font-mono text-xs">
                  {r.host}:{r.port}
                  {r.path_prefix ? r.path_prefix : ""}
                </td>
                <td className="p-3">{r.resource_type}</td>
                <td className="p-3">{r.published ? "Yes" : "No"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
