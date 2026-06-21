import { useEffect, useState } from "react";
import { fetchPolicies } from "../api";

export function PoliciesPage() {
  const [policies, setPolicies] = useState<Array<Record<string, unknown>>>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchPolicies()
      .then(setPolicies)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Policies</h1>
      <div className="space-y-3">
        {policies.map((p) => (
          <div key={String(p.id)} className="rounded border border-slate-800 bg-slate-900 p-4">
            <div className="font-medium">{String(p.name)}</div>
            <div className="text-sm text-slate-400 mt-1">
              scope: {String(p.scope)} · version: {String(p.version)} · pushed:{" "}
              {String(p.pushed_at ?? "not pushed")}
            </div>
          </div>
        ))}
        {policies.length === 0 && <p className="text-slate-500">No policies defined.</p>}
      </div>
    </div>
  );
}
