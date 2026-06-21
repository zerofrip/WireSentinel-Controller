import { useEffect, useState } from "react";
import { fetchMixnetHealth, type MixnetHealthSummary } from "../api";

export function CoverTrafficPage() {
  const [health, setHealth] = useState<MixnetHealthSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchMixnetHealth()
      .then(setHealth)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!health) return <p>Loading cover traffic status…</p>;

  const profiles = health.snapshots
    .map((s) => s.cover_traffic_profile)
    .filter((p): p is string => Boolean(p));

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Cover Traffic</h1>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Agent profiles</h2>
        {profiles.length === 0 ? (
          <p className="text-sm text-slate-500">No cover traffic profiles reported</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {profiles.map((p, i) => (
              <li key={`${p}-${i}`} className="p-2 rounded bg-slate-800/50">
                {p}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
