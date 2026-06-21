import { useEffect, useState } from "react";
import { fetchAnonymityAnalytics, type AnonymityAnalyticsSummary } from "../api";

export function EntropyViewPage() {
  const [analytics, setAnalytics] = useState<AnonymityAnalyticsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAnonymityAnalytics()
      .then(setAnalytics)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!analytics) return <p>Loading entropy analytics…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Entropy</h1>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="Avg entropy bits" value={analytics.avg_entropy_bits.toFixed(1)} />
        <Stat label="Route entropy" value={analytics.avg_route_entropy.toFixed(2)} />
        <Stat label="Path diversity" value={analytics.avg_path_diversity.toFixed(2)} />
        <Stat label="Cover traffic" value={analytics.avg_cover_traffic_effectiveness.toFixed(2)} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Rollups</h2>
        {analytics.rollups.length === 0 ? (
          <p className="text-sm text-slate-500">No analytics rollups yet</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {analytics.rollups.map((r) => (
              <li key={r.id} className="flex justify-between p-2 rounded bg-slate-800/50">
                <span>{r.devices_reporting} devices</span>
                <span className="text-slate-400">
                  score {r.avg_anonymity_score.toFixed(0)} · entropy {r.avg_entropy_bits.toFixed(1)} ·{" "}
                  {r.rolled_up_at}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="text-sm text-slate-400">{label}</div>
      <div className="text-3xl font-bold mt-2">{value}</div>
    </div>
  );
}
