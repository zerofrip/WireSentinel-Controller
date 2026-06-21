import { useEffect, useState } from "react";
import { fetchAnonymity, type AnonymityHealthSummary } from "../api";

export function AnonymityDashboardPage() {
  const [health, setHealth] = useState<AnonymityHealthSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAnonymity()
      .then(setHealth)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!health) return <p>Loading anonymity dashboard…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Anonymity</h1>
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Stat label="Connected" value={health.connected_devices} />
        <Stat label="Healthy" value={health.healthy_devices} />
        <Stat label="Stub mode" value={health.stub_devices} />
        <Stat label="Active routes" value={health.total_active_routes} />
        <Stat label="Avg score" value={Math.round(health.avg_anonymity_score)} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Recent snapshots</h2>
        {health.snapshots.length === 0 ? (
          <p className="text-sm text-slate-500">No anonymity snapshots yet</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {health.snapshots.slice(0, 20).map((s) => (
              <li key={s.id} className="flex justify-between p-2 rounded bg-slate-800/50">
                <span className="font-mono text-xs">{s.device_id.slice(0, 8)}…</span>
                <span className="text-slate-400">
                  score {s.anonymity_score} · {s.anonymity_connected ? "connected" : "offline"} ·{" "}
                  {s.active_route_count} routes
                </span>
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
