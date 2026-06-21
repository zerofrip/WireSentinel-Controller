import { useEffect, useState } from "react";
import { fetchZtnaDashboard, type ZtnaDashboardSummary } from "../api";

export function ZtnaDashboardPage() {
  const [summary, setSummary] = useState<ZtnaDashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchZtnaDashboard()
      .then(setSummary)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading ZTNA dashboard…</p>;

  const a = summary.analytics;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">ZTNA Dashboard</h1>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="Policies" value={summary.policy_count} />
        <Stat label="Published resources" value={summary.published_resource_count} />
        <Stat label="Trusted devices" value={summary.trusted_devices} />
        <Stat label="Connectors" value={summary.connector_count} />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="Reporting devices" value={a.devices_reporting} />
        <Stat label="Avg trust score" value={Math.round(a.avg_trust_score)} />
        <Stat label="Healthy connectors" value={a.healthy_connectors} />
        <Stat label="Recent denials" value={a.total_denials} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Recent heartbeats</h2>
        {a.snapshots.length === 0 ? (
          <p className="text-sm text-slate-500">No ZTNA heartbeats yet</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {a.snapshots.slice(0, 20).map((s) => (
              <li key={s.id} className="flex justify-between p-2 rounded bg-slate-800/50">
                <span className="font-mono text-xs">{s.device_id.slice(0, 8)}…</span>
                <span className="text-slate-400">
                  trust {Math.round(s.avg_trust_score)} ·{" "}
                  {s.gateway_active ? "gateway active" : "gateway idle"} · {s.connector_count} connectors
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
