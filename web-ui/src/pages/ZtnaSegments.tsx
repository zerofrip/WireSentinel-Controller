import { useEffect, useState } from "react";
import { fetchZtnaAnalytics, type ZtnaAnalyticsSummary } from "../api";

export function ZtnaSegmentsPage() {
  const [analytics, setAnalytics] = useState<ZtnaAnalyticsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchZtnaAnalytics()
      .then(setAnalytics)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!analytics) return <p>Loading segment analytics…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">ZTNA Segments & Analytics</h1>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="Devices reporting" value={analytics.devices_reporting} />
        <Stat label="Gateway active" value={analytics.gateway_active_devices} />
        <Stat label="Total connectors" value={analytics.total_connectors} />
        <Stat label="Published resources" value={analytics.published_resources} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Access telemetry</h2>
        <p className="text-sm text-slate-300">
          Average trust score: <strong>{analytics.avg_trust_score.toFixed(1)}</strong> · Recent
          denials: <strong>{analytics.total_denials}</strong> · Healthy connectors:{" "}
          <strong>{analytics.healthy_connectors}</strong>
        </p>
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
