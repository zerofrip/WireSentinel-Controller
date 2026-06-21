import { useEffect, useState } from "react";
import { fetchSseUeba, type UebaSummary } from "../api";

export function SseUebaPage() {
  const [summary, setSummary] = useState<UebaSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchSseUeba()
      .then(setSummary)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading UEBA anomalies…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">UEBA Anomalies</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Anomalies" value={summary.anomaly_count} />
        <Stat label="Avg score" value={Math.round(summary.avg_anomaly_score)} />
        <Stat label="Alerting devices" value={summary.alerting_devices} />
      </div>
      <ul className="space-y-2 text-sm">
        {summary.anomalies.map((a) => (
          <li key={a.id} className="p-2 rounded bg-slate-800/50">
            <div className="font-medium">{a.description}</div>
            <div className="text-slate-400">{a.anomaly_kind} · score {Math.round(a.score)}</div>
          </li>
        ))}
      </ul>
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
