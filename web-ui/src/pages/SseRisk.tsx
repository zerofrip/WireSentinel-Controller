import { useEffect, useState } from "react";
import { fetchSseRisk, type RiskSummary } from "../api";

export function SseRiskPage() {
  const [summary, setSummary] = useState<RiskSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchSseRisk()
      .then(setSummary)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading risk scores…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Risk Scores</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Devices scored" value={summary.devices_scored} />
        <Stat label="Avg risk score" value={Math.round(summary.avg_risk_score)} />
        <Stat label="High risk devices" value={summary.high_risk_devices} />
      </div>
      <ul className="space-y-2 text-sm">
        {summary.scores.map((s) => (
          <li key={s.id} className="flex justify-between p-2 rounded bg-slate-800/50">
            <span className="font-mono text-xs">{s.device_id.slice(0, 8)}…</span>
            <span>{s.risk_score} · {s.risk_level}</span>
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
