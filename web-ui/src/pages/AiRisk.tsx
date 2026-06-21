import { useEffect, useState } from "react";
import { fetchAiRisk, type AiRiskSummary } from "../api";

export function AiRiskPage() {
  const [summary, setSummary] = useState<AiRiskSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAiRisk().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading risk scores…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">AI Risk Scores</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Scores" value={summary.score_count} />
        <Stat label="Average" value={Math.round(summary.avg_risk_score)} />
        <Stat label="High risk" value={summary.high_risk_count} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <ul className="space-y-2 text-sm">
          {summary.scores.map((s) => (
            <li key={s.id} className="p-2 rounded bg-slate-800/50">
              <div className="font-medium">{s.scope_kind} · {s.risk_score}</div>
              <div className="text-slate-400">{s.risk_level}</div>
            </li>
          ))}
        </ul>
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
