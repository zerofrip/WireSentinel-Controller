import { useEffect, useState } from "react";
import { fetchAiThreats, type ThreatsSummary } from "../api";

export function AiThreatsPage() {
  const [summary, setSummary] = useState<ThreatsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAiThreats().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading threats…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">AI Correlated Threats</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Threats" value={summary.threat_count} />
        <Stat label="Open" value={summary.open_threats} />
        <Stat label="High confidence" value={summary.high_confidence} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Correlated threats</h2>
        <ul className="space-y-2 text-sm">
          {summary.threats.map((t) => (
            <li key={t.id} className="p-2 rounded bg-slate-800/50">
              <div className="font-medium">{t.title}</div>
              <div className="text-slate-400">{t.severity} · {t.status} · {(t.confidence * 100).toFixed(0)}%</div>
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
