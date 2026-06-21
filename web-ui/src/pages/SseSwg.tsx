import { useEffect, useState } from "react";
import { fetchSseSwg, type SwgSummary } from "../api";

export function SseSwgPage() {
  const [summary, setSummary] = useState<SwgSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchSseSwg()
      .then(setSummary)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading SWG summary…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Secure Web Gateway</h1>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="Policies" value={summary.policy_count} />
        <Stat label="Requests" value={summary.total_requests} />
        <Stat label="Blocked" value={summary.blocked_count} />
        <Stat label="Threat matches" value={summary.threat_match_count} />
      </div>
      <ThreatList threats={summary.recent_threats} />
    </div>
  );
}

function ThreatList({ threats }: { threats: SwgSummary["recent_threats"] }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className="text-sm font-medium text-slate-400 mb-3">Recent threat matches</h2>
      {threats.length === 0 ? (
        <p className="text-sm text-slate-500">No threats recorded</p>
      ) : (
        <ul className="space-y-2 text-sm">
          {threats.slice(0, 20).map((t) => (
            <li key={t.id} className="flex justify-between p-2 rounded bg-slate-800/50">
              <span>{t.threat_kind} · {t.category}</span>
              <span className="text-slate-400">{t.severity} · {t.action}</span>
            </li>
          ))}
        </ul>
      )}
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
