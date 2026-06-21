import { useEffect, useState } from "react";
import { fetchSseSwg, type SseThreatMatch } from "../api";

export function SseThreatsPage() {
  const [threats, setThreats] = useState<SseThreatMatch[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchSseSwg()
      .then((s) => setThreats(s.recent_threats))
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Threat Matches</h1>
      {threats.length === 0 ? (
        <p className="text-slate-500">No threat matches recorded</p>
      ) : (
        <ul className="space-y-2 text-sm">
          {threats.map((t) => (
            <li key={t.id} className="rounded-lg border border-slate-800 bg-slate-900 p-4">
              <div className="font-medium">{t.threat_kind} · {t.category}</div>
              <div className="text-slate-400 mt-1">{t.url ?? t.signature ?? "—"}</div>
              <div className="text-xs text-slate-500 mt-2">
                {t.severity} · {t.action} · device {t.device_id.slice(0, 8)}…
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
