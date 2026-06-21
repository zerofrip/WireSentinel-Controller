import { useEffect, useState } from "react";
import { fetchXdrMitre, type MitreSummary } from "../api";

export function XdrMitrePage() {
  const [summary, setSummary] = useState<MitreSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchXdrMitre()
      .then(setSummary)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading MITRE ATT&CK…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">MITRE ATT&CK</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Stat label="Techniques" value={summary.technique_count} />
        <Stat label="Mappings" value={summary.mapping_count} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Techniques</h2>
        {summary.techniques.length === 0 ? (
          <p className="text-sm text-slate-500">No techniques seeded</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {summary.techniques.map((t) => (
              <li key={t.id} className="p-2 rounded bg-slate-800/50">
                <div className="font-medium">
                  {t.technique_id} — {t.name}
                </div>
                <div className="text-slate-400">{t.tactic}</div>
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
