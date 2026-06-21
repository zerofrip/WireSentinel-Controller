import { useEffect, useState } from "react";
import { fetchZtnaTrust, type DeviceTrustRecord } from "../api";

export function ZtnaTrustPage() {
  const [records, setRecords] = useState<DeviceTrustRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchZtnaTrust()
      .then(setRecords)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (records.length === 0 && !error) return <p>Loading device trust…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Device Trust</h1>
      <div className="rounded-lg border border-slate-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="text-left p-3">Device</th>
              <th className="text-left p-3">Trust level</th>
              <th className="text-left p-3">Score</th>
              <th className="text-left p-3">Last evaluated</th>
            </tr>
          </thead>
          <tbody>
            {records.map((r) => (
              <tr key={r.id} className="border-t border-slate-800">
                <td className="p-3 font-mono text-xs">{r.device_id.slice(0, 12)}…</td>
                <td className="p-3">{r.trust_level}</td>
                <td className="p-3">{r.trust_score}</td>
                <td className="p-3 text-slate-400">{r.last_evaluated_at}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
