import { useEffect, useState } from "react";
import { fetchXdrDetections, type DetectionsSummary } from "../api";

export function XdrDetectionsPage() {
  const [summary, setSummary] = useState<DetectionsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchXdrDetections()
      .then(setSummary)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading detections…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">XDR Detections</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Detections" value={summary.detection_count} />
        <Stat label="New" value={summary.new_detections} />
        <Stat label="Rules" value={summary.rule_count} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Recent detections</h2>
        {summary.detections.length === 0 ? (
          <p className="text-sm text-slate-500">No detections</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {summary.detections.map((d) => (
              <li key={d.id} className="p-2 rounded bg-slate-800/50">
                <div className="font-medium">{d.title}</div>
                <div className="text-slate-400">
                  {d.severity} · {d.status} · confidence {d.confidence.toFixed(2)}
                </div>
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
