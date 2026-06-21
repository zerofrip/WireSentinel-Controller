import { useEffect, useState } from "react";
import { fetchHealth } from "../api";

export function HealthPage() {
  const [health, setHealth] = useState<{ status: string; service: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!health) return <p>Checking health…</p>;

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Health</h1>
      <div className="rounded border border-slate-800 bg-slate-900 p-6 max-w-md">
        <div className="text-sm text-slate-400">Service</div>
        <div className="text-lg">{health.service}</div>
        <div className="text-sm text-slate-400 mt-4">Status</div>
        <div className="text-lg text-emerald-400">{health.status}</div>
      </div>
    </div>
  );
}
