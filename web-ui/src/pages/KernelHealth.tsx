import { useEffect, useState } from "react";
import { fetchKernelStatus, type KernelSnapshot } from "../api";

export function KernelHealthPage() {
  const [snapshots, setSnapshots] = useState<KernelSnapshot[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchKernelStatus()
      .then((s) => setSnapshots(s.snapshots))
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!snapshots) return <p>Loading kernel health…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Kernel Health</h1>
      {snapshots.length === 0 ? (
        <p className="text-sm text-slate-500">No kernel health snapshots yet</p>
      ) : (
        <ul className="space-y-3">
          {snapshots.map((s) => (
            <li key={s.id} className="rounded-lg border border-slate-800 bg-slate-900 p-4 text-sm">
              <div className="flex justify-between gap-4">
                <span className="font-medium">{s.device_id}</span>
                <span className={s.healthy ? "text-emerald-400" : "text-red-400"}>
                  {s.healthy ? "healthy" : "degraded"}
                </span>
              </div>
              <p className="text-slate-400 mt-2">
                {s.guardian_mode} · {s.lifecycle_state} · filters {s.filter_count} · callouts{" "}
                {s.callouts_registered}
              </p>
              <p className="text-slate-500 mt-1">
                kill switch: {s.kill_switch_mode ?? "—"} · routes {s.active_route_count} ·{" "}
                {s.reported_at}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
