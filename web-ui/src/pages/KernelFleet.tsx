import { useEffect, useState } from "react";
import { fetchKernelStatus, type KernelStatusSummary } from "../api";

export function KernelFleetPage() {
  const [status, setStatus] = useState<KernelStatusSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchKernelStatus()
      .then(setStatus)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!status) return <p>Loading kernel fleet…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Kernel Fleet</h1>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="Reporting" value={status.reporting_devices} />
        <Stat label="Healthy" value={status.healthy_devices} />
        <Stat label="Kernel mode" value={status.kernel_devices} />
        <Stat label="NDIS enabled" value={status.ndis_devices} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Recent snapshots</h2>
        {status.snapshots.length === 0 ? (
          <p className="text-sm text-slate-500">No kernel heartbeats received yet</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {status.snapshots.map((s) => (
              <li key={s.id} className="flex justify-between gap-4 p-2 rounded bg-slate-800/50">
                <span>{s.device_id.slice(0, 8)}…</span>
                <span className="text-slate-400">
                  {s.guardian_mode} · {s.lifecycle_state} ·{" "}
                  {s.healthy ? "healthy" : "unhealthy"}
                </span>
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
