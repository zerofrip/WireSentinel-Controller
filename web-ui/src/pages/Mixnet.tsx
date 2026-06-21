import { useEffect, useState } from "react";
import { fetchMixnet, type MixnetInventorySummary } from "../api";

export function MixnetPage() {
  const [inventory, setInventory] = useState<MixnetInventorySummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchMixnet()
      .then(setInventory)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!inventory) return <p>Loading mixnet inventory…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Mixnet</h1>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Stat label="Nodes" value={inventory.node_count} />
        <Stat label="Routes" value={inventory.route_count} />
        <Stat label="Active routes" value={inventory.active_route_count} />
        <Stat label="Reporting devices" value={inventory.devices_reporting} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Nodes</h2>
        {inventory.nodes.length === 0 ? (
          <p className="text-sm text-slate-500">No mixnet nodes reported yet</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {inventory.nodes.map((n) => (
              <li key={n.id} className="flex justify-between gap-4 p-2 rounded bg-slate-800/50">
                <span>{n.gateway_id}</span>
                <span className="text-slate-400">
                  {n.country ?? "—"} · {n.latency_ms != null ? `${n.latency_ms} ms` : "—"} ·{" "}
                  {n.healthy ? "healthy" : "unhealthy"}
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
