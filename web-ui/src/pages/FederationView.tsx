import { useEffect, useState } from "react";
import { fetchAnonymity, type AnonymityHealthSummary } from "../api";

export function FederationViewPage() {
  const [health, setHealth] = useState<AnonymityHealthSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAnonymity()
      .then(setHealth)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!health) return <p>Loading federation view…</p>;

  const federation = health.federation;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Federation</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Stat label="Total peers" value={federation.total_peers} />
        <Stat label="Healthy peers" value={federation.healthy_peers} />
        <Stat label="Devices federated" value={federation.devices_with_federation} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Peers</h2>
        {federation.peers.length === 0 ? (
          <p className="text-sm text-slate-500">No federation peers reported</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {federation.peers.map((peer) => (
              <li key={peer.peer_id} className="flex justify-between p-2 rounded bg-slate-800/50">
                <span>{peer.peer_id}</span>
                <span className="text-slate-400">
                  {peer.region ?? "—"} · {peer.healthy ? "healthy" : "unhealthy"}
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
