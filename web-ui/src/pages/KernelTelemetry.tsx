import { useEffect, useState } from "react";
import { fetchKernelTelemetry, type KernelTelemetrySummary } from "../api";

export function KernelTelemetryPage() {
  const [telemetry, setTelemetry] = useState<KernelTelemetrySummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchKernelTelemetry()
      .then(setTelemetry)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!telemetry) return <p>Loading kernel telemetry…</p>;

  const cards = [
    ["Classify", telemetry.classify_count],
    ["Block", telemetry.block_count],
    ["Route", telemetry.route_count],
    ["Permit", telemetry.permit_count],
    ["Observe", telemetry.observe_count],
    ["Errors", telemetry.error_count],
    ["Avg latency (ns)", telemetry.avg_classify_latency_ns],
    ["Max latency (ns)", telemetry.max_classify_latency_ns],
    ["Packets/s", telemetry.packets_per_sec],
  ] as const;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Kernel Telemetry</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {cards.map(([label, value]) => (
          <div key={label} className="rounded-lg border border-slate-800 bg-slate-900 p-4">
            <div className="text-sm text-slate-400">{label}</div>
            <div className="text-2xl font-bold mt-2">{value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
