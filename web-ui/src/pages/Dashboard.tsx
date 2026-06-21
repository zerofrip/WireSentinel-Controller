import { useEffect, useState } from "react";
import { fetchMetrics, fetchKernelStatus, fetchKernelTelemetry, fetchMixnet, fetchMixnetHealth, type KernelStatusSummary, type KernelTelemetrySummary, type MixnetHealthSummary, type MixnetInventorySummary } from "../api";

export function DashboardPage() {
  const [metrics, setMetrics] = useState<Record<string, number> | null>(null);
  const [mixnet, setMixnet] = useState<MixnetInventorySummary | null>(null);
  const [mixnetHealth, setMixnetHealth] = useState<MixnetHealthSummary | null>(null);
  const [kernelStatus, setKernelStatus] = useState<KernelStatusSummary | null>(null);
  const [kernelTelemetry, setKernelTelemetry] = useState<KernelTelemetrySummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      fetchMetrics(),
      fetchMixnet().catch(() => null),
      fetchMixnetHealth().catch(() => null),
      fetchKernelStatus().catch(() => null),
      fetchKernelTelemetry().catch(() => null),
    ])
      .then(([m, inv, health, kernel, telemetry]) => {
        setMetrics(m);
        setMixnet(inv);
        setMixnetHealth(health);
        setKernelStatus(kernel);
        setKernelTelemetry(telemetry);
      })
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!metrics) return <p>Loading metrics…</p>;

  const cards = [
    ["Active devices", metrics.devices_active],
    ["Pending devices", metrics.devices_pending],
    ["Active policies", metrics.policies_active],
    ["Audit events", metrics.audit_events_total],
    ["Uptime (s)", metrics.uptime_seconds],
  ];

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Dashboard</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        {cards.map(([label, value]) => (
          <div key={label} className="rounded-lg border border-slate-800 bg-slate-900 p-4">
            <div className="text-sm text-slate-400">{label}</div>
            <div className="text-3xl font-bold mt-2">{value ?? 0}</div>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <div className="text-sm text-slate-400">Mixnet status</div>
          <div className="text-2xl font-bold mt-2">
            {mixnet ? `${mixnet.active_route_count} active routes` : "—"}
          </div>
          <p className="text-xs text-slate-500 mt-1">
            {mixnet
              ? `${mixnet.node_count} nodes · ${mixnet.devices_reporting} device(s) reporting`
              : "No mixnet data"}
          </p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <div className="text-sm text-slate-400">Mixnet health</div>
          <div className="text-2xl font-bold mt-2">
            {mixnetHealth ? `${mixnetHealth.connected_devices} connected` : "—"}
          </div>
          <p className="text-xs text-slate-500 mt-1">
            {mixnetHealth
              ? `${mixnetHealth.healthy_devices} healthy · ${mixnetHealth.stub_devices} stub`
              : "No health snapshots"}
          </p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <div className="text-sm text-slate-400">Kernel guardian</div>
          <div className="text-2xl font-bold mt-2">
            {kernelStatus ? `${kernelStatus.healthy_devices} healthy` : "—"}
          </div>
          <p className="text-xs text-slate-500 mt-1">
            {kernelStatus
              ? `${kernelStatus.kernel_devices} kernel · ${kernelStatus.ndis_devices} NDIS`
              : "No kernel data"}
          </p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <div className="text-sm text-slate-400">Kernel flows</div>
          <div className="text-2xl font-bold mt-2">
            {kernelStatus ? kernelStatus.total_active_routes : "—"}
          </div>
          <p className="text-xs text-slate-500 mt-1">active kernel routes</p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <div className="text-sm text-slate-400">Kernel latency</div>
          <div className="text-2xl font-bold mt-2">
            {kernelTelemetry ? `${kernelTelemetry.avg_classify_latency_ns} ns` : "—"}
          </div>
          <p className="text-xs text-slate-500 mt-1">
            max {kernelTelemetry?.max_classify_latency_ns ?? "—"} ns
          </p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <div className="text-sm text-slate-400">Packet rate</div>
          <div className="text-2xl font-bold mt-2">
            {kernelTelemetry ? kernelTelemetry.packets_per_sec : "—"}
          </div>
          <p className="text-xs text-slate-500 mt-1">packets/s aggregated</p>
        </div>
      </div>
    </div>
  );
}
