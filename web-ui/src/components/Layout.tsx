import { NavLink, Outlet } from "react-router-dom";
import { clearToken } from "../api";

const links = [
  { to: "/", label: "Dashboard" },
  { to: "/devices", label: "Devices" },
  { to: "/policies", label: "Policies" },
  { to: "/audit", label: "Audit" },
  { to: "/health", label: "Health" },
  { to: "/updates", label: "Updates" },
  { to: "/mixnet", label: "Mixnet" },
  { to: "/anonymous-routes", label: "Anonymous Routes" },
  { to: "/cover-traffic", label: "Cover Traffic" },
  { to: "/privacy-analytics", label: "Privacy Analytics" },
  { to: "/kernel", label: "Kernel Fleet" },
  { to: "/kernel/health", label: "Kernel Health" },
  { to: "/kernel/telemetry", label: "Kernel Telemetry" },
  { to: "/anonymity", label: "Anonymity" },
  { to: "/anonymity/federation", label: "Federation" },
  { to: "/anonymity/entropy", label: "Entropy" },
  { to: "/ztna", label: "ZTNA" },
  { to: "/ztna/resources", label: "ZTNA Resources" },
  { to: "/ztna/trust", label: "ZTNA Trust" },
  { to: "/ztna/segments", label: "ZTNA Segments" },
  { to: "/sse/swg", label: "SSE SWG" },
  { to: "/sse/casb", label: "SSE CASB" },
  { to: "/sse/dlp", label: "SSE DLP" },
  { to: "/sse/threats", label: "SSE Threats" },
  { to: "/sse/risk", label: "SSE Risk" },
  { to: "/sse/ueba", label: "SSE UEBA" },
  { to: "/xdr/incidents", label: "XDR Incidents" },
  { to: "/xdr/cases", label: "XDR Cases" },
  { to: "/xdr/hunts", label: "XDR Hunts" },
  { to: "/xdr/detections", label: "XDR Detections" },
  { to: "/xdr/attack-graph", label: "XDR Attack Graph" },
  { to: "/xdr/mitre", label: "XDR MITRE" },
  { to: "/xdr/soar", label: "XDR SOAR" },
  { to: "/cnapp/posture", label: "CNAPP Posture" },
  { to: "/cnapp/workloads", label: "CNAPP Workloads" },
  { to: "/cnapp/kubernetes", label: "CNAPP Kubernetes" },
  { to: "/cnapp/containers", label: "CNAPP Containers" },
  { to: "/cnapp/iac", label: "CNAPP IaC" },
  { to: "/cnapp/secrets", label: "CNAPP Secrets" },
  { to: "/cnapp/supply-chain", label: "CNAPP Supply Chain" },
  { to: "/cnapp/sbom", label: "CNAPP SBOM" },
  { to: "/cnapp/vulnerabilities", label: "CNAPP Vulnerabilities" },
  { to: "/cnapp/compliance", label: "CNAPP Compliance" },
  { to: "/cnapp/attack-paths", label: "CNAPP Attack Paths" },
  { to: "/ai/copilot", label: "AI Copilot" },
  { to: "/ai/investigations", label: "AI Investigations" },
  { to: "/ai/threats", label: "AI Threats" },
  { to: "/ai/knowledge-graph", label: "AI Knowledge Graph" },
  { to: "/ai/detections", label: "AI Detections" },
  { to: "/ai/playbooks", label: "AI Playbooks" },
  { to: "/ai/policies", label: "AI Policies" },
  { to: "/ai/intelligence", label: "AI Intelligence" },
  { to: "/ai/reports", label: "AI Reports" },
  { to: "/ai/risk", label: "AI Risk" },
  { to: "/tcp/session-control", label: "TCP Session Control" },
  { to: "/tcp/reconnect-policies", label: "TCP Reconnect Policies" },
  { to: "/split-templates", label: "Split Tunnel Templates" },
];

export function Layout() {
  return (
    <div className="min-h-screen flex">
      <aside className="w-56 bg-slate-900 border-r border-slate-800 p-4 flex flex-col gap-2">
        <div className="text-lg font-semibold mb-4">WireSentinel Controller</div>
        {links.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            end={l.to === "/"}
            className={({ isActive }) =>
              `rounded px-3 py-2 text-sm ${isActive ? "bg-cyan-900 text-cyan-100" : "hover:bg-slate-800"}`
            }
          >
            {l.label}
          </NavLink>
        ))}
        <button
          className="mt-auto text-left text-sm text-slate-400 hover:text-white"
          onClick={() => {
            clearToken();
            window.location.href = "/login";
          }}
        >
          Sign out
        </button>
      </aside>
      <main className="flex-1 p-8">
        <Outlet />
      </main>
    </div>
  );
}
