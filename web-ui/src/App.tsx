import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { getToken } from "./api";
import { AuditPage } from "./pages/Audit";
import { DashboardPage } from "./pages/Dashboard";
import { DevicesPage } from "./pages/Devices";
import { HealthPage } from "./pages/Health";
import { LoginPage } from "./pages/Login";
import { PoliciesPage } from "./pages/Policies";
import { UpdatesPage } from "./pages/Updates";
import { MixnetPage } from "./pages/Mixnet";
import { AnonymousRoutesPage } from "./pages/AnonymousRoutes";
import { CoverTrafficPage } from "./pages/CoverTraffic";
import { PrivacyAnalyticsPage } from "./pages/PrivacyAnalytics";
import { KernelFleetPage } from "./pages/KernelFleet";
import { KernelHealthPage } from "./pages/KernelHealth";
import { KernelTelemetryPage } from "./pages/KernelTelemetry";
import { AnonymityDashboardPage } from "./pages/AnonymityDashboard";
import { FederationViewPage } from "./pages/FederationView";
import { EntropyViewPage } from "./pages/EntropyView";
import { ZtnaDashboardPage } from "./pages/ZtnaDashboard";
import { ZtnaResourcesPage } from "./pages/ZtnaResources";
import { ZtnaTrustPage } from "./pages/ZtnaTrust";
import { ZtnaSegmentsPage } from "./pages/ZtnaSegments";
import { SseSwgPage } from "./pages/SseSwg";
import { SseCasbPage } from "./pages/SseCasb";
import { SseDlpPage } from "./pages/SseDlp";
import { SseThreatsPage } from "./pages/SseThreats";
import { SseRiskPage } from "./pages/SseRisk";
import { SseUebaPage } from "./pages/SseUeba";
import { XdrIncidentsPage } from "./pages/XdrIncidents";
import { XdrCasesPage } from "./pages/XdrCases";
import { XdrHuntsPage } from "./pages/XdrHunts";
import { XdrDetectionsPage } from "./pages/XdrDetections";
import { XdrAttackGraphPage } from "./pages/XdrAttackGraph";
import { XdrMitrePage } from "./pages/XdrMitre";
import { XdrSoarPage } from "./pages/XdrSoar";
import { CnappPosturePage } from "./pages/CnappPosture";
import { CnappWorkloadsPage } from "./pages/CnappWorkloads";
import { CnappKubernetesPage } from "./pages/CnappKubernetes";
import { CnappContainersPage } from "./pages/CnappContainers";
import { CnappIacPage } from "./pages/CnappIac";
import { CnappSecretsPage } from "./pages/CnappSecrets";
import { CnappSupplyChainPage } from "./pages/CnappSupplyChain";
import { CnappSbomPage } from "./pages/CnappSbom";
import { CnappVulnerabilitiesPage } from "./pages/CnappVulnerabilities";
import { CnappCompliancePage } from "./pages/CnappCompliance";
import { CnappAttackPathsPage } from "./pages/CnappAttackPaths";
import { AiCopilotPage } from "./pages/AiCopilot";
import { AiInvestigationsPage } from "./pages/AiInvestigations";
import { AiThreatsPage } from "./pages/AiThreats";
import { AiKnowledgeGraphPage } from "./pages/AiKnowledgeGraph";
import { AiDetectionsPage } from "./pages/AiDetections";
import { AiPlaybooksPage } from "./pages/AiPlaybooks";
import { AiPoliciesPage } from "./pages/AiPolicies";
import { AiIntelligencePage } from "./pages/AiIntelligence";
import { AiReportsPage } from "./pages/AiReports";
import { AiRiskPage } from "./pages/AiRisk";
import { TcpSessionControlPage } from "./pages/TcpSessionControl";
import { TcpReconnectPoliciesPage } from "./pages/TcpReconnectPolicies";
import { SplitTunnelTemplatesPage } from "./pages/SplitTunnelTemplates";

function RequireAuth({ children }: { children: React.ReactNode }) {
  if (!getToken()) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route index element={<DashboardPage />} />
          <Route path="devices" element={<DevicesPage />} />
          <Route path="policies" element={<PoliciesPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="health" element={<HealthPage />} />
          <Route path="updates" element={<UpdatesPage />} />
          <Route path="mixnet" element={<MixnetPage />} />
          <Route path="anonymous-routes" element={<AnonymousRoutesPage />} />
          <Route path="cover-traffic" element={<CoverTrafficPage />} />
          <Route path="privacy-analytics" element={<PrivacyAnalyticsPage />} />
          <Route path="kernel" element={<KernelFleetPage />} />
          <Route path="kernel/health" element={<KernelHealthPage />} />
          <Route path="kernel/telemetry" element={<KernelTelemetryPage />} />
          <Route path="anonymity" element={<AnonymityDashboardPage />} />
          <Route path="anonymity/federation" element={<FederationViewPage />} />
          <Route path="anonymity/entropy" element={<EntropyViewPage />} />
          <Route path="ztna" element={<ZtnaDashboardPage />} />
          <Route path="ztna/resources" element={<ZtnaResourcesPage />} />
          <Route path="ztna/trust" element={<ZtnaTrustPage />} />
          <Route path="ztna/segments" element={<ZtnaSegmentsPage />} />
          <Route path="sse/swg" element={<SseSwgPage />} />
          <Route path="sse/casb" element={<SseCasbPage />} />
          <Route path="sse/dlp" element={<SseDlpPage />} />
          <Route path="sse/threats" element={<SseThreatsPage />} />
          <Route path="sse/risk" element={<SseRiskPage />} />
          <Route path="sse/ueba" element={<SseUebaPage />} />
          <Route path="xdr/incidents" element={<XdrIncidentsPage />} />
          <Route path="xdr/cases" element={<XdrCasesPage />} />
          <Route path="xdr/hunts" element={<XdrHuntsPage />} />
          <Route path="xdr/detections" element={<XdrDetectionsPage />} />
          <Route path="xdr/attack-graph" element={<XdrAttackGraphPage />} />
          <Route path="xdr/mitre" element={<XdrMitrePage />} />
          <Route path="xdr/soar" element={<XdrSoarPage />} />
          <Route path="cnapp/posture" element={<CnappPosturePage />} />
          <Route path="cnapp/workloads" element={<CnappWorkloadsPage />} />
          <Route path="cnapp/kubernetes" element={<CnappKubernetesPage />} />
          <Route path="cnapp/containers" element={<CnappContainersPage />} />
          <Route path="cnapp/iac" element={<CnappIacPage />} />
          <Route path="cnapp/secrets" element={<CnappSecretsPage />} />
          <Route path="cnapp/supply-chain" element={<CnappSupplyChainPage />} />
          <Route path="cnapp/sbom" element={<CnappSbomPage />} />
          <Route path="cnapp/vulnerabilities" element={<CnappVulnerabilitiesPage />} />
          <Route path="cnapp/compliance" element={<CnappCompliancePage />} />
          <Route path="cnapp/attack-paths" element={<CnappAttackPathsPage />} />
          <Route path="ai/copilot" element={<AiCopilotPage />} />
          <Route path="ai/investigations" element={<AiInvestigationsPage />} />
          <Route path="ai/threats" element={<AiThreatsPage />} />
          <Route path="ai/knowledge-graph" element={<AiKnowledgeGraphPage />} />
          <Route path="ai/detections" element={<AiDetectionsPage />} />
          <Route path="ai/playbooks" element={<AiPlaybooksPage />} />
          <Route path="ai/policies" element={<AiPoliciesPage />} />
          <Route path="ai/intelligence" element={<AiIntelligencePage />} />
          <Route path="ai/reports" element={<AiReportsPage />} />
          <Route path="ai/risk" element={<AiRiskPage />} />
          <Route path="tcp/session-control" element={<TcpSessionControlPage />} />
          <Route path="tcp/reconnect-policies" element={<TcpReconnectPoliciesPage />} />
          <Route path="split-templates" element={<SplitTunnelTemplatesPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
