const TOKEN_KEY = "ws_controller_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const resp = await fetch(path, { ...init, headers });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(body || resp.statusText);
  }
  if (resp.status === 204) return undefined as T;
  return resp.json() as Promise<T>;
}

export async function login(username: string, password: string) {
  return apiFetch<{ token: string; username: string; role: string }>(
    "/api/v1/auth/login",
    {
      method: "POST",
      body: JSON.stringify({ username, password }),
    },
  );
}

export async function fetchDevices() {
  return apiFetch<Array<Record<string, unknown>>>("/api/v1/devices");
}

export async function fetchPolicies() {
  return apiFetch<Array<Record<string, unknown>>>("/api/v1/policies");
}

export async function fetchAudit() {
  return apiFetch<Array<Record<string, unknown>>>("/api/v1/audit?limit=50");
}

export async function fetchMetrics() {
  return apiFetch<Record<string, number>>("/api/v1/metrics");
}

export async function fetchHealth() {
  return apiFetch<{ status: string; service: string }>("/health");
}

export interface MixnetNodeRecord {
  id: string;
  device_id: string;
  node_id: string;
  gateway_id: string;
  country?: string | null;
  latency_ms?: number | null;
  healthy: boolean;
  last_seen_at: string;
}

export interface MixnetRouteRecord {
  id: string;
  device_id: string;
  route_id: string;
  label: string;
  hops: string[];
  socks_port?: number | null;
  cover_traffic_profile?: string | null;
  active: boolean;
  last_seen_at: string;
}

export interface MixnetInventorySummary {
  node_count: number;
  route_count: number;
  active_route_count: number;
  devices_reporting: number;
  nodes: MixnetNodeRecord[];
}

export interface MixnetHealthSnapshot {
  id: string;
  device_id: string;
  mixnet_connected: boolean;
  stub_mode: boolean;
  healthy: boolean;
  active_route_count: number;
  cover_traffic_profile?: string | null;
  reported_at: string;
}

export interface MixnetHealthSummary {
  connected_devices: number;
  healthy_devices: number;
  stub_devices: number;
  total_active_routes: number;
  snapshots: MixnetHealthSnapshot[];
}

export async function fetchMixnet() {
  return apiFetch<MixnetInventorySummary>("/api/v1/mixnet");
}

export async function fetchMixnetRoutes() {
  return apiFetch<MixnetRouteRecord[]>("/api/v1/mixnet/routes");
}

export async function fetchMixnetHealth() {
  return apiFetch<MixnetHealthSummary>("/api/v1/mixnet/health");
}

export interface KernelSnapshot {
  id: string;
  device_id: string;
  guardian_mode: string;
  driver_connected: boolean;
  lifecycle_state: string;
  kill_switch_mode?: string | null;
  stub_mode: boolean;
  wfp_engine: string;
  ndis_enabled: boolean;
  healthy: boolean;
  filter_count: number;
  callouts_registered: number;
  active_route_count: number;
  reported_at: string;
}

export interface KernelStatusSummary {
  reporting_devices: number;
  healthy_devices: number;
  kernel_devices: number;
  ndis_devices: number;
  stub_devices: number;
  total_active_routes: number;
  snapshots: KernelSnapshot[];
}

export interface KernelTelemetrySummary {
  classify_count: number;
  block_count: number;
  route_count: number;
  permit_count: number;
  observe_count: number;
  error_count: number;
  avg_classify_latency_ns: number;
  max_classify_latency_ns: number;
  packets_per_sec: number;
  snapshots: KernelSnapshot[];
}

export interface KernelRouteRecord {
  id: string;
  device_id: string;
  route_id: string;
  app_id: string;
  route_kind: string;
  profile_id?: number | null;
  label?: string | null;
  active: boolean;
  last_seen_at: string;
}

export async function fetchKernelStatus() {
  return apiFetch<KernelStatusSummary>("/api/v1/kernel/status");
}

export async function fetchKernelTelemetry() {
  return apiFetch<KernelTelemetrySummary>("/api/v1/kernel/telemetry");
}

export async function fetchKernelRoutes() {
  return apiFetch<KernelRouteRecord[]>("/api/v1/kernel/routes");
}

export interface AnonymityRouteRecord {
  id: string;
  device_id: string;
  route_id: string;
  label: string;
  hops: string[];
  chain_kind?: string | null;
  entropy_score?: number | null;
  active: boolean;
  last_seen_at: string;
}

export interface FederationPeerSummary {
  peer_id: string;
  region?: string | null;
  healthy: boolean;
}

export interface FederationSummary {
  total_peers: number;
  healthy_peers: number;
  devices_with_federation: number;
  peers: FederationPeerSummary[];
}

export interface EntropySummary {
  avg_entropy_bits: number;
  avg_route_entropy: number;
  avg_path_diversity: number;
  devices_reporting: number;
}

export interface AnonymitySnapshot {
  id: string;
  device_id: string;
  anonymity_connected: boolean;
  stub_mode: boolean;
  healthy: boolean;
  anonymity_score: number;
  route_entropy: number;
  path_diversity: number;
  cover_traffic_effectiveness: number;
  federation_peer_count: number;
  entropy_bits: number;
  active_route_count: number;
  reported_at: string;
}

export interface AnonymityHealthSummary {
  connected_devices: number;
  healthy_devices: number;
  stub_devices: number;
  total_active_routes: number;
  avg_anonymity_score: number;
  federation: FederationSummary;
  entropy: EntropySummary;
  snapshots: AnonymitySnapshot[];
}

export interface AnonymityAnalyticsRollup {
  id: string;
  devices_reporting: number;
  avg_anonymity_score: number;
  avg_route_entropy: number;
  avg_path_diversity: number;
  avg_cover_traffic_effectiveness: number;
  federation_peers_total: number;
  avg_entropy_bits: number;
  rolled_up_at: string;
}

export interface AnonymityAnalyticsSummary {
  devices_reporting: number;
  avg_anonymity_score: number;
  avg_route_entropy: number;
  avg_path_diversity: number;
  avg_cover_traffic_effectiveness: number;
  federation_peers_total: number;
  avg_entropy_bits: number;
  rollups: AnonymityAnalyticsRollup[];
}

export async function fetchAnonymity() {
  return apiFetch<AnonymityHealthSummary>("/api/v1/anonymity");
}

export async function fetchAnonymityRoutes() {
  return apiFetch<AnonymityRouteRecord[]>("/api/v1/anonymity/routes");
}

export async function fetchAnonymityAnalytics() {
  return apiFetch<AnonymityAnalyticsSummary>("/api/v1/anonymity/analytics");
}

export interface ZtnaPolicyRecord {
  id: string;
  name: string;
  enabled: boolean;
  min_trust_level: string;
  min_trust_score: number;
  default_action: string;
}

export interface PublishedResourceRecord {
  id: string;
  name: string;
  resource_type: string;
  host: string;
  port: number;
  path_prefix?: string | null;
  published: boolean;
}

export interface DeviceTrustRecord {
  id: string;
  device_id: string;
  trust_level: string;
  trust_score: number;
  last_evaluated_at: string;
}

export interface ZtnaHeartbeatSnapshot {
  id: string;
  device_id: string;
  avg_trust_score: number;
  gateway_active: boolean;
  connector_count: number;
}

export interface ZtnaAnalyticsSummary {
  devices_reporting: number;
  avg_trust_score: number;
  total_connectors: number;
  healthy_connectors: number;
  total_denials: number;
  published_resources: number;
  gateway_active_devices: number;
  snapshots: ZtnaHeartbeatSnapshot[];
}

export interface ZtnaDashboardSummary {
  policy_count: number;
  published_resource_count: number;
  trusted_devices: number;
  connector_count: number;
  analytics: ZtnaAnalyticsSummary;
}

export async function fetchZtnaDashboard() {
  return apiFetch<ZtnaDashboardSummary>("/api/v1/ztna");
}

export async function fetchZtnaPolicies() {
  return apiFetch<ZtnaPolicyRecord[]>("/api/v1/ztna/policies");
}

export async function fetchZtnaResources() {
  return apiFetch<PublishedResourceRecord[]>("/api/v1/ztna/resources");
}

export async function fetchZtnaTrust() {
  return apiFetch<DeviceTrustRecord[]>("/api/v1/ztna/trust");
}

export async function fetchZtnaAnalytics() {
  return apiFetch<ZtnaAnalyticsSummary>("/api/v1/ztna/analytics");
}

export interface SseThreatMatch {
  id: string;
  device_id: string;
  threat_kind: string;
  category: string;
  url?: string | null;
  signature?: string | null;
  severity: string;
  action: string;
  matched_at: string;
}

export interface SseIncident {
  id: string;
  device_id: string;
  incident_kind: string;
  severity: string;
  title: string;
  description?: string | null;
  resource?: string | null;
  action_taken: string;
  status: string;
  detected_at: string;
}

export interface SwgSummary {
  policy_count: number;
  total_requests: number;
  blocked_count: number;
  allowed_count: number;
  threat_match_count: number;
  reporting_devices: number;
  recent_threats: SseThreatMatch[];
}

export interface CasbSummary {
  incident_count: number;
  open_incidents: number;
  blocked_actions: number;
  incidents: SseIncident[];
}

export interface DlpSummary {
  incident_count: number;
  open_incidents: number;
  blocked_actions: number;
  incidents: SseIncident[];
}

export interface SseRiskScore {
  id: string;
  device_id: string;
  risk_score: number;
  risk_level: string;
  evaluated_at: string;
}

export interface RiskSummary {
  devices_scored: number;
  avg_risk_score: number;
  high_risk_devices: number;
  scores: SseRiskScore[];
}

export interface SseUebaAnomaly {
  id: string;
  device_id: string;
  user_id?: string | null;
  anomaly_kind: string;
  score: number;
  description: string;
  detected_at: string;
}

export interface UebaSummary {
  anomaly_count: number;
  avg_anomaly_score: number;
  alerting_devices: number;
  anomalies: SseUebaAnomaly[];
}

export async function fetchSseSwg() {
  return apiFetch<SwgSummary>("/api/v1/sse/swg");
}

export async function fetchSseCasb() {
  return apiFetch<CasbSummary>("/api/v1/sse/casb");
}

export async function fetchSseDlp() {
  return apiFetch<DlpSummary>("/api/v1/sse/dlp");
}

export async function fetchSseRisk() {
  return apiFetch<RiskSummary>("/api/v1/sse/risk");
}

export async function fetchSseUeba() {
  return apiFetch<UebaSummary>("/api/v1/sse/ueba");
}

export interface XdrIncident {
  id: string;
  device_id?: string | null;
  title: string;
  severity: string;
  status: string;
  detected_at: string;
}

export interface IncidentsSummary {
  incident_count: number;
  open_incidents: number;
  high_severity: number;
  incidents: XdrIncident[];
}

export interface XdrCase {
  id: string;
  title: string;
  status: string;
  priority: string;
  assignee?: string | null;
  opened_at: string;
}

export interface CasesSummary {
  case_count: number;
  open_cases: number;
  cases: XdrCase[];
}

export interface XdrDetection {
  id: string;
  device_id?: string | null;
  title: string;
  severity: string;
  status: string;
  confidence: number;
  detected_at: string;
}

export interface DetectionsSummary {
  detection_count: number;
  new_detections: number;
  rule_count: number;
  detections: XdrDetection[];
}

export interface XdrHunt {
  id: string;
  name: string;
  status: string;
  query_kind: string;
  owner?: string | null;
}

export interface HuntsSummary {
  hunt_count: number;
  active_hunts: number;
  result_count: number;
  hunts: XdrHunt[];
}

export interface XdrAttackGraphNode {
  id: string;
  node_kind: string;
  label: string;
}

export interface XdrAttackGraphEdge {
  id: string;
  source_node_id: string;
  target_node_id: string;
  edge_kind: string;
}

export interface AttackGraphSummary {
  node_count: number;
  edge_count: number;
  nodes: XdrAttackGraphNode[];
  edges: XdrAttackGraphEdge[];
}

export interface XdrMitreTechnique {
  id: string;
  technique_id: string;
  name: string;
  tactic: string;
}

export interface MitreSummary {
  technique_count: number;
  mapping_count: number;
  techniques: XdrMitreTechnique[];
}

export interface XdrPlaybook {
  id: string;
  name: string;
  playbook_kind: string;
  enabled: boolean;
}

export interface SoarSummary {
  playbook_count: number;
  enabled_playbooks: number;
  execution_count: number;
  playbooks: XdrPlaybook[];
}

export async function fetchXdrIncidents() {
  return apiFetch<IncidentsSummary>("/api/v1/xdr/incidents");
}

export async function fetchXdrCases() {
  return apiFetch<CasesSummary>("/api/v1/xdr/cases");
}

export async function fetchXdrDetections() {
  return apiFetch<DetectionsSummary>("/api/v1/xdr/detections");
}

export async function fetchXdrHunts() {
  return apiFetch<HuntsSummary>("/api/v1/xdr/hunts");
}

export async function fetchXdrAttackGraph() {
  return apiFetch<AttackGraphSummary>("/api/v1/xdr/attack-graph");
}

export async function fetchXdrMitre() {
  return apiFetch<MitreSummary>("/api/v1/xdr/mitre");
}

export async function fetchXdrSoar() {
  return apiFetch<SoarSummary>("/api/v1/xdr/soar/playbooks");
}

export interface PostureSummary {
  finding_count: number;
  open_findings: number;
  high_severity: number;
  resource_count: number;
  avg_risk_score: number;
  findings: { id: string; title: string; severity: string; status: string; framework?: string | null }[];
  resources: { id: string; name: string; resource_type: string; risk_score: number }[];
  risk_scores: { id: string; risk_score: number; risk_level: string }[];
}

export interface WorkloadsSummary {
  workload_count: number;
  active_workloads: number;
  threat_count: number;
  open_threats: number;
  workloads: { id: string; name: string; workload_kind: string; namespace?: string | null; status: string }[];
  threats: { id: string; title: string; severity: string; status: string }[];
}

export interface KubernetesSummary {
  cluster_count: number;
  resource_count: number;
  finding_count: number;
  open_findings: number;
  clusters: { id: string; name: string; provider: string; status: string; node_count: number }[];
  resources: { id: string; name: string; resource_kind: string; namespace?: string | null }[];
  findings: { id: string; title: string; severity: string; status: string }[];
}

export interface ContainersSummary {
  image_count: number;
  scanned_images: number;
  finding_count: number;
  critical_findings: number;
  images: { id: string; repository: string; tag?: string | null; scan_status: string }[];
  findings: { id: string; title: string; severity: string; cve_id?: string | null }[];
}

export interface IacSummary {
  scan_count: number;
  finding_count: number;
  open_findings: number;
  scans: { id: string; scan_kind: string; repository?: string | null; status: string }[];
  findings: { id: string; title: string; severity: string; file_path?: string | null }[];
}

export interface SecretsSummary {
  finding_count: number;
  open_findings: number;
  high_severity: number;
  findings: { id: string; secret_kind: string; severity: string; file_path?: string | null; source?: string | null }[];
}

export interface SupplyChainSummary {
  dependency_count: number;
  direct_dependencies: number;
  threat_count: number;
  open_threats: number;
  dependencies: { id: string; package_name: string; ecosystem: string; version?: string | null }[];
  threats: { id: string; title: string; threat_kind: string; severity: string }[];
}

export interface SbomSummary {
  document_count: number;
  component_count: number;
  documents: { id: string; name: string; format: string; component_count: number }[];
  components: { id: string; name: string; version?: string | null; kind: string }[];
}

export interface VulnerabilitiesSummary {
  vulnerability_count: number;
  critical_count: number;
  affected_asset_count: number;
  remediation_count: number;
  vulnerabilities: { id: string; cve_id: string; title: string; severity: string; score?: number | null }[];
  affected_assets: { id: string; asset_ref: string; asset_kind: string; status: string }[];
  remediation_plans: { id: string; title: string; plan_kind: string; priority: string }[];
}

export interface ComplianceSummary {
  control_count: number;
  violation_count: number;
  open_violations: number;
  avg_score: number;
  controls: { id: string; framework: string; control_id: string; title: string }[];
  scores: { id: string; framework: string; score: number }[];
  violations: { id: string; title: string; severity: string; status: string }[];
}

export interface AttackPathsSummary {
  path_count: number;
  open_paths: number;
  node_count: number;
  edge_count: number;
  paths: { id: string; name: string; severity: string; entry_asset?: string | null; target_asset?: string | null }[];
  nodes: { id: string; label: string; node_kind: string }[];
  edges: { id: string; source_node_id: string; target_node_id: string; edge_kind: string }[];
}

export async function fetchCnappPosture() {
  return apiFetch<PostureSummary>("/api/v1/cnapp/posture");
}

export async function fetchCnappWorkloads() {
  return apiFetch<WorkloadsSummary>("/api/v1/cnapp/workloads");
}

export async function fetchCnappKubernetes() {
  return apiFetch<KubernetesSummary>("/api/v1/cnapp/kubernetes");
}

export async function fetchCnappContainers() {
  return apiFetch<ContainersSummary>("/api/v1/cnapp/containers");
}

export async function fetchCnappIac() {
  return apiFetch<IacSummary>("/api/v1/cnapp/iac");
}

export async function fetchCnappSecrets() {
  return apiFetch<SecretsSummary>("/api/v1/cnapp/secrets");
}

export async function fetchCnappSupplyChain() {
  return apiFetch<SupplyChainSummary>("/api/v1/cnapp/supply-chain");
}

export async function fetchCnappSbom() {
  return apiFetch<SbomSummary>("/api/v1/cnapp/sbom");
}

export async function fetchCnappVulnerabilities() {
  return apiFetch<VulnerabilitiesSummary>("/api/v1/cnapp/vulnerabilities");
}

export async function fetchCnappCompliance() {
  return apiFetch<ComplianceSummary>("/api/v1/cnapp/compliance");
}

export async function fetchCnappAttackPaths() {
  return apiFetch<AttackPathsSummary>("/api/v1/cnapp/attack-paths");
}

export interface InvestigationsSummary {
  investigation_count: number;
  open_investigations: number;
  high_severity: number;
  investigations: { id: string; title: string; status: string; severity: string; priority: string }[];
}

export interface ThreatsSummary {
  threat_count: number;
  open_threats: number;
  high_confidence: number;
  threats: { id: string; title: string; severity: string; status: string; confidence: number }[];
}

export interface KnowledgeGraphSummary {
  node_count: number;
  edge_count: number;
  nodes: { id: string; label: string; node_kind: string; entity_ref?: string | null }[];
  edges: { id: string; source_node_id: string; target_node_id: string; edge_kind: string; label?: string | null }[];
}

export interface ReportsSummary {
  intel_count: number;
  executive_count: number;
  intel_reports: { id: string; title: string; report_kind: string; summary?: string | null }[];
  executive_reports: { id: string; title: string; report_kind: string; summary?: string | null }[];
}

export interface AiRiskSummary {
  score_count: number;
  avg_risk_score: number;
  high_risk_count: number;
  scores: { id: string; scope_kind: string; risk_score: number; risk_level: string }[];
}

export interface AiDetectionsSummary {
  suggestion_count: number;
  pending_suggestions: number;
  suggestions: { id: string; rule_title: string; rule_logic: string; severity: string; confidence: number; status: string }[];
}

export interface PlaybooksSummary {
  suggestion_count: number;
  pending_suggestions: number;
  suggestions: { id: string; name: string; playbook_kind: string; status: string }[];
}

export interface PoliciesSummary {
  suggestion_count: number;
  pending_suggestions: number;
  suggestions: { id: string; title: string; policy_kind: string; status: string; rationale?: string | null }[];
}

export interface IntelligenceSummary {
  report_count: number;
  reports: { id: string; title: string; report_kind: string; summary?: string | null }[];
}

export interface CopilotQueryResult {
  query: { id: string; query_text: string; status: string };
  response: { id: string; response_text: string; model_id: string; latency_ms: number };
}

export async function postAiCopilotQuery(query_text: string) {
  return apiFetch<CopilotQueryResult>("/api/v1/ai/copilot/query", {
    method: "POST",
    body: JSON.stringify({ query_text }),
  });
}

export async function fetchAiInvestigations() {
  return apiFetch<InvestigationsSummary>("/api/v1/ai/investigations");
}

export async function fetchAiThreats() {
  return apiFetch<ThreatsSummary>("/api/v1/ai/threats");
}

export async function fetchAiKnowledgeGraph() {
  return apiFetch<KnowledgeGraphSummary>("/api/v1/ai/knowledge-graph");
}

export async function fetchAiReports() {
  return apiFetch<ReportsSummary>("/api/v1/ai/reports");
}

export async function fetchAiRisk() {
  return apiFetch<AiRiskSummary>("/api/v1/ai/risk");
}

export async function fetchAiDetections() {
  return apiFetch<AiDetectionsSummary>("/api/v1/ai/detections");
}

export async function fetchAiPlaybooks() {
  return apiFetch<PlaybooksSummary>("/api/v1/ai/playbooks");
}

export async function fetchAiPolicies() {
  return apiFetch<PoliciesSummary>("/api/v1/ai/policies");
}

export async function fetchAiIntelligence() {
  return apiFetch<IntelligenceSummary>("/api/v1/ai/intelligence");
}

export async function generateAiDetection(context: string) {
  return apiFetch<AiDetectionsSummary["suggestions"][0]>("/api/v1/ai/detections/generate", {
    method: "POST",
    body: JSON.stringify({ context }),
  });
}

export async function generateAiPlaybook(context: string) {
  return apiFetch<PlaybooksSummary["suggestions"][0]>("/api/v1/ai/playbooks/generate", {
    method: "POST",
    body: JSON.stringify({ context }),
  });
}

export async function generateAiPolicy(context: string) {
  return apiFetch<PoliciesSummary["suggestions"][0]>("/api/v1/ai/policies/generate", {
    method: "POST",
    body: JSON.stringify({ context }),
  });
}

export interface TcpTerminationSettings {
  mode: string;
  updated_at: string;
}

export interface TcpTerminationRule {
  id: string;
  process_path?: string | null;
  process_name?: string | null;
  profile_id?: string | null;
  route?: Record<string, unknown> | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface TcpTerminationRulesSummary {
  rule_count: number;
  enabled_count: number;
  rules: TcpTerminationRule[];
}

export async function fetchTcpTerminationSettings() {
  return apiFetch<TcpTerminationSettings>("/api/v1/tcp-termination/settings");
}

export async function updateTcpTerminationSettings(mode: string) {
  return apiFetch<TcpTerminationSettings>("/api/v1/tcp-termination/settings", {
    method: "PUT",
    body: JSON.stringify({ mode }),
  });
}

export async function fetchTcpTerminationRules() {
  return apiFetch<TcpTerminationRulesSummary>("/api/v1/tcp-termination/rules");
}

export async function createTcpTerminationRule(body: {
  process_path?: string;
  process_name?: string;
  profile_id?: string;
  route?: Record<string, unknown>;
  enabled?: boolean;
}) {
  return apiFetch<TcpTerminationRule>("/api/v1/tcp-termination/rules", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function updateTcpTerminationRule(
  id: string,
  body: Partial<{
    process_path: string | null;
    process_name: string | null;
    profile_id: string | null;
    route: Record<string, unknown> | null;
    enabled: boolean;
  }>,
) {
  return apiFetch<TcpTerminationRule>(`/api/v1/tcp-termination/rules/${id}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

export async function deleteTcpTerminationRule(id: string) {
  return apiFetch<void>(`/api/v1/tcp-termination/rules/${id}`, { method: "DELETE" });
}

export interface SplitTunnelTemplate {
  id: string;
  name: string;
  description: string;
  default_route: Record<string, unknown>;
  app_rules: Array<Record<string, unknown>>;
  domain_rules: Array<Record<string, unknown>>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface SplitTemplateModeSettings {
  mode: string;
  active_template_id?: string | null;
  updated_at: string;
}

export interface SplitTemplatesSummary {
  template_count: number;
  enabled_count: number;
  templates: SplitTunnelTemplate[];
  mode: SplitTemplateModeSettings;
}

export async function fetchSplitTemplates() {
  return apiFetch<SplitTemplatesSummary>("/api/v1/split-templates");
}

export async function createSplitTemplate(body: {
  name: string;
  description?: string;
  default_route: Record<string, unknown>;
  enabled?: boolean;
}) {
  return apiFetch<SplitTunnelTemplate>("/api/v1/split-templates", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function updateSplitTemplateMode(body: {
  mode: string;
  active_template_id?: string | null;
}) {
  return apiFetch<SplitTemplateModeSettings>("/api/v1/split-templates/mode", {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

export async function deleteSplitTemplate(id: string) {
  return apiFetch<void>(`/api/v1/split-templates/${id}`, { method: "DELETE" });
}

