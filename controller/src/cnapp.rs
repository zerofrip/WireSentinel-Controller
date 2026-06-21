use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! details_json {
    ($input:expr) => {
        $input
            .details
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "{}".into())
    };
}

// --- Records ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappPostureFindingRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub resource_id: Option<String>,
    pub finding_kind: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub status: String,
    pub framework: Option<String>,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappCloudResourceRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub provider: String,
    pub resource_type: String,
    pub name: String,
    pub region: Option<String>,
    pub risk_score: u8,
    pub status: String,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappRiskScoreRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub scope_kind: String,
    pub risk_score: u8,
    pub risk_level: String,
    pub evaluated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappWorkloadRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub workload_kind: String,
    pub name: String,
    pub namespace: Option<String>,
    pub status: String,
    pub image_ref: Option<String>,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappWorkloadThreatRecord {
    pub id: String,
    pub workload_id: Option<String>,
    pub device_id: Option<String>,
    pub threat_kind: String,
    pub severity: String,
    pub title: String,
    pub status: String,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappK8sClusterRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub name: String,
    pub provider: String,
    pub version: Option<String>,
    pub node_count: u32,
    pub status: String,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappK8sResourceRecord {
    pub id: String,
    pub cluster_id: String,
    pub resource_kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappK8sFindingRecord {
    pub id: String,
    pub cluster_id: Option<String>,
    pub finding_kind: String,
    pub severity: String,
    pub title: String,
    pub status: String,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappContainerImageRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
    pub scan_status: String,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappContainerFindingRecord {
    pub id: String,
    pub image_id: Option<String>,
    pub severity: String,
    pub title: String,
    pub cve_id: Option<String>,
    pub package_name: Option<String>,
    pub status: String,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappIacScanRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub scan_kind: String,
    pub repository: Option<String>,
    pub status: String,
    pub finding_count: u32,
    pub scanned_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappIacFindingRecord {
    pub id: String,
    pub scan_id: Option<String>,
    pub severity: String,
    pub title: String,
    pub file_path: Option<String>,
    pub rule_id: Option<String>,
    pub status: String,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappSecretFindingRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub secret_kind: String,
    pub severity: String,
    pub source: Option<String>,
    pub file_path: Option<String>,
    pub status: String,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappDependencyRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub ecosystem: String,
    pub package_name: String,
    pub version: Option<String>,
    pub direct: bool,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappSupplyChainThreatRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub threat_kind: String,
    pub severity: String,
    pub title: String,
    pub status: String,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappSbomDocumentRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub format: String,
    pub name: String,
    pub component_count: u32,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappSbomComponentRecord {
    pub id: String,
    pub document_id: String,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappVulnerabilityRecord {
    pub id: String,
    pub cve_id: String,
    pub severity: String,
    pub score: Option<f64>,
    pub title: String,
    pub published_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappAffectedAssetRecord {
    pub id: String,
    pub vulnerability_id: String,
    pub device_id: Option<String>,
    pub asset_kind: String,
    pub asset_ref: String,
    pub status: String,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappRemediationPlanRecord {
    pub id: String,
    pub finding_ref: String,
    pub plan_kind: String,
    pub status: String,
    pub title: String,
    pub priority: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappAttackPathRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub name: String,
    pub severity: String,
    pub status: String,
    pub entry_asset: Option<String>,
    pub target_asset: Option<String>,
    pub node_count: u32,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappAttackPathNodeRecord {
    pub id: String,
    pub path_id: Option<String>,
    pub node_kind: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappAttackPathEdgeRecord {
    pub id: String,
    pub path_id: Option<String>,
    pub source_node_id: String,
    pub target_node_id: String,
    pub edge_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappComplianceControlRecord {
    pub id: String,
    pub framework: String,
    pub control_id: String,
    pub title: String,
    pub category: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappComplianceScoreRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub framework: String,
    pub score: f64,
    pub passing_controls: u32,
    pub failing_controls: u32,
    pub evaluated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappComplianceViolationRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub severity: String,
    pub title: String,
    pub resource_ref: Option<String>,
    pub status: String,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappTelemetrySnapshot {
    pub id: String,
    pub device_id: String,
    pub posture_finding_count: u32,
    pub workload_count: u32,
    pub k8s_finding_count: u32,
    pub container_finding_count: u32,
    pub iac_finding_count: u32,
    pub secret_finding_count: u32,
    pub vulnerability_count: u32,
    pub compliance_violation_count: u32,
    pub reported_at: String,
}

// --- Summaries ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureSummary {
    pub finding_count: i64,
    pub open_findings: i64,
    pub high_severity: i64,
    pub resource_count: i64,
    pub avg_risk_score: f64,
    pub findings: Vec<CnappPostureFindingRecord>,
    pub resources: Vec<CnappCloudResourceRecord>,
    pub risk_scores: Vec<CnappRiskScoreRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadsSummary {
    pub workload_count: i64,
    pub active_workloads: i64,
    pub threat_count: i64,
    pub open_threats: i64,
    pub workloads: Vec<CnappWorkloadRecord>,
    pub threats: Vec<CnappWorkloadThreatRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesSummary {
    pub cluster_count: i64,
    pub resource_count: i64,
    pub finding_count: i64,
    pub open_findings: i64,
    pub clusters: Vec<CnappK8sClusterRecord>,
    pub resources: Vec<CnappK8sResourceRecord>,
    pub findings: Vec<CnappK8sFindingRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainersSummary {
    pub image_count: i64,
    pub scanned_images: i64,
    pub finding_count: i64,
    pub critical_findings: i64,
    pub images: Vec<CnappContainerImageRecord>,
    pub findings: Vec<CnappContainerFindingRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacSummary {
    pub scan_count: i64,
    pub finding_count: i64,
    pub open_findings: i64,
    pub scans: Vec<CnappIacScanRecord>,
    pub findings: Vec<CnappIacFindingRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsSummary {
    pub finding_count: i64,
    pub open_findings: i64,
    pub high_severity: i64,
    pub findings: Vec<CnappSecretFindingRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainSummary {
    pub dependency_count: i64,
    pub direct_dependencies: i64,
    pub threat_count: i64,
    pub open_threats: i64,
    pub dependencies: Vec<CnappDependencyRecord>,
    pub threats: Vec<CnappSupplyChainThreatRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomSummary {
    pub document_count: i64,
    pub component_count: i64,
    pub documents: Vec<CnappSbomDocumentRecord>,
    pub components: Vec<CnappSbomComponentRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilitiesSummary {
    pub vulnerability_count: i64,
    pub critical_count: i64,
    pub affected_asset_count: i64,
    pub remediation_count: i64,
    pub vulnerabilities: Vec<CnappVulnerabilityRecord>,
    pub affected_assets: Vec<CnappAffectedAssetRecord>,
    pub remediation_plans: Vec<CnappRemediationPlanRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    pub control_count: i64,
    pub violation_count: i64,
    pub open_violations: i64,
    pub avg_score: f64,
    pub controls: Vec<CnappComplianceControlRecord>,
    pub scores: Vec<CnappComplianceScoreRecord>,
    pub violations: Vec<CnappComplianceViolationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathsSummary {
    pub path_count: i64,
    pub open_paths: i64,
    pub node_count: i64,
    pub edge_count: i64,
    pub paths: Vec<CnappAttackPathRecord>,
    pub nodes: Vec<CnappAttackPathNodeRecord>,
    pub edges: Vec<CnappAttackPathEdgeRecord>,
}

// --- Inputs ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappPostureFindingInput {
    pub resource_id: Option<String>,
    pub finding_kind: Option<String>,
    pub severity: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub status: Option<String>,
    pub framework: Option<String>,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappCloudResourceInput {
    pub provider: Option<String>,
    pub resource_type: String,
    pub resource_arn: Option<String>,
    pub name: String,
    pub region: Option<String>,
    pub account_id: Option<String>,
    pub tags: Option<serde_json::Value>,
    pub risk_score: Option<u8>,
    pub details: Option<serde_json::Value>,
    pub discovered_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappWorkloadInput {
    pub workload_kind: Option<String>,
    pub name: String,
    pub namespace: Option<String>,
    pub cluster_id: Option<String>,
    pub status: Option<String>,
    pub image_ref: Option<String>,
    pub labels: Option<serde_json::Value>,
    pub details: Option<serde_json::Value>,
    pub discovered_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappWorkloadThreatInput {
    pub workload_id: Option<String>,
    pub threat_kind: Option<String>,
    pub severity: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappK8sClusterInput {
    pub name: String,
    pub provider: Option<String>,
    pub version: Option<String>,
    pub node_count: Option<u32>,
    pub status: Option<String>,
    pub details: Option<serde_json::Value>,
    pub discovered_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappK8sFindingInput {
    pub cluster_id: Option<String>,
    pub resource_id: Option<String>,
    pub finding_kind: Option<String>,
    pub severity: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappContainerImageInput {
    pub registry: Option<String>,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
    pub scan_status: Option<String>,
    pub details: Option<serde_json::Value>,
    pub discovered_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappContainerFindingInput {
    pub image_id: Option<String>,
    pub finding_kind: Option<String>,
    pub severity: Option<String>,
    pub title: String,
    pub cve_id: Option<String>,
    pub package_name: Option<String>,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappIacScanInput {
    pub scan_kind: Option<String>,
    pub repository: Option<String>,
    pub branch: Option<String>,
    pub commit_sha: Option<String>,
    pub status: Option<String>,
    pub details: Option<serde_json::Value>,
    pub scanned_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappIacFindingInput {
    pub scan_id: Option<String>,
    pub finding_kind: Option<String>,
    pub severity: Option<String>,
    pub title: String,
    pub file_path: Option<String>,
    pub line_number: Option<i64>,
    pub rule_id: Option<String>,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappSecretFindingInput {
    pub secret_kind: Option<String>,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub file_path: Option<String>,
    pub redacted_preview: Option<String>,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappDependencyInput {
    pub ecosystem: Option<String>,
    pub package_name: String,
    pub version: Option<String>,
    pub license: Option<String>,
    pub direct: Option<bool>,
    pub details: Option<serde_json::Value>,
    pub discovered_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappSupplyChainThreatInput {
    pub dependency_id: Option<String>,
    pub threat_kind: Option<String>,
    pub severity: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappSbomDocumentInput {
    pub format: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub source: Option<String>,
    pub components: Option<Vec<CnappSbomComponentInput>>,
    pub details: Option<serde_json::Value>,
    pub generated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappSbomComponentInput {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub license: Option<String>,
    pub kind: Option<String>,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappVulnerabilityInput {
    pub cve_id: String,
    pub severity: Option<String>,
    pub score: Option<f64>,
    pub title: String,
    pub description: Option<String>,
    pub published_at: Option<String>,
    pub asset_kind: Option<String>,
    pub asset_ref: Option<String>,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappComplianceViolationInput {
    pub control_id: Option<String>,
    pub severity: Option<String>,
    pub title: String,
    pub resource_ref: Option<String>,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappAttackPathInput {
    pub name: String,
    pub severity: Option<String>,
    pub entry_asset: Option<String>,
    pub target_asset: Option<String>,
    pub details: Option<serde_json::Value>,
    pub discovered_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappTelemetryIngest {
    pub posture_findings: Option<Vec<CnappPostureFindingInput>>,
    pub cloud_resources: Option<Vec<CnappCloudResourceInput>>,
    pub workloads: Option<Vec<CnappWorkloadInput>>,
    pub workload_threats: Option<Vec<CnappWorkloadThreatInput>>,
    pub k8s_clusters: Option<Vec<CnappK8sClusterInput>>,
    pub k8s_findings: Option<Vec<CnappK8sFindingInput>>,
    pub container_findings: Option<Vec<CnappContainerFindingInput>>,
    pub secret_findings: Option<Vec<CnappSecretFindingInput>>,
    pub compliance_violations: Option<Vec<CnappComplianceViolationInput>>,
    pub reported_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnappScanIngest {
    pub iac_scans: Option<Vec<CnappIacScanInput>>,
    pub iac_findings: Option<Vec<CnappIacFindingInput>>,
    pub container_images: Option<Vec<CnappContainerImageInput>>,
    pub container_findings: Option<Vec<CnappContainerFindingInput>>,
    pub sbom_documents: Option<Vec<CnappSbomDocumentInput>>,
    pub dependencies: Option<Vec<CnappDependencyInput>>,
    pub supply_chain_threats: Option<Vec<CnappSupplyChainThreatInput>>,
    pub vulnerabilities: Option<Vec<CnappVulnerabilityInput>>,
    pub attack_paths: Option<Vec<CnappAttackPathInput>>,
    pub scanned_at: Option<String>,
}

pub struct CnappManager {
    pool: DbPool,
}

impl CnappManager {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn posture_summary(&self) -> Result<PostureSummary, DbError> {
        let findings = self.list_posture_findings(Some(50)).await?;
        let resources = self.list_cloud_resources(Some(50)).await?;
        let risk_scores = self.list_risk_scores(Some(20)).await?;
        let finding_count = findings.len() as i64;
        let open_findings = findings.iter().filter(|f| f.status == "open").count() as i64;
        let high_severity = findings
            .iter()
            .filter(|f| f.severity == "high" || f.severity == "critical")
            .count() as i64;
        let avg_risk_score = if resources.is_empty() {
            0.0
        } else {
            resources.iter().map(|r| f64::from(r.risk_score)).sum::<f64>() / resources.len() as f64
        };
        Ok(PostureSummary {
            finding_count,
            open_findings,
            high_severity,
            resource_count: resources.len() as i64,
            avg_risk_score,
            findings,
            resources,
            risk_scores,
        })
    }

    pub async fn workloads_summary(&self) -> Result<WorkloadsSummary, DbError> {
        let workloads = self.list_workloads(Some(50)).await?;
        let threats = self.list_workload_threats(Some(50)).await?;
        Ok(WorkloadsSummary {
            workload_count: workloads.len() as i64,
            active_workloads: workloads.iter().filter(|w| w.status == "running").count() as i64,
            threat_count: threats.len() as i64,
            open_threats: threats.iter().filter(|t| t.status == "open").count() as i64,
            workloads,
            threats,
        })
    }

    pub async fn kubernetes_summary(&self) -> Result<KubernetesSummary, DbError> {
        let clusters = self.list_k8s_clusters(Some(20)).await?;
        let resources = self.list_k8s_resources(Some(50)).await?;
        let findings = self.list_k8s_findings(Some(50)).await?;
        Ok(KubernetesSummary {
            cluster_count: clusters.len() as i64,
            resource_count: resources.len() as i64,
            finding_count: findings.len() as i64,
            open_findings: findings.iter().filter(|f| f.status == "open").count() as i64,
            clusters,
            resources,
            findings,
        })
    }

    pub async fn containers_summary(&self) -> Result<ContainersSummary, DbError> {
        let images = self.list_container_images(Some(50)).await?;
        let findings = self.list_container_findings(Some(50)).await?;
        Ok(ContainersSummary {
            image_count: images.len() as i64,
            scanned_images: images.iter().filter(|i| i.scan_status == "completed").count() as i64,
            finding_count: findings.len() as i64,
            critical_findings: findings.iter().filter(|f| f.severity == "critical").count() as i64,
            images,
            findings,
        })
    }

    pub async fn iac_summary(&self) -> Result<IacSummary, DbError> {
        let scans = self.list_iac_scans(Some(20)).await?;
        let findings = self.list_iac_findings(Some(50)).await?;
        Ok(IacSummary {
            scan_count: scans.len() as i64,
            finding_count: findings.len() as i64,
            open_findings: findings.iter().filter(|f| f.status == "open").count() as i64,
            scans,
            findings,
        })
    }

    pub async fn secrets_summary(&self) -> Result<SecretsSummary, DbError> {
        let findings = self.list_secret_findings(Some(50)).await?;
        Ok(SecretsSummary {
            finding_count: findings.len() as i64,
            open_findings: findings.iter().filter(|f| f.status == "open").count() as i64,
            high_severity: findings
                .iter()
                .filter(|f| f.severity == "high" || f.severity == "critical")
                .count() as i64,
            findings,
        })
    }

    pub async fn supply_chain_summary(&self) -> Result<SupplyChainSummary, DbError> {
        let dependencies = self.list_dependencies(Some(50)).await?;
        let threats = self.list_supply_chain_threats(Some(50)).await?;
        Ok(SupplyChainSummary {
            dependency_count: dependencies.len() as i64,
            direct_dependencies: dependencies.iter().filter(|d| d.direct).count() as i64,
            threat_count: threats.len() as i64,
            open_threats: threats.iter().filter(|t| t.status == "open").count() as i64,
            dependencies,
            threats,
        })
    }

    pub async fn sbom_summary(&self) -> Result<SbomSummary, DbError> {
        let documents = self.list_sbom_documents(Some(20)).await?;
        let component_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM cnapp_sbom_components")
                .fetch_one(&self.pool)
                .await?;
        let components = self.list_sbom_components(Some(50)).await?;
        Ok(SbomSummary {
            document_count: documents.len() as i64,
            component_count: component_count.0,
            documents,
            components,
        })
    }

    pub async fn vulnerabilities_summary(&self) -> Result<VulnerabilitiesSummary, DbError> {
        let vulnerabilities = self.list_vulnerabilities(Some(50)).await?;
        let affected_assets = self.list_affected_assets(Some(50)).await?;
        let remediation_plans = self.list_remediation_plans(Some(20)).await?;
        Ok(VulnerabilitiesSummary {
            vulnerability_count: vulnerabilities.len() as i64,
            critical_count: vulnerabilities
                .iter()
                .filter(|v| v.severity == "critical")
                .count() as i64,
            affected_asset_count: affected_assets.len() as i64,
            remediation_count: remediation_plans.len() as i64,
            vulnerabilities,
            affected_assets,
            remediation_plans,
        })
    }

    pub async fn compliance_summary(&self) -> Result<ComplianceSummary, DbError> {
        let controls = self.list_compliance_controls().await?;
        let scores = self.list_compliance_scores(Some(20)).await?;
        let violations = self.list_compliance_violations(Some(50)).await?;
        let avg_score = if scores.is_empty() {
            0.0
        } else {
            scores.iter().map(|s| s.score).sum::<f64>() / scores.len() as f64
        };
        Ok(ComplianceSummary {
            control_count: controls.len() as i64,
            violation_count: violations.len() as i64,
            open_violations: violations.iter().filter(|v| v.status == "open").count() as i64,
            avg_score,
            controls,
            scores,
            violations,
        })
    }

    pub async fn attack_paths_summary(&self) -> Result<AttackPathsSummary, DbError> {
        let paths = self.list_attack_paths(Some(20)).await?;
        let nodes = self.list_attack_path_nodes(Some(100)).await?;
        let edges = self.list_attack_path_edges(Some(200)).await?;
        Ok(AttackPathsSummary {
            path_count: paths.len() as i64,
            open_paths: paths.iter().filter(|p| p.status == "open").count() as i64,
            node_count: nodes.len() as i64,
            edge_count: edges.len() as i64,
            paths,
            nodes,
            edges,
        })
    }

    pub async fn create_posture_finding(
        &self,
        device_id: &str,
        input: &CnappPostureFindingInput,
    ) -> Result<CnappPostureFindingRecord, DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let detected_at = input.detected_at.clone().unwrap_or_else(|| now.clone());
        let finding_kind = input.finding_kind.clone().unwrap_or_else(|| "misconfiguration".into());
        let severity = input.severity.clone().unwrap_or_else(|| "medium".into());
        let status = input.status.clone().unwrap_or_else(|| "open".into());
        let details_json = details_json!(input);

        sqlx::query(
            "INSERT INTO cnapp_posture_findings (
                id, device_id, resource_id, finding_kind, severity, title, description,
                status, framework, details_json, detected_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(&input.resource_id)
        .bind(&finding_kind)
        .bind(&severity)
        .bind(&input.title)
        .bind(&input.description)
        .bind(&status)
        .bind(&input.framework)
        .bind(&details_json)
        .bind(&detected_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(CnappPostureFindingRecord {
            id,
            device_id: Some(device_id.to_string()),
            resource_id: input.resource_id.clone(),
            finding_kind,
            severity,
            title: input.title.clone(),
            description: input.description.clone(),
            status,
            framework: input.framework.clone(),
            detected_at,
        })
    }

    pub async fn ingest_sbom(
        &self,
        device_id: &str,
        input: &CnappSbomDocumentInput,
    ) -> Result<CnappSbomDocumentRecord, DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let format = input.format.clone().unwrap_or_else(|| "cyclonedx".into());
        let generated_at = input.generated_at.clone().unwrap_or_else(|| now.clone());
        let details_json = details_json!(input);
        let components = input.components.clone().unwrap_or_default();
        let component_count = components.len() as u32;

        sqlx::query(
            "INSERT INTO cnapp_sbom_documents (
                id, device_id, format, name, version, source, component_count,
                details_json, generated_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(&format)
        .bind(&input.name)
        .bind(&input.version)
        .bind(&input.source)
        .bind(i64::from(component_count))
        .bind(&details_json)
        .bind(&generated_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        for comp in &components {
            let comp_id = Uuid::new_v4().to_string();
            let kind = comp.kind.clone().unwrap_or_else(|| "library".into());
            let comp_details = comp
                .details
                .as_ref()
                .map(|d| d.to_string())
                .unwrap_or_else(|| "{}".into());
            sqlx::query(
                "INSERT INTO cnapp_sbom_components (
                    id, document_id, device_id, name, version, purl, license, kind, details_json, created_at
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&comp_id)
            .bind(&id)
            .bind(device_id)
            .bind(&comp.name)
            .bind(&comp.version)
            .bind(&comp.purl)
            .bind(&comp.license)
            .bind(&kind)
            .bind(&comp_details)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        }

        Ok(CnappSbomDocumentRecord {
            id,
            device_id: Some(device_id.to_string()),
            format,
            name: input.name.clone(),
            component_count,
            generated_at,
        })
    }

    pub async fn ingest_telemetry(
        &self,
        device_id: &str,
        payload: &CnappTelemetryIngest,
    ) -> Result<CnappTelemetrySnapshot, DbError> {
        let now = now_iso();
        let reported_at = payload.reported_at.clone().unwrap_or_else(|| now.clone());
        let mut posture_finding_count = 0u32;
        let mut workload_count = 0u32;
        let mut k8s_finding_count = 0u32;
        let mut container_finding_count = 0u32;
        let mut secret_finding_count = 0u32;
        let mut compliance_violation_count = 0u32;

        if let Some(resources) = &payload.cloud_resources {
            for r in resources {
                self.insert_cloud_resource(device_id, r).await?;
            }
        }

        if let Some(findings) = &payload.posture_findings {
            for f in findings {
                self.create_posture_finding(device_id, f).await?;
                posture_finding_count += 1;
            }
        }

        if let Some(workloads) = &payload.workloads {
            for w in workloads {
                self.insert_workload(device_id, w).await?;
                workload_count += 1;
            }
        }

        if let Some(threats) = &payload.workload_threats {
            for t in threats {
                self.insert_workload_threat(device_id, t).await?;
            }
        }

        if let Some(clusters) = &payload.k8s_clusters {
            for c in clusters {
                self.insert_k8s_cluster(device_id, c).await?;
            }
        }

        if let Some(findings) = &payload.k8s_findings {
            for f in findings {
                self.insert_k8s_finding(device_id, f).await?;
                k8s_finding_count += 1;
            }
        }

        if let Some(findings) = &payload.container_findings {
            for f in findings {
                self.insert_container_finding(device_id, f).await?;
                container_finding_count += 1;
            }
        }

        if let Some(findings) = &payload.secret_findings {
            for f in findings {
                self.insert_secret_finding(device_id, f).await?;
                secret_finding_count += 1;
            }
        }

        if let Some(violations) = &payload.compliance_violations {
            for v in violations {
                self.insert_compliance_violation(device_id, v).await?;
                compliance_violation_count += 1;
            }
        }

        let vulnerability_count = 0u32;
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO cnapp_telemetry_snapshots (
                id, device_id, posture_finding_count, workload_count, k8s_finding_count,
                container_finding_count, iac_finding_count, secret_finding_count,
                vulnerability_count, compliance_violation_count, reported_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(i64::from(posture_finding_count))
        .bind(i64::from(workload_count))
        .bind(i64::from(k8s_finding_count))
        .bind(i64::from(container_finding_count))
        .bind(i64::from(secret_finding_count))
        .bind(i64::from(vulnerability_count))
        .bind(i64::from(compliance_violation_count))
        .bind(&reported_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(CnappTelemetrySnapshot {
            id,
            device_id: device_id.to_string(),
            posture_finding_count,
            workload_count,
            k8s_finding_count,
            container_finding_count,
            iac_finding_count: 0,
            secret_finding_count,
            vulnerability_count,
            compliance_violation_count,
            reported_at,
        })
    }

    pub async fn ingest_scan(
        &self,
        device_id: &str,
        payload: &CnappScanIngest,
    ) -> Result<serde_json::Value, DbError> {
        let mut iac_scans = 0u32;
        let mut iac_findings = 0u32;
        let mut container_images = 0u32;
        let mut container_findings = 0u32;
        let mut sbom_documents = 0u32;
        let mut dependencies = 0u32;
        let mut supply_chain_threats = 0u32;
        let mut vulnerabilities = 0u32;
        let mut attack_paths = 0u32;

        if let Some(scans) = &payload.iac_scans {
            for s in scans {
                self.insert_iac_scan(device_id, s).await?;
                iac_scans += 1;
            }
        }

        if let Some(findings) = &payload.iac_findings {
            for f in findings {
                self.insert_iac_finding(device_id, f).await?;
                iac_findings += 1;
            }
        }

        if let Some(images) = &payload.container_images {
            for i in images {
                self.insert_container_image(device_id, i).await?;
                container_images += 1;
            }
        }

        if let Some(findings) = &payload.container_findings {
            for f in findings {
                self.insert_container_finding(device_id, f).await?;
                container_findings += 1;
            }
        }

        if let Some(docs) = &payload.sbom_documents {
            for d in docs {
                self.ingest_sbom(device_id, d).await?;
                sbom_documents += 1;
            }
        }

        if let Some(deps) = &payload.dependencies {
            for d in deps {
                self.insert_dependency(device_id, d).await?;
                dependencies += 1;
            }
        }

        if let Some(threats) = &payload.supply_chain_threats {
            for t in threats {
                self.insert_supply_chain_threat(device_id, t).await?;
                supply_chain_threats += 1;
            }
        }

        if let Some(vulns) = &payload.vulnerabilities {
            for v in vulns {
                self.insert_vulnerability(device_id, v).await?;
                vulnerabilities += 1;
            }
        }

        if let Some(paths) = &payload.attack_paths {
            for p in paths {
                self.insert_attack_path(device_id, p).await?;
                attack_paths += 1;
            }
        }

        Ok(serde_json::json!({
            "iac_scans": iac_scans,
            "iac_findings": iac_findings,
            "container_images": container_images,
            "container_findings": container_findings,
            "sbom_documents": sbom_documents,
            "dependencies": dependencies,
            "supply_chain_threats": supply_chain_threats,
            "vulnerabilities": vulnerabilities,
            "attack_paths": attack_paths,
            "scanned_at": payload.scanned_at.clone().unwrap_or_else(|| now_iso()),
        }))
    }

    pub async fn seed_defaults(&self) -> Result<(), DbError> {
        let control_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM cnapp_compliance_controls")
                .fetch_one(&self.pool)
                .await?;
        if control_count.0 == 0 {
            let now = now_iso();
            let controls = [
                ("cis", "1.1", "Ensure MFA is enabled", "identity"),
                ("cis", "2.1", "Ensure logging is enabled", "logging"),
                ("cis", "3.4", "Ensure security groups restrict traffic", "network"),
                ("pci", "1.2.1", "Restrict inbound traffic", "network"),
                ("pci", "8.3", "Secure authentication", "identity"),
            ];
            for (framework, control_id, title, category) in controls {
                let id = Uuid::new_v4().to_string();
                sqlx::query(
                    "INSERT INTO cnapp_compliance_controls (
                        id, framework, control_id, title, description, category, enabled,
                        details_json, created_at
                     ) VALUES (?, ?, ?, ?, NULL, ?, 1, '{}', ?)",
                )
                .bind(&id)
                .bind(framework)
                .bind(control_id)
                .bind(title)
                .bind(category)
                .bind(&now)
                .execute(&self.pool)
                .await?;
            }
        }

        let remediation_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM cnapp_remediation_plans")
                .fetch_one(&self.pool)
                .await?;
        if remediation_count.0 == 0 {
            let now = now_iso();
            let plans = [
                ("patch", "Apply security patch", "high"),
                ("rotate", "Rotate exposed credentials", "critical"),
                ("harden", "Apply CIS benchmark hardening", "medium"),
            ];
            for (kind, title, priority) in plans {
                let id = Uuid::new_v4().to_string();
                sqlx::query(
                    "INSERT INTO cnapp_remediation_plans (
                        id, finding_ref, plan_kind, status, title, steps_json, priority,
                        details_json, created_at, updated_at
                     ) VALUES (?, 'default', ?, 'pending', ?, '[]', ?, '{}', ?, ?)",
                )
                .bind(&id)
                .bind(kind)
                .bind(title)
                .bind(priority)
                .bind(&now)
                .bind(&now)
                .execute(&self.pool)
                .await?;
            }
        }

        Ok(())
    }

    // --- private insert/list helpers ---

    async fn insert_cloud_resource(
        &self,
        device_id: &str,
        input: &CnappCloudResourceInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let discovered_at = input.discovered_at.clone().unwrap_or_else(|| now.clone());
        let tags_json = input
            .tags
            .as_ref()
            .map(|t| t.to_string())
            .unwrap_or_else(|| "{}".into());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_cloud_resources (
                id, device_id, provider, resource_type, resource_arn, name, region, account_id,
                tags_json, risk_score, status, details_json, discovered_at, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(input.provider.as_deref().unwrap_or("aws"))
        .bind(&input.resource_type)
        .bind(&input.resource_arn)
        .bind(&input.name)
        .bind(&input.region)
        .bind(&input.account_id)
        .bind(&tags_json)
        .bind(i64::from(input.risk_score.unwrap_or(0)))
        .bind(&details_json)
        .bind(&discovered_at)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_workload(
        &self,
        device_id: &str,
        input: &CnappWorkloadInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let discovered_at = input.discovered_at.clone().unwrap_or_else(|| now.clone());
        let labels_json = input
            .labels
            .as_ref()
            .map(|l| l.to_string())
            .unwrap_or_else(|| "{}".into());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_workloads (
                id, device_id, workload_kind, name, namespace, cluster_id, status, image_ref,
                labels_json, details_json, discovered_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(input.workload_kind.as_deref().unwrap_or("pod"))
        .bind(&input.name)
        .bind(&input.namespace)
        .bind(&input.cluster_id)
        .bind(input.status.as_deref().unwrap_or("running"))
        .bind(&input.image_ref)
        .bind(&labels_json)
        .bind(&details_json)
        .bind(&discovered_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_workload_threat(
        &self,
        device_id: &str,
        input: &CnappWorkloadThreatInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let detected_at = input.detected_at.clone().unwrap_or_else(|| now.clone());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_workload_threats (
                id, workload_id, device_id, threat_kind, severity, title, description,
                status, details_json, detected_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.workload_id)
        .bind(device_id)
        .bind(input.threat_kind.as_deref().unwrap_or("runtime"))
        .bind(input.severity.as_deref().unwrap_or("medium"))
        .bind(&input.title)
        .bind(&input.description)
        .bind(&details_json)
        .bind(&detected_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_k8s_cluster(
        &self,
        device_id: &str,
        input: &CnappK8sClusterInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let discovered_at = input.discovered_at.clone().unwrap_or_else(|| now.clone());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_k8s_clusters (
                id, device_id, name, provider, version, node_count, status, details_json,
                discovered_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(&input.name)
        .bind(input.provider.as_deref().unwrap_or("eks"))
        .bind(&input.version)
        .bind(i64::from(input.node_count.unwrap_or(0)))
        .bind(input.status.as_deref().unwrap_or("healthy"))
        .bind(&details_json)
        .bind(&discovered_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_k8s_finding(
        &self,
        device_id: &str,
        input: &CnappK8sFindingInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let detected_at = input.detected_at.clone().unwrap_or_else(|| now.clone());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_k8s_findings (
                id, cluster_id, resource_id, device_id, finding_kind, severity, title,
                description, status, details_json, detected_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.cluster_id)
        .bind(&input.resource_id)
        .bind(device_id)
        .bind(input.finding_kind.as_deref().unwrap_or("policy"))
        .bind(input.severity.as_deref().unwrap_or("medium"))
        .bind(&input.title)
        .bind(&input.description)
        .bind(&details_json)
        .bind(&detected_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_container_image(
        &self,
        device_id: &str,
        input: &CnappContainerImageInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let discovered_at = input.discovered_at.clone().unwrap_or_else(|| now.clone());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_container_images (
                id, device_id, registry, repository, tag, digest, scan_status, details_json,
                discovered_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(&input.registry)
        .bind(&input.repository)
        .bind(&input.tag)
        .bind(&input.digest)
        .bind(input.scan_status.as_deref().unwrap_or("completed"))
        .bind(&details_json)
        .bind(&discovered_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_container_finding(
        &self,
        device_id: &str,
        input: &CnappContainerFindingInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let detected_at = input.detected_at.clone().unwrap_or_else(|| now.clone());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_container_findings (
                id, image_id, device_id, finding_kind, severity, title, cve_id, package_name,
                status, details_json, detected_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.image_id)
        .bind(device_id)
        .bind(input.finding_kind.as_deref().unwrap_or("vulnerability"))
        .bind(input.severity.as_deref().unwrap_or("medium"))
        .bind(&input.title)
        .bind(&input.cve_id)
        .bind(&input.package_name)
        .bind(&details_json)
        .bind(&detected_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_iac_scan(&self, device_id: &str, input: &CnappIacScanInput) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let scanned_at = input.scanned_at.clone().unwrap_or_else(|| now.clone());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_iac_scans (
                id, device_id, scan_kind, repository, branch, commit_sha, status,
                finding_count, details_json, scanned_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(input.scan_kind.as_deref().unwrap_or("terraform"))
        .bind(&input.repository)
        .bind(&input.branch)
        .bind(&input.commit_sha)
        .bind(input.status.as_deref().unwrap_or("completed"))
        .bind(&details_json)
        .bind(&scanned_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_iac_finding(
        &self,
        device_id: &str,
        input: &CnappIacFindingInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let detected_at = input.detected_at.clone().unwrap_or_else(|| now.clone());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_iac_findings (
                id, scan_id, device_id, finding_kind, severity, title, file_path, line_number,
                rule_id, status, details_json, detected_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.scan_id)
        .bind(device_id)
        .bind(input.finding_kind.as_deref().unwrap_or("misconfiguration"))
        .bind(input.severity.as_deref().unwrap_or("medium"))
        .bind(&input.title)
        .bind(&input.file_path)
        .bind(input.line_number)
        .bind(&input.rule_id)
        .bind(&details_json)
        .bind(&detected_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_secret_finding(
        &self,
        device_id: &str,
        input: &CnappSecretFindingInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let detected_at = input.detected_at.clone().unwrap_or_else(|| now.clone());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_secret_findings (
                id, device_id, secret_kind, severity, source, file_path, redacted_preview,
                status, details_json, detected_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(input.secret_kind.as_deref().unwrap_or("api_key"))
        .bind(input.severity.as_deref().unwrap_or("high"))
        .bind(&input.source)
        .bind(&input.file_path)
        .bind(&input.redacted_preview)
        .bind(&details_json)
        .bind(&detected_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_dependency(
        &self,
        device_id: &str,
        input: &CnappDependencyInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let discovered_at = input.discovered_at.clone().unwrap_or_else(|| now.clone());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_dependencies (
                id, device_id, ecosystem, package_name, version, license, direct,
                details_json, discovered_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(input.ecosystem.as_deref().unwrap_or("npm"))
        .bind(&input.package_name)
        .bind(&input.version)
        .bind(&input.license)
        .bind(i64::from(input.direct.unwrap_or(true)))
        .bind(&details_json)
        .bind(&discovered_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_supply_chain_threat(
        &self,
        device_id: &str,
        input: &CnappSupplyChainThreatInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let detected_at = input.detected_at.clone().unwrap_or_else(|| now.clone());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_supply_chain_threats (
                id, dependency_id, device_id, threat_kind, severity, title, description,
                status, details_json, detected_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.dependency_id)
        .bind(device_id)
        .bind(input.threat_kind.as_deref().unwrap_or("typosquat"))
        .bind(input.severity.as_deref().unwrap_or("medium"))
        .bind(&input.title)
        .bind(&input.description)
        .bind(&details_json)
        .bind(&detected_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_vulnerability(
        &self,
        device_id: &str,
        input: &CnappVulnerabilityInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let severity = input.severity.clone().unwrap_or_else(|| "medium".into());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_vulnerabilities (
                id, cve_id, severity, score, title, description, published_at, details_json, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.cve_id)
        .bind(&severity)
        .bind(input.score)
        .bind(&input.title)
        .bind(&input.description)
        .bind(&input.published_at)
        .bind(&details_json)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        if let Some(asset_ref) = &input.asset_ref {
            let asset_id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO cnapp_affected_assets (
                    id, vulnerability_id, device_id, asset_kind, asset_ref, status,
                    details_json, detected_at, created_at
                 ) VALUES (?, ?, ?, ?, ?, 'open', '{}', ?, ?)",
            )
            .bind(&asset_id)
            .bind(&id)
            .bind(device_id)
            .bind(input.asset_kind.as_deref().unwrap_or("container"))
            .bind(asset_ref)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn insert_compliance_violation(
        &self,
        device_id: &str,
        input: &CnappComplianceViolationInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let detected_at = input.detected_at.clone().unwrap_or_else(|| now.clone());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_compliance_violations (
                id, control_id, device_id, severity, title, resource_ref, status,
                details_json, detected_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.control_id)
        .bind(device_id)
        .bind(input.severity.as_deref().unwrap_or("medium"))
        .bind(&input.title)
        .bind(&input.resource_ref)
        .bind(&details_json)
        .bind(&detected_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_attack_path(
        &self,
        device_id: &str,
        input: &CnappAttackPathInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let discovered_at = input.discovered_at.clone().unwrap_or_else(|| now.clone());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO cnapp_attack_paths (
                id, device_id, name, severity, status, entry_asset, target_asset,
                node_count, details_json, discovered_at, created_at
             ) VALUES (?, ?, ?, ?, 'open', ?, ?, 0, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(&input.name)
        .bind(input.severity.as_deref().unwrap_or("high"))
        .bind(&input.entry_asset)
        .bind(&input.target_asset)
        .bind(&details_json)
        .bind(&discovered_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_posture_findings(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappPostureFindingRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, Option<String>, String, String, String, Option<String>, String, Option<String>, String)> =
            sqlx::query_as(
                "SELECT id, device_id, resource_id, finding_kind, severity, title, description,
                        status, framework, detected_at
                 FROM cnapp_posture_findings ORDER BY detected_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, resource_id, finding_kind, severity, title, description, status, framework, detected_at)| {
            CnappPostureFindingRecord { id, device_id, resource_id, finding_kind, severity, title, description, status, framework, detected_at }
        }).collect())
    }

    async fn list_cloud_resources(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappCloudResourceRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, String, String, String, Option<String>, i64, String, String)> =
            sqlx::query_as(
                "SELECT id, device_id, provider, resource_type, name, region, risk_score, status, discovered_at
                 FROM cnapp_cloud_resources ORDER BY discovered_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, provider, resource_type, name, region, risk_score, status, discovered_at)| {
            CnappCloudResourceRecord { id, device_id, provider, resource_type, name, region, risk_score: risk_score as u8, status, discovered_at }
        }).collect())
    }

    async fn list_risk_scores(&self, limit: Option<i64>) -> Result<Vec<CnappRiskScoreRecord>, DbError> {
        let limit = limit.unwrap_or(20);
        let rows: Vec<(String, Option<String>, String, i64, String, String)> = sqlx::query_as(
            "SELECT id, device_id, scope_kind, risk_score, risk_level, evaluated_at
             FROM cnapp_risk_scores ORDER BY evaluated_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, device_id, scope_kind, risk_score, risk_level, evaluated_at)| {
            CnappRiskScoreRecord { id, device_id, scope_kind, risk_score: risk_score as u8, risk_level, evaluated_at }
        }).collect())
    }

    async fn list_workloads(&self, limit: Option<i64>) -> Result<Vec<CnappWorkloadRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, String, String, Option<String>, String, Option<String>, String)> =
            sqlx::query_as(
                "SELECT id, device_id, workload_kind, name, namespace, status, image_ref, discovered_at
                 FROM cnapp_workloads ORDER BY discovered_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, workload_kind, name, namespace, status, image_ref, discovered_at)| {
            CnappWorkloadRecord { id, device_id, workload_kind, name, namespace, status, image_ref, discovered_at }
        }).collect())
    }

    async fn list_workload_threats(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappWorkloadThreatRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, Option<String>, String, String, String, String, String)> =
            sqlx::query_as(
                "SELECT id, workload_id, device_id, threat_kind, severity, title, status, detected_at
                 FROM cnapp_workload_threats ORDER BY detected_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, workload_id, device_id, threat_kind, severity, title, status, detected_at)| {
            CnappWorkloadThreatRecord { id, workload_id, device_id, threat_kind, severity, title, status, detected_at }
        }).collect())
    }

    async fn list_k8s_clusters(&self, limit: Option<i64>) -> Result<Vec<CnappK8sClusterRecord>, DbError> {
        let limit = limit.unwrap_or(20);
        let rows: Vec<(String, Option<String>, String, String, Option<String>, i64, String, String)> =
            sqlx::query_as(
                "SELECT id, device_id, name, provider, version, node_count, status, discovered_at
                 FROM cnapp_k8s_clusters ORDER BY discovered_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, name, provider, version, node_count, status, discovered_at)| {
            CnappK8sClusterRecord { id, device_id, name, provider, version, node_count: node_count as u32, status, discovered_at }
        }).collect())
    }

    async fn list_k8s_resources(&self, limit: Option<i64>) -> Result<Vec<CnappK8sResourceRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, String, String, Option<String>, String, String)> = sqlx::query_as(
            "SELECT id, cluster_id, resource_kind, namespace, name, discovered_at
             FROM cnapp_k8s_resources ORDER BY discovered_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, cluster_id, resource_kind, namespace, name, discovered_at)| {
            CnappK8sResourceRecord { id, cluster_id, resource_kind, namespace, name, discovered_at }
        }).collect())
    }

    async fn list_k8s_findings(&self, limit: Option<i64>) -> Result<Vec<CnappK8sFindingRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, String, String, String, String, String)> = sqlx::query_as(
            "SELECT id, cluster_id, finding_kind, severity, title, status, detected_at
             FROM cnapp_k8s_findings ORDER BY detected_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, cluster_id, finding_kind, severity, title, status, detected_at)| {
            CnappK8sFindingRecord { id, cluster_id, finding_kind, severity, title, status, detected_at }
        }).collect())
    }

    async fn list_container_images(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappContainerImageRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, String, Option<String>, Option<String>, String, String)> =
            sqlx::query_as(
                "SELECT id, device_id, repository, tag, digest, scan_status, discovered_at
                 FROM cnapp_container_images ORDER BY discovered_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, repository, tag, digest, scan_status, discovered_at)| {
            CnappContainerImageRecord { id, device_id, repository, tag, digest, scan_status, discovered_at }
        }).collect())
    }

    async fn list_container_findings(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappContainerFindingRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, String, String, Option<String>, Option<String>, String, String)> =
            sqlx::query_as(
                "SELECT id, image_id, severity, title, cve_id, package_name, status, detected_at
                 FROM cnapp_container_findings ORDER BY detected_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, image_id, severity, title, cve_id, package_name, status, detected_at)| {
            CnappContainerFindingRecord { id, image_id, severity, title, cve_id, package_name, status, detected_at }
        }).collect())
    }

    async fn list_iac_scans(&self, limit: Option<i64>) -> Result<Vec<CnappIacScanRecord>, DbError> {
        let limit = limit.unwrap_or(20);
        let rows: Vec<(String, Option<String>, String, Option<String>, String, i64, String)> =
            sqlx::query_as(
                "SELECT id, device_id, scan_kind, repository, status, finding_count, scanned_at
                 FROM cnapp_iac_scans ORDER BY scanned_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, scan_kind, repository, status, finding_count, scanned_at)| {
            CnappIacScanRecord { id, device_id, scan_kind, repository, status, finding_count: finding_count as u32, scanned_at }
        }).collect())
    }

    async fn list_iac_findings(&self, limit: Option<i64>) -> Result<Vec<CnappIacFindingRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, String, String, Option<String>, Option<String>, String, String)> =
            sqlx::query_as(
                "SELECT id, scan_id, severity, title, file_path, rule_id, status, detected_at
                 FROM cnapp_iac_findings ORDER BY detected_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, scan_id, severity, title, file_path, rule_id, status, detected_at)| {
            CnappIacFindingRecord { id, scan_id, severity, title, file_path, rule_id, status, detected_at }
        }).collect())
    }

    async fn list_secret_findings(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappSecretFindingRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, String, String, Option<String>, Option<String>, String, String)> =
            sqlx::query_as(
                "SELECT id, device_id, secret_kind, severity, source, file_path, status, detected_at
                 FROM cnapp_secret_findings ORDER BY detected_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, secret_kind, severity, source, file_path, status, detected_at)| {
            CnappSecretFindingRecord { id, device_id, secret_kind, severity, source, file_path, status, detected_at }
        }).collect())
    }

    async fn list_dependencies(&self, limit: Option<i64>) -> Result<Vec<CnappDependencyRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, String, String, Option<String>, i64, String)> =
            sqlx::query_as(
                "SELECT id, device_id, ecosystem, package_name, version, direct, discovered_at
                 FROM cnapp_dependencies ORDER BY discovered_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, ecosystem, package_name, version, direct, discovered_at)| {
            CnappDependencyRecord { id, device_id, ecosystem, package_name, version, direct: direct != 0, discovered_at }
        }).collect())
    }

    async fn list_supply_chain_threats(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappSupplyChainThreatRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, String, String, String, String, String)> =
            sqlx::query_as(
                "SELECT id, device_id, threat_kind, severity, title, status, detected_at
                 FROM cnapp_supply_chain_threats ORDER BY detected_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, threat_kind, severity, title, status, detected_at)| {
            CnappSupplyChainThreatRecord { id, device_id, threat_kind, severity, title, status, detected_at }
        }).collect())
    }

    async fn list_sbom_documents(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappSbomDocumentRecord>, DbError> {
        let limit = limit.unwrap_or(20);
        let rows: Vec<(String, Option<String>, String, String, i64, String)> = sqlx::query_as(
            "SELECT id, device_id, format, name, component_count, generated_at
             FROM cnapp_sbom_documents ORDER BY generated_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, device_id, format, name, component_count, generated_at)| {
            CnappSbomDocumentRecord { id, device_id, format, name, component_count: component_count as u32, generated_at }
        }).collect())
    }

    async fn list_sbom_components(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappSbomComponentRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, String, String, Option<String>, Option<String>, String)> =
            sqlx::query_as(
                "SELECT id, document_id, name, version, purl, kind
                 FROM cnapp_sbom_components ORDER BY created_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, document_id, name, version, purl, kind)| {
            CnappSbomComponentRecord { id, document_id, name, version, purl, kind }
        }).collect())
    }

    async fn list_vulnerabilities(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappVulnerabilityRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, String, String, Option<f64>, String, Option<String>)> = sqlx::query_as(
            "SELECT id, cve_id, severity, score, title, published_at
             FROM cnapp_vulnerabilities ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, cve_id, severity, score, title, published_at)| {
            CnappVulnerabilityRecord { id, cve_id, severity, score, title, published_at }
        }).collect())
    }

    async fn list_affected_assets(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappAffectedAssetRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, String, Option<String>, String, String, String, String)> =
            sqlx::query_as(
                "SELECT id, vulnerability_id, device_id, asset_kind, asset_ref, status, detected_at
                 FROM cnapp_affected_assets ORDER BY detected_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, vulnerability_id, device_id, asset_kind, asset_ref, status, detected_at)| {
            CnappAffectedAssetRecord { id, vulnerability_id, device_id, asset_kind, asset_ref, status, detected_at }
        }).collect())
    }

    async fn list_remediation_plans(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappRemediationPlanRecord>, DbError> {
        let limit = limit.unwrap_or(20);
        let rows: Vec<(String, String, String, String, String, String)> = sqlx::query_as(
            "SELECT id, finding_ref, plan_kind, status, title, priority
             FROM cnapp_remediation_plans ORDER BY updated_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, finding_ref, plan_kind, status, title, priority)| {
            CnappRemediationPlanRecord { id, finding_ref, plan_kind, status, title, priority }
        }).collect())
    }

    async fn list_compliance_controls(&self) -> Result<Vec<CnappComplianceControlRecord>, DbError> {
        let rows: Vec<(String, String, String, String, Option<String>, i64)> = sqlx::query_as(
            "SELECT id, framework, control_id, title, category, enabled
             FROM cnapp_compliance_controls ORDER BY framework, control_id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, framework, control_id, title, category, enabled)| {
            CnappComplianceControlRecord { id, framework, control_id, title, category, enabled: enabled != 0 }
        }).collect())
    }

    async fn list_compliance_scores(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappComplianceScoreRecord>, DbError> {
        let limit = limit.unwrap_or(20);
        let rows: Vec<(String, Option<String>, String, f64, i64, i64, String)> = sqlx::query_as(
            "SELECT id, device_id, framework, score, passing_controls, failing_controls, evaluated_at
             FROM cnapp_compliance_scores ORDER BY evaluated_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, device_id, framework, score, passing_controls, failing_controls, evaluated_at)| {
            CnappComplianceScoreRecord {
                id,
                device_id,
                framework,
                score,
                passing_controls: passing_controls as u32,
                failing_controls: failing_controls as u32,
                evaluated_at,
            }
        }).collect())
    }

    async fn list_compliance_violations(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappComplianceViolationRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, String, String, Option<String>, String, String)> =
            sqlx::query_as(
                "SELECT id, device_id, severity, title, resource_ref, status, detected_at
                 FROM cnapp_compliance_violations ORDER BY detected_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, severity, title, resource_ref, status, detected_at)| {
            CnappComplianceViolationRecord { id, device_id, severity, title, resource_ref, status, detected_at }
        }).collect())
    }

    async fn list_attack_paths(&self, limit: Option<i64>) -> Result<Vec<CnappAttackPathRecord>, DbError> {
        let limit = limit.unwrap_or(20);
        let rows: Vec<(String, Option<String>, String, String, String, Option<String>, Option<String>, i64, String)> =
            sqlx::query_as(
                "SELECT id, device_id, name, severity, status, entry_asset, target_asset, node_count, discovered_at
                 FROM cnapp_attack_paths ORDER BY discovered_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, name, severity, status, entry_asset, target_asset, node_count, discovered_at)| {
            CnappAttackPathRecord { id, device_id, name, severity, status, entry_asset, target_asset, node_count: node_count as u32, discovered_at }
        }).collect())
    }

    async fn list_attack_path_nodes(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappAttackPathNodeRecord>, DbError> {
        let limit = limit.unwrap_or(100);
        let rows: Vec<(String, Option<String>, String, String)> = sqlx::query_as(
            "SELECT id, path_id, node_kind, label FROM cnapp_attack_path_nodes ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, path_id, node_kind, label)| {
            CnappAttackPathNodeRecord { id, path_id, node_kind, label }
        }).collect())
    }

    async fn list_attack_path_edges(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<CnappAttackPathEdgeRecord>, DbError> {
        let limit = limit.unwrap_or(200);
        let rows: Vec<(String, Option<String>, String, String, String)> = sqlx::query_as(
            "SELECT id, path_id, source_node_id, target_node_id, edge_kind
             FROM cnapp_attack_path_edges ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, path_id, source_node_id, target_node_id, edge_kind)| {
            CnappAttackPathEdgeRecord { id, path_id, source_node_id, target_node_id, edge_kind }
        }).collect())
    }
}
