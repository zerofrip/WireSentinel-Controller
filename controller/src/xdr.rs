use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrIncidentRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub status: String,
    pub source: String,
    pub mitre_techniques: Vec<String>,
    pub detected_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrCaseRecord {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub status: String,
    pub priority: String,
    pub assignee: Option<String>,
    pub incident_ids: Vec<String>,
    pub opened_at: String,
    pub closed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrDetectionRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub rule_id: Option<String>,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub confidence: f64,
    pub detected_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrHuntRecord {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub query_kind: String,
    pub query_text: String,
    pub status: String,
    pub owner: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrPlaybookRecord {
    pub id: String,
    pub name: String,
    pub playbook_kind: String,
    pub enabled: bool,
    pub steps: Vec<serde_json::Value>,
    pub triggers: Vec<serde_json::Value>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrAttackGraphNode {
    pub id: String,
    pub incident_id: Option<String>,
    pub node_kind: String,
    pub label: String,
    pub entity_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrAttackGraphEdge {
    pub id: String,
    pub incident_id: Option<String>,
    pub source_node_id: String,
    pub target_node_id: String,
    pub edge_kind: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrMitreTechnique {
    pub id: String,
    pub technique_id: String,
    pub name: String,
    pub tactic: String,
    pub description: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrMitreMapping {
    pub id: String,
    pub detection_rule_id: Option<String>,
    pub technique_id: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrResponseActionRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub incident_id: Option<String>,
    pub action_kind: String,
    pub status: String,
    pub requested_by: Option<String>,
    pub parameters: serde_json::Value,
    pub result: serde_json::Value,
    pub requested_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrTelemetrySnapshot {
    pub id: String,
    pub device_id: String,
    pub edr_event_count: u32,
    pub ndr_event_count: u32,
    pub itdr_threat_count: u32,
    pub detection_count: u32,
    pub open_incident_count: u32,
    pub reported_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentsSummary {
    pub incident_count: i64,
    pub open_incidents: i64,
    pub high_severity: i64,
    pub incidents: Vec<XdrIncidentRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasesSummary {
    pub case_count: i64,
    pub open_cases: i64,
    pub cases: Vec<XdrCaseRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionsSummary {
    pub detection_count: i64,
    pub new_detections: i64,
    pub rule_count: i64,
    pub detections: Vec<XdrDetectionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntsSummary {
    pub hunt_count: i64,
    pub active_hunts: i64,
    pub result_count: i64,
    pub hunts: Vec<XdrHuntRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraphSummary {
    pub node_count: i64,
    pub edge_count: i64,
    pub nodes: Vec<XdrAttackGraphNode>,
    pub edges: Vec<XdrAttackGraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreSummary {
    pub technique_count: i64,
    pub mapping_count: i64,
    pub techniques: Vec<XdrMitreTechnique>,
    pub mappings: Vec<XdrMitreMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarSummary {
    pub playbook_count: i64,
    pub enabled_playbooks: i64,
    pub execution_count: i64,
    pub playbooks: Vec<XdrPlaybookRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrIncidentInput {
    pub device_id: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub source: Option<String>,
    pub mitre_techniques: Option<Vec<String>>,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrCaseInput {
    pub title: String,
    pub description: Option<String>,
    pub status: Option<String>,
    pub priority: Option<String>,
    pub assignee: Option<String>,
    pub incident_ids: Option<Vec<String>>,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrDetectionInput {
    pub device_id: Option<String>,
    pub rule_id: Option<String>,
    pub title: String,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub confidence: Option<f64>,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrHuntInput {
    pub name: String,
    pub description: Option<String>,
    pub query_kind: Option<String>,
    pub query_text: Option<String>,
    pub status: Option<String>,
    pub owner: Option<String>,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrPlaybookInput {
    pub name: String,
    pub playbook_kind: Option<String>,
    pub enabled: Option<bool>,
    pub steps: Option<Vec<serde_json::Value>>,
    pub triggers: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrEdrEventInput {
    pub event_kind: Option<String>,
    pub process_name: Option<String>,
    pub process_id: Option<i64>,
    pub parent_process_id: Option<i64>,
    pub user_name: Option<String>,
    pub file_path: Option<String>,
    pub command_line: Option<String>,
    pub hash_sha256: Option<String>,
    pub severity: Option<String>,
    pub details: Option<serde_json::Value>,
    pub observed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrNdrEventInput {
    pub event_kind: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<i64>,
    pub dst_port: Option<i64>,
    pub protocol: Option<String>,
    pub bytes: Option<i64>,
    pub severity: Option<String>,
    pub details: Option<serde_json::Value>,
    pub observed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrItdrThreatInput {
    pub threat_kind: Option<String>,
    pub user_id: Option<String>,
    pub identity_provider: Option<String>,
    pub severity: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrTelemetryIngest {
    pub edr_events: Option<Vec<XdrEdrEventInput>>,
    pub ndr_events: Option<Vec<XdrNdrEventInput>>,
    pub itdr_threats: Option<Vec<XdrItdrThreatInput>>,
    pub detections: Option<Vec<XdrDetectionInput>>,
    pub incidents: Option<Vec<XdrIncidentInput>>,
    pub reported_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrResponseExecuteInput {
    pub device_id: Option<String>,
    pub incident_id: Option<String>,
    pub action_kind: String,
    pub requested_by: Option<String>,
    pub parameters: Option<serde_json::Value>,
}

pub struct XdrManager {
    pool: DbPool,
}

impl XdrManager {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn incidents_summary(&self) -> Result<IncidentsSummary, DbError> {
        let incidents = self.list_incidents(Some(50)).await?;
        let incident_count = incidents.len() as i64;
        let open_incidents = incidents.iter().filter(|i| i.status == "open").count() as i64;
        let high_severity = incidents
            .iter()
            .filter(|i| i.severity == "high" || i.severity == "critical")
            .count() as i64;
        Ok(IncidentsSummary {
            incident_count,
            open_incidents,
            high_severity,
            incidents,
        })
    }

    pub async fn create_incident(&self, input: &XdrIncidentInput) -> Result<XdrIncidentRecord, DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let detected_at = input.detected_at.clone().unwrap_or_else(|| now.clone());
        let severity = input.severity.clone().unwrap_or_else(|| "medium".into());
        let status = input.status.clone().unwrap_or_else(|| "open".into());
        let source = input.source.clone().unwrap_or_else(|| "xdr".into());
        let mitre_json = serde_json::to_string(&input.mitre_techniques.clone().unwrap_or_default())
            .unwrap_or_else(|_| "[]".into());
        let details_json = input
            .details
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "{}".into());

        sqlx::query(
            "INSERT INTO xdr_incidents (
                id, device_id, title, description, severity, status, source,
                mitre_techniques_json, details_json, detected_at, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.device_id)
        .bind(&input.title)
        .bind(&input.description)
        .bind(&severity)
        .bind(&status)
        .bind(&source)
        .bind(&mitre_json)
        .bind(&details_json)
        .bind(&detected_at)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(XdrIncidentRecord {
            id,
            device_id: input.device_id.clone(),
            title: input.title.clone(),
            description: input.description.clone(),
            severity,
            status,
            source,
            mitre_techniques: input.mitre_techniques.clone().unwrap_or_default(),
            detected_at,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn cases_summary(&self) -> Result<CasesSummary, DbError> {
        let cases = self.list_cases(Some(50)).await?;
        let case_count = cases.len() as i64;
        let open_cases = cases.iter().filter(|c| c.status == "open").count() as i64;
        Ok(CasesSummary {
            case_count,
            open_cases,
            cases,
        })
    }

    pub async fn create_case(&self, input: &XdrCaseInput) -> Result<XdrCaseRecord, DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let status = input.status.clone().unwrap_or_else(|| "open".into());
        let priority = input.priority.clone().unwrap_or_else(|| "medium".into());
        let incident_ids_json =
            serde_json::to_string(&input.incident_ids.clone().unwrap_or_default())
                .unwrap_or_else(|_| "[]".into());
        let details_json = input
            .details
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "{}".into());

        sqlx::query(
            "INSERT INTO xdr_cases (
                id, title, description, status, priority, assignee, incident_ids_json,
                details_json, opened_at, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.title)
        .bind(&input.description)
        .bind(&status)
        .bind(&priority)
        .bind(&input.assignee)
        .bind(&incident_ids_json)
        .bind(&details_json)
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(XdrCaseRecord {
            id,
            title: input.title.clone(),
            description: input.description.clone(),
            status,
            priority,
            assignee: input.assignee.clone(),
            incident_ids: input.incident_ids.clone().unwrap_or_default(),
            opened_at: now.clone(),
            closed_at: None,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn detections_summary(&self) -> Result<DetectionsSummary, DbError> {
        let detections = self.list_detections(Some(50)).await?;
        let detection_count = detections.len() as i64;
        let new_detections = detections.iter().filter(|d| d.status == "new").count() as i64;
        let rule_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM xdr_detection_rules")
                .fetch_one(&self.pool)
                .await?;
        Ok(DetectionsSummary {
            detection_count,
            new_detections,
            rule_count: rule_count.0,
            detections,
        })
    }

    pub async fn create_detection(
        &self,
        input: &XdrDetectionInput,
    ) -> Result<XdrDetectionRecord, DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let detected_at = input.detected_at.clone().unwrap_or_else(|| now.clone());
        let severity = input.severity.clone().unwrap_or_else(|| "medium".into());
        let status = input.status.clone().unwrap_or_else(|| "new".into());
        let confidence = input.confidence.unwrap_or(0.5);
        let details_json = input
            .details
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "{}".into());

        sqlx::query(
            "INSERT INTO xdr_detections (
                id, device_id, rule_id, title, severity, status, confidence,
                details_json, detected_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.device_id)
        .bind(&input.rule_id)
        .bind(&input.title)
        .bind(&severity)
        .bind(&status)
        .bind(confidence)
        .bind(&details_json)
        .bind(&detected_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(XdrDetectionRecord {
            id,
            device_id: input.device_id.clone(),
            rule_id: input.rule_id.clone(),
            title: input.title.clone(),
            severity,
            status,
            confidence,
            detected_at,
            created_at: now,
        })
    }

    pub async fn hunts_summary(&self) -> Result<HuntsSummary, DbError> {
        let hunts = self.list_hunts(Some(50)).await?;
        let hunt_count = hunts.len() as i64;
        let active_hunts = hunts
            .iter()
            .filter(|h| h.status == "running" || h.status == "active")
            .count() as i64;
        let result_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM xdr_hunt_results")
                .fetch_one(&self.pool)
                .await?;
        Ok(HuntsSummary {
            hunt_count,
            active_hunts,
            result_count: result_count.0,
            hunts,
        })
    }

    pub async fn create_hunt(&self, input: &XdrHuntInput) -> Result<XdrHuntRecord, DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let query_kind = input.query_kind.clone().unwrap_or_else(|| "kql".into());
        let query_text = input.query_text.clone().unwrap_or_default();
        let status = input.status.clone().unwrap_or_else(|| "draft".into());
        let details_json = input
            .details
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "{}".into());

        sqlx::query(
            "INSERT INTO xdr_hunts (
                id, name, description, query_kind, query_text, status, owner,
                details_json, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&query_kind)
        .bind(&query_text)
        .bind(&status)
        .bind(&input.owner)
        .bind(&details_json)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(XdrHuntRecord {
            id,
            name: input.name.clone(),
            description: input.description.clone(),
            query_kind,
            query_text,
            status,
            owner: input.owner.clone(),
            started_at: None,
            completed_at: None,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn attack_graph_summary(&self) -> Result<AttackGraphSummary, DbError> {
        let nodes = self.list_attack_nodes(Some(100)).await?;
        let edges = self.list_attack_edges(Some(200)).await?;
        Ok(AttackGraphSummary {
            node_count: nodes.len() as i64,
            edge_count: edges.len() as i64,
            nodes,
            edges,
        })
    }

    pub async fn mitre_summary(&self) -> Result<MitreSummary, DbError> {
        let techniques = self.list_mitre_techniques().await?;
        let mappings = self.list_mitre_mappings().await?;
        Ok(MitreSummary {
            technique_count: techniques.len() as i64,
            mapping_count: mappings.len() as i64,
            techniques,
            mappings,
        })
    }

    pub async fn soar_summary(&self) -> Result<SoarSummary, DbError> {
        let playbooks = self.list_playbooks().await?;
        let playbook_count = playbooks.len() as i64;
        let enabled_playbooks = playbooks.iter().filter(|p| p.enabled).count() as i64;
        let execution_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM xdr_playbook_executions")
                .fetch_one(&self.pool)
                .await?;
        Ok(SoarSummary {
            playbook_count,
            enabled_playbooks,
            execution_count: execution_count.0,
            playbooks,
        })
    }

    pub async fn create_playbook(
        &self,
        input: &XdrPlaybookInput,
    ) -> Result<XdrPlaybookRecord, DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let playbook_kind = input.playbook_kind.clone().unwrap_or_else(|| "response".into());
        let enabled = input.enabled.unwrap_or(true);
        let steps_json =
            serde_json::to_string(&input.steps.clone().unwrap_or_default()).unwrap_or_else(|_| "[]".into());
        let triggers_json = serde_json::to_string(&input.triggers.clone().unwrap_or_default())
            .unwrap_or_else(|_| "[]".into());

        sqlx::query(
            "INSERT INTO xdr_playbooks (
                id, name, playbook_kind, enabled, steps_json, triggers_json, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.name)
        .bind(&playbook_kind)
        .bind(i64::from(enabled))
        .bind(&steps_json)
        .bind(&triggers_json)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(XdrPlaybookRecord {
            id,
            name: input.name.clone(),
            playbook_kind,
            enabled,
            steps: input.steps.clone().unwrap_or_default(),
            triggers: input.triggers.clone().unwrap_or_default(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn ingest_telemetry(
        &self,
        device_id: &str,
        payload: &XdrTelemetryIngest,
    ) -> Result<XdrTelemetrySnapshot, DbError> {
        let now = now_iso();
        let reported_at = payload.reported_at.clone().unwrap_or_else(|| now.clone());
        let mut edr_count = 0u32;
        let mut ndr_count = 0u32;
        let mut itdr_count = 0u32;
        let mut detection_count = 0u32;
        let mut incident_count = 0u32;

        if let Some(events) = &payload.edr_events {
            for event in events {
                self.insert_edr_event(device_id, event).await?;
                edr_count += 1;
            }
        }

        if let Some(events) = &payload.ndr_events {
            for event in events {
                self.insert_ndr_event(device_id, event).await?;
                ndr_count += 1;
            }
        }

        if let Some(threats) = &payload.itdr_threats {
            for threat in threats {
                self.insert_itdr_threat(device_id, threat).await?;
                itdr_count += 1;
            }
        }

        if let Some(detections) = &payload.detections {
            for detection in detections {
                let mut d = detection.clone();
                if d.device_id.is_none() {
                    d.device_id = Some(device_id.to_string());
                }
                self.create_detection(&d).await?;
                detection_count += 1;
            }
        }

        if let Some(incidents) = &payload.incidents {
            for incident in incidents {
                let mut i = incident.clone();
                if i.device_id.is_none() {
                    i.device_id = Some(device_id.to_string());
                }
                self.create_incident(&i).await?;
                incident_count += 1;
            }
        }

        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO xdr_telemetry_snapshots (
                id, device_id, edr_event_count, ndr_event_count, itdr_threat_count,
                detection_count, open_incident_count, reported_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(i64::from(edr_count))
        .bind(i64::from(ndr_count))
        .bind(i64::from(itdr_count))
        .bind(i64::from(detection_count))
        .bind(i64::from(incident_count))
        .bind(&reported_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(XdrTelemetrySnapshot {
            id,
            device_id: device_id.to_string(),
            edr_event_count: edr_count,
            ndr_event_count: ndr_count,
            itdr_threat_count: itdr_count,
            detection_count,
            open_incident_count: incident_count,
            reported_at,
        })
    }

    pub async fn execute_response(
        &self,
        input: &XdrResponseExecuteInput,
    ) -> Result<XdrResponseActionRecord, DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let parameters_json = input
            .parameters
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "{}".into());
        let result_json = serde_json::json!({
            "status": "completed",
            "message": format!("Action {} executed", input.action_kind),
        })
        .to_string();

        sqlx::query(
            "INSERT INTO xdr_response_actions (
                id, device_id, incident_id, action_kind, status, requested_by,
                parameters_json, result_json, requested_at, completed_at, created_at
             ) VALUES (?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.device_id)
        .bind(&input.incident_id)
        .bind(&input.action_kind)
        .bind(&input.requested_by)
        .bind(&parameters_json)
        .bind(&result_json)
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(XdrResponseActionRecord {
            id,
            device_id: input.device_id.clone(),
            incident_id: input.incident_id.clone(),
            action_kind: input.action_kind.clone(),
            status: "completed".into(),
            requested_by: input.requested_by.clone(),
            parameters: input.parameters.clone().unwrap_or(serde_json::json!({})),
            result: serde_json::from_str(&result_json).unwrap_or(serde_json::json!({})),
            requested_at: now.clone(),
            completed_at: Some(now),
        })
    }

    pub async fn seed_defaults(&self) -> Result<(), DbError> {
        let rule_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM xdr_detection_rules")
                .fetch_one(&self.pool)
                .await?;
        if rule_count.0 == 0 {
            let now = now_iso();
            let rules = [
                ("Suspicious PowerShell", "sigma", "high"),
                ("Lateral SMB Movement", "sigma", "medium"),
                ("Beaconing Detection", "behavioral", "high"),
            ];
            for (name, kind, severity) in rules {
                let id = Uuid::new_v4().to_string();
                sqlx::query(
                    "INSERT INTO xdr_detection_rules (
                        id, name, rule_kind, enabled, severity, query_json, mitre_techniques_json,
                        created_at, updated_at
                     ) VALUES (?, ?, ?, 1, ?, '{}', '[]', ?, ?)",
                )
                .bind(&id)
                .bind(name)
                .bind(kind)
                .bind(severity)
                .bind(&now)
                .bind(&now)
                .execute(&self.pool)
                .await?;
            }
        }

        let technique_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM xdr_mitre_techniques")
                .fetch_one(&self.pool)
                .await?;
        if technique_count.0 == 0 {
            let now = now_iso();
            let techniques = [
                ("T1059", "Command and Scripting Interpreter", "execution"),
                ("T1071", "Application Layer Protocol", "command-and-control"),
                ("T1021", "Remote Services", "lateral-movement"),
            ];
            for (tid, name, tactic) in techniques {
                let id = Uuid::new_v4().to_string();
                sqlx::query(
                    "INSERT INTO xdr_mitre_techniques (
                        id, technique_id, name, tactic, description, url, created_at
                     ) VALUES (?, ?, ?, ?, NULL, NULL, ?)",
                )
                .bind(&id)
                .bind(tid)
                .bind(name)
                .bind(tactic)
                .bind(&now)
                .execute(&self.pool)
                .await?;
            }
        }

        let playbook_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM xdr_playbooks")
                .fetch_one(&self.pool)
                .await?;
        if playbook_count.0 == 0 {
            let now = now_iso();
            let playbooks = [
                ("Isolate Host", "response"),
                ("Collect Forensics", "investigation"),
                ("Reset Credentials", "remediation"),
            ];
            for (name, kind) in playbooks {
                let id = Uuid::new_v4().to_string();
                sqlx::query(
                    "INSERT INTO xdr_playbooks (
                        id, name, playbook_kind, enabled, steps_json, triggers_json, created_at, updated_at
                     ) VALUES (?, ?, ?, 1, '[]', '[]', ?, ?)",
                )
                .bind(&id)
                .bind(name)
                .bind(kind)
                .bind(&now)
                .bind(&now)
                .execute(&self.pool)
                .await?;
            }
        }

        Ok(())
    }

    async fn list_incidents(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<XdrIncidentRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(
            String,
            Option<String>,
            String,
            Option<String>,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        )> = sqlx::query_as(
            "SELECT id, device_id, title, description, severity, status, source,
                    mitre_techniques_json, detected_at, created_at, updated_at
             FROM xdr_incidents ORDER BY detected_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    device_id,
                    title,
                    description,
                    severity,
                    status,
                    source,
                    mitre_json,
                    detected_at,
                    created_at,
                    updated_at,
                )| {
                    XdrIncidentRecord {
                        id,
                        device_id,
                        title,
                        description,
                        severity,
                        status,
                        source,
                        mitre_techniques: serde_json::from_str(&mitre_json).unwrap_or_default(),
                        detected_at,
                        created_at,
                        updated_at,
                    }
                },
            )
            .collect())
    }

    async fn list_cases(&self, limit: Option<i64>) -> Result<Vec<XdrCaseRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(
            String,
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            String,
            String,
        )> = sqlx::query_as(
            "SELECT id, title, description, status, priority, assignee, incident_ids_json,
                    opened_at, closed_at, created_at, updated_at
             FROM xdr_cases ORDER BY updated_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    title,
                    description,
                    status,
                    priority,
                    assignee,
                    incident_ids_json,
                    opened_at,
                    closed_at,
                    created_at,
                    updated_at,
                )| {
                    XdrCaseRecord {
                        id,
                        title,
                        description,
                        status,
                        priority,
                        assignee,
                        incident_ids: serde_json::from_str(&incident_ids_json).unwrap_or_default(),
                        opened_at,
                        closed_at,
                        created_at,
                        updated_at,
                    }
                },
            )
            .collect())
    }

    async fn list_detections(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<XdrDetectionRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(
            String,
            Option<String>,
            Option<String>,
            String,
            String,
            String,
            f64,
            String,
            String,
        )> = sqlx::query_as(
            "SELECT id, device_id, rule_id, title, severity, status, confidence, detected_at, created_at
             FROM xdr_detections ORDER BY detected_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    device_id,
                    rule_id,
                    title,
                    severity,
                    status,
                    confidence,
                    detected_at,
                    created_at,
                )| {
                    XdrDetectionRecord {
                        id,
                        device_id,
                        rule_id,
                        title,
                        severity,
                        status,
                        confidence,
                        detected_at,
                        created_at,
                    }
                },
            )
            .collect())
    }

    async fn list_hunts(&self, limit: Option<i64>) -> Result<Vec<XdrHuntRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(
            String,
            String,
            Option<String>,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            String,
        )> = sqlx::query_as(
            "SELECT id, name, description, query_kind, query_text, status, owner,
                    started_at, completed_at, created_at, updated_at
             FROM xdr_hunts ORDER BY updated_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    description,
                    query_kind,
                    query_text,
                    status,
                    owner,
                    started_at,
                    completed_at,
                    created_at,
                    updated_at,
                )| {
                    XdrHuntRecord {
                        id,
                        name,
                        description,
                        query_kind,
                        query_text,
                        status,
                        owner,
                        started_at,
                        completed_at,
                        created_at,
                        updated_at,
                    }
                },
            )
            .collect())
    }

    async fn list_playbooks(&self) -> Result<Vec<XdrPlaybookRecord>, DbError> {
        let rows: Vec<(String, String, String, i64, String, String, String, String)> =
            sqlx::query_as(
                "SELECT id, name, playbook_kind, enabled, steps_json, triggers_json, created_at, updated_at
                 FROM xdr_playbooks ORDER BY updated_at DESC",
            )
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, name, playbook_kind, enabled, steps_json, triggers_json, created_at, updated_at)| {
                    XdrPlaybookRecord {
                        id,
                        name,
                        playbook_kind,
                        enabled: enabled != 0,
                        steps: serde_json::from_str(&steps_json).unwrap_or_default(),
                        triggers: serde_json::from_str(&triggers_json).unwrap_or_default(),
                        created_at,
                        updated_at,
                    }
                },
            )
            .collect())
    }

    async fn list_attack_nodes(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<XdrAttackGraphNode>, DbError> {
        let limit = limit.unwrap_or(100);
        let rows: Vec<(String, Option<String>, String, String, Option<String>)> = sqlx::query_as(
            "SELECT id, incident_id, node_kind, label, entity_id
             FROM xdr_attack_graph_nodes ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(id, incident_id, node_kind, label, entity_id)| XdrAttackGraphNode {
                id,
                incident_id,
                node_kind,
                label,
                entity_id,
            })
            .collect())
    }

    async fn list_attack_edges(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<XdrAttackGraphEdge>, DbError> {
        let limit = limit.unwrap_or(200);
        let rows: Vec<(String, Option<String>, String, String, String, Option<String>)> =
            sqlx::query_as(
                "SELECT id, incident_id, source_node_id, target_node_id, edge_kind, label
                 FROM xdr_attack_graph_edges ORDER BY created_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, incident_id, source_node_id, target_node_id, edge_kind, label)| {
                    XdrAttackGraphEdge {
                        id,
                        incident_id,
                        source_node_id,
                        target_node_id,
                        edge_kind,
                        label,
                    }
                },
            )
            .collect())
    }

    async fn list_mitre_techniques(&self) -> Result<Vec<XdrMitreTechnique>, DbError> {
        let rows: Vec<(String, String, String, String, Option<String>, Option<String>)> =
            sqlx::query_as(
                "SELECT id, technique_id, name, tactic, description, url
                 FROM xdr_mitre_techniques ORDER BY technique_id",
            )
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(|(id, technique_id, name, tactic, description, url)| XdrMitreTechnique {
                id,
                technique_id,
                name,
                tactic,
                description,
                url,
            })
            .collect())
    }

    async fn list_mitre_mappings(&self) -> Result<Vec<XdrMitreMapping>, DbError> {
        let rows: Vec<(String, Option<String>, String, f64)> = sqlx::query_as(
            "SELECT id, detection_rule_id, technique_id, confidence
             FROM xdr_mitre_mappings ORDER BY technique_id",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(id, detection_rule_id, technique_id, confidence)| XdrMitreMapping {
                id,
                detection_rule_id,
                technique_id,
                confidence,
            })
            .collect())
    }

    async fn insert_edr_event(
        &self,
        device_id: &str,
        input: &XdrEdrEventInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let observed_at = input.observed_at.clone().unwrap_or_else(|| now.clone());
        let details_json = input
            .details
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "{}".into());

        sqlx::query(
            "INSERT INTO xdr_edr_events (
                id, device_id, event_kind, process_name, process_id, parent_process_id,
                user_name, file_path, command_line, hash_sha256, severity, details_json,
                observed_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(input.event_kind.as_deref().unwrap_or("process"))
        .bind(&input.process_name)
        .bind(input.process_id)
        .bind(input.parent_process_id)
        .bind(&input.user_name)
        .bind(&input.file_path)
        .bind(&input.command_line)
        .bind(&input.hash_sha256)
        .bind(input.severity.as_deref().unwrap_or("info"))
        .bind(&details_json)
        .bind(&observed_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn insert_ndr_event(
        &self,
        device_id: &str,
        input: &XdrNdrEventInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let observed_at = input.observed_at.clone().unwrap_or_else(|| now.clone());
        let details_json = input
            .details
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "{}".into());

        sqlx::query(
            "INSERT INTO xdr_ndr_events (
                id, device_id, event_kind, src_ip, dst_ip, src_port, dst_port,
                protocol, bytes, severity, details_json, observed_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(input.event_kind.as_deref().unwrap_or("flow"))
        .bind(&input.src_ip)
        .bind(&input.dst_ip)
        .bind(input.src_port)
        .bind(input.dst_port)
        .bind(&input.protocol)
        .bind(input.bytes)
        .bind(input.severity.as_deref().unwrap_or("info"))
        .bind(&details_json)
        .bind(&observed_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn insert_itdr_threat(
        &self,
        device_id: &str,
        input: &XdrItdrThreatInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let detected_at = input.detected_at.clone().unwrap_or_else(|| now.clone());
        let details_json = input
            .details
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "{}".into());

        sqlx::query(
            "INSERT INTO xdr_itdr_threats (
                id, device_id, threat_kind, user_id, identity_provider, severity,
                title, description, details_json, detected_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(input.threat_kind.as_deref().unwrap_or("credential"))
        .bind(&input.user_id)
        .bind(&input.identity_provider)
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
}
