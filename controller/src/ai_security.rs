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
pub struct AiCopilotQueryRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub query_text: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCopilotResponseRecord {
    pub id: String,
    pub query_id: String,
    pub response_text: String,
    pub model_id: String,
    pub tokens_used: u32,
    pub latency_ms: u32,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCopilotQueryResult {
    pub query: AiCopilotQueryRecord,
    pub response: AiCopilotResponseRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiInvestigationRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub status: String,
    pub severity: String,
    pub priority: String,
    pub owner: Option<String>,
    pub source: String,
    pub opened_at: String,
    pub closed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiInvestigationArtifactRecord {
    pub id: String,
    pub investigation_id: String,
    pub artifact_kind: String,
    pub name: String,
    pub uri: Option<String>,
    pub collected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiInvestigationTimelineRecord {
    pub id: String,
    pub investigation_id: String,
    pub event_kind: String,
    pub title: String,
    pub description: Option<String>,
    pub actor: Option<String>,
    pub occurred_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCorrelatedThreatRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub threat_kind: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub status: String,
    pub confidence: f64,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCorrelationLinkRecord {
    pub id: String,
    pub threat_id: String,
    pub entity_kind: String,
    pub entity_id: String,
    pub link_kind: String,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiKgNodeRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub node_kind: String,
    pub label: String,
    pub entity_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiKgEdgeRecord {
    pub id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub edge_kind: String,
    pub label: Option<String>,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiDetectionSuggestionRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub investigation_id: Option<String>,
    pub rule_title: String,
    pub rule_logic: String,
    pub severity: String,
    pub confidence: f64,
    pub status: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPlaybookSuggestionRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub investigation_id: Option<String>,
    pub name: String,
    pub playbook_kind: String,
    pub status: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPolicySuggestionRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub investigation_id: Option<String>,
    pub policy_kind: String,
    pub title: String,
    pub status: String,
    pub rationale: Option<String>,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiIntelReportRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub report_kind: String,
    pub title: String,
    pub summary: Option<String>,
    pub published_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiExecutiveReportRecord {
    pub id: String,
    pub report_kind: String,
    pub title: String,
    pub summary: Option<String>,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
    pub published_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRiskScoreRecord {
    pub id: String,
    pub device_id: Option<String>,
    pub scope_kind: String,
    pub risk_score: u8,
    pub risk_level: String,
    pub evaluated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTelemetrySnapshot {
    pub id: String,
    pub device_id: String,
    pub investigation_count: u32,
    pub threat_count: u32,
    pub suggestion_count: u32,
    pub kg_node_count: u32,
    pub reported_at: String,
}

// --- Summaries ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationsSummary {
    pub investigation_count: i64,
    pub open_investigations: i64,
    pub high_severity: i64,
    pub investigations: Vec<AiInvestigationRecord>,
    pub artifacts: Vec<AiInvestigationArtifactRecord>,
    pub timelines: Vec<AiInvestigationTimelineRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatsSummary {
    pub threat_count: i64,
    pub open_threats: i64,
    pub high_confidence: i64,
    pub threats: Vec<AiCorrelatedThreatRecord>,
    pub links: Vec<AiCorrelationLinkRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeGraphSummary {
    pub node_count: i64,
    pub edge_count: i64,
    pub nodes: Vec<AiKgNodeRecord>,
    pub edges: Vec<AiKgEdgeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportsSummary {
    pub intel_count: i64,
    pub executive_count: i64,
    pub intel_reports: Vec<AiIntelReportRecord>,
    pub executive_reports: Vec<AiExecutiveReportRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRiskSummary {
    pub score_count: i64,
    pub avg_risk_score: f64,
    pub high_risk_count: i64,
    pub scores: Vec<AiRiskScoreRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiDetectionsSummary {
    pub suggestion_count: i64,
    pub pending_suggestions: i64,
    pub suggestions: Vec<AiDetectionSuggestionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybooksSummary {
    pub suggestion_count: i64,
    pub pending_suggestions: i64,
    pub suggestions: Vec<AiPlaybookSuggestionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoliciesSummary {
    pub suggestion_count: i64,
    pub pending_suggestions: i64,
    pub suggestions: Vec<AiPolicySuggestionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceSummary {
    pub report_count: i64,
    pub reports: Vec<AiIntelReportRecord>,
}

// --- Inputs ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCopilotQueryInput {
    pub query_text: String,
    pub session_id: Option<String>,
    pub context: Option<serde_json::Value>,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiInvestigationInput {
    pub device_id: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub priority: Option<String>,
    pub owner: Option<String>,
    pub source: Option<String>,
    pub tags: Option<Vec<String>>,
    pub details: Option<serde_json::Value>,
    pub opened_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCorrelatedThreatInput {
    pub threat_kind: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub confidence: Option<f64>,
    pub source_refs: Option<Vec<String>>,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiKgNodeInput {
    pub node_kind: Option<String>,
    pub label: String,
    pub entity_ref: Option<String>,
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiKgEdgeInput {
    pub source_node_id: String,
    pub target_node_id: String,
    pub edge_kind: Option<String>,
    pub label: Option<String>,
    pub weight: Option<f64>,
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiGenerateInput {
    pub device_id: Option<String>,
    pub investigation_id: Option<String>,
    pub context: Option<String>,
    pub threat_ref: Option<String>,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTelemetryIngest {
    pub investigations: Option<Vec<AiInvestigationInput>>,
    pub threats: Option<Vec<AiCorrelatedThreatInput>>,
    pub kg_nodes: Option<Vec<AiKgNodeInput>>,
    pub kg_edges: Option<Vec<AiKgEdgeInput>>,
    pub reported_at: Option<String>,
}

pub struct AiSecurityManager {
    pool: DbPool,
}

impl AiSecurityManager {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn copilot_query(
        &self,
        device_id: Option<&str>,
        user_id: Option<&str>,
        input: &AiCopilotQueryInput,
    ) -> Result<AiCopilotQueryResult, DbError> {
        let now = now_iso();
        let query_id = Uuid::new_v4().to_string();
        let response_id = Uuid::new_v4().to_string();
        let context_json = input
            .context
            .as_ref()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "{}".into());
        let details_json = details_json!(input);
        let prompt_hash = format!("{:x}", md5_hash(&input.query_text));

        sqlx::query(
            "INSERT INTO ai_copilot_queries (
                id, device_id, user_id, session_id, query_text, context_json,
                status, details_json, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, 'completed', ?, ?)",
        )
        .bind(&query_id)
        .bind(device_id)
        .bind(user_id)
        .bind(&input.session_id)
        .bind(&input.query_text)
        .bind(&context_json)
        .bind(&details_json)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        let response_text = format!(
            "Analysis for: {}. Correlated threats and investigation context were evaluated. \
             Recommended next steps: review detections, validate identity signals, and isolate affected endpoints if confidence exceeds threshold.",
            input.query_text
        );
        let citations = serde_json::json!([
            {"source": "knowledge-graph", "ref": "kg-threat-correlation"},
            {"source": "intel", "ref": "ai-intel-reports"}
        ]);

        sqlx::query(
            "INSERT INTO ai_copilot_responses (
                id, query_id, response_text, model_id, tokens_used, latency_ms,
                citations_json, details_json, created_at
             ) VALUES (?, ?, ?, 'wiresentinel-copilot', ?, 120, ?, '{}', ?)",
        )
        .bind(&response_id)
        .bind(&query_id)
        .bind(&response_text)
        .bind(i64::from(response_text.len() as u32 / 4))
        .bind(citations.to_string())
        .bind(&now)
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "INSERT INTO ai_prompt_audit_log (
                id, user_id, device_id, prompt_kind, prompt_hash, model_id,
                tokens_in, tokens_out, blocked, details_json, created_at
             ) VALUES (?, ?, ?, 'copilot', ?, 'wiresentinel-copilot', ?, ?, 0, '{}', ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(device_id)
        .bind(&prompt_hash)
        .bind(i64::from(input.query_text.len() as u32 / 4))
        .bind(i64::from(response_text.len() as u32 / 4))
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(AiCopilotQueryResult {
            query: AiCopilotQueryRecord {
                id: query_id.clone(),
                device_id: device_id.map(str::to_string),
                user_id: user_id.map(str::to_string),
                session_id: input.session_id.clone(),
                query_text: input.query_text.clone(),
                status: "completed".into(),
                created_at: now.clone(),
            },
            response: AiCopilotResponseRecord {
                id: response_id,
                query_id,
                response_text,
                model_id: "wiresentinel-copilot".into(),
                tokens_used: 0,
                latency_ms: 120,
                created_at: now,
            },
        })
    }

    pub async fn investigations_summary(&self) -> Result<InvestigationsSummary, DbError> {
        let investigations = self.list_investigations(Some(50)).await?;
        let artifacts = self.list_artifacts(Some(50)).await?;
        let timelines = self.list_timelines(Some(50)).await?;
        Ok(InvestigationsSummary {
            investigation_count: investigations.len() as i64,
            open_investigations: investigations.iter().filter(|i| i.status == "open").count() as i64,
            high_severity: investigations
                .iter()
                .filter(|i| i.severity == "high" || i.severity == "critical")
                .count() as i64,
            investigations,
            artifacts,
            timelines,
        })
    }

    pub async fn create_investigation(
        &self,
        input: &AiInvestigationInput,
    ) -> Result<AiInvestigationRecord, DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let opened_at = input.opened_at.clone().unwrap_or_else(|| now.clone());
        let status = input.status.clone().unwrap_or_else(|| "open".into());
        let severity = input.severity.clone().unwrap_or_else(|| "medium".into());
        let priority = input.priority.clone().unwrap_or_else(|| "medium".into());
        let source = input.source.clone().unwrap_or_else(|| "ai".into());
        let tags_json = serde_json::to_string(&input.tags.clone().unwrap_or_default())
            .unwrap_or_else(|_| "[]".into());
        let details_json = details_json!(input);

        sqlx::query(
            "INSERT INTO ai_investigations (
                id, device_id, title, description, status, severity, priority, owner, source,
                tags_json, details_json, opened_at, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.device_id)
        .bind(&input.title)
        .bind(&input.description)
        .bind(&status)
        .bind(&severity)
        .bind(&priority)
        .bind(&input.owner)
        .bind(&source)
        .bind(&tags_json)
        .bind(&details_json)
        .bind(&opened_at)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        let timeline_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO ai_investigation_timelines (
                id, investigation_id, event_kind, title, description, actor,
                details_json, occurred_at, created_at
             ) VALUES (?, ?, 'opened', 'Investigation opened', ?, ?, '{}', ?, ?)",
        )
        .bind(&timeline_id)
        .bind(&id)
        .bind(&input.description)
        .bind(&input.owner)
        .bind(&opened_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(AiInvestigationRecord {
            id,
            device_id: input.device_id.clone(),
            title: input.title.clone(),
            description: input.description.clone(),
            status,
            severity,
            priority,
            owner: input.owner.clone(),
            source,
            opened_at,
            closed_at: None,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn get_investigation(&self, id: &str) -> Result<AiInvestigationRecord, DbError> {
        let row: Option<(String, Option<String>, String, Option<String>, String, String, String, Option<String>, String, String, Option<String>, String, String)> =
            sqlx::query_as(
                "SELECT id, device_id, title, description, status, severity, priority, owner, source,
                        opened_at, closed_at, created_at, updated_at
                 FROM ai_investigations WHERE id = ?",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        let Some((id, device_id, title, description, status, severity, priority, owner, source, opened_at, closed_at, created_at, updated_at)) = row else {
            return Err(DbError::NotFound(format!("investigation {id}")));
        };
        Ok(AiInvestigationRecord {
            id,
            device_id,
            title,
            description,
            status,
            severity,
            priority,
            owner,
            source,
            opened_at,
            closed_at,
            created_at,
            updated_at,
        })
    }

    pub async fn threats_summary(&self) -> Result<ThreatsSummary, DbError> {
        let threats = self.list_threats(Some(50)).await?;
        let links = self.list_correlation_links(Some(100)).await?;
        Ok(ThreatsSummary {
            threat_count: threats.len() as i64,
            open_threats: threats.iter().filter(|t| t.status == "open").count() as i64,
            high_confidence: threats.iter().filter(|t| t.confidence >= 0.8).count() as i64,
            threats,
            links,
        })
    }

    pub async fn knowledge_graph_summary(&self) -> Result<KnowledgeGraphSummary, DbError> {
        let nodes = self.list_kg_nodes(Some(100)).await?;
        let edges = self.list_kg_edges(Some(200)).await?;
        Ok(KnowledgeGraphSummary {
            node_count: nodes.len() as i64,
            edge_count: edges.len() as i64,
            nodes,
            edges,
        })
    }

    pub async fn reports_summary(&self) -> Result<ReportsSummary, DbError> {
        let intel_reports = self.list_intel_reports(Some(20)).await?;
        let executive_reports = self.list_executive_reports(Some(10)).await?;
        Ok(ReportsSummary {
            intel_count: intel_reports.len() as i64,
            executive_count: executive_reports.len() as i64,
            intel_reports,
            executive_reports,
        })
    }

    pub async fn intelligence_summary(&self) -> Result<IntelligenceSummary, DbError> {
        let reports = self.list_intel_reports(Some(50)).await?;
        Ok(IntelligenceSummary {
            report_count: reports.len() as i64,
            reports,
        })
    }

    pub async fn risk_summary(&self) -> Result<AiRiskSummary, DbError> {
        let scores = self.list_risk_scores(Some(20)).await?;
        let avg_risk_score = if scores.is_empty() {
            0.0
        } else {
            scores.iter().map(|s| f64::from(s.risk_score)).sum::<f64>() / scores.len() as f64
        };
        Ok(AiRiskSummary {
            score_count: scores.len() as i64,
            avg_risk_score,
            high_risk_count: scores
                .iter()
                .filter(|s| s.risk_level == "high" || s.risk_level == "critical")
                .count() as i64,
            scores,
        })
    }

    pub async fn detections_summary(&self) -> Result<AiDetectionsSummary, DbError> {
        let suggestions = self.list_detection_suggestions(Some(50)).await?;
        Ok(AiDetectionsSummary {
            suggestion_count: suggestions.len() as i64,
            pending_suggestions: suggestions.iter().filter(|s| s.status == "suggested").count() as i64,
            suggestions,
        })
    }

    pub async fn playbooks_summary(&self) -> Result<PlaybooksSummary, DbError> {
        let suggestions = self.list_playbook_suggestions(Some(50)).await?;
        Ok(PlaybooksSummary {
            suggestion_count: suggestions.len() as i64,
            pending_suggestions: suggestions.iter().filter(|s| s.status == "suggested").count() as i64,
            suggestions,
        })
    }

    pub async fn policies_summary(&self) -> Result<PoliciesSummary, DbError> {
        let suggestions = self.list_policy_suggestions(Some(50)).await?;
        Ok(PoliciesSummary {
            suggestion_count: suggestions.len() as i64,
            pending_suggestions: suggestions.iter().filter(|s| s.status == "suggested").count() as i64,
            suggestions,
        })
    }

    pub async fn generate_detection(
        &self,
        input: &AiGenerateInput,
    ) -> Result<AiDetectionSuggestionRecord, DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let context = input.context.clone().unwrap_or_else(|| "general".into());
        let rule_title = format!("AI suggested detection for {context}");
        let rule_logic = format!(
            "event.severity >= 'medium' AND correlation.confidence >= 0.7 AND context == '{context}'"
        );
        let mitre = serde_json::json!(["T1078", "T1059"]);
        let details_json = details_json!(input);

        sqlx::query(
            "INSERT INTO ai_detection_suggestions (
                id, device_id, investigation_id, rule_title, rule_logic, severity, confidence,
                status, mitre_techniques_json, details_json, generated_at, created_at
             ) VALUES (?, ?, ?, ?, ?, 'medium', 0.75, 'suggested', ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.device_id)
        .bind(&input.investigation_id)
        .bind(&rule_title)
        .bind(&rule_logic)
        .bind(mitre.to_string())
        .bind(&details_json)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(AiDetectionSuggestionRecord {
            id,
            device_id: input.device_id.clone(),
            investigation_id: input.investigation_id.clone(),
            rule_title,
            rule_logic,
            severity: "medium".into(),
            confidence: 0.75,
            status: "suggested".into(),
            generated_at: now,
        })
    }

    pub async fn generate_playbook(
        &self,
        input: &AiGenerateInput,
    ) -> Result<AiPlaybookSuggestionRecord, DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let context = input.context.clone().unwrap_or_else(|| "incident".into());
        let name = format!("AI response playbook — {context}");
        let steps = serde_json::json!([
            {"step": "triage", "action": "Validate alert and enrich with KG context"},
            {"step": "contain", "action": "Isolate affected endpoint via ZTNA policy"},
            {"step": "remediate", "action": "Apply detection rule and close investigation"}
        ]);
        let triggers = serde_json::json!([{"kind": "severity", "threshold": "high"}]);
        let details_json = details_json!(input);

        sqlx::query(
            "INSERT INTO ai_playbook_suggestions (
                id, device_id, investigation_id, name, playbook_kind, steps_json, triggers_json,
                status, details_json, generated_at, created_at
             ) VALUES (?, ?, ?, ?, 'response', ?, ?, 'suggested', ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.device_id)
        .bind(&input.investigation_id)
        .bind(&name)
        .bind(steps.to_string())
        .bind(triggers.to_string())
        .bind(&details_json)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(AiPlaybookSuggestionRecord {
            id,
            device_id: input.device_id.clone(),
            investigation_id: input.investigation_id.clone(),
            name,
            playbook_kind: "response".into(),
            status: "suggested".into(),
            generated_at: now,
        })
    }

    pub async fn generate_policy(
        &self,
        input: &AiGenerateInput,
    ) -> Result<AiPolicySuggestionRecord, DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let context = input.context.clone().unwrap_or_else(|| "access".into());
        let title = format!("AI policy recommendation — {context}");
        let policy = serde_json::json!({
            "effect": "deny",
            "scope": context,
            "conditions": {"risk_score": {"gte": 70}}
        });
        let rationale = format!("Generated from AI correlation context: {context}");
        let details_json = details_json!(input);

        sqlx::query(
            "INSERT INTO ai_policy_suggestions (
                id, device_id, investigation_id, policy_kind, title, policy_json, status,
                rationale, details_json, generated_at, created_at
             ) VALUES (?, ?, ?, 'access', ?, ?, 'suggested', ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.device_id)
        .bind(&input.investigation_id)
        .bind(&title)
        .bind(policy.to_string())
        .bind(&rationale)
        .bind(&details_json)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(AiPolicySuggestionRecord {
            id,
            device_id: input.device_id.clone(),
            investigation_id: input.investigation_id.clone(),
            policy_kind: "access".into(),
            title,
            status: "suggested".into(),
            rationale: Some(rationale),
            generated_at: now,
        })
    }

    pub async fn ingest_telemetry(
        &self,
        device_id: &str,
        payload: &AiTelemetryIngest,
    ) -> Result<AiTelemetrySnapshot, DbError> {
        let now = now_iso();
        let reported_at = payload.reported_at.clone().unwrap_or_else(|| now.clone());
        let mut investigation_count = 0u32;
        let mut threat_count = 0u32;
        let mut kg_node_count = 0u32;

        if let Some(items) = &payload.investigations {
            for item in items {
                let mut input = item.clone();
                if input.device_id.is_none() {
                    input.device_id = Some(device_id.to_string());
                }
                self.create_investigation(&input).await?;
                investigation_count += 1;
            }
        }

        if let Some(items) = &payload.threats {
            for item in items {
                self.insert_threat(device_id, item).await?;
                threat_count += 1;
            }
        }

        if let Some(items) = &payload.kg_nodes {
            for item in items {
                self.insert_kg_node(device_id, item).await?;
                kg_node_count += 1;
            }
        }

        if let Some(items) = &payload.kg_edges {
            for item in items {
                self.insert_kg_edge(item).await?;
            }
        }

        let suggestion_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM ai_detection_suggestions WHERE device_id = ?",
        )
        .bind(device_id)
        .fetch_one(&self.pool)
        .await?;

        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO ai_telemetry_snapshots (
                id, device_id, investigation_count, threat_count, suggestion_count,
                kg_node_count, reported_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(i64::from(investigation_count))
        .bind(i64::from(threat_count))
        .bind(suggestion_count.0)
        .bind(i64::from(kg_node_count))
        .bind(&reported_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(AiTelemetrySnapshot {
            id,
            device_id: device_id.to_string(),
            investigation_count,
            threat_count,
            suggestion_count: suggestion_count.0 as u32,
            kg_node_count,
            reported_at,
        })
    }

    pub async fn seed_defaults(&self) -> Result<(), DbError> {
        let investigation_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM ai_investigations")
                .fetch_one(&self.pool)
                .await?;
        if investigation_count.0 == 0 {
            let now = now_iso();
            let inv_id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO ai_investigations (
                    id, title, description, status, severity, priority, owner, source,
                    tags_json, details_json, opened_at, created_at, updated_at
                 ) VALUES (?, 'Suspicious lateral movement', 'AI-correlated identity and network signals', 'open', 'high', 'high', 'soc-lead', 'ai', '[\"identity\",\"lateral\"]', '{}', ?, ?, ?)",
            )
            .bind(&inv_id)
            .bind(&now)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;

            let threat_id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO ai_correlated_threats (
                    id, threat_kind, title, description, severity, status, confidence,
                    source_refs_json, details_json, detected_at, created_at
                 ) VALUES (?, 'correlation', 'Credential abuse chain', 'Linked login anomaly with C2 beacon', 'high', 'open', 0.87, '[\"xdr\",\"ztna\"]', '{}', ?, ?)",
            )
            .bind(&threat_id)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;

            let node_a = Uuid::new_v4().to_string();
            let node_b = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO ai_kg_nodes (id, node_kind, label, entity_ref, properties_json, created_at)
                 VALUES (?, 'user', 'compromised-user', 'user:alice', '{}', ?)",
            )
            .bind(&node_a)
            .bind(&now)
            .execute(&self.pool)
            .await?;
            sqlx::query(
                "INSERT INTO ai_kg_nodes (id, node_kind, label, entity_ref, properties_json, created_at)
                 VALUES (?, 'host', 'finance-server', 'host:fin-01', '{}', ?)",
            )
            .bind(&node_b)
            .bind(&now)
            .execute(&self.pool)
            .await?;
            sqlx::query(
                "INSERT INTO ai_kg_edges (id, source_node_id, target_node_id, edge_kind, label, weight, properties_json, created_at)
                 VALUES (?, ?, ?, 'accessed', 'lateral_movement', 0.9, '{}', ?)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&node_a)
            .bind(&node_b)
            .bind(&now)
            .execute(&self.pool)
            .await?;

            sqlx::query(
                "INSERT INTO ai_intel_reports (
                    id, report_kind, title, summary, content_json, sources_json, published_at, created_at
                 ) VALUES (?, 'threat_intel', 'Weekly AI threat brief', 'Summarized correlated campaigns', '{}', '[]', ?, ?)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;

            sqlx::query(
                "INSERT INTO ai_executive_reports (
                    id, report_kind, title, summary, content_json, period_start, period_end, published_at, created_at
                 ) VALUES (?, 'executive', 'Security posture executive summary', 'Risk trend and top AI investigations', '{}', ?, ?, ?, ?)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&now)
            .bind(&now)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;

            sqlx::query(
                "INSERT INTO ai_risk_scores (
                    id, scope_kind, risk_score, risk_level, factors_json, evaluated_at, created_at
                 ) VALUES (?, 'organization', 62, 'medium', '{\"ai_correlation\": 0.7}', ?, ?)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn insert_threat(&self, device_id: &str, input: &AiCorrelatedThreatInput) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let detected_at = input.detected_at.clone().unwrap_or_else(|| now.clone());
        let refs_json = serde_json::to_string(&input.source_refs.clone().unwrap_or_default())
            .unwrap_or_else(|_| "[]".into());
        let details_json = details_json!(input);
        sqlx::query(
            "INSERT INTO ai_correlated_threats (
                id, device_id, threat_kind, title, description, severity, status, confidence,
                source_refs_json, details_json, detected_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(input.threat_kind.as_deref().unwrap_or("correlation"))
        .bind(&input.title)
        .bind(&input.description)
        .bind(input.severity.as_deref().unwrap_or("medium"))
        .bind(input.confidence.unwrap_or(0.5))
        .bind(&refs_json)
        .bind(&details_json)
        .bind(&detected_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_kg_node(&self, device_id: &str, input: &AiKgNodeInput) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let props = input
            .properties
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "{}".into());
        sqlx::query(
            "INSERT INTO ai_kg_nodes (id, device_id, node_kind, label, entity_ref, properties_json, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(input.node_kind.as_deref().unwrap_or("entity"))
        .bind(&input.label)
        .bind(&input.entity_ref)
        .bind(&props)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_kg_edge(&self, input: &AiKgEdgeInput) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let props = input
            .properties
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "{}".into());
        sqlx::query(
            "INSERT INTO ai_kg_edges (id, source_node_id, target_node_id, edge_kind, label, weight, properties_json, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&input.source_node_id)
        .bind(&input.target_node_id)
        .bind(input.edge_kind.as_deref().unwrap_or("related"))
        .bind(&input.label)
        .bind(input.weight.unwrap_or(1.0))
        .bind(&props)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_investigations(&self, limit: Option<i64>) -> Result<Vec<AiInvestigationRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, String, Option<String>, String, String, String, Option<String>, String, String, Option<String>, String, String)> =
            sqlx::query_as(
                "SELECT id, device_id, title, description, status, severity, priority, owner, source,
                        opened_at, closed_at, created_at, updated_at
                 FROM ai_investigations ORDER BY opened_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, title, description, status, severity, priority, owner, source, opened_at, closed_at, created_at, updated_at)| {
            AiInvestigationRecord { id, device_id, title, description, status, severity, priority, owner, source, opened_at, closed_at, created_at, updated_at }
        }).collect())
    }

    async fn list_artifacts(&self, limit: Option<i64>) -> Result<Vec<AiInvestigationArtifactRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, String, String, String, Option<String>, String)> = sqlx::query_as(
            "SELECT id, investigation_id, artifact_kind, name, uri, collected_at
             FROM ai_investigation_artifacts ORDER BY collected_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, investigation_id, artifact_kind, name, uri, collected_at)| {
            AiInvestigationArtifactRecord { id, investigation_id, artifact_kind, name, uri, collected_at }
        }).collect())
    }

    async fn list_timelines(&self, limit: Option<i64>) -> Result<Vec<AiInvestigationTimelineRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, String, String, String, Option<String>, Option<String>, String)> =
            sqlx::query_as(
                "SELECT id, investigation_id, event_kind, title, description, actor, occurred_at
                 FROM ai_investigation_timelines ORDER BY occurred_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, investigation_id, event_kind, title, description, actor, occurred_at)| {
            AiInvestigationTimelineRecord { id, investigation_id, event_kind, title, description, actor, occurred_at }
        }).collect())
    }

    async fn list_threats(&self, limit: Option<i64>) -> Result<Vec<AiCorrelatedThreatRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, String, String, Option<String>, String, String, f64, String)> =
            sqlx::query_as(
                "SELECT id, device_id, threat_kind, title, description, severity, status, confidence, detected_at
                 FROM ai_correlated_threats ORDER BY detected_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, threat_kind, title, description, severity, status, confidence, detected_at)| {
            AiCorrelatedThreatRecord { id, device_id, threat_kind, title, description, severity, status, confidence, detected_at }
        }).collect())
    }

    async fn list_correlation_links(&self, limit: Option<i64>) -> Result<Vec<AiCorrelationLinkRecord>, DbError> {
        let limit = limit.unwrap_or(100);
        let rows: Vec<(String, String, String, String, String, f64)> = sqlx::query_as(
            "SELECT id, threat_id, entity_kind, entity_id, link_kind, weight
             FROM ai_correlation_links ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, threat_id, entity_kind, entity_id, link_kind, weight)| {
            AiCorrelationLinkRecord { id, threat_id, entity_kind, entity_id, link_kind, weight }
        }).collect())
    }

    async fn list_kg_nodes(&self, limit: Option<i64>) -> Result<Vec<AiKgNodeRecord>, DbError> {
        let limit = limit.unwrap_or(100);
        let rows: Vec<(String, Option<String>, String, String, Option<String>)> = sqlx::query_as(
            "SELECT id, device_id, node_kind, label, entity_ref FROM ai_kg_nodes ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, device_id, node_kind, label, entity_ref)| {
            AiKgNodeRecord { id, device_id, node_kind, label, entity_ref }
        }).collect())
    }

    async fn list_kg_edges(&self, limit: Option<i64>) -> Result<Vec<AiKgEdgeRecord>, DbError> {
        let limit = limit.unwrap_or(200);
        let rows: Vec<(String, String, String, String, Option<String>, f64)> = sqlx::query_as(
            "SELECT id, source_node_id, target_node_id, edge_kind, label, weight
             FROM ai_kg_edges ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, source_node_id, target_node_id, edge_kind, label, weight)| {
            AiKgEdgeRecord { id, source_node_id, target_node_id, edge_kind, label, weight }
        }).collect())
    }

    async fn list_intel_reports(&self, limit: Option<i64>) -> Result<Vec<AiIntelReportRecord>, DbError> {
        let limit = limit.unwrap_or(20);
        let rows: Vec<(String, Option<String>, String, String, Option<String>, String)> =
            sqlx::query_as(
                "SELECT id, device_id, report_kind, title, summary, published_at
                 FROM ai_intel_reports ORDER BY published_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, report_kind, title, summary, published_at)| {
            AiIntelReportRecord { id, device_id, report_kind, title, summary, published_at }
        }).collect())
    }

    async fn list_executive_reports(&self, limit: Option<i64>) -> Result<Vec<AiExecutiveReportRecord>, DbError> {
        let limit = limit.unwrap_or(10);
        let rows: Vec<(String, String, String, Option<String>, Option<String>, Option<String>, String)> =
            sqlx::query_as(
                "SELECT id, report_kind, title, summary, period_start, period_end, published_at
                 FROM ai_executive_reports ORDER BY published_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, report_kind, title, summary, period_start, period_end, published_at)| {
            AiExecutiveReportRecord { id, report_kind, title, summary, period_start, period_end, published_at }
        }).collect())
    }

    async fn list_risk_scores(&self, limit: Option<i64>) -> Result<Vec<AiRiskScoreRecord>, DbError> {
        let limit = limit.unwrap_or(20);
        let rows: Vec<(String, Option<String>, String, i64, String, String)> = sqlx::query_as(
            "SELECT id, device_id, scope_kind, risk_score, risk_level, evaluated_at
             FROM ai_risk_scores ORDER BY evaluated_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, device_id, scope_kind, risk_score, risk_level, evaluated_at)| {
            AiRiskScoreRecord { id, device_id, scope_kind, risk_score: risk_score as u8, risk_level, evaluated_at }
        }).collect())
    }

    async fn list_detection_suggestions(&self, limit: Option<i64>) -> Result<Vec<AiDetectionSuggestionRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, Option<String>, String, String, String, f64, String, String)> =
            sqlx::query_as(
                "SELECT id, device_id, investigation_id, rule_title, rule_logic, severity, confidence, status, generated_at
                 FROM ai_detection_suggestions ORDER BY generated_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, investigation_id, rule_title, rule_logic, severity, confidence, status, generated_at)| {
            AiDetectionSuggestionRecord { id, device_id, investigation_id, rule_title, rule_logic, severity, confidence, status, generated_at }
        }).collect())
    }

    async fn list_playbook_suggestions(&self, limit: Option<i64>) -> Result<Vec<AiPlaybookSuggestionRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, Option<String>, String, String, String, String)> =
            sqlx::query_as(
                "SELECT id, device_id, investigation_id, name, playbook_kind, status, generated_at
                 FROM ai_playbook_suggestions ORDER BY generated_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, investigation_id, name, playbook_kind, status, generated_at)| {
            AiPlaybookSuggestionRecord { id, device_id, investigation_id, name, playbook_kind, status, generated_at }
        }).collect())
    }

    async fn list_policy_suggestions(&self, limit: Option<i64>) -> Result<Vec<AiPolicySuggestionRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, Option<String>, Option<String>, String, String, String, Option<String>, String)> =
            sqlx::query_as(
                "SELECT id, device_id, investigation_id, policy_kind, title, status, rationale, generated_at
                 FROM ai_policy_suggestions ORDER BY generated_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(id, device_id, investigation_id, policy_kind, title, status, rationale, generated_at)| {
            AiPolicySuggestionRecord { id, device_id, investigation_id, policy_kind, title, status, rationale, generated_at }
        }).collect())
    }
}

fn md5_hash(input: &str) -> u64 {
    let mut hash: u64 = 5381;
    for b in input.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u64::from(b));
    }
    hash
}
