use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsePolicyRecord {
    pub id: String,
    pub name: String,
    pub policy_kind: String,
    pub enabled: bool,
    pub rules: Vec<serde_json::Value>,
    pub default_action: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseIncidentRecord {
    pub id: String,
    pub device_id: String,
    pub incident_kind: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub resource: Option<String>,
    pub action_taken: String,
    pub status: String,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseThreatMatchRecord {
    pub id: String,
    pub device_id: String,
    pub threat_kind: String,
    pub category: String,
    pub url: Option<String>,
    pub signature: Option<String>,
    pub severity: String,
    pub action: String,
    pub matched_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseRiskRecord {
    pub id: String,
    pub device_id: String,
    pub risk_score: u8,
    pub risk_level: String,
    pub factors: serde_json::Value,
    pub evaluated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseUebaRecord {
    pub id: String,
    pub device_id: String,
    pub user_id: Option<String>,
    pub anomaly_kind: String,
    pub score: f64,
    pub description: String,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseTelemetrySnapshot {
    pub id: String,
    pub device_id: String,
    pub swg_requests: u64,
    pub swg_blocked: u64,
    pub swg_allowed: u64,
    pub threat_count: u32,
    pub casb_incidents: u32,
    pub dlp_incidents: u32,
    pub risk_score: u8,
    pub ueba_alerts: u32,
    pub reported_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwgSummary {
    pub policy_count: i64,
    pub total_requests: i64,
    pub blocked_count: i64,
    pub allowed_count: i64,
    pub threat_match_count: i64,
    pub reporting_devices: i64,
    pub recent_threats: Vec<SseThreatMatchRecord>,
    pub snapshots: Vec<SseTelemetrySnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasbSummary {
    pub incident_count: i64,
    pub open_incidents: i64,
    pub blocked_actions: i64,
    pub incidents: Vec<SseIncidentRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpSummary {
    pub incident_count: i64,
    pub open_incidents: i64,
    pub blocked_actions: i64,
    pub incidents: Vec<SseIncidentRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    pub devices_scored: i64,
    pub avg_risk_score: f64,
    pub high_risk_devices: i64,
    pub scores: Vec<SseRiskRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaSummary {
    pub anomaly_count: i64,
    pub avg_anomaly_score: f64,
    pub alerting_devices: i64,
    pub anomalies: Vec<SseUebaRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseIncidentInput {
    pub severity: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub resource: Option<String>,
    pub action_taken: Option<String>,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseThreatMatchInput {
    pub threat_kind: Option<String>,
    pub category: Option<String>,
    pub url: Option<String>,
    pub signature: Option<String>,
    pub severity: Option<String>,
    pub action: Option<String>,
    pub matched_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseUebaInput {
    pub user_id: Option<String>,
    pub anomaly_kind: Option<String>,
    pub score: Option<f64>,
    pub description: String,
    pub details: Option<serde_json::Value>,
    pub detected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseTelemetryIngest {
    pub swg_requests: Option<u64>,
    pub swg_blocked: Option<u64>,
    pub swg_allowed: Option<u64>,
    pub threat_matches: Option<Vec<SseThreatMatchInput>>,
    pub casb_incidents: Option<Vec<SseIncidentInput>>,
    pub dlp_incidents: Option<Vec<SseIncidentInput>>,
    pub risk_score: Option<u8>,
    pub risk_level: Option<String>,
    pub risk_factors: Option<serde_json::Value>,
    pub ueba_anomalies: Option<Vec<SseUebaInput>>,
    pub reported_at: Option<String>,
}

pub struct SseManager {
    pool: DbPool,
}

impl SseManager {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn list_policies(&self) -> Result<Vec<SsePolicyRecord>, DbError> {
        let rows: Vec<(String, String, String, i64, String, String, String, String)> =
            sqlx::query_as(
                "SELECT id, name, policy_kind, enabled, rules_json, default_action, created_at, updated_at
                 FROM sse_policies ORDER BY updated_at DESC",
            )
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, name, policy_kind, enabled, rules_json, default_action, created_at, updated_at)| {
                    SsePolicyRecord {
                        id,
                        name,
                        policy_kind,
                        enabled: enabled != 0,
                        rules: serde_json::from_str(&rules_json).unwrap_or_default(),
                        default_action,
                        created_at,
                        updated_at,
                    }
                },
            )
            .collect())
    }

    pub async fn swg_summary(&self) -> Result<SwgSummary, DbError> {
        let policy_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sse_policies")
            .fetch_one(&self.pool)
            .await?;
        let threat_match_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM sse_threat_matches")
                .fetch_one(&self.pool)
                .await?;
        let snapshots = self.list_snapshots(Some(50)).await?;
        let reporting_devices = snapshots.len() as i64;
        let total_requests: i64 = snapshots.iter().map(|s| s.swg_requests as i64).sum();
        let blocked_count: i64 = snapshots.iter().map(|s| s.swg_blocked as i64).sum();
        let allowed_count: i64 = snapshots.iter().map(|s| s.swg_allowed as i64).sum();
        let recent_threats = self.list_threat_matches(Some(20)).await?;

        Ok(SwgSummary {
            policy_count: policy_count.0,
            total_requests,
            blocked_count,
            allowed_count,
            threat_match_count: threat_match_count.0,
            reporting_devices,
            recent_threats,
            snapshots,
        })
    }

    pub async fn casb_summary(&self) -> Result<CasbSummary, DbError> {
        let incidents = self.list_incidents("casb", Some(50)).await?;
        let incident_count = incidents.len() as i64;
        let open_incidents = incidents.iter().filter(|i| i.status == "open").count() as i64;
        let blocked_actions = incidents
            .iter()
            .filter(|i| i.action_taken == "blocked")
            .count() as i64;

        Ok(CasbSummary {
            incident_count,
            open_incidents,
            blocked_actions,
            incidents,
        })
    }

    pub async fn dlp_summary(&self) -> Result<DlpSummary, DbError> {
        let incidents = self.list_incidents("dlp", Some(50)).await?;
        let incident_count = incidents.len() as i64;
        let open_incidents = incidents.iter().filter(|i| i.status == "open").count() as i64;
        let blocked_actions = incidents
            .iter()
            .filter(|i| i.action_taken == "blocked")
            .count() as i64;

        Ok(DlpSummary {
            incident_count,
            open_incidents,
            blocked_actions,
            incidents,
        })
    }

    pub async fn risk_summary(&self) -> Result<RiskSummary, DbError> {
        let scores = self.list_risk_scores().await?;
        let devices_scored = scores.len() as i64;
        let avg_risk_score = if devices_scored == 0 {
            0.0
        } else {
            scores.iter().map(|s| f64::from(s.risk_score)).sum::<f64>() / devices_scored as f64
        };
        let high_risk_devices = scores.iter().filter(|s| s.risk_score >= 70).count() as i64;

        Ok(RiskSummary {
            devices_scored,
            avg_risk_score,
            high_risk_devices,
            scores,
        })
    }

    pub async fn ueba_summary(&self) -> Result<UebaSummary, DbError> {
        let anomalies = self.list_ueba_anomalies(Some(50)).await?;
        let anomaly_count = anomalies.len() as i64;
        let avg_anomaly_score = if anomaly_count == 0 {
            0.0
        } else {
            anomalies.iter().map(|a| a.score).sum::<f64>() / anomaly_count as f64
        };
        let alerting_devices = anomalies
            .iter()
            .map(|a| a.device_id.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len() as i64;

        Ok(UebaSummary {
            anomaly_count,
            avg_anomaly_score,
            alerting_devices,
            anomalies,
        })
    }

    pub async fn ingest_telemetry(
        &self,
        device_id: &str,
        payload: &SseTelemetryIngest,
    ) -> Result<SseTelemetrySnapshot, DbError> {
        let now = now_iso();
        let reported_at = payload.reported_at.clone().unwrap_or_else(|| now.clone());
        let swg_requests = payload.swg_requests.unwrap_or(0);
        let swg_blocked = payload.swg_blocked.unwrap_or(0);
        let swg_allowed = payload.swg_allowed.unwrap_or(0);

        let mut threat_count = 0u32;
        if let Some(matches) = &payload.threat_matches {
            for m in matches {
                self.insert_threat_match(device_id, m).await?;
                threat_count += 1;
            }
        }

        let mut casb_incidents = 0u32;
        if let Some(incidents) = &payload.casb_incidents {
            for inc in incidents {
                self.insert_incident(device_id, "casb", inc).await?;
                casb_incidents += 1;
            }
        }

        let mut dlp_incidents = 0u32;
        if let Some(incidents) = &payload.dlp_incidents {
            for inc in incidents {
                self.insert_incident(device_id, "dlp", inc).await?;
                dlp_incidents += 1;
            }
        }

        let risk_score = if let Some(score) = payload.risk_score {
            self.upsert_risk_score(
                device_id,
                score,
                payload.risk_level.as_deref().unwrap_or("medium"),
                payload.risk_factors.as_ref(),
                &reported_at,
            )
            .await?;
            score
        } else {
            0
        };

        let mut ueba_alerts = 0u32;
        if let Some(anomalies) = &payload.ueba_anomalies {
            for a in anomalies {
                self.insert_ueba_anomaly(device_id, a).await?;
                ueba_alerts += 1;
            }
        }

        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO sse_telemetry_snapshots (
                id, device_id, swg_requests, swg_blocked, swg_allowed, threat_count,
                casb_incidents, dlp_incidents, risk_score, ueba_alerts, reported_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(swg_requests as i64)
        .bind(swg_blocked as i64)
        .bind(swg_allowed as i64)
        .bind(i64::from(threat_count))
        .bind(i64::from(casb_incidents))
        .bind(i64::from(dlp_incidents))
        .bind(i64::from(risk_score))
        .bind(i64::from(ueba_alerts))
        .bind(&reported_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(SseTelemetrySnapshot {
            id,
            device_id: device_id.to_string(),
            swg_requests,
            swg_blocked,
            swg_allowed,
            threat_count,
            casb_incidents,
            dlp_incidents,
            risk_score,
            ueba_alerts,
            reported_at,
        })
    }

    pub async fn report_dlp_incident(
        &self,
        device_id: &str,
        incident: &SseIncidentInput,
    ) -> Result<SseIncidentRecord, DbError> {
        self.insert_incident(device_id, "dlp", incident).await
    }

    pub async fn seed_defaults(&self) -> Result<(), DbError> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sse_policies")
            .fetch_one(&self.pool)
            .await?;
        if count.0 > 0 {
            return Ok(());
        }

        let now = now_iso();
        let policies = [
            ("Default SWG Policy", "swg", "block"),
            ("Default CASB Policy", "casb", "block"),
            ("Default DLP Policy", "dlp", "block"),
        ];
        for (name, kind, action) in policies {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO sse_policies (
                    id, name, policy_kind, enabled, rules_json, default_action, content_json, created_at, updated_at
                 ) VALUES (?, ?, ?, 1, '[]', ?, '{}', ?, ?)",
            )
            .bind(&id)
            .bind(name)
            .bind(kind)
            .bind(action)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn list_snapshots(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<SseTelemetrySnapshot>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, String, i64, i64, i64, i64, i64, i64, i64, i64, String)> =
            sqlx::query_as(
                "SELECT id, device_id, swg_requests, swg_blocked, swg_allowed, threat_count,
                        casb_incidents, dlp_incidents, risk_score, ueba_alerts, reported_at
                 FROM sse_telemetry_snapshots ORDER BY reported_at DESC LIMIT ?",
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
                    swg_requests,
                    swg_blocked,
                    swg_allowed,
                    threat_count,
                    casb_incidents,
                    dlp_incidents,
                    risk_score,
                    ueba_alerts,
                    reported_at,
                )| {
                    SseTelemetrySnapshot {
                        id,
                        device_id,
                        swg_requests: swg_requests.max(0) as u64,
                        swg_blocked: swg_blocked.max(0) as u64,
                        swg_allowed: swg_allowed.max(0) as u64,
                        threat_count: threat_count.max(0) as u32,
                        casb_incidents: casb_incidents.max(0) as u32,
                        dlp_incidents: dlp_incidents.max(0) as u32,
                        risk_score: risk_score.clamp(0, 100) as u8,
                        ueba_alerts: ueba_alerts.max(0) as u32,
                        reported_at,
                    }
                },
            )
            .collect())
    }

    async fn list_threat_matches(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<SseThreatMatchRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, String, String, String, Option<String>, Option<String>, String, String, String)> =
            sqlx::query_as(
                "SELECT id, device_id, threat_kind, category, url, signature, severity, action, matched_at
                 FROM sse_threat_matches ORDER BY matched_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, device_id, threat_kind, category, url, signature, severity, action, matched_at)| {
                    SseThreatMatchRecord {
                        id,
                        device_id,
                        threat_kind,
                        category,
                        url,
                        signature,
                        severity,
                        action,
                        matched_at,
                    }
                },
            )
            .collect())
    }

    async fn list_incidents(
        &self,
        kind: &str,
        limit: Option<i64>,
    ) -> Result<Vec<SseIncidentRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, String, String, String, String, Option<String>, Option<String>, String, String, String)> =
            sqlx::query_as(
                "SELECT id, device_id, incident_kind, severity, title, description, resource, action_taken, status, detected_at
                 FROM sse_incidents WHERE incident_kind = ? ORDER BY detected_at DESC LIMIT ?",
            )
            .bind(kind)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    device_id,
                    incident_kind,
                    severity,
                    title,
                    description,
                    resource,
                    action_taken,
                    status,
                    detected_at,
                )| {
                    SseIncidentRecord {
                        id,
                        device_id,
                        incident_kind,
                        severity,
                        title,
                        description,
                        resource,
                        action_taken,
                        status,
                        detected_at,
                    }
                },
            )
            .collect())
    }

    async fn list_risk_scores(&self) -> Result<Vec<SseRiskRecord>, DbError> {
        let rows: Vec<(String, String, i64, String, String, String)> = sqlx::query_as(
            "SELECT id, device_id, risk_score, risk_level, factors_json, evaluated_at
             FROM sse_risk_scores ORDER BY evaluated_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(id, device_id, risk_score, risk_level, factors_json, evaluated_at)| {
                SseRiskRecord {
                    id,
                    device_id,
                    risk_score: risk_score.clamp(0, 100) as u8,
                    risk_level,
                    factors: serde_json::from_str(&factors_json).unwrap_or(serde_json::json!({})),
                    evaluated_at,
                }
            })
            .collect())
    }

    async fn list_ueba_anomalies(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<SseUebaRecord>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows: Vec<(String, String, Option<String>, String, f64, String, String)> =
            sqlx::query_as(
                "SELECT id, device_id, user_id, anomaly_kind, score, description, detected_at
                 FROM sse_ueba_anomalies ORDER BY detected_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, device_id, user_id, anomaly_kind, score, description, detected_at)| {
                    SseUebaRecord {
                        id,
                        device_id,
                        user_id,
                        anomaly_kind,
                        score,
                        description,
                        detected_at,
                    }
                },
            )
            .collect())
    }

    async fn insert_threat_match(
        &self,
        device_id: &str,
        input: &SseThreatMatchInput,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let matched_at = input.matched_at.clone().unwrap_or_else(|| now.clone());

        sqlx::query(
            "INSERT INTO sse_threat_matches (
                id, device_id, threat_kind, category, url, signature, severity, action, matched_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(input.threat_kind.as_deref().unwrap_or("malware"))
        .bind(input.category.as_deref().unwrap_or("web"))
        .bind(&input.url)
        .bind(&input.signature)
        .bind(input.severity.as_deref().unwrap_or("medium"))
        .bind(input.action.as_deref().unwrap_or("blocked"))
        .bind(&matched_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn insert_incident(
        &self,
        device_id: &str,
        kind: &str,
        input: &SseIncidentInput,
    ) -> Result<SseIncidentRecord, DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let detected_at = input.detected_at.clone().unwrap_or_else(|| now.clone());
        let details_json = input
            .details
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "{}".into());
        let severity = input.severity.clone().unwrap_or_else(|| "medium".into());
        let action_taken = input.action_taken.clone().unwrap_or_else(|| "blocked".into());

        sqlx::query(
            "INSERT INTO sse_incidents (
                id, device_id, incident_kind, severity, title, description, resource,
                action_taken, status, details_json, detected_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(kind)
        .bind(&severity)
        .bind(&input.title)
        .bind(&input.description)
        .bind(&input.resource)
        .bind(&action_taken)
        .bind(&details_json)
        .bind(&detected_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(SseIncidentRecord {
            id,
            device_id: device_id.to_string(),
            incident_kind: kind.to_string(),
            severity,
            title: input.title.clone(),
            description: input.description.clone(),
            resource: input.resource.clone(),
            action_taken,
            status: "open".into(),
            detected_at,
        })
    }

    async fn upsert_risk_score(
        &self,
        device_id: &str,
        score: u8,
        level: &str,
        factors: Option<&serde_json::Value>,
        evaluated_at: &str,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let id = Uuid::new_v4().to_string();
        let factors_json = factors
            .map(|f| f.to_string())
            .unwrap_or_else(|| "{}".into());

        sqlx::query(
            "INSERT INTO sse_risk_scores (
                id, device_id, risk_score, risk_level, factors_json, evaluated_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(device_id) DO UPDATE SET
               risk_score = excluded.risk_score,
               risk_level = excluded.risk_level,
               factors_json = excluded.factors_json,
               evaluated_at = excluded.evaluated_at",
        )
        .bind(&id)
        .bind(device_id)
        .bind(i64::from(score))
        .bind(level)
        .bind(&factors_json)
        .bind(evaluated_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn insert_ueba_anomaly(
        &self,
        device_id: &str,
        input: &SseUebaInput,
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
            "INSERT INTO sse_ueba_anomalies (
                id, device_id, user_id, anomaly_kind, score, description, details_json, detected_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(&input.user_id)
        .bind(input.anomaly_kind.as_deref().unwrap_or("behavior"))
        .bind(input.score.unwrap_or(0.0))
        .bind(&input.description)
        .bind(&details_json)
        .bind(&detected_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
