use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymityRouteRecord {
    pub id: String,
    pub device_id: String,
    pub route_id: String,
    pub label: String,
    pub hops: Vec<String>,
    pub chain_kind: Option<String>,
    pub entropy_score: Option<f64>,
    pub active: bool,
    pub last_seen_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymitySnapshot {
    pub id: String,
    pub device_id: String,
    pub anonymity_connected: bool,
    pub stub_mode: bool,
    pub healthy: bool,
    pub anonymity_score: u8,
    pub route_entropy: f64,
    pub path_diversity: f64,
    pub cover_traffic_effectiveness: f64,
    pub federation_peer_count: i64,
    pub entropy_bits: f64,
    pub active_route_count: i64,
    pub federation: Option<Value>,
    pub reported_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationPeerSummary {
    pub peer_id: String,
    pub region: Option<String>,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationSummary {
    pub total_peers: i64,
    pub healthy_peers: i64,
    pub devices_with_federation: i64,
    pub peers: Vec<FederationPeerSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropySummary {
    pub avg_entropy_bits: f64,
    pub avg_route_entropy: f64,
    pub avg_path_diversity: f64,
    pub devices_reporting: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymityHealthSummary {
    pub connected_devices: i64,
    pub healthy_devices: i64,
    pub stub_devices: i64,
    pub total_active_routes: i64,
    pub avg_anonymity_score: f64,
    pub federation: FederationSummary,
    pub entropy: EntropySummary,
    pub snapshots: Vec<AnonymitySnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymityAnalyticsRollup {
    pub id: String,
    pub devices_reporting: i64,
    pub avg_anonymity_score: f64,
    pub avg_route_entropy: f64,
    pub avg_path_diversity: f64,
    pub avg_cover_traffic_effectiveness: f64,
    pub federation_peers_total: i64,
    pub avg_entropy_bits: f64,
    pub rollup: Value,
    pub rolled_up_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymityAnalyticsSummary {
    pub devices_reporting: i64,
    pub avg_anonymity_score: f64,
    pub avg_route_entropy: f64,
    pub avg_path_diversity: f64,
    pub avg_cover_traffic_effectiveness: f64,
    pub federation_peers_total: i64,
    pub avg_entropy_bits: f64,
    pub rollups: Vec<AnonymityAnalyticsRollup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymityHeartbeatRoute {
    pub route_id: String,
    pub label: String,
    pub hops: Vec<String>,
    pub chain_kind: Option<String>,
    pub entropy_score: Option<f64>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymityHeartbeatFederationPeer {
    pub peer_id: String,
    pub region: Option<String>,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymityHeartbeat {
    pub anonymity_connected: bool,
    pub stub_mode: bool,
    pub anonymity_score: Option<u8>,
    pub route_entropy: Option<f64>,
    pub path_diversity: Option<f64>,
    pub cover_traffic_effectiveness: Option<f64>,
    pub entropy_bits: Option<f64>,
    pub federation_peers: Vec<AnonymityHeartbeatFederationPeer>,
    pub active_routes: Vec<AnonymityHeartbeatRoute>,
    pub reported_at: Option<String>,
}

pub struct AnonymityHealthAggregator {
    pool: DbPool,
}

impl AnonymityHealthAggregator {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn list_routes(&self) -> Result<Vec<AnonymityRouteRecord>, DbError> {
        let rows = sqlx::query_as::<_, database::models::AnonymityRouteRow>(
            "SELECT id, device_id, route_id, label, hops_json, chain_kind, entropy_score, active, last_seen_at, created_at, updated_at
             FROM anonymity_routes ORDER BY last_seen_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_route).collect()
    }

    pub async fn list_snapshots(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<AnonymitySnapshot>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows = sqlx::query_as::<_, database::models::AnonymitySnapshotRow>(
            "SELECT id, device_id, anonymity_connected, stub_mode, healthy, anonymity_score, route_entropy, path_diversity,
                    cover_traffic_effectiveness, federation_peer_count, entropy_bits, active_route_count, federation_json,
                    reported_at, created_at
             FROM anonymity_snapshots ORDER BY reported_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_snapshot).collect()
    }

    pub async fn summary(&self) -> Result<AnonymityHealthSummary, DbError> {
        let snapshots = self.list_snapshots(Some(100)).await?;
        let connected_devices = snapshots.iter().filter(|s| s.anonymity_connected).count() as i64;
        let healthy_devices = snapshots.iter().filter(|s| s.healthy).count() as i64;
        let stub_devices = snapshots.iter().filter(|s| s.stub_mode).count() as i64;
        let total_active_routes: i64 = snapshots.iter().map(|s| s.active_route_count).sum();
        let avg_anonymity_score = if snapshots.is_empty() {
            0.0
        } else {
            snapshots
                .iter()
                .map(|s| f64::from(s.anonymity_score))
                .sum::<f64>()
                / snapshots.len() as f64
        };

        Ok(AnonymityHealthSummary {
            connected_devices,
            healthy_devices,
            stub_devices,
            total_active_routes,
            avg_anonymity_score,
            federation: self.federation_summary(&snapshots).await?,
            entropy: self.entropy_summary(&snapshots),
            snapshots,
        })
    }

    pub async fn analytics_summary(&self) -> Result<AnonymityAnalyticsSummary, DbError> {
        let rollups = self.list_rollups(Some(50)).await?;
        let latest = rollups.first();
        Ok(AnonymityAnalyticsSummary {
            devices_reporting: latest.map(|r| r.devices_reporting).unwrap_or(0),
            avg_anonymity_score: latest.map(|r| r.avg_anonymity_score).unwrap_or(0.0),
            avg_route_entropy: latest.map(|r| r.avg_route_entropy).unwrap_or(0.0),
            avg_path_diversity: latest.map(|r| r.avg_path_diversity).unwrap_or(0.0),
            avg_cover_traffic_effectiveness: latest
                .map(|r| r.avg_cover_traffic_effectiveness)
                .unwrap_or(0.0),
            federation_peers_total: latest.map(|r| r.federation_peers_total).unwrap_or(0),
            avg_entropy_bits: latest.map(|r| r.avg_entropy_bits).unwrap_or(0.0),
            rollups,
        })
    }

    pub async fn ingest_heartbeat(
        &self,
        device_id: &str,
        hb: &AnonymityHeartbeat,
    ) -> Result<AnonymitySnapshot, DbError> {
        let now = now_iso();
        let reported_at = hb.reported_at.clone().unwrap_or_else(|| now.clone());

        for route in &hb.active_routes {
            let row_id = Uuid::new_v4().to_string();
            let hops_json =
                serde_json::to_string(&route.hops).unwrap_or_else(|_| "[]".into());
            sqlx::query(
                "INSERT INTO anonymity_routes (id, device_id, route_id, label, hops_json, chain_kind, entropy_score, active, last_seen_at, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(device_id, route_id) DO UPDATE SET
                   label = excluded.label,
                   hops_json = excluded.hops_json,
                   chain_kind = excluded.chain_kind,
                   entropy_score = excluded.entropy_score,
                   active = excluded.active,
                   last_seen_at = excluded.last_seen_at,
                   updated_at = excluded.updated_at",
            )
            .bind(&row_id)
            .bind(device_id)
            .bind(&route.route_id)
            .bind(&route.label)
            .bind(&hops_json)
            .bind(&route.chain_kind)
            .bind(route.entropy_score)
            .bind(route.active)
            .bind(&reported_at)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        }

        let anonymity_score = hb.anonymity_score.unwrap_or(0);
        let route_entropy = hb.route_entropy.unwrap_or(0.0);
        let path_diversity = hb.path_diversity.unwrap_or(0.0);
        let cover_traffic_effectiveness = hb.cover_traffic_effectiveness.unwrap_or(0.0);
        let entropy_bits = hb.entropy_bits.unwrap_or(0.0);
        let federation_peer_count = hb.federation_peers.len() as i64;
        let federation_json = if hb.federation_peers.is_empty() {
            None
        } else {
            serde_json::to_string(&hb.federation_peers).ok()
        };
        let healthy = hb.anonymity_connected
            && !hb.stub_mode
            && anonymity_score >= 50
            && hb
                .federation_peers
                .iter()
                .filter(|p| p.healthy)
                .count()
                >= hb.federation_peers.len().saturating_sub(1);
        let active_route_count = hb.active_routes.iter().filter(|r| r.active).count() as i64;
        let id = Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO anonymity_snapshots (
                id, device_id, anonymity_connected, stub_mode, healthy, anonymity_score, route_entropy,
                path_diversity, cover_traffic_effectiveness, federation_peer_count, entropy_bits,
                active_route_count, federation_json, reported_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(hb.anonymity_connected)
        .bind(hb.stub_mode)
        .bind(healthy)
        .bind(i64::from(anonymity_score))
        .bind(route_entropy)
        .bind(path_diversity)
        .bind(cover_traffic_effectiveness)
        .bind(federation_peer_count)
        .bind(entropy_bits)
        .bind(active_route_count)
        .bind(&federation_json)
        .bind(&reported_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        self.record_rollup_from_snapshots().await?;

        let federation = federation_json
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok());

        Ok(AnonymitySnapshot {
            id,
            device_id: device_id.to_string(),
            anonymity_connected: hb.anonymity_connected,
            stub_mode: hb.stub_mode,
            healthy,
            anonymity_score,
            route_entropy,
            path_diversity,
            cover_traffic_effectiveness,
            federation_peer_count,
            entropy_bits,
            active_route_count,
            federation,
            reported_at,
            created_at: now,
        })
    }

    async fn federation_summary(
        &self,
        snapshots: &[AnonymitySnapshot],
    ) -> Result<FederationSummary, DbError> {
        let mut peers: Vec<FederationPeerSummary> = Vec::new();
        let mut devices_with_federation = 0_i64;

        for snapshot in snapshots {
            if snapshot.federation_peer_count == 0 {
                continue;
            }
            devices_with_federation += 1;
            if let Some(Value::Array(items)) = snapshot.federation.as_ref() {
                for item in items {
                    if let Ok(peer) = serde_json::from_value::<AnonymityHeartbeatFederationPeer>(item.clone())
                    {
                        if !peers.iter().any(|p| p.peer_id == peer.peer_id) {
                            peers.push(FederationPeerSummary {
                                peer_id: peer.peer_id,
                                region: peer.region,
                                healthy: peer.healthy,
                            });
                        }
                    }
                }
            }
        }

        let healthy_peers = peers.iter().filter(|p| p.healthy).count() as i64;
        Ok(FederationSummary {
            total_peers: peers.len() as i64,
            healthy_peers,
            devices_with_federation,
            peers,
        })
    }

    fn entropy_summary(&self, snapshots: &[AnonymitySnapshot]) -> EntropySummary {
        let devices_reporting = snapshots.len() as i64;
        if devices_reporting == 0 {
            return EntropySummary {
                avg_entropy_bits: 0.0,
                avg_route_entropy: 0.0,
                avg_path_diversity: 0.0,
                devices_reporting: 0,
            };
        }
        let avg_entropy_bits =
            snapshots.iter().map(|s| s.entropy_bits).sum::<f64>() / devices_reporting as f64;
        let avg_route_entropy =
            snapshots.iter().map(|s| s.route_entropy).sum::<f64>() / devices_reporting as f64;
        let avg_path_diversity =
            snapshots.iter().map(|s| s.path_diversity).sum::<f64>() / devices_reporting as f64;
        EntropySummary {
            avg_entropy_bits,
            avg_route_entropy,
            avg_path_diversity,
            devices_reporting,
        }
    }

    async fn record_rollup_from_snapshots(&self) -> Result<(), DbError> {
        let snapshots = self.list_snapshots(Some(100)).await?;
        if snapshots.is_empty() {
            return Ok(());
        }

        let devices_reporting = snapshots.len() as i64;
        let avg_anonymity_score = snapshots
            .iter()
            .map(|s| f64::from(s.anonymity_score))
            .sum::<f64>()
            / devices_reporting as f64;
        let avg_route_entropy =
            snapshots.iter().map(|s| s.route_entropy).sum::<f64>() / devices_reporting as f64;
        let avg_path_diversity =
            snapshots.iter().map(|s| s.path_diversity).sum::<f64>() / devices_reporting as f64;
        let avg_cover_traffic_effectiveness = snapshots
            .iter()
            .map(|s| s.cover_traffic_effectiveness)
            .sum::<f64>()
            / devices_reporting as f64;
        let federation_peers_total: i64 = snapshots.iter().map(|s| s.federation_peer_count).sum();
        let avg_entropy_bits =
            snapshots.iter().map(|s| s.entropy_bits).sum::<f64>() / devices_reporting as f64;

        let rollup = serde_json::json!({
            "devices_reporting": devices_reporting,
            "avg_anonymity_score": avg_anonymity_score,
            "avg_route_entropy": avg_route_entropy,
            "avg_path_diversity": avg_path_diversity,
            "avg_cover_traffic_effectiveness": avg_cover_traffic_effectiveness,
            "federation_peers_total": federation_peers_total,
            "avg_entropy_bits": avg_entropy_bits,
        });
        let rollup_json = serde_json::to_string(&rollup).unwrap_or_else(|_| "{}".into());
        let id = Uuid::new_v4().to_string();
        let now = now_iso();

        sqlx::query(
            "INSERT INTO anonymity_analytics_rollups (
                id, devices_reporting, avg_anonymity_score, avg_route_entropy, avg_path_diversity,
                avg_cover_traffic_effectiveness, federation_peers_total, avg_entropy_bits,
                rollup_json, rolled_up_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(devices_reporting)
        .bind(avg_anonymity_score)
        .bind(avg_route_entropy)
        .bind(avg_path_diversity)
        .bind(avg_cover_traffic_effectiveness)
        .bind(federation_peers_total)
        .bind(avg_entropy_bits)
        .bind(&rollup_json)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_rollups(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<AnonymityAnalyticsRollup>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows = sqlx::query_as::<_, database::models::AnonymityAnalyticsRollupRow>(
            "SELECT id, devices_reporting, avg_anonymity_score, avg_route_entropy, avg_path_diversity,
                    avg_cover_traffic_effectiveness, federation_peers_total, avg_entropy_bits,
                    rollup_json, rolled_up_at, created_at
             FROM anonymity_analytics_rollups ORDER BY rolled_up_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| AnonymityAnalyticsRollup {
                id: row.id,
                devices_reporting: row.devices_reporting,
                avg_anonymity_score: row.avg_anonymity_score,
                avg_route_entropy: row.avg_route_entropy,
                avg_path_diversity: row.avg_path_diversity,
                avg_cover_traffic_effectiveness: row.avg_cover_traffic_effectiveness,
                federation_peers_total: row.federation_peers_total,
                avg_entropy_bits: row.avg_entropy_bits,
                rollup: serde_json::from_str(&row.rollup_json).unwrap_or(serde_json::json!({})),
                rolled_up_at: row.rolled_up_at,
                created_at: row.created_at,
            })
            .collect())
    }
}

fn row_to_route(row: database::models::AnonymityRouteRow) -> Result<AnonymityRouteRecord, DbError> {
    let hops: Vec<String> = serde_json::from_str(&row.hops_json).unwrap_or_default();
    Ok(AnonymityRouteRecord {
        id: row.id,
        device_id: row.device_id,
        route_id: row.route_id,
        label: row.label,
        hops,
        chain_kind: row.chain_kind,
        entropy_score: row.entropy_score,
        active: row.active != 0,
        last_seen_at: row.last_seen_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn row_to_snapshot(
    row: database::models::AnonymitySnapshotRow,
) -> Result<AnonymitySnapshot, DbError> {
    let federation = row
        .federation_json
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok());
    Ok(AnonymitySnapshot {
        id: row.id,
        device_id: row.device_id,
        anonymity_connected: row.anonymity_connected != 0,
        stub_mode: row.stub_mode != 0,
        healthy: row.healthy != 0,
        anonymity_score: row.anonymity_score.clamp(0, 100) as u8,
        route_entropy: row.route_entropy,
        path_diversity: row.path_diversity,
        cover_traffic_effectiveness: row.cover_traffic_effectiveness,
        federation_peer_count: row.federation_peer_count,
        entropy_bits: row.entropy_bits,
        active_route_count: row.active_route_count,
        federation,
        reported_at: row.reported_at,
        created_at: row.created_at,
    })
}
