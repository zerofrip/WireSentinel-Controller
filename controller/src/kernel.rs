use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSnapshot {
    pub id: String,
    pub device_id: String,
    pub guardian_mode: String,
    pub driver_connected: bool,
    pub lifecycle_state: String,
    pub kill_switch_mode: Option<String>,
    pub stub_mode: bool,
    pub wfp_engine: String,
    pub ndis_enabled: bool,
    pub healthy: bool,
    pub filter_count: i64,
    pub callouts_registered: i64,
    pub transform_profile: Option<String>,
    pub cover_traffic_profile: Option<String>,
    pub telemetry: Option<Value>,
    pub active_route_count: i64,
    pub reported_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelRouteRecord {
    pub id: String,
    pub device_id: String,
    pub route_id: String,
    pub app_id: String,
    pub route_kind: String,
    pub profile_id: Option<i64>,
    pub interface_luid: Option<i64>,
    pub socks_port: Option<i32>,
    pub label: Option<String>,
    pub active: bool,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelFlowStatRecord {
    pub id: String,
    pub device_id: String,
    pub flow_id: String,
    pub process_id: Option<i64>,
    pub protocol: Option<i64>,
    pub bytes: i64,
    pub direction: Option<String>,
    pub route_kind: Option<String>,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelStatusSummary {
    pub reporting_devices: i64,
    pub healthy_devices: i64,
    pub kernel_devices: i64,
    pub ndis_devices: i64,
    pub stub_devices: i64,
    pub total_active_routes: i64,
    pub snapshots: Vec<KernelSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelTelemetrySummary {
    pub classify_count: i64,
    pub block_count: i64,
    pub route_count: i64,
    pub permit_count: i64,
    pub observe_count: i64,
    pub error_count: i64,
    pub avg_classify_latency_ns: i64,
    pub max_classify_latency_ns: i64,
    pub packets_per_sec: i64,
    pub snapshots: Vec<KernelSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelHeartbeatTelemetry {
    pub classify_count: Option<u64>,
    pub block_count: Option<u64>,
    pub route_count: Option<u64>,
    pub permit_count: Option<u64>,
    pub observe_count: Option<u64>,
    pub error_count: Option<u64>,
    pub avg_classify_latency_ns: Option<u64>,
    pub max_classify_latency_ns: Option<u64>,
    pub packets_per_sec: Option<u64>,
    pub ndis_classify_count: Option<u64>,
    pub ndis_redirect_count: Option<u64>,
    pub ndis_transform_count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelHeartbeatRoute {
    pub route_id: String,
    pub app_id: String,
    pub route_kind: String,
    pub profile_id: Option<u64>,
    pub interface_luid: Option<u64>,
    pub socks_port: Option<u16>,
    pub label: Option<String>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelHeartbeatFlowStat {
    pub flow_id: String,
    pub process_id: Option<u32>,
    pub protocol: Option<u32>,
    pub bytes: Option<u64>,
    pub direction: Option<String>,
    pub route_kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelHeartbeat {
    #[serde(default)]
    pub guardian_mode: Option<String>,
    #[serde(default)]
    pub driver_connected: bool,
    pub lifecycle_state: Option<String>,
    pub kill_switch_mode: Option<String>,
    #[serde(default)]
    pub stub_mode: bool,
    pub wfp_engine: Option<String>,
    #[serde(default)]
    pub ndis_enabled: bool,
    pub filter_count: Option<u32>,
    pub callouts_registered: Option<u32>,
    pub transform_profile: Option<String>,
    pub cover_traffic_profile: Option<String>,
    pub telemetry: Option<KernelHeartbeatTelemetry>,
    #[serde(default)]
    pub routes: Vec<KernelHeartbeatRoute>,
    #[serde(default)]
    pub flow_stats: Vec<KernelHeartbeatFlowStat>,
    pub reported_at: Option<String>,
}

pub struct KernelHealthAggregator {
    pool: DbPool,
}

impl KernelHealthAggregator {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn list_snapshots(&self, limit: Option<i64>) -> Result<Vec<KernelSnapshot>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows = sqlx::query_as::<_, database::models::KernelSnapshotRow>(
            "SELECT id, device_id, guardian_mode, driver_connected, lifecycle_state, kill_switch_mode,
                    stub_mode, wfp_engine, ndis_enabled, healthy, filter_count, callouts_registered,
                    transform_profile, cover_traffic_profile, telemetry_json, active_route_count,
                    reported_at, created_at
             FROM kernel_snapshots ORDER BY reported_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_snapshot).collect()
    }

    pub async fn status_summary(&self) -> Result<KernelStatusSummary, DbError> {
        let snapshots = self.list_snapshots(Some(100)).await?;
        let reporting_devices = snapshots.len() as i64;
        let healthy_devices = snapshots.iter().filter(|s| s.healthy).count() as i64;
        let kernel_devices = snapshots
            .iter()
            .filter(|s| s.guardian_mode == "kernel" || s.wfp_engine == "kernel")
            .count() as i64;
        let ndis_devices = snapshots.iter().filter(|s| s.ndis_enabled).count() as i64;
        let stub_devices = snapshots.iter().filter(|s| s.stub_mode).count() as i64;
        let total_active_routes: i64 = snapshots.iter().map(|s| s.active_route_count).sum();

        Ok(KernelStatusSummary {
            reporting_devices,
            healthy_devices,
            kernel_devices,
            ndis_devices,
            stub_devices,
            total_active_routes,
            snapshots,
        })
    }

    pub async fn telemetry_summary(&self) -> Result<KernelTelemetrySummary, DbError> {
        let snapshots = self.list_snapshots(Some(100)).await?;
        let mut summary = KernelTelemetrySummary {
            classify_count: 0,
            block_count: 0,
            route_count: 0,
            permit_count: 0,
            observe_count: 0,
            error_count: 0,
            avg_classify_latency_ns: 0,
            max_classify_latency_ns: 0,
            packets_per_sec: 0,
            snapshots,
        };

        for snap in &summary.snapshots {
            if let Some(Value::Object(map)) = snap.telemetry.as_ref() {
                summary.classify_count += map
                    .get("classify_count")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                summary.block_count += map
                    .get("block_count")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                summary.route_count += map
                    .get("route_count")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                summary.permit_count += map
                    .get("permit_count")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                summary.observe_count += map
                    .get("observe_count")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                summary.error_count += map
                    .get("error_count")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                summary.avg_classify_latency_ns += map
                    .get("avg_classify_latency_ns")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                summary.max_classify_latency_ns = summary
                    .max_classify_latency_ns
                    .max(map.get("max_classify_latency_ns").and_then(|v| v.as_i64()).unwrap_or(0));
                summary.packets_per_sec += map
                    .get("packets_per_sec")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
            }
        }

        Ok(summary)
    }

    pub async fn list_routes(&self) -> Result<Vec<KernelRouteRecord>, DbError> {
        let rows = sqlx::query_as::<_, database::models::KernelFlowStatRow>(
            "SELECT id, device_id, stat_type, flow_id, process_id, protocol, bytes, direction,
                    route_kind, profile_id, label, active, last_seen_at, created_at, updated_at
             FROM kernel_flow_stats WHERE stat_type = 'route' ORDER BY last_seen_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| KernelRouteRecord {
                id: row.id,
                device_id: row.device_id,
                route_id: row.flow_id,
                app_id: row.label.clone().unwrap_or_else(|| "unknown".into()),
                route_kind: row.route_kind.unwrap_or_else(|| "direct".into()),
                profile_id: row.profile_id,
                interface_luid: None,
                socks_port: None,
                label: row.label,
                active: row.active != 0,
                last_seen_at: row.last_seen_at,
            })
            .collect())
    }

    pub async fn list_flow_stats(&self) -> Result<Vec<KernelFlowStatRecord>, DbError> {
        let rows = sqlx::query_as::<_, database::models::KernelFlowStatRow>(
            "SELECT id, device_id, stat_type, flow_id, process_id, protocol, bytes, direction,
                    route_kind, profile_id, label, active, last_seen_at, created_at, updated_at
             FROM kernel_flow_stats WHERE stat_type = 'flow' ORDER BY last_seen_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| KernelFlowStatRecord {
                id: row.id,
                device_id: row.device_id,
                flow_id: row.flow_id,
                process_id: row.process_id,
                protocol: row.protocol,
                bytes: row.bytes,
                direction: row.direction,
                route_kind: row.route_kind,
                last_seen_at: row.last_seen_at,
            })
            .collect())
    }

    pub async fn ingest(
        &self,
        device_id: &str,
        hb: &KernelHeartbeat,
    ) -> Result<KernelSnapshot, DbError> {
        let now = now_iso();
        let reported_at = hb.reported_at.clone().unwrap_or_else(|| now.clone());
        let guardian_mode = hb
            .guardian_mode
            .clone()
            .or_else(|| hb.wfp_engine.clone())
            .unwrap_or_else(|| "userspace".into());
        let lifecycle_state = hb
            .lifecycle_state
            .clone()
            .unwrap_or_else(|| "stopped".into());
        let wfp_engine = hb
            .wfp_engine
            .clone()
            .unwrap_or_else(|| guardian_mode.clone());
        let healthy = hb.driver_connected
            && !hb.stub_mode
            && (lifecycle_state == "running" || lifecycle_state == "recovering");
        let active_route_count = hb.routes.iter().filter(|r| r.active).count() as i64;
        let telemetry_json = hb
            .telemetry
            .as_ref()
            .and_then(|t| serde_json::to_value(t).ok())
            .map(|v| serde_json::to_string(&v).unwrap_or_else(|_| "{}".into()));
        let id = Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO kernel_snapshots (
                id, device_id, guardian_mode, driver_connected, lifecycle_state, kill_switch_mode,
                stub_mode, wfp_engine, ndis_enabled, healthy, filter_count, callouts_registered,
                transform_profile, cover_traffic_profile, telemetry_json, active_route_count,
                reported_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(&guardian_mode)
        .bind(hb.driver_connected)
        .bind(&lifecycle_state)
        .bind(&hb.kill_switch_mode)
        .bind(hb.stub_mode)
        .bind(&wfp_engine)
        .bind(hb.ndis_enabled)
        .bind(healthy)
        .bind(hb.filter_count.map(|v| v as i64).unwrap_or(0))
        .bind(hb.callouts_registered.map(|v| v as i64).unwrap_or(0))
        .bind(&hb.transform_profile)
        .bind(&hb.cover_traffic_profile)
        .bind(&telemetry_json)
        .bind(active_route_count)
        .bind(&reported_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        for route in &hb.routes {
            let row_id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO kernel_flow_stats (
                    id, device_id, stat_type, flow_id, process_id, protocol, bytes, direction,
                    route_kind, profile_id, label, active, last_seen_at, created_at, updated_at
                 ) VALUES (?, ?, 'route', ?, NULL, NULL, 0, NULL, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(device_id, stat_type, flow_id) DO UPDATE SET
                   route_kind = excluded.route_kind,
                   profile_id = excluded.profile_id,
                   label = excluded.label,
                   active = excluded.active,
                   last_seen_at = excluded.last_seen_at,
                   updated_at = excluded.updated_at",
            )
            .bind(&row_id)
            .bind(device_id)
            .bind(&route.route_id)
            .bind(&route.route_kind)
            .bind(route.profile_id.map(|v| v as i64))
            .bind(route.label.as_deref().unwrap_or(&route.app_id))
            .bind(route.active)
            .bind(&reported_at)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        }

        for flow in &hb.flow_stats {
            let row_id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO kernel_flow_stats (
                    id, device_id, stat_type, flow_id, process_id, protocol, bytes, direction,
                    route_kind, profile_id, label, active, last_seen_at, created_at, updated_at
                 ) VALUES (?, ?, 'flow', ?, ?, ?, ?, ?, ?, NULL, NULL, 1, ?, ?, ?)
                 ON CONFLICT(device_id, stat_type, flow_id) DO UPDATE SET
                   process_id = excluded.process_id,
                   protocol = excluded.protocol,
                   bytes = excluded.bytes,
                   direction = excluded.direction,
                   route_kind = excluded.route_kind,
                   last_seen_at = excluded.last_seen_at,
                   updated_at = excluded.updated_at",
            )
            .bind(&row_id)
            .bind(device_id)
            .bind(&flow.flow_id)
            .bind(flow.process_id.map(|v| v as i64))
            .bind(flow.protocol.map(|v| v as i64))
            .bind(flow.bytes.map(|v| v as i64).unwrap_or(0))
            .bind(&flow.direction)
            .bind(&flow.route_kind)
            .bind(&reported_at)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        }

        Ok(KernelSnapshot {
            id,
            device_id: device_id.to_string(),
            guardian_mode,
            driver_connected: hb.driver_connected,
            lifecycle_state,
            kill_switch_mode: hb.kill_switch_mode.clone(),
            stub_mode: hb.stub_mode,
            wfp_engine,
            ndis_enabled: hb.ndis_enabled,
            healthy,
            filter_count: hb.filter_count.map(|v| v as i64).unwrap_or(0),
            callouts_registered: hb.callouts_registered.map(|v| v as i64).unwrap_or(0),
            transform_profile: hb.transform_profile.clone(),
            cover_traffic_profile: hb.cover_traffic_profile.clone(),
            telemetry: telemetry_json
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok()),
            active_route_count,
            reported_at,
            created_at: now,
        })
    }
}

fn row_to_snapshot(row: database::models::KernelSnapshotRow) -> Result<KernelSnapshot, DbError> {
    let telemetry = row
        .telemetry_json
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok());
    Ok(KernelSnapshot {
        id: row.id,
        device_id: row.device_id,
        guardian_mode: row.guardian_mode,
        driver_connected: row.driver_connected != 0,
        lifecycle_state: row.lifecycle_state,
        kill_switch_mode: row.kill_switch_mode,
        stub_mode: row.stub_mode != 0,
        wfp_engine: row.wfp_engine,
        ndis_enabled: row.ndis_enabled != 0,
        healthy: row.healthy != 0,
        filter_count: row.filter_count,
        callouts_registered: row.callouts_registered,
        transform_profile: row.transform_profile,
        cover_traffic_profile: row.cover_traffic_profile,
        telemetry,
        active_route_count: row.active_route_count,
        reported_at: row.reported_at,
        created_at: row.created_at,
    })
}
