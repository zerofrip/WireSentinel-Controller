use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use controller::{
    AuditCollector, AuditQuery, AuthService, Claims, CloudControllerManager, CloudReporter,
    CloudHealthIngest, CloudLogsIngest, CloudUsageIngest,
    CreateCloudControllerRequest, CreateEnrollmentTokenRequest, CreatePolicyRequest,
    DeviceHeartbeat, DeviceManager, EnrollmentManager, FederationService, IngestAuditEvent,
    AnonymityHealthAggregator, AnonymityHeartbeat, ConnectorRegistration, KernelHealthAggregator,
    KernelHeartbeat, LoginRequest, MetricsAggregator, MixnetHealthAggregator, MixnetHeartbeat,
    MixnetInventoryManager, PolicyDistributor, PushPolicyRequest, SseTelemetryIngest, SseManager,
    CnappManager, CnappScanIngest, CnappTelemetryIngest,
    AiCopilotQueryInput, AiGenerateInput, AiSecurityManager, AiTelemetryIngest,
    XdrCaseInput, XdrDetectionInput, XdrHuntInput, XdrIncidentInput, XdrManager, XdrPlaybookInput,
    XdrResponseExecuteInput, XdrTelemetryIngest,
    ZtnaHeartbeat, ZtnaManager,
    RegisterFromCloudRequest, RevokePolicyRequest, RegisterDeviceRequest, Role,
    TcpTerminationManager, CreateTcpTerminationRuleInput, UpdateTcpTerminationRuleInput,
    UpdateTcpTerminationSettingsInput,
    SplitTemplateManager, CreateSplitTemplateInput, UpdateSplitTemplateInput,
    UpdateSplitTemplateModeInput,
};
use database::DbPool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::error::ApiError;
use crate::middleware as auth_mw;

#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub auth: Arc<AuthService>,
    pub enrollment: Arc<EnrollmentManager>,
    pub devices: Arc<DeviceManager>,
    pub policies: Arc<PolicyDistributor>,
    pub audit: Arc<AuditCollector>,
    pub metrics: Arc<MetricsAggregator>,
    pub mixnet_inventory: Arc<MixnetInventoryManager>,
    pub mixnet_health: Arc<MixnetHealthAggregator>,
    pub kernel_health: Arc<KernelHealthAggregator>,
    pub anonymity_health: Arc<AnonymityHealthAggregator>,
    pub ztna: Arc<ZtnaManager>,
    pub sse: Arc<SseManager>,
    pub xdr: Arc<XdrManager>,
    pub cnapp: Arc<CnappManager>,
    pub ai: Arc<AiSecurityManager>,
    pub federation: Arc<FederationService>,
    pub cloud_controllers: Arc<CloudControllerManager>,
    pub cloud_reporter: Arc<CloudReporter>,
    pub tcp_termination: Arc<TcpTerminationManager>,
    pub split_templates: Arc<SplitTemplateManager>,
}

pub fn build_router(state: AppState) -> Router {
    let public = Router::new()
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/devices/register", post(register_device))
        .route("/api/v1/devices/{id}/heartbeat", post(device_heartbeat))
        .route("/api/v1/policies/global", get(get_global_policy))
        .route("/api/v1/policies/devices/{id}", get(get_device_policy))
        .route("/api/v1/agents/{id}/metrics", post(agent_metrics_push))
        .route("/api/v1/agents/{id}/audit/ingest", post(agent_audit_ingest))
        .route("/api/v1/agents/{id}/mixnet/heartbeat", post(agent_mixnet_heartbeat))
        .route("/api/v1/agents/{id}/kernel/heartbeat", post(agent_kernel_heartbeat))
        .route("/api/v1/agents/{id}/anonymity/heartbeat", post(agent_anonymity_heartbeat))
        .route("/api/v1/agents/{id}/ztna/heartbeat", post(agent_ztna_heartbeat))
        .route(
            "/api/v1/agents/{id}/ztna/connectors",
            post(agent_register_connector),
        )
        .route(
            "/api/v1/agents/{id}/sse/telemetry",
            post(agent_sse_telemetry),
        )
        .route(
            "/api/v1/agents/{id}/xdr/telemetry",
            post(agent_xdr_telemetry),
        )
        .route(
            "/api/v1/agents/{id}/xdr/response",
            post(agent_xdr_response),
        )
        .route(
            "/api/v1/agents/{id}/cnapp/telemetry",
            post(agent_cnapp_telemetry),
        )
        .route(
            "/api/v1/agents/{id}/ai/telemetry",
            post(agent_ai_telemetry),
        )
        .route(
            "/api/v1/agents/{id}/ai/copilot/query",
            post(agent_ai_copilot_query),
        )
        .route("/api/v1/federation/register", post(federation_register))
        .route("/api/v1/federation/sync", get(federation_pull_sync).post(federation_push_sync))
        .route("/api/v1/cloud/usage", post(cloud_usage_ingest))
        .route("/api/v1/cloud/health", post(cloud_health_ingest))
        .route("/api/v1/cloud/logs", post(cloud_logs_ingest))
        .route("/health", get(health));

    let protected = Router::new()
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/enrollment/tokens", get(list_enrollment_tokens).post(create_enrollment_token))
        .route(
            "/api/v1/enrollment/tokens/{id}/revoke",
            post(revoke_enrollment_token),
        )
        .route(
            "/api/v1/enrollment/tokens/{id}/rotate",
            post(rotate_enrollment_token),
        )
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/devices/{id}", get(get_device))
        .route("/api/v1/policies", get(list_policies).post(create_policy))
        .route("/api/v1/policies/{id}", get(get_policy))
        .route("/api/v1/policies/push", post(push_policy))
        .route("/api/v1/policies/revoke", post(revoke_policy))
        .route("/api/v1/audit", get(list_audit))
        .route("/api/v1/audit/ingest", post(ingest_audit))
        .route("/api/v1/metrics", get(get_metrics))
        .route("/api/v1/mixnet", get(get_mixnet_inventory))
        .route("/api/v1/mixnet/routes", get(list_mixnet_routes))
        .route("/api/v1/mixnet/health", get(get_mixnet_health))
        .route("/api/v1/anonymity", get(get_anonymity_health))
        .route("/api/v1/anonymity/routes", get(list_anonymity_routes))
        .route("/api/v1/anonymity/analytics", get(get_anonymity_analytics))
        .route("/api/v1/ztna/policies", get(list_ztna_policies))
        .route("/api/v1/ztna/resources", get(list_ztna_resources))
        .route("/api/v1/ztna/trust", get(list_ztna_trust))
        .route("/api/v1/ztna/analytics", get(get_ztna_analytics))
        .route("/api/v1/ztna", get(get_ztna_dashboard))
        .route("/api/v1/sse/swg", get(get_sse_swg))
        .route("/api/v1/sse/casb", get(get_sse_casb))
        .route("/api/v1/sse/dlp", get(get_sse_dlp))
        .route("/api/v1/sse/risk", get(get_sse_risk))
        .route("/api/v1/sse/ueba", get(get_sse_ueba))
        .route("/api/v1/xdr/incidents", get(get_xdr_incidents).post(create_xdr_incident))
        .route("/api/v1/xdr/cases", get(get_xdr_cases).post(create_xdr_case))
        .route("/api/v1/xdr/detections", get(get_xdr_detections).post(create_xdr_detection))
        .route("/api/v1/xdr/hunts", get(get_xdr_hunts).post(create_xdr_hunt))
        .route("/api/v1/xdr/attack-graph", get(get_xdr_attack_graph))
        .route("/api/v1/xdr/mitre", get(get_xdr_mitre))
        .route(
            "/api/v1/xdr/soar/playbooks",
            get(get_xdr_soar_playbooks).post(create_xdr_playbook),
        )
        .route("/api/v1/xdr/telemetry/ingest", post(ingest_xdr_telemetry))
        .route("/api/v1/xdr/response/execute", post(execute_xdr_response))
        .route("/api/v1/cnapp/posture", get(get_cnapp_posture))
        .route("/api/v1/cnapp/workloads", get(get_cnapp_workloads))
        .route("/api/v1/cnapp/kubernetes", get(get_cnapp_kubernetes))
        .route("/api/v1/cnapp/containers", get(get_cnapp_containers))
        .route("/api/v1/cnapp/iac", get(get_cnapp_iac))
        .route("/api/v1/cnapp/secrets", get(get_cnapp_secrets))
        .route("/api/v1/cnapp/supply-chain", get(get_cnapp_supply_chain))
        .route("/api/v1/cnapp/sbom", get(get_cnapp_sbom))
        .route("/api/v1/cnapp/vulnerabilities", get(get_cnapp_vulnerabilities))
        .route("/api/v1/cnapp/compliance", get(get_cnapp_compliance))
        .route("/api/v1/cnapp/attack-paths", get(get_cnapp_attack_paths))
        .route("/api/v1/cnapp/telemetry/ingest", post(ingest_cnapp_telemetry))
        .route("/api/v1/cnapp/scan/ingest", post(ingest_cnapp_scan))
        .route("/api/v1/ai/copilot/query", post(ai_copilot_query))
        .route("/api/v1/ai/investigations", get(get_ai_investigations))
        .route("/api/v1/ai/threats", get(get_ai_threats))
        .route("/api/v1/ai/knowledge-graph", get(get_ai_knowledge_graph))
        .route("/api/v1/ai/reports", get(get_ai_reports))
        .route("/api/v1/ai/risk", get(get_ai_risk))
        .route("/api/v1/ai/detections", get(get_ai_detections))
        .route("/api/v1/ai/playbooks", get(get_ai_playbooks))
        .route("/api/v1/ai/policies", get(get_ai_policies))
        .route("/api/v1/ai/intelligence", get(get_ai_intelligence))
        .route("/api/v1/ai/playbooks/generate", post(generate_ai_playbook))
        .route("/api/v1/ai/policies/generate", post(generate_ai_policy))
        .route("/api/v1/ai/detections/generate", post(generate_ai_detection))
        .route("/api/v1/ai/telemetry/ingest", post(ingest_ai_telemetry))
        .route("/api/v1/kernel/status", get(get_kernel_status))
        .route("/api/v1/kernel/telemetry", get(get_kernel_telemetry))
        .route("/api/v1/kernel/routes", get(list_kernel_routes))
        .route(
            "/api/v1/cloud/controllers",
            get(list_cloud_controllers).post(create_cloud_controller),
        )
        .route("/api/v1/cloud/controllers/{id}", get(get_cloud_controller))
        .route(
            "/api/v1/cloud/controllers/{id}/provision",
            post(provision_cloud_controller),
        )
        .route(
            "/api/v1/cloud/controllers/{id}/diagnostics",
            post(run_cloud_controller_diagnostics),
        )
        .route(
            "/api/v1/cloud/controllers/{id}/backup",
            post(backup_cloud_controller),
        )
        .route(
            "/api/v1/cloud/controllers/{id}/restore",
            post(restore_cloud_controller),
        )
        .route(
            "/api/v1/tcp-termination/settings",
            get(get_tcp_termination_settings).put(put_tcp_termination_settings),
        )
        .route(
            "/api/v1/tcp-termination/rules",
            get(get_tcp_termination_rules).post(create_tcp_termination_rule),
        )
        .route(
            "/api/v1/tcp-termination/rules/{id}",
            put(update_tcp_termination_rule).delete(delete_tcp_termination_rule),
        )
        .route(
            "/api/v1/split-templates",
            get(get_split_templates).post(create_split_template),
        )
        .route(
            "/api/v1/split-templates/mode",
            get(get_split_template_mode).put(put_split_template_mode),
        )
        .route(
            "/api/v1/split-templates/{id}",
            put(update_split_template).delete(delete_split_template),
        )
        .layer(middleware::from_fn_with_state(state.clone(), auth_mw::require_auth));

    Router::new()
        .merge(public)
        .merge(protected)
        .with_state(state)
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
        .layer(TraceLayer::new_for_http())
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<controller::LoginResponse>, ApiError> {
    let resp = state.auth.login(req).await.map_err(ApiError::from)?;
    let _ = state
        .audit
        .ingest(IngestAuditEvent {
            source: "controller".into(),
            actor: Some(resp.username.clone()),
            action: "auth.login".into(),
            resource_type: Some("user".into()),
            resource_id: None,
            details: None,
        })
        .await;
    Ok(Json(resp))
}

async fn me(auth: auth_mw::AuthUser) -> Json<MeResponse> {
    Json(MeResponse {
        user_id: auth.claims.sub.clone(),
        username: auth.claims.username.clone(),
        role: auth.claims.role,
    })
}

#[derive(Serialize)]
struct MeResponse {
    user_id: String,
    username: String,
    role: Role,
}

async fn create_enrollment_token(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(req): Json<CreateEnrollmentTokenRequest>,
) -> Result<Json<EnrollmentTokenCreatedResponse>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let (token, raw) = state.enrollment.create_token(req).await?;
    Ok(Json(EnrollmentTokenCreatedResponse { token, secret: raw }))
}

#[derive(Serialize)]
struct EnrollmentTokenCreatedResponse {
    #[serde(flatten)]
    token: controller::EnrollmentToken,
    secret: String,
}

async fn list_enrollment_tokens(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<Vec<controller::EnrollmentToken>>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.enrollment.list_tokens().await?))
}

async fn revoke_enrollment_token(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Path(id): Path<String>,
) -> Result<Json<controller::EnrollmentToken>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(state.enrollment.revoke_token(&id).await?))
}

async fn rotate_enrollment_token(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Path(id): Path<String>,
) -> Result<Json<controller::RotateEnrollmentTokenResponse>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(state.enrollment.rotate_token(&id).await?))
}

async fn register_device(
    State(state): State<AppState>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<(StatusCode, Json<controller::Device>), ApiError> {
    let enrollment = state
        .enrollment
        .validate_raw_token(&req.enrollment_token)
        .await?;
    let device = state.devices.register(req, &enrollment).await?;
    Ok((StatusCode::CREATED, Json(device)))
}

async fn list_devices(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<Vec<controller::Device>>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.devices.list().await?))
}

async fn get_device(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Path(id): Path<String>,
) -> Result<Json<controller::Device>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.devices.get(&id).await?))
}

async fn device_heartbeat(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(hb): Json<DeviceHeartbeat>,
) -> Result<Json<controller::Device>, ApiError> {
    Ok(Json(state.devices.heartbeat(&id, hb).await?))
}

async fn create_policy(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<controller::Policy>), ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let policy = state.policies.create(req).await?;
    Ok((StatusCode::CREATED, Json(policy)))
}

async fn list_policies(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<Vec<controller::Policy>>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.policies.list().await?))
}

async fn get_policy(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Path(id): Path<String>,
) -> Result<Json<controller::Policy>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.policies.get(&id).await?))
}

async fn push_policy(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(req): Json<PushPolicyRequest>,
) -> Result<Json<controller::Policy>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(state.policies.push(req).await?))
}

async fn revoke_policy(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(req): Json<RevokePolicyRequest>,
) -> Result<Json<controller::Policy>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(state.policies.revoke(req).await?))
}

async fn get_global_policy(
    State(state): State<AppState>,
) -> Result<Json<controller::DevicePolicyBundle>, ApiError> {
    Ok(Json(state.policies.global_bundle().await?))
}

async fn get_device_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<controller::DevicePolicyBundle>, ApiError> {
    Ok(Json(state.policies.device_bundle(&id).await?))
}

#[derive(Deserialize)]
struct AgentMetricsBody {
    active_tunnels: u32,
    active_transports: u32,
    blocked_requests: u64,
    dns_queries: u64,
    open_leak_incidents: u32,
    route_changes_24h: u64,
}

async fn agent_metrics_push(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<AgentMetricsBody>,
) -> Result<StatusCode, ApiError> {
    let _ = state.devices.get(&id).await?;
    let device_id = id.clone();
    state
        .metrics
        .ingest_agent_metrics(
            &id,
            controller::metrics::AgentMetricsPayload {
                device_id,
                active_tunnels: body.active_tunnels,
                active_transports: body.active_transports,
                blocked_requests: body.blocked_requests,
                dns_queries: body.dns_queries,
                open_leak_incidents: body.open_leak_incidents,
                route_changes_24h: body.route_changes_24h,
            },
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn agent_mixnet_heartbeat(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(hb): Json<MixnetHeartbeat>,
) -> Result<StatusCode, ApiError> {
    let _ = state.devices.get(&id).await?;
    state.mixnet_inventory.ingest_heartbeat(&id, &hb).await?;
    state.mixnet_health.ingest(&id, &hb).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn agent_kernel_heartbeat(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(hb): Json<KernelHeartbeat>,
) -> Result<StatusCode, ApiError> {
    let _ = state.devices.get(&id).await?;
    state.kernel_health.ingest(&id, &hb).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn agent_anonymity_heartbeat(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(hb): Json<AnonymityHeartbeat>,
) -> Result<StatusCode, ApiError> {
    let _ = state.devices.get(&id).await?;
    state.anonymity_health.ingest_heartbeat(&id, &hb).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_anonymity_health(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::AnonymityHealthSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.anonymity_health.summary().await?))
}

async fn list_anonymity_routes(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<Vec<controller::AnonymityRouteRecord>>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.anonymity_health.list_routes().await?))
}

async fn get_anonymity_analytics(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::AnonymityAnalyticsSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.anonymity_health.analytics_summary().await?))
}

async fn agent_ztna_heartbeat(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(hb): Json<ZtnaHeartbeat>,
) -> Result<StatusCode, ApiError> {
    let _ = state.devices.get(&id).await?;
    state.ztna.ingest_heartbeat(&id, &hb).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn agent_register_connector(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(reg): Json<ConnectorRegistration>,
) -> Result<(StatusCode, Json<controller::ConnectorRecord>), ApiError> {
    let _ = state.devices.get(&id).await?;
    let record = state.ztna.register_connector(&id, &reg).await?;
    Ok((StatusCode::CREATED, Json(record)))
}

async fn list_ztna_policies(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<Vec<controller::ZtnaPolicyRecord>>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ztna.list_policies().await?))
}

async fn list_ztna_resources(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<Vec<controller::PublishedResourceRecord>>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ztna.list_resources().await?))
}

async fn list_ztna_trust(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<Vec<controller::DeviceTrustRecord>>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ztna.list_trust().await?))
}

async fn get_ztna_analytics(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::ZtnaAnalyticsSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ztna.analytics().await?))
}

async fn get_ztna_dashboard(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::ZtnaDashboardSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ztna.dashboard().await?))
}

async fn agent_sse_telemetry(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<SseTelemetryIngest>,
) -> Result<StatusCode, ApiError> {
    let _ = state.devices.get(&id).await?;
    state.sse.ingest_telemetry(&id, &payload).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_sse_swg(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::SwgSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.sse.swg_summary().await?))
}

async fn get_sse_casb(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::CasbSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.sse.casb_summary().await?))
}

async fn get_sse_dlp(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::DlpSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.sse.dlp_summary().await?))
}

async fn get_sse_risk(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::RiskSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.sse.risk_summary().await?))
}

async fn get_sse_ueba(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::UebaSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.sse.ueba_summary().await?))
}

async fn agent_xdr_telemetry(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<XdrTelemetryIngest>,
) -> Result<StatusCode, ApiError> {
    let _ = state.devices.get(&id).await?;
    state.xdr.ingest_telemetry(&id, &payload).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn agent_xdr_response(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(mut payload): Json<XdrResponseExecuteInput>,
) -> Result<Json<controller::XdrResponseActionRecord>, ApiError> {
    let _ = state.devices.get(&id).await?;
    if payload.device_id.is_none() {
        payload.device_id = Some(id);
    }
    Ok(Json(state.xdr.execute_response(&payload).await?))
}

async fn get_xdr_incidents(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::IncidentsSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.xdr.incidents_summary().await?))
}

async fn create_xdr_incident(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(payload): Json<XdrIncidentInput>,
) -> Result<(StatusCode, Json<controller::XdrIncidentRecord>), ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok((
        StatusCode::CREATED,
        Json(state.xdr.create_incident(&payload).await?),
    ))
}

async fn get_xdr_cases(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::CasesSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.xdr.cases_summary().await?))
}

async fn create_xdr_case(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(payload): Json<XdrCaseInput>,
) -> Result<(StatusCode, Json<controller::XdrCaseRecord>), ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok((
        StatusCode::CREATED,
        Json(state.xdr.create_case(&payload).await?),
    ))
}

async fn get_xdr_detections(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::DetectionsSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.xdr.detections_summary().await?))
}

async fn create_xdr_detection(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(payload): Json<XdrDetectionInput>,
) -> Result<(StatusCode, Json<controller::XdrDetectionRecord>), ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok((
        StatusCode::CREATED,
        Json(state.xdr.create_detection(&payload).await?),
    ))
}

async fn get_xdr_hunts(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::HuntsSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.xdr.hunts_summary().await?))
}

async fn create_xdr_hunt(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(payload): Json<XdrHuntInput>,
) -> Result<(StatusCode, Json<controller::XdrHuntRecord>), ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok((
        StatusCode::CREATED,
        Json(state.xdr.create_hunt(&payload).await?),
    ))
}

async fn get_xdr_attack_graph(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::AttackGraphSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.xdr.attack_graph_summary().await?))
}

async fn get_xdr_mitre(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::MitreSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.xdr.mitre_summary().await?))
}

async fn get_xdr_soar_playbooks(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::SoarSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.xdr.soar_summary().await?))
}

async fn create_xdr_playbook(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(payload): Json<XdrPlaybookInput>,
) -> Result<(StatusCode, Json<controller::XdrPlaybookRecord>), ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok((
        StatusCode::CREATED,
        Json(state.xdr.create_playbook(&payload).await?),
    ))
}

#[derive(Debug, Deserialize)]
struct XdrTelemetryIngestRequest {
    device_id: String,
    #[serde(flatten)]
    payload: XdrTelemetryIngest,
}

async fn ingest_xdr_telemetry(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(body): Json<XdrTelemetryIngestRequest>,
) -> Result<Json<controller::XdrTelemetrySnapshot>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let _ = state.devices.get(&body.device_id).await?;
    Ok(Json(
        state
            .xdr
            .ingest_telemetry(&body.device_id, &body.payload)
            .await?,
    ))
}

async fn execute_xdr_response(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(payload): Json<XdrResponseExecuteInput>,
) -> Result<Json<controller::XdrResponseActionRecord>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(state.xdr.execute_response(&payload).await?))
}

async fn agent_cnapp_telemetry(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<CnappTelemetryIngest>,
) -> Result<StatusCode, ApiError> {
    let _ = state.devices.get(&id).await?;
    state.cnapp.ingest_telemetry(&id, &payload).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_cnapp_posture(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::PostureSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cnapp.posture_summary().await?))
}

async fn get_cnapp_workloads(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::WorkloadsSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cnapp.workloads_summary().await?))
}

async fn get_cnapp_kubernetes(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::KubernetesSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cnapp.kubernetes_summary().await?))
}

async fn get_cnapp_containers(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::ContainersSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cnapp.containers_summary().await?))
}

async fn get_cnapp_iac(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::IacSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cnapp.iac_summary().await?))
}

async fn get_cnapp_secrets(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::SecretsSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cnapp.secrets_summary().await?))
}

async fn get_cnapp_supply_chain(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::SupplyChainSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cnapp.supply_chain_summary().await?))
}

async fn get_cnapp_sbom(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::SbomSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cnapp.sbom_summary().await?))
}

async fn get_cnapp_vulnerabilities(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::VulnerabilitiesSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cnapp.vulnerabilities_summary().await?))
}

async fn get_cnapp_compliance(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::ComplianceSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cnapp.compliance_summary().await?))
}

async fn get_cnapp_attack_paths(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::AttackPathsSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cnapp.attack_paths_summary().await?))
}

#[derive(Debug, Deserialize)]
struct CnappTelemetryIngestRequest {
    device_id: String,
    #[serde(flatten)]
    payload: CnappTelemetryIngest,
}

async fn ingest_cnapp_telemetry(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(body): Json<CnappTelemetryIngestRequest>,
) -> Result<Json<controller::CnappTelemetrySnapshot>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let _ = state.devices.get(&body.device_id).await?;
    Ok(Json(
        state
            .cnapp
            .ingest_telemetry(&body.device_id, &body.payload)
            .await?,
    ))
}

#[derive(Debug, Deserialize)]
struct CnappScanIngestRequest {
    device_id: String,
    #[serde(flatten)]
    payload: CnappScanIngest,
}

async fn ingest_cnapp_scan(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(body): Json<CnappScanIngestRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let _ = state.devices.get(&body.device_id).await?;
    Ok(Json(
        state
            .cnapp
            .ingest_scan(&body.device_id, &body.payload)
            .await?,
    ))
}

async fn agent_ai_telemetry(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<AiTelemetryIngest>,
) -> Result<StatusCode, ApiError> {
    let _ = state.devices.get(&id).await?;
    state.ai.ingest_telemetry(&id, &payload).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct AgentAiCopilotQueryRequest {
    #[serde(flatten)]
    query: AiCopilotQueryInput,
}

async fn agent_ai_copilot_query(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<AgentAiCopilotQueryRequest>,
) -> Result<Json<controller::AiCopilotQueryResult>, ApiError> {
    let _ = state.devices.get(&id).await?;
    Ok(Json(
        state
            .ai
            .copilot_query(Some(&id), None, &body.query)
            .await?,
    ))
}

async fn ai_copilot_query(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(body): Json<AiCopilotQueryInput>,
) -> Result<Json<controller::AiCopilotQueryResult>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(
        state
            .ai
            .copilot_query(None, Some(&auth.claims.sub), &body)
            .await?,
    ))
}

async fn get_ai_investigations(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::InvestigationsSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ai.investigations_summary().await?))
}

async fn get_ai_threats(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::ThreatsSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ai.threats_summary().await?))
}

async fn get_ai_knowledge_graph(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::KnowledgeGraphSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ai.knowledge_graph_summary().await?))
}

async fn get_ai_reports(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::ReportsSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ai.reports_summary().await?))
}

async fn get_ai_risk(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::AiRiskSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ai.risk_summary().await?))
}

async fn get_ai_detections(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::AiDetectionsSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ai.detections_summary().await?))
}

async fn get_ai_playbooks(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::PlaybooksSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ai.playbooks_summary().await?))
}

async fn get_ai_policies(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::PoliciesSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ai.policies_summary().await?))
}

async fn get_ai_intelligence(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::IntelligenceSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.ai.intelligence_summary().await?))
}

async fn generate_ai_playbook(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(body): Json<AiGenerateInput>,
) -> Result<Json<controller::AiPlaybookSuggestionRecord>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(state.ai.generate_playbook(&body).await?))
}

async fn generate_ai_policy(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(body): Json<AiGenerateInput>,
) -> Result<Json<controller::AiPolicySuggestionRecord>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(state.ai.generate_policy(&body).await?))
}

async fn generate_ai_detection(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(body): Json<AiGenerateInput>,
) -> Result<Json<controller::AiDetectionSuggestionRecord>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(state.ai.generate_detection(&body).await?))
}

#[derive(Debug, Deserialize)]
struct AiTelemetryIngestRequest {
    device_id: String,
    #[serde(flatten)]
    payload: AiTelemetryIngest,
}

async fn ingest_ai_telemetry(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(body): Json<AiTelemetryIngestRequest>,
) -> Result<Json<controller::AiTelemetrySnapshot>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let _ = state.devices.get(&body.device_id).await?;
    Ok(Json(
        state
            .ai
            .ingest_telemetry(&body.device_id, &body.payload)
            .await?,
    ))
}

async fn get_kernel_status(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::KernelStatusSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.kernel_health.status_summary().await?))
}

async fn get_kernel_telemetry(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::KernelTelemetrySummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.kernel_health.telemetry_summary().await?))
}

async fn list_kernel_routes(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<Vec<controller::KernelRouteRecord>>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.kernel_health.list_routes().await?))
}

async fn get_mixnet_inventory(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::MixnetInventorySummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.mixnet_inventory.summary().await?))
}

async fn list_mixnet_routes(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<Vec<controller::MixnetRouteRecord>>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.mixnet_inventory.list_routes().await?))
}

async fn get_mixnet_health(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::MixnetHealthSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.mixnet_health.summary().await?))
}

async fn agent_audit_ingest(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(mut event): Json<IngestAuditEvent>,
) -> Result<(StatusCode, Json<controller::AuditEvent>), ApiError> {
    let _ = state.devices.get(&id).await?;
    event.source = format!("agent:{id}");
    let saved = state.audit.ingest(event).await?;
    Ok((StatusCode::CREATED, Json(saved)))
}

#[derive(Deserialize)]
struct AuditListQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    action: Option<String>,
    source: Option<String>,
}

async fn list_audit(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Query(q): Query<AuditListQuery>,
) -> Result<Json<Vec<controller::AuditEvent>>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(
        state
            .audit
            .list(AuditQuery {
                limit: q.limit,
                offset: q.offset,
                action: q.action,
                source: q.source,
            })
            .await?,
    ))
}

async fn ingest_audit(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(event): Json<IngestAuditEvent>,
) -> Result<(StatusCode, Json<controller::AuditEvent>), ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let saved = state.audit.ingest(event).await?;
    Ok((StatusCode::CREATED, Json(saved)))
}

async fn get_metrics(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    let snapshot = state.metrics.snapshot().await?;
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    if accept.contains("text/plain") || accept.contains("application/openmetrics-text") {
        let body = state.metrics.to_prometheus(&snapshot);
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            body,
        )
            .into_response())
    } else {
        Ok(Json(snapshot).into_response())
    }
}

async fn federation_register(
    State(state): State<AppState>,
    Json(req): Json<RegisterFromCloudRequest>,
) -> Result<(StatusCode, Json<controller::FederatedRegistration>), ApiError> {
    let registration = state
        .federation
        .register_from_cloud(&req.token, &req.tenant_id, &req.cloud_base_url)
        .await?;
    Ok((StatusCode::CREATED, Json(registration)))
}

#[derive(Deserialize)]
struct FederationSyncPushBody {
    bundle: serde_json::Value,
    tenant_id: Option<String>,
}

async fn federation_push_sync(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<FederationSyncPushBody>,
) -> Result<StatusCode, ApiError> {
    validate_federation_header(&state, &headers).await?;
    let bundle_json = serde_json::to_string(&body.bundle).unwrap_or_else(|_| "{}".into());
    state
        .federation
        .push_sync_bundle(&bundle_json, body.tenant_id.as_deref())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn federation_pull_sync(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<FederationSyncQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_federation_header(&state, &headers).await?;
    let bundle = state
        .federation
        .pull_sync_bundle(q.tenant_id.as_deref())
        .await?
        .unwrap_or(serde_json::json!({}));
    Ok(Json(bundle))
}

#[derive(Deserialize)]
struct FederationSyncQuery {
    tenant_id: Option<String>,
}

async fn validate_federation_header(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    let token = headers
        .get("X-Federation-Token")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    match state.federation.validate_cloud_request(token).await {
        Ok(_) => Ok(()),
        Err(database::DbError::NotFound(_)) => Err(ApiError::Unauthorized),
        Err(e) => Err(ApiError::from(e)),
    }
}

async fn list_cloud_controllers(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<Vec<controller::CloudControllerLink>>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cloud_controllers.list().await?))
}

async fn create_cloud_controller(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(req): Json<CreateCloudControllerRequest>,
) -> Result<(StatusCode, Json<controller::CloudControllerLink>), ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let link = state.cloud_controllers.create(req).await?;
    Ok((StatusCode::CREATED, Json(link)))
}

async fn get_cloud_controller(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Path(id): Path<String>,
) -> Result<Json<controller::CloudControllerLink>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cloud_controllers.get(&id).await?))
}

async fn provision_cloud_controller(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Path(id): Path<String>,
) -> Result<Json<controller::CloudControllerJobStub>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(state.cloud_controllers.provision(&id).await?))
}

async fn run_cloud_controller_diagnostics(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Path(id): Path<String>,
) -> Result<Json<controller::CloudControllerDiagnosticsStub>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.cloud_controllers.diagnostics(&id).await?))
}

async fn backup_cloud_controller(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Path(id): Path<String>,
) -> Result<Json<controller::CloudControllerBackupStub>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(state.cloud_controllers.backup(&id).await?))
}

async fn restore_cloud_controller(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Path(id): Path<String>,
) -> Result<Json<controller::CloudControllerRestoreStub>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(state.cloud_controllers.restore(&id).await?))
}

async fn cloud_usage_ingest(
    State(state): State<AppState>,
    Query(q): Query<CloudIngestQuery>,
    Json(payload): Json<CloudUsageIngest>,
) -> Result<StatusCode, ApiError> {
    if let Some(ref device_id) = q.device_id {
        let _ = state.devices.get(device_id).await?;
    }
    state
        .cloud_reporter
        .ingest_usage(q.device_id.as_deref(), payload)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn cloud_health_ingest(
    State(state): State<AppState>,
    Json(payload): Json<CloudHealthIngest>,
) -> Result<StatusCode, ApiError> {
    state.cloud_reporter.ingest_health(payload).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn cloud_logs_ingest(
    State(state): State<AppState>,
    Query(q): Query<CloudIngestQuery>,
    Json(payload): Json<CloudLogsIngest>,
) -> Result<StatusCode, ApiError> {
    if let Some(ref device_id) = q.device_id {
        let _ = state.devices.get(device_id).await?;
    }
    state
        .cloud_reporter
        .ingest_logs(q.device_id.as_deref(), payload)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct CloudIngestQuery {
    device_id: Option<String>,
}

async fn get_tcp_termination_settings(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::TcpTerminationSettings>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.tcp_termination.get_settings().await?))
}

async fn put_tcp_termination_settings(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(input): Json<UpdateTcpTerminationSettingsInput>,
) -> Result<Json<controller::TcpTerminationSettings>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(state.tcp_termination.set_settings(input).await?))
}

async fn get_tcp_termination_rules(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::TcpTerminationRulesSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.tcp_termination.rules_summary().await?))
}

async fn create_tcp_termination_rule(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(input): Json<CreateTcpTerminationRuleInput>,
) -> Result<(StatusCode, Json<controller::TcpTerminationRule>), ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let rule = state.tcp_termination.create_rule(input).await?;
    Ok((StatusCode::CREATED, Json(rule)))
}

async fn update_tcp_termination_rule(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Path(id): Path<String>,
    Json(input): Json<UpdateTcpTerminationRuleInput>,
) -> Result<Json<controller::TcpTerminationRule>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let id = uuid::Uuid::parse_str(&id).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(state.tcp_termination.update_rule(id, input).await?))
}

async fn delete_tcp_termination_rule(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let id = uuid::Uuid::parse_str(&id).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    state.tcp_termination.delete_rule(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_split_templates(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::SplitTemplatesSummary>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.split_templates.summary().await?))
}

async fn create_split_template(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(input): Json<CreateSplitTemplateInput>,
) -> Result<(StatusCode, Json<controller::SplitTunnelTemplate>), ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let template = state.split_templates.create_template(input).await?;
    Ok((StatusCode::CREATED, Json(template)))
}

async fn get_split_template_mode(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
) -> Result<Json<controller::SplitTemplateModeSettings>, ApiError> {
    require_role(&auth.claims, Role::Viewer)?;
    Ok(Json(state.split_templates.get_mode().await?))
}

async fn put_split_template_mode(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Json(input): Json<UpdateSplitTemplateModeInput>,
) -> Result<Json<controller::SplitTemplateModeSettings>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    Ok(Json(state.split_templates.set_mode(input).await?))
}

async fn update_split_template(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Path(id): Path<String>,
    Json(input): Json<UpdateSplitTemplateInput>,
) -> Result<Json<controller::SplitTunnelTemplate>, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let id = uuid::Uuid::parse_str(&id).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(state.split_templates.update_template(id, input).await?))
}

async fn delete_split_template(
    State(state): State<AppState>,
    auth: auth_mw::AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_role(&auth.claims, Role::Operator)?;
    let id = uuid::Uuid::parse_str(&id).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    state.split_templates.delete_template(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "wiresentinel-controller",
    })
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

fn require_role(claims: &Claims, min: Role) -> Result<(), ApiError> {
    let level = |r: Role| match r {
        Role::Admin => 3,
        Role::Operator => 2,
        Role::Viewer => 1,
    };
    if level(claims.role) >= level(min) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}
