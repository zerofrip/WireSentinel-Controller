use controller::ControllerSecurityPolicy;
use controller::{
    AnonymityHealthAggregator, AuditCollector, AuthService, CloudControllerManager, DeviceManager, EnrollmentManager,
    FederationService, KernelHealthAggregator, MetricsAggregator, MixnetHealthAggregator,
    MixnetInventoryManager, PolicyDistributor, SseManager, XdrManager, CnappManager, AiSecurityManager, SplitTemplateManager, TcpTerminationManager, ZtnaManager,
};
use database::setup;
use serde_json::{json, Value};
use std::sync::Arc;

async fn spawn_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let pool = setup("sqlite::memory:").await.expect("db");
    let policy = ControllerSecurityPolicy {
        jwt_secret: "kernel-test-secret".into(),
        bcrypt_cost: 4,
        ..Default::default()
    };
    let auth = Arc::new(AuthService::new(pool.clone(), policy));
    auth.ensure_default_admin().await.expect("admin");

    let state = controller_api::AppState {
        pool: pool.clone(),
        auth,
        enrollment: Arc::new(EnrollmentManager::new(pool.clone())),
        devices: Arc::new(DeviceManager::new(pool.clone())),
        policies: Arc::new(PolicyDistributor::new(pool.clone())),
        audit: Arc::new(AuditCollector::new(pool.clone())),
        metrics: Arc::new(MetricsAggregator::new(pool.clone())),
        mixnet_inventory: Arc::new(MixnetInventoryManager::new(pool.clone())),
        mixnet_health: Arc::new(MixnetHealthAggregator::new(pool.clone())),
        kernel_health: Arc::new(KernelHealthAggregator::new(pool.clone())),
        anonymity_health: Arc::new(AnonymityHealthAggregator::new(pool.clone())),
        ztna: Arc::new(ZtnaManager::new(pool.clone())),
        sse: Arc::new(SseManager::new(pool.clone())),
        xdr: Arc::new(XdrManager::new(pool.clone())),
        cnapp: Arc::new(CnappManager::new(pool.clone())),
        ai: Arc::new(AiSecurityManager::new(pool.clone())),
        federation: Arc::new(FederationService::new(pool.clone())),
        cloud_controllers: Arc::new(CloudControllerManager::new(pool.clone())),
        cloud_reporter: Arc::new(controller::CloudReporter::new(pool.clone())),
        tcp_termination: Arc::new(TcpTerminationManager::new(pool.clone())),
        split_templates: Arc::new(SplitTemplateManager::new(pool)),
    };

    let app = controller_api::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let base = format!("http://{addr}");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    (base, handle)
}

async fn login(base: &str) -> String {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/v1/auth/login"))
        .json(&json!({"username":"admin","password":"admin"}))
        .send()
        .await
        .expect("login");
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.expect("json");
    body["token"].as_str().expect("token").to_string()
}

async fn register_device(base: &str, token: &str) -> String {
    let client = reqwest::Client::new();
    let create = client
        .post(format!("{base}/api/v1/enrollment/tokens"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({"label":"kernel-agent"}))
        .send()
        .await
        .expect("create token");
    let created: Value = create.json().await.expect("json");
    let secret = created["secret"].as_str().expect("secret");

    let register = client
        .post(format!("{base}/api/v1/devices/register"))
        .json(&json!({
            "enrollment_token": secret,
            "name": "kernel-host",
            "os": "windows"
        }))
        .send()
        .await
        .expect("register");
    assert_eq!(register.status(), 201);
    let device: Value = register.json().await.expect("json");
    device["id"].as_str().expect("id").to_string()
}

#[tokio::test]
async fn integration_kernel_heartbeat_and_status() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let device_id = register_device(&base, &token).await;
    let client = reqwest::Client::new();

    let heartbeat = client
        .post(format!("{base}/api/v1/agents/{device_id}/kernel/heartbeat"))
        .json(&json!({
            "guardian_mode": "kernel",
            "driver_connected": true,
            "lifecycle_state": "running",
            "kill_switch_mode": "off",
            "stub_mode": false,
            "wfp_engine": "kernel",
            "ndis_enabled": true,
            "filter_count": 12,
            "callouts_registered": 4,
            "telemetry": {
                "classify_count": 1000,
                "block_count": 12,
                "route_count": 88,
                "permit_count": 900,
                "observe_count": 50,
                "error_count": 1,
                "avg_classify_latency_ns": 1200,
                "max_classify_latency_ns": 9000,
                "packets_per_sec": 250
            },
            "routes": [{
                "route_id": "route-1",
                "app_id": "app-1",
                "route_kind": "vpn",
                "profile_id": 42,
                "active": true,
                "label": "default-vpn"
            }],
            "flow_stats": [{
                "flow_id": "flow-1",
                "process_id": 1234,
                "protocol": 6,
                "bytes": 4096,
                "direction": "outbound",
                "route_kind": "vpn"
            }]
        }))
        .send()
        .await
        .expect("heartbeat");
    assert_eq!(heartbeat.status(), 204);

    let status = client
        .get(format!("{base}/api/v1/kernel/status"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("status");
    assert!(status.status().is_success());
    let status_body: Value = status.json().await.expect("json");
    assert_eq!(status_body["reporting_devices"], 1);
    assert_eq!(status_body["healthy_devices"], 1);

    let telemetry = client
        .get(format!("{base}/api/v1/kernel/telemetry"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("telemetry");
    assert!(telemetry.status().is_success());
    let telemetry_body: Value = telemetry.json().await.expect("json");
    assert_eq!(telemetry_body["classify_count"], 1000);

    let routes = client
        .get(format!("{base}/api/v1/kernel/routes"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("routes");
    assert!(routes.status().is_success());
    let route_list: Vec<Value> = routes.json().await.expect("json");
    assert_eq!(route_list.len(), 1);
    assert_eq!(route_list[0]["route_kind"], "vpn");

    handle.abort();
}

#[tokio::test]
async fn integration_kernel_heartbeat_requires_device() {
    let (base, handle) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/v1/agents/missing-device/kernel/heartbeat"))
        .json(&json!({"driver_connected": false, "stub_mode": true, "routes": [], "flow_stats": []}))
        .send()
        .await
        .expect("heartbeat");
    assert_eq!(resp.status(), 404);
    handle.abort();
}
