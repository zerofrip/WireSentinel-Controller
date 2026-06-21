use controller::ControllerSecurityPolicy;
use controller::{
    AnonymityHealthAggregator, AuditCollector, AuthService, CloudControllerManager, DeviceManager,
    EnrollmentManager, FederationService, KernelHealthAggregator, MetricsAggregator,
    MixnetHealthAggregator, MixnetInventoryManager, PolicyDistributor, SseManager, XdrManager, CnappManager, AiSecurityManager, SplitTemplateManager, TcpTerminationManager,
    ZtnaManager,
};
use database::setup;
use serde_json::{json, Value};
use std::sync::Arc;

async fn spawn_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let pool = setup("sqlite::memory:").await.expect("db");
    let policy = ControllerSecurityPolicy {
        jwt_secret: "anonymity-test-secret".into(),
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
        .json(&json!({"label":"anonymity-agent"}))
        .send()
        .await
        .expect("create token");
    let created: Value = create.json().await.expect("json");
    let secret = created["secret"].as_str().expect("secret");

    let register = client
        .post(format!("{base}/api/v1/devices/register"))
        .json(&json!({
            "enrollment_token": secret,
            "name": "anonymity-host",
            "os": "linux"
        }))
        .send()
        .await
        .expect("register");
    assert_eq!(register.status(), 201);
    let device: Value = register.json().await.expect("json");
    device["id"].as_str().expect("id").to_string()
}

#[tokio::test]
async fn integration_anonymity_heartbeat_and_list() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let device_id = register_device(&base, &token).await;
    let client = reqwest::Client::new();

    let heartbeat = client
        .post(format!("{base}/api/v1/agents/{device_id}/anonymity/heartbeat"))
        .json(&json!({
            "anonymity_connected": true,
            "stub_mode": false,
            "anonymity_score": 88,
            "route_entropy": 2.4,
            "path_diversity": 0.75,
            "cover_traffic_effectiveness": 0.6,
            "entropy_bits": 128.0,
            "federation_peers": [{
                "peer_id": "peer-eu-1",
                "region": "eu-west",
                "healthy": true
            }],
            "active_routes": [{
                "route_id": "anon-route-1",
                "label": "federated-chain",
                "hops": ["entry", "mix", "exit"],
                "chain_kind": "mixnet",
                "entropy_score": 0.82,
                "active": true
            }]
        }))
        .send()
        .await
        .expect("heartbeat");
    assert_eq!(heartbeat.status(), 204);

    let health = client
        .get(format!("{base}/api/v1/anonymity"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("health");
    assert!(health.status().is_success());
    let health_body: Value = health.json().await.expect("json");
    assert_eq!(health_body["connected_devices"], 1);
    assert_eq!(health_body["federation"]["total_peers"], 1);

    let routes = client
        .get(format!("{base}/api/v1/anonymity/routes"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("routes");
    assert!(routes.status().is_success());
    let route_list: Vec<Value> = routes.json().await.expect("json");
    assert_eq!(route_list.len(), 1);
    assert_eq!(route_list[0]["label"], "federated-chain");

    let analytics = client
        .get(format!("{base}/api/v1/anonymity/analytics"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("analytics");
    assert!(analytics.status().is_success());
    let analytics_body: Value = analytics.json().await.expect("json");
    assert_eq!(analytics_body["devices_reporting"], 1);
    assert!(analytics_body["rollups"].as_array().unwrap().len() >= 1);

    handle.abort();
}

#[tokio::test]
async fn integration_anonymity_heartbeat_requires_device() {
    let (base, handle) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/v1/agents/missing-device/anonymity/heartbeat"))
        .json(&json!({"anonymity_connected": false, "stub_mode": true, "active_routes": [], "federation_peers": []}))
        .send()
        .await
        .expect("heartbeat");
    assert_eq!(resp.status(), 404);
    handle.abort();
}
