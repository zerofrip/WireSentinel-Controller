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
        jwt_secret: "ztna-test-secret".into(),
        bcrypt_cost: 4,
        ..Default::default()
    };
    let auth = Arc::new(AuthService::new(pool.clone(), policy));
    auth.ensure_default_admin().await.expect("admin");

    let ztna = Arc::new(ZtnaManager::new(pool.clone()));
    ztna.seed_defaults().await.expect("seed");
    let sse = Arc::new(SseManager::new(pool.clone()));
    sse.seed_defaults().await.expect("sse seed");
    let xdr = Arc::new(XdrManager::new(pool.clone()));
    xdr.seed_defaults().await.expect("xdr seed");
    let cnapp = Arc::new(CnappManager::new(pool.clone()));
    cnapp.seed_defaults().await.expect("cnapp seed");
    let ai = Arc::new(AiSecurityManager::new(pool.clone()));
    ai.seed_defaults().await.expect("ai seed");

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
        ztna,
        sse,
        xdr,
        cnapp,
        ai,
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
        .json(&json!({"label":"ztna-agent"}))
        .send()
        .await
        .expect("create token");
    let created: Value = create.json().await.expect("json");
    let secret = created["secret"].as_str().expect("secret");

    let register = client
        .post(format!("{base}/api/v1/devices/register"))
        .json(&json!({
            "enrollment_token": secret,
            "name": "ztna-host",
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
async fn integration_ztna_heartbeat_and_list() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let device_id = register_device(&base, &token).await;
    let client = reqwest::Client::new();

    let heartbeat = client
        .post(format!("{base}/api/v1/agents/{device_id}/ztna/heartbeat"))
        .json(&json!({
            "identity_connected": true,
            "active_provider": "generic_oidc",
            "gateway_active": true,
            "connector_count": 2,
            "healthy_connectors": 2,
            "avg_trust_score": 78.5,
            "published_resource_count": 1,
            "recent_denials": 0,
            "trust_level": "high",
            "trust_score": 78,
            "posture": {"compliant": true, "firewall_enabled": true}
        }))
        .send()
        .await
        .expect("heartbeat");
    assert_eq!(heartbeat.status(), 204);

    let connector = client
        .post(format!("{base}/api/v1/agents/{device_id}/ztna/connectors"))
        .json(&json!({
            "connector_id": "conn-1",
            "name": "Edge Connector",
            "endpoint": "https://edge.local:8443",
            "resource_ids": ["res-1"],
            "healthy": true,
            "latency_ms": 12
        }))
        .send()
        .await
        .expect("connector");
    assert_eq!(connector.status(), 201);

    let policies = client
        .get(format!("{base}/api/v1/ztna/policies"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("policies");
    assert!(policies.status().is_success());
    let policy_list: Vec<Value> = policies.json().await.expect("json");
    assert!(!policy_list.is_empty());

    let resources = client
        .get(format!("{base}/api/v1/ztna/resources"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("resources");
    let resource_list: Vec<Value> = resources.json().await.expect("json");
    assert!(!resource_list.is_empty());

    let trust = client
        .get(format!("{base}/api/v1/ztna/trust"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("trust");
    let trust_list: Vec<Value> = trust.json().await.expect("json");
    assert_eq!(trust_list.len(), 1);
    assert_eq!(trust_list[0]["trust_score"], 78);

    let analytics = client
        .get(format!("{base}/api/v1/ztna/analytics"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("analytics");
    let analytics_body: Value = analytics.json().await.expect("json");
    assert_eq!(analytics_body["devices_reporting"], 1);

    handle.abort();
}

#[tokio::test]
async fn integration_ztna_heartbeat_requires_device() {
    let (base, handle) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/v1/agents/missing-device/ztna/heartbeat"))
        .json(&json!({"identity_connected": false, "gateway_active": false}))
        .send()
        .await
        .expect("heartbeat");
    assert_eq!(resp.status(), 404);
    handle.abort();
}
