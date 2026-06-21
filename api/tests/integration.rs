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
        jwt_secret: "integration-test-secret".into(),
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

#[tokio::test]
async fn integration_login_and_list_devices() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/api/v1/devices"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("list devices");
    assert_eq!(resp.status(), 200);
    let devices: Vec<Value> = resp.json().await.expect("json");
    assert!(devices.is_empty());

    handle.abort();
}

#[tokio::test]
async fn integration_enrollment_register_heartbeat() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let client = reqwest::Client::new();

    let create = client
        .post(format!("{base}/api/v1/enrollment/tokens"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({"label":"test-laptop"}))
        .send()
        .await
        .expect("create token");
    assert!(create.status().is_success());
    let created: Value = create.json().await.expect("json");
    let secret = created["secret"].as_str().expect("secret").to_string();

    let register = client
        .post(format!("{base}/api/v1/devices/register"))
        .json(&json!({
            "enrollment_token": secret,
            "name": "workstation-1",
            "hostname": "ws1",
            "os": "linux"
        }))
        .send()
        .await
        .expect("register");
    assert_eq!(register.status(), 201);
    let device: Value = register.json().await.expect("json");
    let device_id = device["id"].as_str().expect("id").to_string();

    let heartbeat = client
        .post(format!("{base}/api/v1/devices/{device_id}/heartbeat"))
        .json(&json!({"agent_version":"0.1.0"}))
        .send()
        .await
        .expect("heartbeat");
    assert!(heartbeat.status().is_success());

    handle.abort();
}

#[tokio::test]
async fn integration_policy_push_and_metrics() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let client = reqwest::Client::new();

    let create = client
        .post(format!("{base}/api/v1/policies"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "name": "default-global",
            "scope": "global",
            "content": {"dns": {"mode": "strict"}}
        }))
        .send()
        .await
        .expect("create policy");
    assert!(create.status().is_success());
    let policy: Value = create.json().await.expect("json");
    let policy_id = policy["id"].as_str().expect("id");

    let push = client
        .post(format!("{base}/api/v1/policies/push"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({"policy_id": policy_id}))
        .send()
        .await
        .expect("push");
    assert!(push.status().is_success());

    let metrics = client
        .get(format!("{base}/api/v1/metrics"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("metrics json");
    assert!(metrics.status().is_success());

    let prom = client
        .get(format!("{base}/api/v1/metrics"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "text/plain")
        .send()
        .await
        .expect("metrics prom");
    assert!(prom.status().is_success());
    let body = prom.text().await.expect("text");
    assert!(body.contains("ws_controller_devices_active"));

    handle.abort();
}

#[tokio::test]
async fn integration_audit_ingest_and_list() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let client = reqwest::Client::new();

    let ingest = client
        .post(format!("{base}/api/v1/audit/ingest"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "source": "agent",
            "action": "policy.applied",
            "details": {"result": "ok"}
        }))
        .send()
        .await
        .expect("ingest");
    assert_eq!(ingest.status(), 201);

    let list = client
        .get(format!("{base}/api/v1/audit"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("list");
    assert!(list.status().is_success());
    let events: Vec<Value> = list.json().await.expect("json");
    assert!(!events.is_empty());

    handle.abort();
}

#[tokio::test]
async fn integration_health_is_public() {
    let (base, handle) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/health"))
        .send()
        .await
        .expect("health");
    assert_eq!(resp.status(), 200);
    handle.abort();
}
