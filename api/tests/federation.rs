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
        jwt_secret: "federation-test-secret".into(),
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
async fn integration_federation_register_and_list_cloud_controllers() {
    let (base, handle) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let register = client
        .post(format!("{base}/api/v1/federation/register"))
        .json(&json!({
            "token": "cloud-reg-token-abc",
            "tenant_id": "tenant-acme",
            "cloud_base_url": "https://cloud.example.com"
        }))
        .send()
        .await
        .expect("register");
    assert_eq!(register.status(), 201);
    let registration: Value = register.json().await.expect("json");
    assert_eq!(registration["tenant_id"], "tenant-acme");
    assert_eq!(registration["cloud_base_url"], "https://cloud.example.com");
    assert!(registration["cloud_controller_id"].is_string());

    let token = login(&base).await;
    let list = client
        .get(format!("{base}/api/v1/cloud/controllers"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("list");
    assert!(list.status().is_success());
    let controllers: Vec<Value> = list.json().await.expect("json");
    assert_eq!(controllers.len(), 1);
    assert_eq!(controllers[0]["tenant_id"], "tenant-acme");
    assert_eq!(controllers[0]["cloud_base_url"], "https://cloud.example.com");

    let controller_id = controllers[0]["id"].as_str().expect("id");
    let get = client
        .get(format!("{base}/api/v1/cloud/controllers/{controller_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("get");
    assert!(get.status().is_success());

    let provision = client
        .post(format!("{base}/api/v1/cloud/controllers/{controller_id}/provision"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({}))
        .send()
        .await
        .expect("provision");
    assert!(provision.status().is_success());
    let job: Value = provision.json().await.expect("json");
    assert_eq!(job["status"], "queued");

    handle.abort();
}

#[tokio::test]
async fn integration_federation_sync_push_and_pull() {
    let (base, handle) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let federation_token = "sync-test-token";

    let register = client
        .post(format!("{base}/api/v1/federation/register"))
        .json(&json!({
            "token": federation_token,
            "tenant_id": "tenant-sync",
            "cloud_base_url": "https://cloud.example.com"
        }))
        .send()
        .await
        .expect("register");
    assert_eq!(register.status(), 201);

    let push = client
        .post(format!("{base}/api/v1/federation/sync"))
        .header("X-Federation-Token", federation_token)
        .json(&json!({
            "tenant_id": "tenant-sync",
            "bundle": {"devices": 2, "policies": 1}
        }))
        .send()
        .await
        .expect("push");
    assert_eq!(push.status(), 204);

    let pull = client
        .get(format!("{base}/api/v1/federation/sync?tenant_id=tenant-sync"))
        .header("X-Federation-Token", federation_token)
        .send()
        .await
        .expect("pull");
    assert!(pull.status().is_success());
    let bundle: Value = pull.json().await.expect("json");
    assert_eq!(bundle["devices"], 2);
    assert_eq!(bundle["policies"], 1);

    handle.abort();
}

#[tokio::test]
async fn integration_federation_sync_rejects_invalid_token() {
    let (base, handle) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/api/v1/federation/sync"))
        .header("X-Federation-Token", "wrong-token")
        .send()
        .await
        .expect("pull");
    assert_eq!(resp.status(), 401);

    handle.abort();
}
