use controller::ControllerSecurityPolicy;
use controller::{
    AnonymityHealthAggregator, AuditCollector, AuthService, CloudControllerManager, DeviceManager,
    EnrollmentManager, FederationService, KernelHealthAggregator, MetricsAggregator,
    MixnetHealthAggregator, MixnetInventoryManager, PolicyDistributor, SseManager, XdrManager,
    CnappManager, AiSecurityManager, SplitTemplateManager, TcpTerminationManager, ZtnaManager,
};
use database::setup;
use serde_json::{json, Value};
use std::sync::Arc;

async fn spawn_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let pool = setup("sqlite::memory:").await.expect("db");
    let policy = ControllerSecurityPolicy {
        jwt_secret: "split-templates-test".into(),
        bcrypt_cost: 4,
        ..Default::default()
    };
    let auth = Arc::new(AuthService::new(pool.clone(), policy));
    auth.ensure_default_admin().await.expect("admin");

    let tcp_termination = Arc::new(TcpTerminationManager::new(pool.clone()));
    tcp_termination.seed_defaults().await.expect("tcp seed");
    let split_templates = Arc::new(SplitTemplateManager::new(pool.clone()));
    split_templates.seed_defaults().await.expect("split seed");

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
        tcp_termination,
        split_templates,
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
    let body: Value = resp.json().await.expect("json");
    body["token"].as_str().expect("token").to_string()
}

#[tokio::test]
async fn integration_split_templates_and_mode() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let client = reqwest::Client::new();

    let mode = client
        .get(format!("{base}/api/v1/split-templates/mode"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("mode");
    assert!(mode.status().is_success());
    let mode_body: Value = mode.json().await.expect("json");
    assert_eq!(mode_body["mode"], "disabled");

    let created = client
        .post(format!("{base}/api/v1/split-templates"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "name": "Office VPN",
            "description": "Route work apps via VPN",
            "default_route": {"type": "direct"},
            "enabled": true
        }))
        .send()
        .await
        .expect("create template");
    assert_eq!(created.status(), 201);
    let template: Value = created.json().await.expect("json");
    let template_id = template["id"].as_str().expect("id").to_string();

    let list = client
        .get(format!("{base}/api/v1/split-templates"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("list");
    let list_body: Value = list.json().await.expect("json");
    assert_eq!(list_body["template_count"], 1);

    let mode_updated = client
        .put(format!("{base}/api/v1/split-templates/mode"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "mode": "merge",
            "active_template_id": template_id
        }))
        .send()
        .await
        .expect("update mode");
    assert!(mode_updated.status().is_success());
    let mode_updated_body: Value = mode_updated.json().await.expect("json");
    assert_eq!(mode_updated_body["mode"], "merge");

    let patched = client
        .put(format!("{base}/api/v1/split-templates/{template_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({"description": "Updated template"}))
        .send()
        .await
        .expect("update template");
    assert!(patched.status().is_success());

    let deleted = client
        .delete(format!("{base}/api/v1/split-templates/{template_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("delete template");
    assert_eq!(deleted.status(), 204);

    handle.abort();
}
