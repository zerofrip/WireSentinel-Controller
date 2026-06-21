use controller::ControllerSecurityPolicy;
use controller::{
    AnonymityHealthAggregator, AuditCollector, AuthService, CloudControllerManager, CloudReporter,
    DeviceManager, EnrollmentManager, FederationService, KernelHealthAggregator, MetricsAggregator,
    MixnetHealthAggregator, MixnetInventoryManager, PolicyDistributor, SseManager, XdrManager, CnappManager, AiSecurityManager,
    SplitTemplateManager, TcpTerminationManager, ZtnaManager,
};
use database::setup;
use serde_json::{json, Value};
use std::sync::Arc;

async fn spawn_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let pool = setup("sqlite::memory:").await.expect("db");
    let policy = ControllerSecurityPolicy {
        jwt_secret: "cloud-reporter-test".into(),
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
        cloud_reporter: Arc::new(CloudReporter::new(pool.clone())),
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

#[tokio::test]
async fn integration_cloud_usage_health_logs_ingress() {
    let (base, handle) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let usage = client
        .post(format!("{base}/api/v1/cloud/usage"))
        .json(&json!({
            "tenant_id": "tenant-telemetry",
            "metric": "bandwidth_bytes",
            "quantity": 4096.0
        }))
        .send()
        .await
        .expect("usage");
    assert_eq!(usage.status(), 204);

    let health = client
        .post(format!("{base}/api/v1/cloud/health"))
        .json(&json!({
            "tenant_id": "tenant-telemetry",
            "healthy": true,
            "reporting_devices": 2,
            "healthy_devices": 2
        }))
        .send()
        .await
        .expect("health");
    assert_eq!(health.status(), 204);

    let logs = client
        .post(format!("{base}/api/v1/cloud/logs"))
        .json(&json!({
            "tenant_id": "tenant-telemetry",
            "entries": [{
                "level": "info",
                "message": "test log line"
            }]
        }))
        .send()
        .await
        .expect("logs");
    assert_eq!(logs.status(), 204);

    handle.abort();
}

#[tokio::test]
async fn integration_cloud_reporter_push_pending_without_federation_is_noop() {
    let pool = setup("sqlite::memory:").await.expect("db");
    let reporter = CloudReporter::new(pool);
    reporter
        .ingest_usage(
            None,
            controller::CloudUsageIngest {
                tenant_id: "tenant-a".into(),
                device_id: None,
                metric: "api_requests".into(),
                quantity: 1.0,
                window_start: None,
                window_end: None,
                metadata: None,
            },
        )
        .await
        .expect("ingest");
    let summary = reporter.push_pending_to_cloud().await.expect("push");
    assert_eq!(summary.usage_forwarded, 0);
}

#[tokio::test]
async fn integration_federation_stores_outbound_token_for_reporter() {
    let (base, handle) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let register = client
        .post(format!("{base}/api/v1/federation/register"))
        .json(&json!({
            "token": "reporter-federation-token",
            "tenant_id": "tenant-reporter",
            "cloud_base_url": "https://cloud.example.com"
        }))
        .send()
        .await
        .expect("register");
    assert_eq!(register.status(), 201);
    let body: Value = register.json().await.expect("json");
    assert_eq!(body["tenant_id"], "tenant-reporter");

    handle.abort();
}
