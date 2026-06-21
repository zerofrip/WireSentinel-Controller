use controller::ControllerSecurityPolicy;
use controller::{
    AiSecurityManager, AnonymityHealthAggregator, AuditCollector, AuthService, CloudControllerManager,
    CnappManager, DeviceManager, EnrollmentManager, FederationService, KernelHealthAggregator,
    MetricsAggregator, MixnetHealthAggregator, MixnetInventoryManager, PolicyDistributor, SseManager,
    SplitTemplateManager, TcpTerminationManager, XdrManager, ZtnaManager,
};
use database::setup;
use serde_json::{json, Value};
use std::sync::Arc;

async fn spawn_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let pool = setup("sqlite::memory:").await.expect("db");
    let policy = ControllerSecurityPolicy {
        jwt_secret: "ai-security-test-secret".into(),
        bcrypt_cost: 4,
        ..Default::default()
    };
    let auth = Arc::new(AuthService::new(pool.clone(), policy));
    auth.ensure_default_admin().await.expect("admin");

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
        ztna: Arc::new(ZtnaManager::new(pool.clone())),
        sse: Arc::new(SseManager::new(pool.clone())),
        xdr: Arc::new(XdrManager::new(pool.clone())),
        cnapp: Arc::new(CnappManager::new(pool.clone())),
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
        .json(&json!({"label":"ai-agent"}))
        .send()
        .await
        .expect("create token");
    let created: Value = create.json().await.expect("json");
    let secret = created["secret"].as_str().expect("secret");

    let register = client
        .post(format!("{base}/api/v1/devices/register"))
        .json(&json!({
            "enrollment_token": secret,
            "name": "ai-endpoint",
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
async fn integration_ai_copilot_and_summaries() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let client = reqwest::Client::new();

    let copilot = client
        .post(format!("{base}/api/v1/ai/copilot/query"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({"query_text": "Summarize open credential abuse investigations"}))
        .send()
        .await
        .expect("copilot");
    assert!(copilot.status().is_success());
    let copilot_body: Value = copilot.json().await.expect("json");
    assert!(copilot_body["response"]["response_text"].as_str().is_some());

    let investigations = client
        .get(format!("{base}/api/v1/ai/investigations"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("investigations");
    let inv_body: Value = investigations.json().await.expect("json");
    assert!(inv_body["investigation_count"].as_i64().unwrap_or(0) >= 1);

    let threats = client
        .get(format!("{base}/api/v1/ai/threats"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("threats");
    let threat_body: Value = threats.json().await.expect("json");
    assert!(threat_body["threat_count"].as_i64().unwrap_or(0) >= 1);

    let kg = client
        .get(format!("{base}/api/v1/ai/knowledge-graph"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("kg");
    let kg_body: Value = kg.json().await.expect("json");
    assert!(kg_body["node_count"].as_i64().unwrap_or(0) >= 2);

    let reports = client
        .get(format!("{base}/api/v1/ai/reports"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("reports");
    let reports_body: Value = reports.json().await.expect("json");
    assert!(reports_body["intel_count"].as_i64().unwrap_or(0) >= 1);

    let risk = client
        .get(format!("{base}/api/v1/ai/risk"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("risk");
    let risk_body: Value = risk.json().await.expect("json");
    assert!(risk_body["score_count"].as_i64().unwrap_or(0) >= 1);

    handle.abort();
}

#[tokio::test]
async fn integration_ai_telemetry_and_generate() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let device_id = register_device(&base, &token).await;
    let client = reqwest::Client::new();

    let telemetry = client
        .post(format!("{base}/api/v1/agents/{device_id}/ai/telemetry"))
        .json(&json!({
            "investigations": [{
                "title": "Agent-reported anomaly",
                "severity": "medium"
            }],
            "threats": [{
                "title": "Local privilege escalation chain",
                "severity": "high",
                "confidence": 0.81
            }]
        }))
        .send()
        .await
        .expect("telemetry");
    assert_eq!(telemetry.status(), 204);

    let detection = client
        .post(format!("{base}/api/v1/ai/detections/generate"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "device_id": device_id,
            "context": "privilege escalation"
        }))
        .send()
        .await
        .expect("detection");
    assert!(detection.status().is_success());

    let playbook = client
        .post(format!("{base}/api/v1/ai/playbooks/generate"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({"context": "contain endpoint"}))
        .send()
        .await
        .expect("playbook");
    assert!(playbook.status().is_success());

    let policy = client
        .post(format!("{base}/api/v1/ai/policies/generate"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({"context": "restrict lateral movement"}))
        .send()
        .await
        .expect("policy");
    assert!(policy.status().is_success());

    let ingest = client
        .post(format!("{base}/api/v1/ai/telemetry/ingest"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "device_id": device_id,
            "threats": [{
                "title": "Controller ingested threat",
                "severity": "medium"
            }]
        }))
        .send()
        .await
        .expect("ingest");
    assert!(ingest.status().is_success());

    let agent_copilot = client
        .post(format!("{base}/api/v1/agents/{device_id}/ai/copilot/query"))
        .json(&json!({"query_text": "What should I investigate next?"}))
        .send()
        .await
        .expect("agent copilot");
    assert!(agent_copilot.status().is_success());

    handle.abort();
}
