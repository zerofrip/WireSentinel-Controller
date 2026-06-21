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
        jwt_secret: "sse-test-secret".into(),
        bcrypt_cost: 4,
        ..Default::default()
    };
    let auth = Arc::new(AuthService::new(pool.clone(), policy));
    auth.ensure_default_admin().await.expect("admin");

    let ztna = Arc::new(ZtnaManager::new(pool.clone()));
    ztna.seed_defaults().await.expect("ztna seed");
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
        .json(&json!({"label":"sse-agent"}))
        .send()
        .await
        .expect("create token");
    let created: Value = create.json().await.expect("json");
    let secret = created["secret"].as_str().expect("secret");

    let register = client
        .post(format!("{base}/api/v1/devices/register"))
        .json(&json!({
            "enrollment_token": secret,
            "name": "sse-host",
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
async fn integration_sse_telemetry_and_summaries() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let device_id = register_device(&base, &token).await;
    let client = reqwest::Client::new();

    let telemetry = client
        .post(format!("{base}/api/v1/agents/{device_id}/sse/telemetry"))
        .json(&json!({
            "swg_requests": 1000,
            "swg_blocked": 42,
            "swg_allowed": 958,
            "threat_matches": [{
                "threat_kind": "malware",
                "category": "web",
                "url": "https://evil.example/malware",
                "severity": "high",
                "action": "blocked"
            }],
            "casb_incidents": [{
                "title": "Unauthorized cloud upload",
                "severity": "medium",
                "resource": "dropbox.com",
                "action_taken": "blocked"
            }],
            "dlp_incidents": [{
                "title": "SSN exfiltration attempt",
                "severity": "high",
                "resource": "email",
                "action_taken": "blocked"
            }],
            "risk_score": 65,
            "risk_level": "medium",
            "ueba_anomalies": [{
                "user_id": "user-1",
                "description": "Unusual download volume",
                "score": 82.5
            }]
        }))
        .send()
        .await
        .expect("telemetry");
    assert_eq!(telemetry.status(), 204);

    let swg = client
        .get(format!("{base}/api/v1/sse/swg"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("swg");
    assert!(swg.status().is_success());
    let swg_body: Value = swg.json().await.expect("json");
    assert_eq!(swg_body["reporting_devices"], 1);
    assert_eq!(swg_body["threat_match_count"], 1);

    let casb = client
        .get(format!("{base}/api/v1/sse/casb"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("casb");
    let casb_body: Value = casb.json().await.expect("json");
    assert_eq!(casb_body["incident_count"], 1);

    let dlp = client
        .get(format!("{base}/api/v1/sse/dlp"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("dlp");
    let dlp_body: Value = dlp.json().await.expect("json");
    assert_eq!(dlp_body["incident_count"], 1);

    let risk = client
        .get(format!("{base}/api/v1/sse/risk"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("risk");
    let risk_body: Value = risk.json().await.expect("json");
    assert_eq!(risk_body["devices_scored"], 1);

    let ueba = client
        .get(format!("{base}/api/v1/sse/ueba"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("ueba");
    let ueba_body: Value = ueba.json().await.expect("json");
    assert_eq!(ueba_body["anomaly_count"], 1);

    handle.abort();
}

#[tokio::test]
async fn integration_sse_telemetry_requires_device() {
    let (base, handle) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/v1/agents/missing-device/sse/telemetry"))
        .json(&json!({"swg_requests": 1}))
        .send()
        .await
        .expect("telemetry");
    assert_eq!(resp.status(), 404);
    handle.abort();
}
