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
        jwt_secret: "xdr-test-secret".into(),
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
        .json(&json!({"label":"xdr-agent"}))
        .send()
        .await
        .expect("create token");
    let created: Value = create.json().await.expect("json");
    let secret = created["secret"].as_str().expect("secret");

    let register = client
        .post(format!("{base}/api/v1/devices/register"))
        .json(&json!({
            "enrollment_token": secret,
            "name": "xdr-host",
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
async fn integration_xdr_telemetry_and_summaries() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let device_id = register_device(&base, &token).await;
    let client = reqwest::Client::new();

    let telemetry = client
        .post(format!("{base}/api/v1/agents/{device_id}/xdr/telemetry"))
        .json(&json!({
            "edr_events": [{
                "event_kind": "process",
                "process_name": "powershell.exe",
                "severity": "high",
                "command_line": "powershell -enc ..."
            }],
            "ndr_events": [{
                "event_kind": "flow",
                "src_ip": "10.0.0.5",
                "dst_ip": "198.51.100.10",
                "dst_port": 443,
                "severity": "medium"
            }],
            "itdr_threats": [{
                "title": "Impossible travel login",
                "threat_kind": "credential",
                "severity": "high"
            }],
            "detections": [{
                "title": "Suspicious encoded command",
                "severity": "high"
            }],
            "incidents": [{
                "title": "Potential compromise",
                "severity": "critical"
            }]
        }))
        .send()
        .await
        .expect("telemetry");
    assert_eq!(telemetry.status(), 204);

    let incidents = client
        .get(format!("{base}/api/v1/xdr/incidents"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("incidents");
    let incidents_body: Value = incidents.json().await.expect("json");
    assert_eq!(incidents_body["incident_count"], 1);

    let detections = client
        .get(format!("{base}/api/v1/xdr/detections"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("detections");
    let detections_body: Value = detections.json().await.expect("json");
    assert_eq!(detections_body["detection_count"], 1);
    assert!(detections_body["rule_count"].as_i64().unwrap_or(0) >= 3);

    let mitre = client
        .get(format!("{base}/api/v1/xdr/mitre"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("mitre");
    let mitre_body: Value = mitre.json().await.expect("json");
    assert!(mitre_body["technique_count"].as_i64().unwrap_or(0) >= 3);

    let soar = client
        .get(format!("{base}/api/v1/xdr/soar/playbooks"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("soar");
    let soar_body: Value = soar.json().await.expect("json");
    assert!(soar_body["playbook_count"].as_i64().unwrap_or(0) >= 3);

    let response = client
        .post(format!("{base}/api/v1/agents/{device_id}/xdr/response"))
        .json(&json!({
            "action_kind": "isolate",
            "requested_by": "agent"
        }))
        .send()
        .await
        .expect("response");
    assert!(response.status().is_success());
    let response_body: Value = response.json().await.expect("json");
    assert_eq!(response_body["status"], "completed");

    handle.abort();
}

#[tokio::test]
async fn integration_xdr_create_case_and_hunt() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let client = reqwest::Client::new();

    let case_resp = client
        .post(format!("{base}/api/v1/xdr/cases"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "title": "Investigate lateral movement",
            "priority": "high"
        }))
        .send()
        .await
        .expect("create case");
    assert_eq!(case_resp.status(), 201);

    let hunt_resp = client
        .post(format!("{base}/api/v1/xdr/hunts"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "name": "SMB lateral scan",
            "query_text": "DeviceNetworkEvents | where RemotePort == 445"
        }))
        .send()
        .await
        .expect("create hunt");
    assert_eq!(hunt_resp.status(), 201);

    let cases = client
        .get(format!("{base}/api/v1/xdr/cases"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("cases");
    let cases_body: Value = cases.json().await.expect("json");
    assert_eq!(cases_body["case_count"], 1);

    let hunts = client
        .get(format!("{base}/api/v1/xdr/hunts"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("hunts");
    let hunts_body: Value = hunts.json().await.expect("json");
    assert_eq!(hunts_body["hunt_count"], 1);

    handle.abort();
}
