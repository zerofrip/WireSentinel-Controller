use controller::ControllerSecurityPolicy;
use controller::{
    AnonymityHealthAggregator, AuditCollector, AuthService, CloudControllerManager, DeviceManager,
    CnappManager, AiSecurityManager, EnrollmentManager, FederationService, KernelHealthAggregator, MetricsAggregator,
    MixnetHealthAggregator, MixnetInventoryManager, PolicyDistributor, SseManager, XdrManager,
    SplitTemplateManager, TcpTerminationManager, ZtnaManager,
};
use database::setup;
use serde_json::{json, Value};
use std::sync::Arc;

async fn spawn_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let pool = setup("sqlite::memory:").await.expect("db");
    let policy = ControllerSecurityPolicy {
        jwt_secret: "cnapp-test-secret".into(),
        bcrypt_cost: 4,
        ..Default::default()
    };
    let auth = Arc::new(AuthService::new(pool.clone(), policy));
    auth.ensure_default_admin().await.expect("admin");

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
        ztna: Arc::new(ZtnaManager::new(pool.clone())),
        sse: Arc::new(SseManager::new(pool.clone())),
        xdr: Arc::new(XdrManager::new(pool.clone())),
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
        .json(&json!({"label":"cnapp-agent"}))
        .send()
        .await
        .expect("create token");
    let created: Value = create.json().await.expect("json");
    let secret = created["secret"].as_str().expect("secret");

    let register = client
        .post(format!("{base}/api/v1/devices/register"))
        .json(&json!({
            "enrollment_token": secret,
            "name": "cnapp-scanner",
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
async fn integration_cnapp_telemetry_and_summaries() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let device_id = register_device(&base, &token).await;
    let client = reqwest::Client::new();

    let telemetry = client
        .post(format!("{base}/api/v1/agents/{device_id}/cnapp/telemetry"))
        .json(&json!({
            "posture_findings": [{
                "title": "S3 bucket public access",
                "severity": "high",
                "framework": "cis"
            }],
            "cloud_resources": [{
                "resource_type": "s3_bucket",
                "name": "logs-bucket",
                "risk_score": 75
            }],
            "workloads": [{
                "name": "api-server",
                "namespace": "prod"
            }],
            "k8s_clusters": [{
                "name": "prod-eks",
                "provider": "eks"
            }],
            "secret_findings": [{
                "title": "AWS key in env",
                "secret_kind": "aws_key",
                "severity": "critical"
            }]
        }))
        .send()
        .await
        .expect("telemetry");
    assert_eq!(telemetry.status(), 204);

    let posture = client
        .get(format!("{base}/api/v1/cnapp/posture"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("posture");
    let posture_body: Value = posture.json().await.expect("json");
    assert_eq!(posture_body["finding_count"], 1);
    assert_eq!(posture_body["resource_count"], 1);

    let workloads = client
        .get(format!("{base}/api/v1/cnapp/workloads"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("workloads");
    let workloads_body: Value = workloads.json().await.expect("json");
    assert_eq!(workloads_body["workload_count"], 1);

    let secrets = client
        .get(format!("{base}/api/v1/cnapp/secrets"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("secrets");
    let secrets_body: Value = secrets.json().await.expect("json");
    assert_eq!(secrets_body["finding_count"], 1);

    let compliance = client
        .get(format!("{base}/api/v1/cnapp/compliance"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("compliance");
    let compliance_body: Value = compliance.json().await.expect("json");
    assert!(compliance_body["control_count"].as_i64().unwrap_or(0) >= 5);

    handle.abort();
}

#[tokio::test]
async fn integration_cnapp_scan_ingest() {
    let (base, handle) = spawn_test_server().await;
    let token = login(&base).await;
    let device_id = register_device(&base, &token).await;
    let client = reqwest::Client::new();

    let scan = client
        .post(format!("{base}/api/v1/cnapp/scan/ingest"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "device_id": device_id,
            "iac_scans": [{
                "scan_kind": "terraform",
                "repository": "infra"
            }],
            "iac_findings": [{
                "title": "Unencrypted EBS volume",
                "severity": "high",
                "file_path": "main.tf"
            }],
            "container_images": [{
                "repository": "nginx",
                "tag": "1.25"
            }],
            "vulnerabilities": [{
                "cve_id": "CVE-2024-1234",
                "title": "OpenSSL buffer overflow",
                "severity": "critical",
                "asset_ref": "nginx:1.25"
            }],
            "sbom_documents": [{
                "name": "api-server",
                "components": [{
                    "name": "openssl",
                    "version": "3.0.12"
                }]
            }]
        }))
        .send()
        .await
        .expect("scan");
    assert!(scan.status().is_success());
    let scan_body: Value = scan.json().await.expect("json");
    assert_eq!(scan_body["iac_findings"], 1);
    assert_eq!(scan_body["sbom_documents"], 1);

    let iac = client
        .get(format!("{base}/api/v1/cnapp/iac"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("iac");
    let iac_body: Value = iac.json().await.expect("json");
    assert_eq!(iac_body["finding_count"], 1);

    let sbom = client
        .get(format!("{base}/api/v1/cnapp/sbom"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("sbom");
    let sbom_body: Value = sbom.json().await.expect("json");
    assert_eq!(sbom_body["document_count"], 1);

    let vulns = client
        .get(format!("{base}/api/v1/cnapp/vulnerabilities"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("vulns");
    let vulns_body: Value = vulns.json().await.expect("json");
    assert_eq!(vulns_body["vulnerability_count"], 1);

    handle.abort();
}
