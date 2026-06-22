use controller::{
    AuditCollector, AuthService, ControllerSecurityPolicy, CreateEnrollmentTokenRequest,
    CreatePolicyRequest, DeviceHeartbeat, DeviceManager, EnrollmentManager, MetricsAggregator,
    PolicyDistributor, PolicyScope, RegisterDeviceRequest,
};
use database::setup;
use serde_json::json;

async fn memory_services() -> (
    AuthService,
    EnrollmentManager,
    DeviceManager,
    PolicyDistributor,
    AuditCollector,
    MetricsAggregator,
) {
    let pool = setup("sqlite::memory:").await.expect("db");
    let policy = ControllerSecurityPolicy {
        jwt_secret: "unit-test".into(),
        bcrypt_cost: 4,
        ..Default::default()
    };
    let auth = AuthService::new(pool.clone(), policy);
    auth.ensure_default_admin().await.expect("admin");
    (
        auth,
        EnrollmentManager::new(pool.clone()),
        DeviceManager::new(pool.clone()),
        PolicyDistributor::new(pool.clone()),
        AuditCollector::new(pool.clone()),
        MetricsAggregator::new(pool),
    )
}

#[tokio::test]
async fn auth_login_issues_jwt() {
    let (auth, ..) = memory_services().await;
    let resp = auth
        .login(controller::LoginRequest {
            username: "admin".into(),
            password: "admin".into(),
        })
        .await
        .expect("login");
    assert!(!resp.token.is_empty());
    assert_eq!(resp.role, controller::Role::Admin);
}

#[tokio::test]
async fn enrollment_rotate_revokes_old_token() {
    let (_, enrollment, ..) = memory_services().await;
    let (_, raw) = enrollment
        .create_token(CreateEnrollmentTokenRequest {
            label: Some("lab".into()),
            expires_in_hours: None,
        })
        .await
        .expect("create");
    let first = enrollment.validate_raw_token(&raw).await.expect("valid");
    let rotated = enrollment.rotate_token(&first.id).await.expect("rotate");
    assert_ne!(rotated.id, first.id);
    assert!(enrollment.validate_raw_token(&raw).await.is_err());
}

#[tokio::test]
async fn device_register_and_heartbeat() {
    let (_, enrollment, devices, ..) = memory_services().await;
    let (_, raw) = enrollment
        .create_token(CreateEnrollmentTokenRequest {
            label: None,
            expires_in_hours: None,
        })
        .await
        .expect("token");
    let token = enrollment.validate_raw_token(&raw).await.expect("valid");
    let device = devices
        .register(
            RegisterDeviceRequest {
                enrollment_token: raw,
                name: "node-a".into(),
                hostname: Some("node-a.local".into()),
                os: Some("linux".into()),
                agent_version: Some("0.1.0".into()),
                metadata: Some(json!({"region":"lab"})),
            },
            &token,
        )
        .await
        .expect("register");

    let updated = devices
        .heartbeat(
            &device.id,
            DeviceHeartbeat {
                agent_version: Some("0.1.1".into()),
                metadata: None,
            },
        )
        .await
        .expect("heartbeat");
    assert_eq!(updated.agent_version.as_deref(), Some("0.1.1"));
}

#[tokio::test]
async fn policy_push_increments_version() {
    let (_, _, _, policies, ..) = memory_services().await;
    let policy = policies
        .create(CreatePolicyRequest {
            name: "baseline".into(),
            scope: PolicyScope::Global,
            scope_target: None,
            content: json!({"vpn": {"enabled": true}}),
        })
        .await
        .expect("create");
    assert_eq!(policy.version, 1);
    let pushed = policies
        .push(controller::PushPolicyRequest {
            policy_id: policy.id.clone(),
        })
        .await
        .expect("push");
    assert_eq!(pushed.version, 2);
    assert!(pushed.pushed_at.is_some());
}

#[tokio::test]
async fn metrics_snapshot_counts_entities() {
    let (_, enrollment, devices, policies, audit, metrics) = memory_services().await;
    let (_, raw) = enrollment
        .create_token(CreateEnrollmentTokenRequest {
            label: None,
            expires_in_hours: None,
        })
        .await
        .expect("token");
    let token = enrollment.validate_raw_token(&raw).await.expect("valid");
    devices
        .register(
            RegisterDeviceRequest {
                enrollment_token: raw,
                name: "m1".into(),
                hostname: None,
                os: None,
                agent_version: None,
                metadata: None,
            },
            &token,
        )
        .await
        .expect("register");
    policies
        .create(CreatePolicyRequest {
            name: "p1".into(),
            scope: PolicyScope::Global,
            scope_target: None,
            content: json!({}),
        })
        .await
        .expect("policy");
    audit
        .ingest(controller::IngestAuditEvent {
            source: "test".into(),
            actor: None,
            action: "test.run".into(),
            resource_type: None,
            resource_id: None,
            details: None,
        })
        .await
        .expect("audit");

    let snap = metrics.snapshot().await.expect("metrics");
    assert_eq!(snap.devices_active, 1);
    assert_eq!(snap.policies_active, 1);
    assert_eq!(snap.audit_events_total, 1);
    assert_eq!(snap.enrollment_tokens_total, 1);
}
