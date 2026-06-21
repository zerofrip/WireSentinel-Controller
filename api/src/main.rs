mod error;
mod middleware;
mod routes;

use controller::{
    AnonymityHealthAggregator, AuditCollector, AuthService, CloudControllerManager, CloudReporter,
    ControllerSecurityPolicy, DeviceManager, EnrollmentManager, FederationService,
    KernelHealthAggregator, MetricsAggregator, MixnetHealthAggregator, MixnetInventoryManager,
    PolicyDistributor, SseManager, XdrManager, ZtnaManager, CnappManager, AiSecurityManager,
    SplitTemplateManager, TcpTerminationManager,
};
use database::setup;
use controller_api::{build_router, AppState};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            "controller_api=debug,tower_http=debug".into()
        }))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://./data/controller.db?mode=rwc".into());
    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());

    let _ = std::fs::create_dir_all("./data");

    let pool = setup(&database_url).await?;
    let policy = ControllerSecurityPolicy::default();
    let auth = Arc::new(AuthService::new(pool.clone(), policy));
    auth.ensure_default_admin().await?;

    let cloud_reporter = Arc::new(CloudReporter::new(pool.clone()));

    let state = AppState {
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
        ztna: {
            let mgr = Arc::new(ZtnaManager::new(pool.clone()));
            mgr.seed_defaults().await?;
            mgr
        },
        sse: {
            let mgr = Arc::new(SseManager::new(pool.clone()));
            mgr.seed_defaults().await?;
            mgr
        },
        xdr: {
            let mgr = Arc::new(XdrManager::new(pool.clone()));
            mgr.seed_defaults().await?;
            mgr
        },
        cnapp: {
            let mgr = Arc::new(CnappManager::new(pool.clone()));
            mgr.seed_defaults().await?;
            mgr
        },
        ai: {
            let mgr = Arc::new(AiSecurityManager::new(pool.clone()));
            mgr.seed_defaults().await?;
            mgr
        },
        tcp_termination: {
            let mgr = Arc::new(TcpTerminationManager::new(pool.clone()));
            mgr.seed_defaults().await?;
            mgr
        },
        split_templates: {
            let mgr = Arc::new(SplitTemplateManager::new(pool.clone()));
            mgr.seed_defaults().await?;
            mgr
        },
        federation: Arc::new(FederationService::new(pool.clone())),
        cloud_controllers: Arc::new(CloudControllerManager::new(pool)),
        cloud_reporter: Arc::clone(&cloud_reporter),
    };

    let interval_secs = std::env::var("CLOUD_REPORTER_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120u64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    CloudReporter::spawn(cloud_reporter, shutdown_rx, interval_secs);

    let app = build_router(state);
    let addr: SocketAddr = bind.parse()?;
    tracing::info!("WireSentinel Controller listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_tx.send(true);
        })
        .await?;
    Ok(())
}
