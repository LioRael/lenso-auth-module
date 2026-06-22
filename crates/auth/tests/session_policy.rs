use auth::admin::AuthAdminData;
use auth::models::AuthUserId;
use auth::public::{SessionCreateOptions, create_session_with_policy};
use auth::repositories::PostgresAuthUserRepository;
use auth::session_policy::{AuthSessionPolicy, SessionCreateDecision, SessionCreateInput};
use chrono::{Duration, Utc};
use platform_core::{AppResult, PLATFORM_MIGRATIONS, apply_migrations};
use platform_module::{AdminDataSource, AdminListQuery};
use platform_runtime::RUNTIME_MIGRATIONS;
use platform_testing::TestDatabase;
use std::sync::Arc;

#[tokio::test]
async fn session_policy_can_attach_a_canonical_device_to_created_sessions() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let migrations = PLATFORM_MIGRATIONS
        .iter()
        .chain(RUNTIME_MIGRATIONS)
        .chain(auth::migrations::AUTH_MIGRATIONS)
        .copied()
        .collect::<Vec<_>>();
    apply_migrations(&db.pool, &migrations)
        .await
        .expect("migrations apply");

    let now = Utc::now();
    let session = create_session_with_policy(
        &db.pool,
        &AuthUserId("usr_device".to_owned()),
        "sess_device".to_owned(),
        "token_device".to_owned(),
        now,
        now + Duration::hours(1),
        SessionCreateOptions {
            device_id: Some("browser_hint".to_owned()),
        },
        &CanonicalDevicePolicy,
    )
    .await
    .expect("session should be created");

    assert_eq!(session.device_id.as_deref(), Some("device_primary"));

    let admin = AuthAdminData::new(Arc::new(PostgresAuthUserRepository::new(db.pool.clone())));
    let page = admin
        .list("sessions", &AdminListQuery::new(10, None))
        .await
        .expect("list sessions");
    assert_eq!(page.records[0]["device_id"], "device_primary");

    db.cleanup().await;
}

#[derive(Debug)]
struct CanonicalDevicePolicy;

#[async_trait::async_trait]
impl AuthSessionPolicy for CanonicalDevicePolicy {
    async fn before_session_create(
        &self,
        input: &SessionCreateInput,
    ) -> AppResult<SessionCreateDecision> {
        assert_eq!(input.proposed_device_id.as_deref(), Some("browser_hint"));
        Ok(SessionCreateDecision {
            device_id: Some("device_primary".to_owned()),
        })
    }
}
