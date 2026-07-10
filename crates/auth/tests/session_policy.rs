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
    sqlx::query("insert into auth.users (id, created_at) values ($1, $2)")
        .bind("usr_device")
        .bind(now)
        .execute(&db.pool)
        .await
        .expect("auth user should insert");
    let session = create_session_with_policy(
        &db.pool,
        &AuthUserId("usr_device".to_owned()),
        "sess_device".to_owned(),
        "token_device".to_owned(),
        now,
        now + Duration::hours(1),
        SessionCreateOptions {
            device_id: Some("browser_hint".to_owned()),
            client: platform_core::ClientRequestMetadata {
                ip: Some("203.0.113.7".to_owned()),
                user_agent: Some("LensoTest/1.0".to_owned()),
            },
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
    assert_eq!(page.records[0]["client_ip"], "203.0.113.7");
    assert_eq!(page.records[0]["user_agent"], "LensoTest/1.0");

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
        assert_eq!(input.client.ip.as_deref(), Some("203.0.113.7"));
        Ok(SessionCreateDecision {
            device_id: Some("device_primary".to_owned()),
        })
    }
}
