use auth::models::{AuthUser, AuthUserId};
use auth::repositories::{AuthUserRepository, PostgresAuthUserRepository};
use auth::session_policy::{AuthHostExtension, AuthSessionPolicy, SessionCreateInput};
use auth_device::admin::AuthDeviceAdminData;
use auth_device::migrations::AUTH_DEVICE_MIGRATIONS;
use auth_device::policy::AuthDevicePolicy;
use auth_device::repositories::PostgresAuthDeviceRepository;
use chrono::{Duration, Utc};
use platform_core::{PLATFORM_MIGRATIONS, apply_migrations};
use platform_module::{AdminDataSource, AdminListQuery};
use platform_runtime::RUNTIME_MIGRATIONS;
use platform_testing::TestDatabase;
use std::sync::Arc;

#[test]
fn linked_module_declares_auth_session_policy_contribution() {
    let module = auth_device::module::linked_module();
    let extensions = module
        .contributions::<AuthHostExtension>()
        .collect::<Vec<_>>();

    assert_eq!(module.module_name, auth_device::module::MODULE_NAME);
    assert_eq!(extensions.len(), 1);
    assert!(extensions[0].session_policy_factory().is_some());
}

#[tokio::test]
async fn device_policy_registers_the_proposed_device_and_exposes_admin_data() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let migrations = PLATFORM_MIGRATIONS
        .iter()
        .chain(RUNTIME_MIGRATIONS)
        .chain(auth::migrations::AUTH_MIGRATIONS)
        .chain(AUTH_DEVICE_MIGRATIONS)
        .copied()
        .collect::<Vec<_>>();
    apply_migrations(&db.pool, &migrations)
        .await
        .expect("migrations apply");

    let now = Utc::now();
    PostgresAuthUserRepository::new(db.pool.clone())
        .insert(&AuthUser {
            id: AuthUserId("usr_device".to_owned()),
            created_at: now,
            disabled_at: None,
            disabled_reason: None,
            disabled_until: None,
        })
        .await
        .expect("user insert");

    let repository = Arc::new(PostgresAuthDeviceRepository::new(db.pool.clone()));
    let policy = AuthDevicePolicy::new(repository.clone());
    let decision = policy
        .before_session_create(&SessionCreateInput {
            user_id: AuthUserId("usr_device".to_owned()),
            session_id: "sess_device".to_owned(),
            proposed_device_id: Some("device_browser".to_owned()),
            created_at: now,
            expires_at: now + Duration::hours(1),
            client: platform_core::ClientRequestMetadata {
                ip: Some("203.0.113.7".to_owned()),
                user_agent: Some("LensoTest/1.0".to_owned()),
            },
        })
        .await
        .expect("policy should allow known device");

    assert_eq!(decision.device_id.as_deref(), Some("device_browser"));

    let admin = AuthDeviceAdminData::new(repository);
    let page = admin
        .list("devices", &AdminListQuery::new(10, None))
        .await
        .expect("list devices");
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0]["id"], "device_browser");
    assert_eq!(page.records[0]["user_id"], "usr_device");
    assert_eq!(page.records[0]["last_seen_ip"], "203.0.113.7");
    assert_eq!(page.records[0]["last_seen_user_agent"], "LensoTest/1.0");

    db.cleanup().await;
}
