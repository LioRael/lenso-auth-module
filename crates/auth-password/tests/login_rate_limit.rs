use auth::models::AuthUserId;
use auth::public::create_anonymous_user_identity_in_tx;
use auth::session_policy::{AuthSessionPolicy, SessionCreateDecision, SessionCreateInput};
use auth_password::config::AuthPasswordConfig;
use auth_password::migrations::AUTH_PASSWORD_MIGRATIONS;
use auth_password::repositories::{PasswordAuthRepository, PasswordSessionOptions};
use chrono::{Duration, Utc};
use platform_core::{
    AppResult, ClientRequestMetadata, ErrorCode, Migration, PLATFORM_MIGRATIONS, apply_migrations,
};
use platform_runtime::RUNTIME_MIGRATIONS;
use platform_testing::TestDatabase;
use std::sync::Arc;

fn migrations() -> Vec<Migration> {
    PLATFORM_MIGRATIONS
        .iter()
        .chain(RUNTIME_MIGRATIONS)
        .chain(auth::migrations::AUTH_MIGRATIONS)
        .chain(AUTH_PASSWORD_MIGRATIONS)
        .copied()
        .collect()
}

#[tokio::test]
async fn register_with_options_attaches_device_id_to_session_tokens() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");
    let repo = PasswordAuthRepository::new(db.pool.clone());
    let config = fast_config();
    let now = Utc::now();
    let token = repo
        .register_with_options(
            "device@example.com",
            "correct-password",
            "usr_password_device".to_owned(),
            "auth_identity_password_device".to_owned(),
            "sess_password_device".to_owned(),
            now,
            now + Duration::hours(1),
            &config,
            PasswordSessionOptions {
                device_id: Some("device_password".to_owned()),
                client: Default::default(),
                ..PasswordSessionOptions::default()
            },
        )
        .await
        .expect("register");

    let auth_password::repositories::AuthToken::Session(session) = token else {
        panic!("session strategy should return a session token");
    };
    assert_eq!(session.device_id.as_deref(), Some("device_password"));

    db.cleanup().await;
}

#[tokio::test]
async fn register_with_options_uses_the_injected_session_policy() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");
    let repo =
        PasswordAuthRepository::new_with_session_policy(db.pool.clone(), Arc::new(FixedPolicy));
    let config = fast_config();
    let now = Utc::now();
    let token = repo
        .register_with_options(
            "policy@example.com",
            "correct-password",
            "usr_password_policy".to_owned(),
            "auth_identity_password_policy".to_owned(),
            "sess_password_policy".to_owned(),
            now,
            now + Duration::hours(1),
            &config,
            PasswordSessionOptions {
                device_id: Some("device_hint".to_owned()),
                client: Default::default(),
                ..PasswordSessionOptions::default()
            },
        )
        .await
        .expect("register");

    let auth_password::repositories::AuthToken::Session(session) = token else {
        panic!("session strategy should return a session token");
    };
    assert_eq!(session.device_id.as_deref(), Some("device_from_policy"));

    db.cleanup().await;
}

#[tokio::test]
async fn register_with_options_links_password_to_anonymous_user() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");
    let config = fast_config();
    let now = Utc::now();
    let anonymous_user_id = AuthUserId("usr_password_anonymous".to_owned());
    let mut tx = db.pool.begin().await.expect("begin tx");
    create_anonymous_user_identity_in_tx(
        &mut tx,
        anonymous_user_id.clone(),
        "auth_identity_password_anonymous".to_owned(),
        "anonymous",
        "anonymous-password-link",
        now,
    )
    .await
    .expect("anonymous identity");
    tx.commit().await.expect("commit anonymous user");

    let token = PasswordAuthRepository::new(db.pool.clone())
        .register_with_options(
            "link@example.com",
            "correct-password",
            "usr_password_new".to_owned(),
            "auth_identity_password_linked".to_owned(),
            "sess_password_linked".to_owned(),
            now,
            now + Duration::hours(1),
            &config,
            PasswordSessionOptions {
                link_anonymous_user_id: Some(anonymous_user_id.clone()),
                ..PasswordSessionOptions::default()
            },
        )
        .await
        .expect("register links anonymous user");

    let auth_password::repositories::AuthToken::Session(session) = token else {
        panic!("session strategy should return a session token");
    };
    assert_eq!(session.user_id, anonymous_user_id);

    let row = sqlx::query_as::<_, (bool, i64)>(
        r#"
        select users.is_anonymous, count(identities.id)
        from auth.users users
        join auth.identities identities on identities.user_id = users.id
        where users.id = $1
        group by users.id
        "#,
    )
    .bind(&anonymous_user_id.0)
    .fetch_one(&db.pool)
    .await
    .expect("linked user row");
    assert!(!row.0);
    assert_eq!(row.1, 2);

    db.cleanup().await;
}

#[derive(Debug)]
struct FixedPolicy;

#[async_trait::async_trait]
impl AuthSessionPolicy for FixedPolicy {
    async fn before_session_create(
        &self,
        input: &SessionCreateInput,
    ) -> AppResult<SessionCreateDecision> {
        assert_eq!(input.proposed_device_id.as_deref(), Some("device_hint"));
        Ok(SessionCreateDecision {
            device_id: Some("device_from_policy".to_owned()),
        })
    }
}

fn fast_config() -> AuthPasswordConfig {
    AuthPasswordConfig {
        argon2_memory_kib: 8 * 1024,
        argon2_time_cost: 1,
        argon2_parallelism: 1,
        ..AuthPasswordConfig::default()
    }
}

#[tokio::test]
async fn login_is_rate_limited_after_repeated_failures() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");
    let repo = PasswordAuthRepository::new(db.pool.clone());
    let config = fast_config();
    let now = Utc::now();
    repo.register(
        "Ada@Example.com",
        "correct-password",
        "usr_rate_limited".to_owned(),
        "auth_identity_rate_limited".to_owned(),
        "sess_register_rate_limited".to_owned(),
        now,
        now + Duration::hours(1),
        &config,
    )
    .await
    .expect("register");

    for attempt in 0..5 {
        let error = repo
            .login(
                "ada@example.com",
                "wrong-password",
                format!("sess_wrong_{attempt}"),
                now + Duration::seconds(attempt),
                now + Duration::hours(1),
                &config,
            )
            .await
            .expect_err("wrong password should fail");
        assert_eq!(error.code, ErrorCode::Unauthorized);
    }

    let error = repo
        .login(
            "ada@example.com",
            "correct-password",
            "sess_blocked".to_owned(),
            now + Duration::seconds(6),
            now + Duration::hours(1),
            &config,
        )
        .await
        .expect_err("locked identifier should be rate limited");
    assert_eq!(error.code, ErrorCode::RateLimited);

    db.cleanup().await;
}

#[tokio::test]
async fn failed_login_records_client_metadata() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");
    let repo = PasswordAuthRepository::new(db.pool.clone());
    let config = fast_config();
    let now = Utc::now();
    repo.register(
        "metadata@example.com",
        "correct-password",
        "usr_failed_metadata".to_owned(),
        "auth_identity_failed_metadata".to_owned(),
        "sess_register_failed_metadata".to_owned(),
        now,
        now + Duration::hours(1),
        &config,
    )
    .await
    .expect("register");

    let error = repo
        .login_with_options(
            "metadata@example.com",
            "wrong-password",
            "sess_failed_metadata".to_owned(),
            now + Duration::seconds(1),
            now + Duration::hours(1),
            &config,
            PasswordSessionOptions {
                device_id: None,
                client: ClientRequestMetadata {
                    ip: Some("203.0.113.8".to_owned()),
                    user_agent: Some("LensoTest/2.0".to_owned()),
                },
                ..PasswordSessionOptions::default()
            },
        )
        .await
        .expect_err("wrong password should fail");
    assert_eq!(error.code, ErrorCode::Unauthorized);

    let row = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        r#"
        select last_failed_ip, last_failed_user_agent
        from auth_password.login_failures
        where identifier = $1
        "#,
    )
    .bind("metadata@example.com")
    .fetch_one(&db.pool)
    .await
    .expect("login failure row");
    assert_eq!(row.0.as_deref(), Some("203.0.113.8"));
    assert_eq!(row.1.as_deref(), Some("LensoTest/2.0"));

    db.cleanup().await;
}

#[tokio::test]
async fn reset_password_replaces_existing_credential_hash() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");
    let repo = PasswordAuthRepository::new(db.pool.clone());
    let config = fast_config();
    let now = Utc::now();
    let user_id = AuthUserId("usr_password_reset".to_owned());
    repo.register(
        "reset@example.com",
        "old-password",
        user_id.0.clone(),
        "auth_identity_password_reset".to_owned(),
        "sess_password_reset_register".to_owned(),
        now,
        now + Duration::hours(1),
        &config,
    )
    .await
    .expect("register");

    let updated = repo
        .reset_password(
            &user_id,
            "new-password",
            now + Duration::seconds(1),
            &config,
        )
        .await
        .expect("reset password");

    assert!(updated);
    assert_eq!(
        repo.login(
            "reset@example.com",
            "old-password",
            "sess_password_reset_old".to_owned(),
            now + Duration::seconds(2),
            now + Duration::hours(1),
            &config,
        )
        .await
        .expect_err("old password should fail")
        .code,
        ErrorCode::Unauthorized
    );
    repo.login(
        "reset@example.com",
        "new-password",
        "sess_password_reset_new".to_owned(),
        now + Duration::seconds(3),
        now + Duration::hours(1),
        &config,
    )
    .await
    .expect("new password should login");

    db.cleanup().await;
}

#[tokio::test]
async fn successful_login_clears_previous_failures() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");
    let repo = PasswordAuthRepository::new(db.pool.clone());
    let config = fast_config();
    let now = Utc::now();
    repo.register(
        "grace@example.com",
        "correct-password",
        "usr_reset_failures".to_owned(),
        "auth_identity_reset_failures".to_owned(),
        "sess_register_reset_failures".to_owned(),
        now,
        now + Duration::hours(1),
        &config,
    )
    .await
    .expect("register");

    for attempt in 0..4 {
        let error = repo
            .login(
                "grace@example.com",
                "wrong-password",
                format!("sess_reset_wrong_{attempt}"),
                now + Duration::seconds(attempt),
                now + Duration::hours(1),
                &config,
            )
            .await
            .expect_err("wrong password should fail");
        assert_eq!(error.code, ErrorCode::Unauthorized);
    }

    repo.login(
        "grace@example.com",
        "correct-password",
        "sess_reset_success".to_owned(),
        now + Duration::seconds(5),
        now + Duration::hours(1),
        &config,
    )
    .await
    .expect("correct password should clear failures");

    let error = repo
        .login(
            "grace@example.com",
            "wrong-password",
            "sess_after_reset_wrong".to_owned(),
            now + Duration::seconds(6),
            now + Duration::hours(1),
            &config,
        )
        .await
        .expect_err("wrong password should fail");
    assert_eq!(error.code, ErrorCode::Unauthorized);

    repo.login(
        "grace@example.com",
        "correct-password",
        "sess_after_reset_success".to_owned(),
        now + Duration::seconds(7),
        now + Duration::hours(1),
        &config,
    )
    .await
    .expect("one new failure after reset should not lock the identifier");

    db.cleanup().await;
}

#[tokio::test]
async fn concurrent_first_login_failures_are_both_counted() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");
    let now = Utc::now();
    const CONCURRENT_FAILURES: usize = 16;
    let barrier = Arc::new(tokio::sync::Barrier::new(CONCURRENT_FAILURES));
    let mut tasks = Vec::with_capacity(CONCURRENT_FAILURES);
    for index in 0..CONCURRENT_FAILURES {
        let repo = PasswordAuthRepository::new(db.pool.clone());
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            repo.record_failed_login_for_provider(
                "phone",
                "+8613800050000",
                now,
                &ClientRequestMetadata {
                    ip: Some(format!("203.0.113.{}", index + 20)),
                    user_agent: Some(format!("concurrent-{index}")),
                },
            )
            .await
        }));
    }
    for task in tasks {
        task.await
            .expect("concurrent task joins")
            .expect("concurrent failure is counted");
    }
    let failed_count: i32 = sqlx::query_scalar(
        "select failed_count from auth_password.login_failures where provider = $1 and identifier = $2",
    )
    .bind("phone")
    .bind("+8613800050000")
    .fetch_one(&db.pool)
    .await
    .expect("failure row");
    assert_eq!(failed_count, CONCURRENT_FAILURES as i32);

    PasswordAuthRepository::new(db.pool.clone())
        .record_failed_login_for_provider(
            "phone",
            "+8613800050000",
            now + Duration::seconds(1),
            &ClientRequestMetadata::default(),
        )
        .await
        .expect("sequential failure remains supported");
    let failed_count: i32 = sqlx::query_scalar(
        "select failed_count from auth_password.login_failures where provider = $1 and identifier = $2",
    )
    .bind("phone")
    .bind("+8613800050000")
    .fetch_one(&db.pool)
    .await
    .expect("updated failure row");
    assert_eq!(failed_count, CONCURRENT_FAILURES as i32 + 1);
    db.cleanup().await;
}
