use auth_password::config::AuthPasswordConfig;
use auth_password::migrations::AUTH_PASSWORD_MIGRATIONS;
use auth_password::repositories::PasswordAuthRepository;
use chrono::{Duration, Utc};
use platform_core::{ErrorCode, Migration, PLATFORM_MIGRATIONS, apply_migrations};
use platform_runtime::RUNTIME_MIGRATIONS;
use platform_testing::TestDatabase;

fn migrations() -> Vec<Migration> {
    PLATFORM_MIGRATIONS
        .iter()
        .chain(RUNTIME_MIGRATIONS)
        .chain(auth::migrations::AUTH_MIGRATIONS)
        .chain(AUTH_PASSWORD_MIGRATIONS)
        .copied()
        .collect()
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
