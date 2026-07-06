use auth::models::AuthUserId;
use auth::session_policy::{AuthSessionPolicy, SessionCreateDecision, SessionCreateInput};
use auth_phone::config::AuthPhoneConfig;
use auth_phone::migrations::AUTH_PHONE_MIGRATIONS;
use auth_phone::repositories::{
    LoginPhonePasswordOptions, PhoneAuthRepository, PhoneOtpPurpose, SetPhonePasswordOptions,
    StartOtpInput, VerifyOtpOptions,
};
use chrono::{Duration, Utc};
use platform_core::{
    AppResult, ClientRequestMetadata, ErrorCode, Migration, PLATFORM_MIGRATIONS, apply_migrations,
};
use platform_testing::TestDatabase;
use std::sync::Arc;

fn migrations() -> Vec<Migration> {
    PLATFORM_MIGRATIONS
        .iter()
        .chain(auth::migrations::AUTH_MIGRATIONS)
        .chain(AUTH_PHONE_MIGRATIONS)
        .copied()
        .collect()
}

fn fast_config() -> AuthPhoneConfig {
    AuthPhoneConfig {
        return_debug_otp_code: true,
        ..AuthPhoneConfig::default()
    }
}

#[tokio::test]
async fn set_password_then_login_creates_session() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let config = fast_config();
    let repo = PhoneAuthRepository::new(db.pool.clone());
    let now = Utc::now();
    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000002",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_password_challenge".to_owned(),
            now,
            config: &config,
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect("otp starts");
    let session = repo
        .verify_otp_with_options(VerifyOtpOptions {
            challenge_id: "phone_password_challenge",
            code: challenge.debug_code.as_deref().expect("debug code"),
            session_id: "sess_phone_password_verified".to_owned(),
            user_id: "usr_phone_password".to_owned(),
            identity_id: "auth_identity_phone_password".to_owned(),
            now: now + Duration::seconds(1),
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: None,
            client: ClientRequestMetadata::default(),
            link_anonymous_user_id: None,
        })
        .await
        .expect("otp verifies")
        .expect("session created");

    let updated = repo
        .set_password(SetPhonePasswordOptions {
            user_id: &session.user_id,
            password: "correct horse",
            now: now + Duration::seconds(2),
            config: &config,
        })
        .await
        .expect("password set");

    assert!(updated);

    let password_session = repo
        .login_password_with_options(LoginPhonePasswordOptions {
            phone: "+86 138 0000 0002",
            password: "correct horse",
            session_id: "sess_phone_password_login".to_owned(),
            now: now + Duration::seconds(3),
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: Some("ios-device".to_owned()),
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect("password login")
        .expect("session created");

    assert_eq!(password_session.user_id, session.user_id);
    assert_eq!(password_session.id, "sess_phone_password_login");
    assert_eq!(password_session.device_id.as_deref(), Some("ios-device"));

    db.cleanup().await;
}

#[tokio::test]
async fn set_password_returns_false_without_phone_identity() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let config = AuthPhoneConfig::default();
    let repo = PhoneAuthRepository::new(db.pool.clone());
    let now = Utc::now();

    let updated = repo
        .set_password(SetPhonePasswordOptions {
            user_id: &AuthUserId("usr_without_phone".to_owned()),
            password: "correct horse",
            now,
            config: &config,
        })
        .await
        .expect("password set result");

    assert!(!updated);

    db.cleanup().await;
}

#[tokio::test]
async fn wrong_phone_password_records_failure_metadata_and_returns_generic_unauthorized() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let config = AuthPhoneConfig::default();
    let repo = PhoneAuthRepository::new(db.pool.clone());
    let now = Utc::now();
    let error = repo
        .login_password_with_options(LoginPhonePasswordOptions {
            phone: "+8613800000003",
            password: "wrong horse",
            session_id: "sess_wrong".to_owned(),
            now,
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: None,
            client: ClientRequestMetadata {
                ip: Some("127.0.0.1".to_owned()),
                user_agent: Some("test-agent".to_owned()),
            },
        })
        .await
        .expect_err("wrong password should error");

    assert_eq!(error.code, ErrorCode::Unauthorized);
    assert_eq!(error.public_message, "Invalid phone or password");

    let row: (i32, Option<String>, Option<String>) = sqlx::query_as(
        r#"
        select failed_count, last_failed_ip, last_failed_user_agent
        from auth_phone.password_failures
        where phone_e164 = $1
        "#,
    )
    .bind("+8613800000003")
    .fetch_one(&db.pool)
    .await
    .expect("failure row");

    assert_eq!(row.0, 1);
    assert_eq!(row.1.as_deref(), Some("127.0.0.1"));
    assert_eq!(row.2.as_deref(), Some("test-agent"));

    db.cleanup().await;
}

#[tokio::test]
async fn short_phone_password_still_returns_generic_unauthorized() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let config = AuthPhoneConfig::default();
    let repo = PhoneAuthRepository::new(db.pool.clone());
    let now = Utc::now();
    let error = repo
        .login_password_with_options(LoginPhonePasswordOptions {
            phone: "+8613800000006",
            password: "short",
            session_id: "sess_short_wrong".to_owned(),
            now,
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: None,
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect_err("short password should still be treated as invalid credentials");

    assert_eq!(error.code, ErrorCode::Unauthorized);
    assert_eq!(error.public_message, "Invalid phone or password");

    db.cleanup().await;
}

#[tokio::test]
async fn successful_phone_password_login_clears_previous_failures() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let config = fast_config();
    let repo = PhoneAuthRepository::new(db.pool.clone());
    let now = Utc::now();
    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000004",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_password_failure_reset".to_owned(),
            now,
            config: &config,
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect("otp starts");
    let session = repo
        .verify_otp_with_options(VerifyOtpOptions {
            challenge_id: "phone_password_failure_reset",
            code: challenge.debug_code.as_deref().expect("debug code"),
            session_id: "sess_phone_password_failure_reset_seed".to_owned(),
            user_id: "usr_phone_password_failure_reset".to_owned(),
            identity_id: "auth_identity_phone_password_failure_reset".to_owned(),
            now: now + Duration::seconds(1),
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: None,
            client: ClientRequestMetadata::default(),
            link_anonymous_user_id: None,
        })
        .await
        .expect("otp verifies")
        .expect("session created");
    repo.set_password(SetPhonePasswordOptions {
        user_id: &session.user_id,
        password: "correct horse",
        now: now + Duration::seconds(2),
        config: &config,
    })
    .await
    .expect("password set");

    for attempt in 0..4 {
        let error = repo
            .login_password_with_options(LoginPhonePasswordOptions {
                phone: "+8613800000004",
                password: "wrong horse",
                session_id: format!("sess_phone_wrong_{attempt}"),
                now: now + Duration::seconds(3 + i64::from(attempt)),
                expires_at: now + Duration::hours(12),
                config: &config,
                device_id: None,
                client: ClientRequestMetadata::default(),
            })
            .await
            .expect_err("wrong password should fail");
        assert_eq!(error.code, ErrorCode::Unauthorized);
    }

    repo.login_password_with_options(LoginPhonePasswordOptions {
        phone: "+8613800000004",
        password: "correct horse",
        session_id: "sess_phone_success_after_failures".to_owned(),
        now: now + Duration::seconds(8),
        expires_at: now + Duration::hours(12),
        config: &config,
        device_id: None,
        client: ClientRequestMetadata::default(),
    })
    .await
    .expect("correct password login")
    .expect("session created");

    let failures_exist = sqlx::query_scalar::<_, bool>(
        r#"
        select exists(
            select 1
            from auth_phone.password_failures
            where phone_e164 = $1
        )
        "#,
    )
    .bind("+8613800000004")
    .fetch_one(&db.pool)
    .await
    .expect("failure lookup");
    assert!(!failures_exist);

    db.cleanup().await;
}

#[tokio::test]
async fn phone_password_login_respects_session_policy() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let config = fast_config();
    let repo = PhoneAuthRepository::new_with_session_policy(db.pool.clone(), Arc::new(FixedPolicy));
    let now = Utc::now();
    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000005",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_password_policy".to_owned(),
            now,
            config: &config,
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect("otp starts");
    let session = repo
        .verify_otp_with_options(VerifyOtpOptions {
            challenge_id: "phone_password_policy",
            code: challenge.debug_code.as_deref().expect("debug code"),
            session_id: "sess_phone_password_policy_seed".to_owned(),
            user_id: "usr_phone_password_policy".to_owned(),
            identity_id: "auth_identity_phone_password_policy".to_owned(),
            now: now + Duration::seconds(1),
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: None,
            client: ClientRequestMetadata::default(),
            link_anonymous_user_id: None,
        })
        .await
        .expect("otp verifies")
        .expect("session created");
    repo.set_password(SetPhonePasswordOptions {
        user_id: &session.user_id,
        password: "correct horse",
        now: now + Duration::seconds(2),
        config: &config,
    })
    .await
    .expect("password set");

    let password_session = repo
        .login_password_with_options(LoginPhonePasswordOptions {
            phone: "+8613800000005",
            password: "correct horse",
            session_id: "sess_phone_password_policy".to_owned(),
            now: now + Duration::seconds(3),
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: Some("device_hint".to_owned()),
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect("login succeeds")
        .expect("session created");

    assert_eq!(
        password_session.device_id.as_deref(),
        Some("device_from_policy")
    );

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
