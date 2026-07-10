use auth::public::{AuthUserId, create_anonymous_user_identity_in_tx};
use auth::session_policy::{AuthSessionPolicy, SessionCreateDecision, SessionCreateInput};
use auth_phone::config::AuthPhoneConfig;
use auth_phone::migrations::AUTH_PHONE_MIGRATIONS;
use auth_phone::otp::hash_otp_code;
use auth_phone::repositories::{
    PhoneAuthRepository, PhoneOtpPurpose, StartOtpInput, VerifyOtpOptions,
};
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::middleware;
use chrono::{DateTime, Duration, Utc};
use platform_core::{
    AppConfig, AppResult, AuthConfig, ClientRequestMetadata, DatabaseConfig, DevActorResolver,
    ErrorCode, HttpConfig, LoggingEventPublisher, Migration, ModuleConfig, ModuleSourcesConfig,
    PLATFORM_MIGRATIONS, RedisConfig, ServiceConfig, TelemetryConfig, apply_migrations,
};
use platform_http::request_context_middleware;
use platform_testing::TestDatabase;
use sqlx::PgPool;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

fn migrations() -> Vec<Migration> {
    PLATFORM_MIGRATIONS
        .iter()
        .chain(auth::migrations::AUTH_MIGRATIONS)
        .chain(AUTH_PHONE_MIGRATIONS)
        .copied()
        .collect()
}

#[tokio::test]
async fn otp_start_route_returns_challenge_without_raw_code() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let response = test_app(db.pool.clone())
        .oneshot(post_json(
            "/v1/auth/phone/otp/start",
            r#"{"phone":"+8613800000100","purpose":"sign_in"}"#,
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert!(
        json["challenge_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("phone_otp_challenge_"))
    );
    assert!(json["expires_at"].as_str().is_some());
    assert!(json["resend_after"].as_str().is_some());
    assert!(json.get("code").is_none());

    db.cleanup().await;
}

#[tokio::test]
async fn otp_start_route_returns_debug_code_when_local_debug_delivery_is_enabled() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let response = test_app_with_config(db.pool.clone(), test_config_with_debug_otp_delivery())
        .oneshot(post_json(
            "/v1/auth/phone/otp/start",
            r#"{"phone":"+8613800000102","purpose":"sign_in"}"#,
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    let debug_code = json["debug_code"].as_str().expect("local debug OTP code");
    assert_eq!(debug_code.len(), 6);
    assert!(
        debug_code
            .chars()
            .all(|character| character.is_ascii_digit())
    );

    let stored_hash: String =
        sqlx::query_scalar("select code_hash from auth_phone.otp_challenges where id = $1")
            .bind(json["challenge_id"].as_str().expect("challenge id"))
            .fetch_one(&db.pool)
            .await
            .expect("stored hash");
    assert_eq!(
        stored_hash,
        hash_otp_code(debug_code, &AuthPhoneConfig::default().otp_secret)
    );
    assert_ne!(stored_hash, debug_code);

    db.cleanup().await;
}

#[tokio::test]
async fn otp_verify_route_creates_phone_session_cookie() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let config = AuthPhoneConfig::default();
    seed_otp_challenge(
        &db.pool,
        "phone_otp_route_verify",
        "+8613800000101",
        "654321",
        Utc::now(),
        &config,
    )
    .await;

    let response = test_app(db.pool.clone())
        .oneshot(post_json(
            "/v1/auth/phone/otp/verify",
            r#"{"challenge_id":"phone_otp_route_verify","code":"654321","device_id":"ios-device"}"#,
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie");
    assert!(set_cookie.contains("lenso_session=sess_"));
    assert!(set_cookie.contains("HttpOnly"));

    let json = response_json(response).await;
    assert!(
        json["user_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("usr_"))
    );
    assert!(
        json["session_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("sess_"))
    );
    assert!(
        json["token"]
            .as_str()
            .is_some_and(|value| value.starts_with("sess_"))
    );
    assert!(json["expires_at"].as_str().is_some());
    assert_eq!(json["primary_identifier"]["kind"].as_str(), Some("phone"));
    assert_eq!(
        json["primary_identifier"]["country_code"].as_str(),
        Some("+86")
    );
    assert_eq!(
        json["primary_identifier"]["masked_national_number"].as_str(),
        Some("138****0101")
    );
    assert!(json.get("phone_e164").is_none());

    let consumed_at: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("select consumed_at from auth_phone.otp_challenges where id = $1")
            .bind("phone_otp_route_verify")
            .fetch_one(&db.pool)
            .await
            .expect("challenge consumed");
    assert!(consumed_at.is_some());

    db.cleanup().await;
}

#[tokio::test]
async fn start_otp_stores_hashed_code_and_consume_once() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let config = AuthPhoneConfig {
        return_debug_otp_code: true,
        ..AuthPhoneConfig::default()
    };
    let repo = PhoneAuthRepository::new(db.pool.clone());
    let now = Utc::now();

    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000000",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_otp_challenge_test".to_owned(),
            now,
            config: &config,
            client: ClientRequestMetadata {
                ip: Some("127.0.0.1".to_owned()),
                user_agent: Some("test-agent".to_owned()),
            },
        })
        .await
        .expect("otp starts");

    assert_eq!(challenge.phone_e164, "+8613800000000");
    assert_eq!(
        challenge.expires_at,
        now + Duration::seconds(config.otp_ttl_seconds)
    );
    assert_eq!(
        challenge.resend_after,
        now + Duration::seconds(config.otp_resend_cooldown_seconds)
    );

    let debug_code = challenge.debug_code.as_deref().expect("local debug code");
    let stored_hash: String =
        sqlx::query_scalar("select code_hash from auth_phone.otp_challenges where id = $1")
            .bind("phone_otp_challenge_test")
            .fetch_one(&db.pool)
            .await
            .expect("stored hash");
    assert_eq!(stored_hash, hash_otp_code(debug_code, &config.otp_secret));
    assert_ne!(stored_hash, debug_code);

    let consumed = repo
        .consume_otp(
            "phone_otp_challenge_test",
            "000000",
            now + Duration::seconds(1),
            &config,
        )
        .await
        .expect("wrong code checked");
    assert!(consumed.is_none());

    let attempts: i32 =
        sqlx::query_scalar("select attempts from auth_phone.otp_challenges where id = $1")
            .bind("phone_otp_challenge_test")
            .fetch_one(&db.pool)
            .await
            .expect("attempt count");
    assert_eq!(attempts, 1);

    let consumed = repo
        .consume_otp(
            "phone_otp_challenge_test",
            debug_code,
            now + Duration::seconds(2),
            &config,
        )
        .await
        .expect("otp consumed")
        .expect("otp should match");
    assert_eq!(consumed.phone_e164, "+8613800000000");

    assert!(
        repo.consume_otp(
            "phone_otp_challenge_test",
            debug_code,
            now + Duration::seconds(3),
            &config,
        )
        .await
        .expect("second consume checked")
        .is_none()
    );

    db.cleanup().await;
}

#[tokio::test]
async fn start_otp_hides_debug_code_by_default() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let config = AuthPhoneConfig::default();
    let repo = PhoneAuthRepository::new(db.pool.clone());

    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000001",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_otp_challenge_hidden_debug_code".to_owned(),
            now: Utc::now(),
            config: &config,
            client: ClientRequestMetadata {
                ip: Some("127.0.0.1".to_owned()),
                user_agent: Some("test-agent".to_owned()),
            },
        })
        .await
        .expect("otp starts");

    assert_eq!(challenge.debug_code, None);

    db.cleanup().await;
}

#[tokio::test]
async fn rate_limit_enforces_phone_cooldown_concurrently_and_per_ip_window() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");
    let config = AuthPhoneConfig {
        return_debug_otp_code: true,
        ..AuthPhoneConfig::default()
    };
    let now = Utc::now();
    let repo = PhoneAuthRepository::new(db.pool.clone());

    repo.start_otp(StartOtpInput {
        phone: "+8613800010000",
        purpose: PhoneOtpPurpose::SignIn,
        challenge_id: "phone_rate_first".to_owned(),
        now,
        config: &config,
        client: ClientRequestMetadata::default(),
    })
    .await
    .expect("first phone start");
    let cooldown = repo
        .start_otp(StartOtpInput {
            phone: "+8613800010000",
            purpose: PhoneOtpPurpose::PasswordReset,
            challenge_id: "phone_rate_second".to_owned(),
            now: now + Duration::seconds(1),
            config: &config,
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect_err("phone cooldown should apply across purposes");
    assert_eq!(cooldown.code, ErrorCode::RateLimited);
    repo.start_otp(StartOtpInput {
        phone: "+8613800010000",
        purpose: PhoneOtpPurpose::SignIn,
        challenge_id: "phone_rate_after_cooldown".to_owned(),
        now: now + Duration::seconds(config.otp_resend_cooldown_seconds),
        config: &config,
        client: ClientRequestMetadata::default(),
    })
    .await
    .expect("start at resend boundary");

    let repo_a = PhoneAuthRepository::new(db.pool.clone());
    let repo_b = PhoneAuthRepository::new(db.pool.clone());
    let input_a = StartOtpInput {
        phone: "+8613800010001",
        purpose: PhoneOtpPurpose::SignIn,
        challenge_id: "phone_rate_concurrent_a".to_owned(),
        now,
        config: &config,
        client: ClientRequestMetadata::default(),
    };
    let input_b = StartOtpInput {
        phone: "+8613800010001",
        purpose: PhoneOtpPurpose::SignIn,
        challenge_id: "phone_rate_concurrent_b".to_owned(),
        now,
        config: &config,
        client: ClientRequestMetadata::default(),
    };
    let (first, second) = tokio::join!(repo_a.start_otp(input_a), repo_b.start_otp(input_b));
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(
        usize::from(
            first
                .as_ref()
                .is_err_and(|error| error.code == ErrorCode::RateLimited)
        ) + usize::from(
            second
                .as_ref()
                .is_err_and(|error| error.code == ErrorCode::RateLimited)
        ),
        1
    );
    let concurrent_rows: i64 =
        sqlx::query_scalar("select count(*) from auth_phone.otp_challenges where phone_e164 = $1")
            .bind("+8613800010001")
            .fetch_one(&db.pool)
            .await
            .expect("concurrent phone row count");
    assert_eq!(concurrent_rows, 1);

    for index in 0..10 {
        repo.start_otp(StartOtpInput {
            phone: &format!("+861380002{:04}", index),
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: format!("phone_rate_ip_{index}"),
            now,
            config: &config,
            client: ClientRequestMetadata {
                ip: Some("203.0.113.10".to_owned()),
                user_agent: None,
            },
        })
        .await
        .expect("first ten starts from IP");
    }
    let ip_limited = repo
        .start_otp(StartOtpInput {
            phone: "+8613800029999",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_rate_ip_limited".to_owned(),
            now,
            config: &config,
            client: ClientRequestMetadata {
                ip: Some("203.0.113.10".to_owned()),
                user_agent: None,
            },
        })
        .await
        .expect_err("eleventh start from IP should be limited");
    assert_eq!(ip_limited.code, ErrorCode::RateLimited);
    repo.start_otp(StartOtpInput {
        phone: "+8613800029999",
        purpose: PhoneOtpPurpose::SignIn,
        challenge_id: "phone_rate_other_ip".to_owned(),
        now,
        config: &config,
        client: ClientRequestMetadata {
            ip: Some("203.0.113.11".to_owned()),
            user_agent: None,
        },
    })
    .await
    .expect("another IP remains available");

    db.cleanup().await;
}

#[tokio::test]
async fn rate_limit_route_returns_problem_details_429() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");
    let app = test_app(db.pool.clone());
    let body = r#"{"phone":"+8613800030000","purpose":"sign_in"}"#;
    let first = app
        .clone()
        .oneshot(post_json("/v1/auth/phone/otp/start", body))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let limited = app
        .oneshot(post_json("/v1/auth/phone/otp/start", body))
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let json = response_json(limited).await;
    assert_eq!(json["code"], "rate_limited");
    assert_eq!(json["status"], 429);
    db.cleanup().await;
}

#[tokio::test]
async fn verify_otp_creates_phone_identity_and_session() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let config = AuthPhoneConfig {
        return_debug_otp_code: true,
        ..AuthPhoneConfig::default()
    };
    let repo = PhoneAuthRepository::new(db.pool.clone());
    let now = Utc::now();

    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000004",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_otp_session".to_owned(),
            now,
            config: &config,
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect("otp starts");

    let session = repo
        .verify_otp_with_options(VerifyOtpOptions {
            challenge_id: "phone_otp_session",
            code: challenge.debug_code.as_deref().expect("debug code"),
            session_id: "sess_phone_otp".to_owned(),
            user_id: "usr_phone_otp".to_owned(),
            identity_id: "auth_identity_phone_otp".to_owned(),
            now: now + Duration::seconds(1),
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: Some("ios-device".to_owned()),
            client: ClientRequestMetadata::default(),
            link_anonymous_user_id: None,
        })
        .await
        .expect("otp verifies")
        .expect("session created");

    assert_eq!(session.user_id.0, "usr_phone_otp");
    assert_eq!(session.id, "sess_phone_otp");
    assert_eq!(session.device_id.as_deref(), Some("ios-device"));

    let identity_row = sqlx::query_as::<_, (String, String, String)>(
        r#"
        select provider, provider_subject, user_id
        from auth.identities
        where id = $1
        "#,
    )
    .bind("auth_identity_phone_otp")
    .fetch_one(&db.pool)
    .await
    .expect("identity row");
    assert_eq!(identity_row.0, "phone");
    assert_eq!(identity_row.1, "+8613800000004");
    assert_eq!(identity_row.2, "usr_phone_otp");

    let phone_metadata = sqlx::query_as::<_, (String, String, String)>(
        r#"
        select identity_id, provider, phone_e164
        from auth_phone.identities
        where identity_id = $1
        "#,
    )
    .bind("auth_identity_phone_otp")
    .fetch_one(&db.pool)
    .await
    .expect("phone identity metadata");
    assert_eq!(phone_metadata.0, "auth_identity_phone_otp");
    assert_eq!(phone_metadata.1, "phone");
    assert_eq!(phone_metadata.2, "+8613800000004");

    db.cleanup().await;
}

#[tokio::test]
async fn verify_otp_links_anonymous_user_when_requested() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let config = AuthPhoneConfig {
        return_debug_otp_code: true,
        ..AuthPhoneConfig::default()
    };
    let repo = PhoneAuthRepository::new(db.pool.clone());
    let now = Utc::now();
    let anonymous_user_id = AuthUserId("usr_anon_phone".to_owned());
    let mut tx = db.pool.begin().await.expect("begin tx");
    create_anonymous_user_identity_in_tx(
        &mut tx,
        anonymous_user_id.clone(),
        "auth_identity_anon".to_owned(),
        "anonymous",
        "anonymous-subject",
        now,
    )
    .await
    .expect("anonymous user");
    tx.commit().await.expect("commit anonymous user");

    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000005",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_otp_link".to_owned(),
            now,
            config: &config,
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect("otp starts");

    let session = repo
        .verify_otp_with_options(VerifyOtpOptions {
            challenge_id: "phone_otp_link",
            code: challenge.debug_code.as_deref().expect("debug code"),
            session_id: "sess_phone_link".to_owned(),
            user_id: "usr_unused_new".to_owned(),
            identity_id: "auth_identity_phone_link".to_owned(),
            now: now + Duration::seconds(1),
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: None,
            client: ClientRequestMetadata::default(),
            link_anonymous_user_id: Some(anonymous_user_id.clone()),
        })
        .await
        .expect("otp verifies")
        .expect("session created");

    assert_eq!(session.user_id, anonymous_user_id);

    let row = sqlx::query_as::<_, (String, bool, i64)>(
        r#"
        select identities.user_id, users.is_anonymous, count(all_identities.id)
        from auth.identities identities
        join auth.users users on users.id = identities.user_id
        join auth.identities all_identities on all_identities.user_id = users.id
        where identities.id = $1
        group by identities.user_id, users.is_anonymous
        "#,
    )
    .bind("auth_identity_phone_link")
    .fetch_one(&db.pool)
    .await
    .expect("linked anonymous user row");
    assert_eq!(row.0, "usr_anon_phone");
    assert!(!row.1);
    assert_eq!(row.2, 2);

    db.cleanup().await;
}

#[tokio::test]
async fn verify_otp_with_options_uses_the_injected_session_policy() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let config = AuthPhoneConfig {
        return_debug_otp_code: true,
        ..AuthPhoneConfig::default()
    };
    let repo = PhoneAuthRepository::new_with_session_policy(db.pool.clone(), Arc::new(FixedPolicy));
    let now = Utc::now();

    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000006",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_otp_policy".to_owned(),
            now,
            config: &config,
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect("otp starts");

    let session = repo
        .verify_otp_with_options(VerifyOtpOptions {
            challenge_id: "phone_otp_policy",
            code: challenge.debug_code.as_deref().expect("debug code"),
            session_id: "sess_phone_policy".to_owned(),
            user_id: "usr_phone_policy".to_owned(),
            identity_id: "auth_identity_phone_policy".to_owned(),
            now: now + Duration::seconds(1),
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: Some("device_hint".to_owned()),
            client: ClientRequestMetadata::default(),
            link_anonymous_user_id: None,
        })
        .await
        .expect("otp verifies")
        .expect("session created");

    assert_eq!(session.device_id.as_deref(), Some("device_from_policy"));

    db.cleanup().await;
}

#[tokio::test]
async fn correct_otp_rolls_back_consumption_when_session_policy_rejects() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");
    let config = AuthPhoneConfig {
        return_debug_otp_code: true,
        ..AuthPhoneConfig::default()
    };
    let now = Utc::now();
    let challenge = PhoneAuthRepository::new(db.pool.clone())
        .start_otp(StartOtpInput {
            phone: "+8613800040000",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_otp_policy_rollback".to_owned(),
            now,
            config: &config,
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect("otp starts");
    let code = challenge.debug_code.as_deref().expect("debug code");

    let rejected =
        PhoneAuthRepository::new_with_session_policy(db.pool.clone(), Arc::new(RejectingPolicy))
            .verify_otp_with_options(VerifyOtpOptions {
                challenge_id: "phone_otp_policy_rollback",
                code,
                session_id: "sess_phone_policy_rejected".to_owned(),
                user_id: "usr_phone_policy_rejected".to_owned(),
                identity_id: "auth_identity_phone_policy_rejected".to_owned(),
                now: now + Duration::seconds(1),
                expires_at: now + Duration::hours(1),
                config: &config,
                device_id: None,
                client: ClientRequestMetadata::default(),
                link_anonymous_user_id: None,
            })
            .await
            .expect_err("session policy should reject");
    assert_eq!(rejected.code, ErrorCode::Forbidden);
    let consumed_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("select consumed_at from auth_phone.otp_challenges where id = $1")
            .bind("phone_otp_policy_rollback")
            .fetch_one(&db.pool)
            .await
            .expect("challenge state");
    assert!(consumed_at.is_none());
    let session_count: i64 = sqlx::query_scalar("select count(*) from auth.sessions where id = $1")
        .bind("sess_phone_policy_rejected")
        .fetch_one(&db.pool)
        .await
        .expect("session count");
    assert_eq!(session_count, 0);

    let session = PhoneAuthRepository::new(db.pool.clone())
        .verify_otp_with_options(VerifyOtpOptions {
            challenge_id: "phone_otp_policy_rollback",
            code,
            session_id: "sess_phone_policy_retry".to_owned(),
            user_id: "usr_phone_policy_retry".to_owned(),
            identity_id: "auth_identity_phone_policy_retry".to_owned(),
            now: now + Duration::seconds(2),
            expires_at: now + Duration::hours(1),
            config: &config,
            device_id: None,
            client: ClientRequestMetadata::default(),
            link_anonymous_user_id: None,
        })
        .await
        .expect("retry verifies")
        .expect("retry session");
    assert_eq!(session.id, "sess_phone_policy_retry");
    let consumed_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("select consumed_at from auth_phone.otp_challenges where id = $1")
            .bind("phone_otp_policy_rollback")
            .fetch_one(&db.pool)
            .await
            .expect("challenge consumed after retry");
    assert!(consumed_at.is_some());
    db.cleanup().await;
}

#[tokio::test]
async fn phone_identity_metadata_rejects_non_phone_or_mismatched_subject() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    insert_identity(
        &db.pool,
        "user_google",
        "identity_google",
        "google",
        "google-subject",
    )
    .await;
    insert_identity(
        &db.pool,
        "user_phone",
        "identity_phone",
        "phone",
        "+8613800000003",
    )
    .await;

    let non_phone_error = sqlx::query(
        r#"
        insert into auth_phone.identities (identity_id, phone_e164, verified_at, created_at, updated_at)
        values ($1, $2, $3, $3, $3)
        "#,
    )
    .bind("identity_google")
    .bind("+8613800000002")
    .bind(Utc::now())
    .execute(&db.pool)
    .await
    .expect_err("non-phone identity should be rejected");
    assert_foreign_key_violation(&non_phone_error);

    let mismatched_subject_error = sqlx::query(
        r#"
        insert into auth_phone.identities (identity_id, phone_e164, verified_at, created_at, updated_at)
        values ($1, $2, $3, $3, $3)
        "#,
    )
    .bind("identity_phone")
    .bind("+8613800000999")
    .bind(Utc::now())
    .execute(&db.pool)
    .await
    .expect_err("mismatched provider subject should be rejected");
    assert_foreign_key_violation(&mismatched_subject_error);

    sqlx::query(
        r#"
        insert into auth_phone.identities (identity_id, phone_e164, verified_at, created_at, updated_at)
        values ($1, $2, $3, $3, $3)
        "#,
    )
    .bind("identity_phone")
    .bind("+8613800000003")
    .bind(Utc::now())
    .execute(&db.pool)
    .await
    .expect("matching phone identity should insert");

    db.cleanup().await;
}

async fn insert_identity(
    pool: &PgPool,
    user_id: &str,
    identity_id: &str,
    provider: &str,
    provider_subject: &str,
) {
    let now = Utc::now();
    sqlx::query("insert into auth.users (id, created_at, disabled_at) values ($1, $2, null)")
        .bind(user_id)
        .bind(now)
        .execute(pool)
        .await
        .expect("insert user");

    sqlx::query(
        r#"
        insert into auth.identities (id, user_id, provider, provider_subject, created_at, updated_at)
        values ($1, $2, $3, $4, $5, $5)
        "#,
    )
    .bind(identity_id)
    .bind(user_id)
    .bind(provider)
    .bind(provider_subject)
    .bind(now)
    .execute(pool)
        .await
        .expect("insert identity");
}

async fn seed_otp_challenge(
    pool: &PgPool,
    challenge_id: &str,
    phone: &str,
    code: &str,
    now: chrono::DateTime<Utc>,
    config: &AuthPhoneConfig,
) {
    sqlx::query(
        r#"
        insert into auth_phone.otp_challenges (
            id,
            phone_e164,
            purpose,
            code_hash,
            attempts,
            max_attempts,
            created_at,
            expires_at,
            resend_after,
            consumed_at
        )
        values ($1, $2, 'sign_in', $3, 0, $4, $5, $6, $5, null)
        "#,
    )
    .bind(challenge_id)
    .bind(phone)
    .bind(hash_otp_code(code, &config.otp_secret))
    .bind(config.otp_max_attempts)
    .bind(now)
    .bind(now + Duration::seconds(config.otp_ttl_seconds))
    .execute(pool)
    .await
    .expect("seed otp challenge");
}

fn test_app(db: platform_core::DbPool) -> axum::Router {
    test_app_with_config(db, test_config())
}

fn test_app_with_config(db: platform_core::DbPool, config: AppConfig) -> axum::Router {
    let (router, _) = auth_phone::routes::router().split_for_parts();
    let ctx = platform_core::AppContext::new(config, db.clone(), Arc::new(LoggingEventPublisher))
        .with_actor_resolver(Arc::new(auth::resolver::AuthActorResolver::new(
            db,
            Arc::new(DevActorResolver::new("local")),
        )));
    router
        .layer(middleware::from_fn_with_state(
            ctx.clone(),
            request_context_middleware,
        ))
        .with_state(ctx)
}

fn test_config_with_debug_otp_delivery() -> AppConfig {
    let mut config = test_config();
    config.modules.insert(
        "auth-phone".to_owned(),
        ModuleConfig {
            enabled: Some(true),
            values: BTreeMap::from([("return_debug_otp_code".to_owned(), serde_json::json!(true))]),
        },
    );
    config
}

fn test_config() -> AppConfig {
    AppConfig {
        auth: AuthConfig::default(),
        console: platform_core::config::ConsoleConfig::default(),
        database: DatabaseConfig {
            max_connections: 1,
            url: "postgres://lenso:lenso@127.0.0.1:5432/lenso".to_owned(),
        },
        http: HttpConfig::default(),
        module_sources: ModuleSourcesConfig::default(),
        modules: BTreeMap::new(),
        redis: RedisConfig::default(),
        service: ServiceConfig {
            environment: "local".to_owned(),
            name: "auth-phone-otp-test".to_owned(),
        },
        telemetry: TelemetryConfig::default(),
    }
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("user-agent", "test-agent")
        .body(Body::from(body.to_owned()))
        .expect("request should build")
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&body).expect("json body")
}

fn assert_foreign_key_violation(error: &sqlx::Error) {
    let database_error = error
        .as_database_error()
        .expect("database error details should exist");
    assert_eq!(database_error.code().as_deref(), Some("23503"));
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

#[derive(Debug)]
struct RejectingPolicy;

#[async_trait::async_trait]
impl AuthSessionPolicy for RejectingPolicy {
    async fn before_session_create(
        &self,
        _input: &SessionCreateInput,
    ) -> AppResult<SessionCreateDecision> {
        Err(platform_core::AppError::new(
            ErrorCode::Forbidden,
            "session rejected by test policy",
        ))
    }
}
