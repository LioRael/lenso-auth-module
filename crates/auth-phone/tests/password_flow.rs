use auth::models::AuthUserId;
use auth::session_policy::{AuthSessionPolicy, SessionCreateDecision, SessionCreateInput};
use auth_password::config::AuthPasswordConfig;
use auth_password::migrations::AUTH_PASSWORD_MIGRATIONS;
use auth_phone::config::AuthPhoneConfig;
use auth_phone::migrations::AUTH_PHONE_MIGRATIONS;
use auth_phone::repositories::{
    LoginPhonePasswordOptions, PhoneAuthRepository, PhoneOtpPurpose, SetPhonePasswordOptions,
    StartOtpInput, VerifyOtpOptions,
};
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::middleware;
use chrono::{Duration, Utc};
use platform_core::{
    AppConfig, AppResult, AuthConfig, ClientRequestMetadata, DatabaseConfig, DevActorResolver,
    ErrorCode, HttpConfig, LoggingEventPublisher, Migration, ModuleSourcesConfig,
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
        .chain(AUTH_PASSWORD_MIGRATIONS)
        .chain(AUTH_PHONE_MIGRATIONS)
        .copied()
        .collect()
}

fn fast_otp_config() -> AuthPhoneConfig {
    AuthPhoneConfig {
        return_debug_otp_code: true,
        ..AuthPhoneConfig::default()
    }
}

fn fast_password_config() -> AuthPasswordConfig {
    AuthPasswordConfig {
        argon2_memory_kib: 8 * 1024,
        argon2_time_cost: 1,
        argon2_parallelism: 1,
        ..AuthPasswordConfig::default()
    }
}

#[tokio::test]
async fn set_password_uses_auth_password_credentials() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let now = Utc::now();
    seed_phone_identity(
        &db.pool,
        "usr_phone_password_credential_module",
        "auth_identity_phone_password_credential_module",
        "+8613800000210",
        now,
    )
    .await;

    let password_config = fast_password_config();
    let updated = PhoneAuthRepository::new(db.pool.clone())
        .set_password(SetPhonePasswordOptions {
            user_id: &AuthUserId("usr_phone_password_credential_module".to_owned()),
            password: "correct horse",
            now,
            config: &password_config,
        })
        .await
        .expect("password set");

    assert!(updated);

    let credentials_exist = sqlx::query_scalar::<_, bool>(
        r#"
        select exists(
            select 1
            from auth_password.credentials
            where identity_id = $1
        )
        "#,
    )
    .bind("auth_identity_phone_password_credential_module")
    .fetch_one(&db.pool)
    .await
    .expect("credential lookup");
    assert!(credentials_exist);
}

#[tokio::test]
async fn password_set_route_updates_current_phone_identity() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    seed_phone_identity(
        &db.pool,
        "usr_phone_password_set_route",
        "auth_identity_phone_password_set_route",
        "+8613800000200",
        Utc::now(),
    )
    .await;

    let response = test_app(db.pool.clone())
        .oneshot(post_json_with_auth(
            "/v1/auth/phone/password/set",
            r#"{"password":"correct horse"}"#,
            "Bearer dev-user:usr_phone_password_set_route",
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["updated"].as_bool(), Some(true));

    let credentials_exist = sqlx::query_scalar::<_, bool>(
        r#"
        select exists(
            select 1
            from auth_password.credentials
            where identity_id = $1
        )
        "#,
    )
    .bind("auth_identity_phone_password_set_route")
    .fetch_one(&db.pool)
    .await
    .expect("credential exists");
    assert!(credentials_exist);

    db.cleanup().await;
}

#[tokio::test]
async fn password_login_route_creates_session_cookie() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let password_config = fast_password_config();
    let repo = PhoneAuthRepository::new(db.pool.clone());
    let user_id = AuthUserId("usr_phone_password_login_route".to_owned());
    seed_phone_identity(
        &db.pool,
        &user_id.0,
        "auth_identity_phone_password_login_route",
        "+8613800000201",
        Utc::now(),
    )
    .await;
    repo.set_password(SetPhonePasswordOptions {
        user_id: &user_id,
        password: "correct horse",
        now: Utc::now(),
        config: &password_config,
    })
    .await
    .expect("password set");

    let response = test_app(db.pool.clone())
        .oneshot(post_json(
            "/v1/auth/phone/password/login",
            r#"{"phone":"+8613800000201","password":"correct horse","device_id":"ios-device"}"#,
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
    assert_eq!(json["user_id"].as_str(), Some(user_id.0.as_str()));
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
        Some("138****0201")
    );
    assert!(json.get("phone_e164").is_none());

    db.cleanup().await;
}

#[tokio::test]
async fn password_login_route_returns_generic_failure() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let response = test_app(db.pool.clone())
        .oneshot(post_json(
            "/v1/auth/phone/password/login",
            r#"{"phone":"+8613800000202","password":"wrong horse"}"#,
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = response_json(response).await;
    assert_eq!(json["detail"].as_str(), Some("Invalid phone or password"));

    db.cleanup().await;
}

#[tokio::test]
async fn set_password_then_login_creates_session() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let otp_config = fast_otp_config();
    let password_config = fast_password_config();
    let repo = PhoneAuthRepository::new(db.pool.clone());
    let now = Utc::now();
    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000002",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_password_challenge".to_owned(),
            now,
            config: &otp_config,
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
            config: &otp_config,
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
            config: &password_config,
        })
        .await
        .expect("password set");

    assert!(updated);

    let credentials_exist = sqlx::query_scalar::<_, bool>(
        r#"
        select exists(
            select 1
            from auth_password.credentials
            where identity_id = $1
        )
        "#,
    )
    .bind("auth_identity_phone_password")
    .fetch_one(&db.pool)
    .await
    .expect("credential exists");
    assert!(credentials_exist);

    let password_session = repo
        .login_password_with_options(LoginPhonePasswordOptions {
            phone: "+8613800000002",
            password: "correct horse",
            session_id: "sess_phone_password_login".to_owned(),
            now: now + Duration::seconds(3),
            expires_at: now + Duration::hours(12),
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

    let config = AuthPasswordConfig::default();
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

    let repo = PhoneAuthRepository::new(db.pool.clone());
    let now = Utc::now();
    let error = repo
        .login_password_with_options(LoginPhonePasswordOptions {
            phone: "+8613800000003",
            password: "wrong horse",
            session_id: "sess_wrong".to_owned(),
            now,
            expires_at: now + Duration::hours(12),
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
        from auth_password.login_failures
        where provider = 'phone' and identifier = $1
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

    let repo = PhoneAuthRepository::new(db.pool.clone());
    let now = Utc::now();
    let error = repo
        .login_password_with_options(LoginPhonePasswordOptions {
            phone: "+8613800000006",
            password: "short",
            session_id: "sess_short_wrong".to_owned(),
            now,
            expires_at: now + Duration::hours(12),
            device_id: None,
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect_err("short password should still be treated as invalid credentials");

    assert_eq!(error.code, ErrorCode::Unauthorized);
    assert_eq!(error.public_message, "Invalid phone or password");

    let row: (i32, Option<String>, Option<String>) = sqlx::query_as(
        r#"
        select failed_count, last_failed_ip, last_failed_user_agent
        from auth_password.login_failures
        where provider = 'phone' and identifier = $1
        "#,
    )
    .bind("+8613800000006")
    .fetch_one(&db.pool)
    .await
    .expect("failure row");

    assert_eq!(row.0, 1);
    assert_eq!(row.1, None);
    assert_eq!(row.2, None);

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

    let otp_config = fast_otp_config();
    let password_config = fast_password_config();
    let repo = PhoneAuthRepository::new(db.pool.clone());
    let now = Utc::now();
    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000004",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_password_failure_reset".to_owned(),
            now,
            config: &otp_config,
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
            config: &otp_config,
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
        config: &password_config,
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
            from auth_password.login_failures
            where provider = 'phone' and identifier = $1
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

    let otp_config = fast_otp_config();
    let password_config = fast_password_config();
    let repo = PhoneAuthRepository::new(db.pool.clone());
    let now = Utc::now();
    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000005",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_password_policy".to_owned(),
            now,
            config: &otp_config,
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
            config: &otp_config,
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
        config: &password_config,
    })
    .await
    .expect("password set");

    let policy_repo =
        PhoneAuthRepository::new_with_session_policy(db.pool.clone(), Arc::new(FixedPolicy));
    let password_session = policy_repo
        .login_password_with_options(LoginPhonePasswordOptions {
            phone: "+8613800000005",
            password: "correct horse",
            session_id: "sess_phone_password_policy".to_owned(),
            now: now + Duration::seconds(3),
            expires_at: now + Duration::hours(12),
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

async fn seed_phone_identity(
    pool: &PgPool,
    user_id: &str,
    identity_id: &str,
    phone: &str,
    now: chrono::DateTime<Utc>,
) {
    sqlx::query("insert into auth.users (id, created_at, disabled_at) values ($1, $2, null)")
        .bind(user_id)
        .bind(now)
        .execute(pool)
        .await
        .expect("insert user");

    sqlx::query(
        r#"
        insert into auth.identities (id, user_id, provider, provider_subject, created_at, updated_at)
        values ($1, $2, 'phone', $3, $4, $4)
        "#,
    )
    .bind(identity_id)
    .bind(user_id)
    .bind(phone)
    .bind(now)
    .execute(pool)
    .await
    .expect("insert auth identity");

    sqlx::query(
        r#"
        insert into auth_phone.identities (
            identity_id,
            provider,
            phone_e164,
            verified_at,
            created_at,
            updated_at
        )
        values ($1, 'phone', $2, $3, $3, $3)
        "#,
    )
    .bind(identity_id)
    .bind(phone)
    .bind(now)
    .execute(pool)
    .await
    .expect("insert phone identity");
}

fn test_app(db: platform_core::DbPool) -> axum::Router {
    let (router, _) = auth_phone::routes::router().split_for_parts();
    let ctx =
        platform_core::AppContext::new(test_config(), db.clone(), Arc::new(LoggingEventPublisher))
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
            name: "auth-phone-password-test".to_owned(),
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

fn post_json_with_auth(uri: &str, body: &str, authorization: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("user-agent", "test-agent")
        .header(header::AUTHORIZATION, authorization)
        .body(Body::from(body.to_owned()))
        .expect("request should build")
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&body).expect("json body")
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
