use auth_oidc::migrations::AUTH_OIDC_MIGRATIONS;
use auth_oidc::repositories::{AuthorizationCodeInput, OidcRepository};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware;
use chrono::{Duration, Utc};
use platform_core::config::ConsoleConfig;
use platform_core::{
    AppConfig, AppContext, AuthConfig, DatabaseConfig, HttpConfig, LoggingEventPublisher,
    Migration, ModuleConfig, ModuleSourcesConfig, PLATFORM_MIGRATIONS, RedisConfig, ServiceConfig,
    TelemetryConfig, apply_migrations,
};
use platform_http::request_context_middleware;
use platform_testing::TestDatabase;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

const CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT_URI: &str = "https://console.example.com/callback";

fn migrations() -> Vec<Migration> {
    PLATFORM_MIGRATIONS
        .iter()
        .chain(auth::migrations::AUTH_MIGRATIONS)
        .chain(AUTH_OIDC_MIGRATIONS)
        .copied()
        .collect()
}

#[tokio::test]
async fn token_endpoint_rejects_wrong_pkce_verifier_without_consuming_code() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let now = Utc::now();
    sqlx::query(
        r"
        insert into auth.users (id, created_at, disabled_at, disabled_reason, disabled_until)
        values ($1, $2, null, null, null)
        ",
    )
    .bind("usr_oidc_token")
    .bind(now)
    .execute(&db.pool)
    .await
    .expect("auth user inserted");

    let code = OidcRepository::new(db.pool.clone())
        .create_authorization_code(AuthorizationCodeInput {
            user_id: auth::models::AuthUserId("usr_oidc_token".to_owned()),
            client_id: "lenso-console".to_owned(),
            redirect_uri: REDIRECT_URI.to_owned(),
            scope: "openid".to_owned(),
            code_challenge: CODE_CHALLENGE.to_owned(),
            code_challenge_method: "S256".to_owned(),
            nonce: Some("nonce-token".to_owned()),
            created_at: now,
            expires_at: now + Duration::minutes(5),
        })
        .await
        .expect("authorization code created");

    let app = test_app(test_context(db.pool.clone()));
    let body = token_request_body(&code.code, &"a".repeat(43));

    let response = app
        .oneshot(post_form("/oauth/token", &body))
        .await
        .expect("token request should complete");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let consumed_at = sqlx::query_scalar::<_, Option<chrono::DateTime<Utc>>>(
        r"
        select consumed_at
        from auth_oidc.authorization_codes
        where code_hash = $1
        ",
    )
    .bind(auth::resolver::session_token_hash(&code.code))
    .fetch_one(&db.pool)
    .await
    .expect("authorization code row");
    assert!(consumed_at.is_none());

    let session_count = sqlx::query_scalar::<_, i64>(
        r"
        select count(*)
        from auth.sessions
        where user_id = $1
        ",
    )
    .bind("usr_oidc_token")
    .fetch_one(&db.pool)
    .await
    .expect("auth session count");
    assert_eq!(session_count, 0);

    db.cleanup().await;
}

fn test_app(ctx: AppContext) -> axum::Router {
    let (router, _) = auth_oidc::routes::router().split_for_parts();
    router
        .layer(middleware::from_fn_with_state(
            ctx.clone(),
            request_context_middleware,
        ))
        .with_state(ctx)
}

fn test_context(db: platform_core::DbPool) -> AppContext {
    AppContext::new(test_config(), db, Arc::new(LoggingEventPublisher))
}

fn test_config() -> AppConfig {
    let mut values = BTreeMap::new();
    values.insert("enabled".to_owned(), json!(true));
    values.insert("issuer".to_owned(), json!("https://example.com/"));
    values.insert("console_redirect_uris".to_owned(), json!([REDIRECT_URI]));
    values.insert(
        "jwks".to_owned(),
        json!({
            "keys": [{
                "alg": "RS256",
                "e": "AQAB",
                "kid": "test-key",
                "kty": "RSA",
                "n": "test-modulus",
                "use": "sig"
            }]
        }),
    );
    values.insert(
        "id_token_private_key_pem".to_owned(),
        json!("unused-test-private-key"),
    );
    values.insert("id_token_key_id".to_owned(), json!("test-key"));

    let mut modules = BTreeMap::new();
    modules.insert(
        auth_oidc::config::CONFIG_PREFIX.to_owned(),
        ModuleConfig {
            enabled: None,
            values,
        },
    );

    AppConfig {
        auth: AuthConfig::default(),
        console: ConsoleConfig::default(),
        database: DatabaseConfig {
            max_connections: 1,
            url: "postgres://lenso:lenso@127.0.0.1:5432/lenso".to_owned(),
        },
        http: HttpConfig::default(),
        module_sources: ModuleSourcesConfig::default(),
        modules,
        redis: RedisConfig::default(),
        service: ServiceConfig {
            environment: "local".to_owned(),
            name: "auth-oidc-token-test".to_owned(),
        },
        telemetry: TelemetryConfig::default(),
    }
}

fn token_request_body(code: &str, verifier: &str) -> String {
    format!(
        "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fconsole.example.com%2Fcallback&client_id=lenso-console&code_verifier={verifier}"
    )
}

fn post_form(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))
        .expect("request should build")
}
