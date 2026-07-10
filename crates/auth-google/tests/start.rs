use auth_google::migrations::AUTH_GOOGLE_MIGRATIONS;
use auth_oauth::migrations::AUTH_OAUTH_MIGRATIONS;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::middleware;
use platform_core::{
    AppConfig, AuthConfig, DatabaseConfig, HttpConfig, LoggingEventPublisher, Migration,
    ModuleConfig, ModuleSourcesConfig, PLATFORM_MIGRATIONS, RedisConfig, ServiceConfig,
    TelemetryConfig, apply_migrations,
};
use platform_http::request_context_middleware;
use platform_testing::TestDatabase;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

fn migrations() -> Vec<Migration> {
    PLATFORM_MIGRATIONS
        .iter()
        .chain(AUTH_OAUTH_MIGRATIONS)
        .chain(AUTH_GOOGLE_MIGRATIONS)
        .copied()
        .collect()
}

#[tokio::test]
async fn start_creates_oauth_flow_and_redirects_to_google() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let response = test_app(db.pool.clone())
        .oneshot(get("/v1/auth/google/start?return_to=/console"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location");
    assert!(location.starts_with("https://accounts.google.example.test/o/oauth2/v2/auth?"));
    assert!(location.contains("response_type=code"));
    assert!(location.contains("client_id=google-client"));
    assert!(location.contains("scope=openid%20profile%20email"));
    assert!(location.contains("code_challenge_method=S256"));
    assert!(location.contains("code_challenge="));
    let state = query_param(location, "state").expect("state param");
    assert!(state.starts_with("oauth_state_"));

    let row = sqlx::query_as::<_, (String, String, Option<String>)>(
        r"
        select provider, return_to, user_agent
        from auth_oauth.flows
        where state_hash = $1
        ",
    )
    .bind(auth::resolver::session_token_hash(&state))
    .fetch_one(&db.pool)
    .await
    .expect("oauth flow row");
    assert_eq!(row.0, "google");
    assert_eq!(row.1, "/console");
    assert_eq!(row.2.as_deref(), Some("test-agent"));

    db.cleanup().await;
}

#[tokio::test]
async fn start_rejects_encoded_backslash_return_to_without_creating_flow() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let response = test_app(db.pool.clone())
        .oneshot(get("/v1/auth/google/start?return_to=/%5Cevil.example/path"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let flow_count = sqlx::query_scalar::<_, i64>("select count(*) from auth_oauth.flows")
        .fetch_one(&db.pool)
        .await
        .expect("flow count query");
    assert_eq!(flow_count, 0);

    db.cleanup().await;
}

fn test_app(db: platform_core::DbPool) -> axum::Router {
    let (router, _) = auth_google::routes::router().split_for_parts();
    let ctx = platform_core::AppContext::new(test_config(), db, Arc::new(LoggingEventPublisher));
    router
        .layer(middleware::from_fn_with_state(
            ctx.clone(),
            request_context_middleware,
        ))
        .with_state(ctx)
}

fn test_config() -> AppConfig {
    let mut values = BTreeMap::new();
    values.insert("client_id".to_owned(), json!("google-client"));
    values.insert("client_secret".to_owned(), json!("google-secret"));
    values.insert(
        "authorize_url".to_owned(),
        json!("https://accounts.google.example.test/o/oauth2/v2/auth"),
    );
    let mut modules = BTreeMap::new();
    modules.insert(
        auth_google::config::CONFIG_PREFIX.to_owned(),
        ModuleConfig {
            enabled: None,
            values,
        },
    );

    AppConfig {
        auth: AuthConfig::default(),
        console: platform_core::config::ConsoleConfig::default(),
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
            name: "auth-google-start-test".to_owned(),
        },
        telemetry: TelemetryConfig::default(),
    }
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("user-agent", "test-agent")
        .body(Body::empty())
        .expect("request should build")
}

fn query_param(uri: &str, name: &str) -> Option<String> {
    let query = uri.split_once('?')?.1;
    query.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == name).then(|| value.to_owned())
    })
}
