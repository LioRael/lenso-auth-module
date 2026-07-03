use auth_anonymous::repositories::{AnonymousAuthRepository, AnonymousSessionOptions};
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::middleware;
use chrono::{Duration, Utc};
use platform_core::{
    AppConfig, AuthConfig, DatabaseConfig, HttpConfig, LoggingEventPublisher, Migration,
    ModuleSourcesConfig, PLATFORM_MIGRATIONS, RedisConfig, ServiceConfig, TelemetryConfig,
    apply_migrations,
};
use platform_http::request_context_middleware;
use platform_testing::TestDatabase;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

fn migrations() -> Vec<Migration> {
    PLATFORM_MIGRATIONS
        .iter()
        .chain(auth::migrations::AUTH_MIGRATIONS)
        .chain(auth_anonymous::migrations::AUTH_ANONYMOUS_MIGRATIONS)
        .copied()
        .collect()
}

#[tokio::test]
async fn sign_in_creates_anonymous_user_identity_and_session() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let now = Utc::now();
    let session = AnonymousAuthRepository::new(db.pool.clone())
        .sign_in(
            "usr_anonymous_sign_in".to_owned(),
            "auth_identity_anonymous_sign_in".to_owned(),
            "sess_anonymous_sign_in".to_owned(),
            now,
            now + Duration::hours(1),
            AnonymousSessionOptions::default(),
        )
        .await
        .expect("anonymous sign in");

    assert_eq!(session.user_id.0, "usr_anonymous_sign_in");
    assert_eq!(session.id, "sess_anonymous_sign_in");
    assert!(session.token.starts_with("sess_"));

    let row = sqlx::query_as::<_, (bool, String)>(
        r#"
        select users.is_anonymous, identities.provider
        from auth.users users
        join auth.identities identities on identities.user_id = users.id
        where users.id = $1
        "#,
    )
    .bind(&session.user_id.0)
    .fetch_one(&db.pool)
    .await
    .expect("anonymous user row");
    assert!(row.0);
    assert_eq!(row.1, "anonymous");

    db.cleanup().await;
}

#[tokio::test]
async fn route_creates_anonymous_session_cookie() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let response = test_app(db.pool.clone())
        .oneshot(post_json("/v1/auth/anonymous/login", "{}"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("lenso_session=sess_"))
    );

    let row = sqlx::query_as::<_, (bool, i64)>(
        r#"
        select users.is_anonymous, count(sessions.id)
        from auth.users users
        join auth.sessions sessions on sessions.user_id = users.id
        group by users.id
        "#,
    )
    .fetch_one(&db.pool)
    .await
    .expect("anonymous session row");
    assert!(row.0);
    assert_eq!(row.1, 1);

    db.cleanup().await;
}

fn test_app(db: platform_core::DbPool) -> axum::Router {
    let (router, _) = auth_anonymous::routes::router().split_for_parts();
    let ctx = platform_core::AppContext::new(test_config(), db, Arc::new(LoggingEventPublisher));
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
            name: "auth-anonymous-test".to_owned(),
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
