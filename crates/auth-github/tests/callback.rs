use auth_github::client::{GitHubAccessToken, GitHubOAuthClient, GitHubUser};
use auth_github::migrations::AUTH_GITHUB_MIGRATIONS;
use auth_oauth::flow::{OAuthFlowInput, OAuthFlowRepository};
use auth_oauth::migrations::AUTH_OAUTH_MIGRATIONS;
use axum::Extension;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::middleware;
use chrono::{Duration, Utc};
use platform_core::{
    AppConfig, AppResult, AuthConfig, ClientRequestMetadata, DatabaseConfig, HttpConfig,
    LoggingEventPublisher, Migration, ModuleConfig, ModuleSourcesConfig, PLATFORM_MIGRATIONS,
    RedisConfig, ServiceConfig, TelemetryConfig, apply_migrations,
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
        .chain(auth::migrations::AUTH_MIGRATIONS)
        .chain(AUTH_OAUTH_MIGRATIONS)
        .chain(AUTH_GITHUB_MIGRATIONS)
        .copied()
        .collect()
}

#[tokio::test]
async fn callback_creates_github_identity_session_and_account_snapshot() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let now = Utc::now();
    let flow = OAuthFlowRepository::new(db.pool.clone())
        .create_flow(OAuthFlowInput {
            provider: "github".to_owned(),
            return_to: "/console".to_owned(),
            client: ClientRequestMetadata {
                ip: Some("127.0.0.1".to_owned()),
                user_agent: Some("test-agent".to_owned()),
            },
            created_at: now,
            expires_at: now + Duration::minutes(10),
        })
        .await
        .expect("flow created");

    let response = test_app(
        db.pool.clone(),
        Arc::new(FakeGitHubClient {
            expected_code: "github-code".to_owned(),
            expected_verifier: flow.code_verifier.clone(),
        }),
    )
    .oneshot(get(&format!(
        "/v1/auth/github/callback?code=github-code&state={}",
        flow.state
    )))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/console")
    );
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("lenso_session="))
    );

    let identity = sqlx::query_as::<_, (String, String, String)>(
        r"
        select id, provider, provider_subject
        from auth.identities
        where provider = 'github'
        ",
    )
    .fetch_one(&db.pool)
    .await
    .expect("github identity");
    assert_eq!(identity.1, "github");
    assert_eq!(identity.2, "123456");

    let account = sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
        r"
        select github_user_id, login, email, avatar_url
        from auth_github.accounts
        where identity_id = $1
        ",
    )
    .bind(&identity.0)
    .fetch_one(&db.pool)
    .await
    .expect("github account snapshot");
    assert_eq!(account.0, "123456");
    assert_eq!(account.1, "octocat");
    assert_eq!(account.2.as_deref(), Some("octocat@example.com"));
    assert_eq!(
        account.3.as_deref(),
        Some("https://avatars.example/octocat.png")
    );

    let session_count = sqlx::query_scalar::<_, i64>("select count(*) from auth.sessions")
        .fetch_one(&db.pool)
        .await
        .expect("session count");
    assert_eq!(session_count, 1);

    let token_columns = sqlx::query_scalar::<_, i64>(
        r"
        select count(*)
        from information_schema.columns
        where table_schema = 'auth_github'
          and table_name = 'accounts'
          and column_name like '%token%'
        ",
    )
    .fetch_one(&db.pool)
    .await
    .expect("token column count");
    assert_eq!(token_columns, 0);

    db.cleanup().await;
}

#[derive(Debug)]
struct FakeGitHubClient {
    expected_code: String,
    expected_verifier: String,
}

#[async_trait::async_trait]
impl GitHubOAuthClient for FakeGitHubClient {
    async fn exchange_code(
        &self,
        _config: &auth_github::config::ResolvedGitHubAuthConfig,
        code: &str,
        code_verifier: &str,
    ) -> AppResult<GitHubAccessToken> {
        assert_eq!(code, self.expected_code);
        assert_eq!(code_verifier, self.expected_verifier);
        Ok(GitHubAccessToken {
            access_token: "github-access-token".to_owned(),
        })
    }

    async fn load_user(
        &self,
        _config: &auth_github::config::ResolvedGitHubAuthConfig,
        access_token: &str,
    ) -> AppResult<GitHubUser> {
        assert_eq!(access_token, "github-access-token");
        Ok(GitHubUser {
            id: 123456,
            login: "octocat".to_owned(),
            email: None,
            avatar_url: Some("https://avatars.example/octocat.png".to_owned()),
        })
    }

    async fn load_primary_email(
        &self,
        _config: &auth_github::config::ResolvedGitHubAuthConfig,
        access_token: &str,
    ) -> AppResult<Option<String>> {
        assert_eq!(access_token, "github-access-token");
        Ok(Some("octocat@example.com".to_owned()))
    }
}

fn test_app(
    db: platform_core::DbPool,
    github_client: auth_github::client::GitHubOAuthClientHandle,
) -> axum::Router {
    let (router, _) = auth_github::routes::router().split_for_parts();
    let ctx = platform_core::AppContext::new(test_config(), db, Arc::new(LoggingEventPublisher));
    router
        .layer(Extension(github_client))
        .layer(middleware::from_fn_with_state(
            ctx.clone(),
            request_context_middleware,
        ))
        .with_state(ctx)
}

fn test_config() -> AppConfig {
    let mut values = BTreeMap::new();
    values.insert("client_id".to_owned(), json!("github-client"));
    values.insert("client_secret".to_owned(), json!("github-secret"));
    let mut modules = BTreeMap::new();
    modules.insert(
        auth_github::config::CONFIG_PREFIX.to_owned(),
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
            name: "auth-github-callback-test".to_owned(),
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
