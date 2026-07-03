use auth_oauth::flow::{OAuthFlowInput, OAuthFlowRepository};
use auth_oauth::migrations::AUTH_OAUTH_MIGRATIONS;
use chrono::{Duration, Utc};
use platform_core::{ClientRequestMetadata, Migration, PLATFORM_MIGRATIONS, apply_migrations};
use platform_testing::TestDatabase;

fn migrations() -> Vec<Migration> {
    PLATFORM_MIGRATIONS
        .iter()
        .chain(AUTH_OAUTH_MIGRATIONS)
        .copied()
        .collect()
}

#[tokio::test]
async fn consume_flow_returns_record_once_and_stores_hashed_state() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let repo = OAuthFlowRepository::new(db.pool.clone());
    let now = Utc::now();
    let created = repo
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

    assert!(created.state.starts_with("oauth_state_"));
    assert!(created.code_verifier.starts_with("oauth_verifier_"));

    let plaintext_rows = sqlx::query_scalar::<_, i64>(
        r"
        select count(*)
        from auth_oauth.flows
        where state_hash = $1
        ",
    )
    .bind(&created.state)
    .fetch_one(&db.pool)
    .await
    .expect("count plaintext state rows");
    assert_eq!(plaintext_rows, 0);

    let hashed_rows = sqlx::query_scalar::<_, i64>(
        r"
        select count(*)
        from auth_oauth.flows
        where state_hash = $1
        ",
    )
    .bind(auth::resolver::session_token_hash(&created.state))
    .fetch_one(&db.pool)
    .await
    .expect("count hashed state rows");
    assert_eq!(hashed_rows, 1);

    let consumed = repo
        .consume_flow("github", &created.state, now + Duration::minutes(1))
        .await
        .expect("flow consumed")
        .expect("flow exists");

    assert_eq!(consumed.provider, "github");
    assert_eq!(consumed.return_to, "/console");
    assert_eq!(consumed.code_verifier, created.code_verifier);
    assert_eq!(consumed.client.ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(consumed.client.user_agent.as_deref(), Some("test-agent"));

    assert!(
        repo.consume_flow("github", &created.state, now + Duration::minutes(2))
            .await
            .expect("second consume checked")
            .is_none()
    );

    db.cleanup().await;
}
