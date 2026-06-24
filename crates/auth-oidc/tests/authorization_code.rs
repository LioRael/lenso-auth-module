use auth_oidc::migrations::AUTH_OIDC_MIGRATIONS;
use auth_oidc::repositories::{AuthorizationCodeInput, OidcRepository};
use chrono::{Duration, Utc};
use platform_core::{Migration, PLATFORM_MIGRATIONS, apply_migrations};
use platform_testing::TestDatabase;

fn migrations() -> Vec<Migration> {
    PLATFORM_MIGRATIONS
        .iter()
        .chain(auth::migrations::AUTH_MIGRATIONS)
        .chain(AUTH_OIDC_MIGRATIONS)
        .copied()
        .collect()
}

#[tokio::test]
async fn authorization_code_is_stored_hashed() {
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
    .bind("usr_oidc_code")
    .bind(now)
    .execute(&db.pool)
    .await
    .expect("auth user inserted");

    let code = OidcRepository::new(db.pool.clone())
        .create_authorization_code(AuthorizationCodeInput {
            user_id: auth::models::AuthUserId("usr_oidc_code".to_owned()),
            client_id: "lenso-console".to_owned(),
            redirect_uri: "https://console.example.com/callback".to_owned(),
            scope: "openid profile".to_owned(),
            code_challenge: "a".repeat(43),
            code_challenge_method: "S256".to_owned(),
            nonce: Some("nonce-1".to_owned()),
            created_at: now,
            expires_at: now + Duration::minutes(5),
        })
        .await
        .expect("create authorization code");

    let row = sqlx::query_as::<_, (String, String, String, String, Option<String>)>(
        r"
        select user_id, client_id, redirect_uri, code_challenge_method, nonce
        from auth_oidc.authorization_codes
        where code_hash = $1
        ",
    )
    .bind(auth::resolver::session_token_hash(&code.code))
    .fetch_one(&db.pool)
    .await
    .expect("authorization code row");

    assert!(code.code.starts_with("oidc_code_"));
    assert_eq!(row.0, "usr_oidc_code");
    assert_eq!(row.1, "lenso-console");
    assert_eq!(row.2, "https://console.example.com/callback");
    assert_eq!(row.3, "S256");
    assert_eq!(row.4.as_deref(), Some("nonce-1"));

    let repository = OidcRepository::new(db.pool.clone());
    let record = repository
        .find_authorization_code(&code.code, now)
        .await
        .expect("authorization code lookup")
        .expect("authorization code is present");
    assert_eq!(record.user_id.0, "usr_oidc_code");
    assert_eq!(record.client_id, "lenso-console");
    assert_eq!(record.redirect_uri, "https://console.example.com/callback");
    assert_eq!(record.scope, "openid profile");
    assert_eq!(record.code_challenge, "a".repeat(43));
    assert_eq!(record.nonce.as_deref(), Some("nonce-1"));

    assert!(
        repository
            .consume_authorization_code(&code.code, now)
            .await
            .expect("authorization code is consumed")
    );
    assert!(
        repository
            .find_authorization_code(&code.code, now)
            .await
            .expect("authorization code lookup")
            .is_none()
    );
    assert!(
        !repository
            .consume_authorization_code(&code.code, now)
            .await
            .expect("authorization code cannot be consumed twice")
    );

    let plaintext_rows = sqlx::query_scalar::<_, i64>(
        r"
        select count(*)
        from auth_oidc.authorization_codes
        where code_hash = $1
        ",
    )
    .bind(&code.code)
    .fetch_one(&db.pool)
    .await
    .expect("count plaintext code rows");
    assert_eq!(plaintext_rows, 0);

    db.cleanup().await;
}
