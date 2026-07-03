use auth::models::AuthUserId;
use auth::public::{create_anonymous_user_identity_in_tx, link_identity_to_anonymous_user_in_tx};
use auth::repositories::{AuthUserRepository, PostgresAuthUserRepository};
use chrono::Utc;
use platform_core::{Migration, PLATFORM_MIGRATIONS, apply_migrations};
use platform_testing::TestDatabase;

fn migrations() -> Vec<Migration> {
    PLATFORM_MIGRATIONS
        .iter()
        .chain(auth::migrations::AUTH_MIGRATIONS)
        .copied()
        .collect()
}

#[tokio::test]
async fn linking_provider_identity_marks_anonymous_user_permanent() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    apply_migrations(&db.pool, &migrations())
        .await
        .expect("migrations apply");

    let now = Utc::now();
    let user_id = AuthUserId("usr_anonymous_link".to_owned());
    let mut tx = db.pool.begin().await.expect("begin tx");
    create_anonymous_user_identity_in_tx(
        &mut tx,
        user_id.clone(),
        "auth_identity_anonymous_link".to_owned(),
        "anonymous",
        "anon_subject_link",
        now,
    )
    .await
    .expect("anonymous identity");
    tx.commit().await.expect("commit anonymous user");

    let repo = PostgresAuthUserRepository::new(db.pool.clone());
    let anonymous_user = repo
        .find_by_id(&user_id)
        .await
        .expect("find anonymous user")
        .expect("anonymous user exists");
    assert!(anonymous_user.is_anonymous);

    let mut tx = db.pool.begin().await.expect("begin tx");
    let linked = link_identity_to_anonymous_user_in_tx(
        &mut tx,
        &user_id,
        "auth_identity_password_link".to_owned(),
        "password",
        "anon@example.com",
        now,
    )
    .await
    .expect("link password identity");
    tx.commit().await.expect("commit link");

    assert_eq!(linked.user_id, user_id);
    let permanent_user = repo
        .find_by_id(&user_id)
        .await
        .expect("find linked user")
        .expect("linked user exists");
    assert!(!permanent_user.is_anonymous);

    let providers = sqlx::query_scalar::<_, String>(
        r#"
        select provider
        from auth.identities
        where user_id = $1
        order by provider
        "#,
    )
    .bind(&user_id.0)
    .fetch_all(&db.pool)
    .await
    .expect("identity providers");
    assert_eq!(providers, vec!["anonymous", "password"]);

    db.cleanup().await;
}
