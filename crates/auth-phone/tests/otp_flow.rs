use auth_phone::config::AuthPhoneConfig;
use auth_phone::migrations::AUTH_PHONE_MIGRATIONS;
use auth_phone::otp::hash_otp_code;
use auth_phone::repositories::{PhoneAuthRepository, PhoneOtpPurpose, StartOtpInput};
use chrono::{Duration, Utc};
use platform_core::{ClientRequestMetadata, Migration, PLATFORM_MIGRATIONS, apply_migrations};
use platform_testing::TestDatabase;
use sqlx::PgPool;

fn migrations() -> Vec<Migration> {
    PLATFORM_MIGRATIONS
        .iter()
        .chain(auth::migrations::AUTH_MIGRATIONS)
        .chain(AUTH_PHONE_MIGRATIONS)
        .copied()
        .collect()
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

fn assert_foreign_key_violation(error: &sqlx::Error) {
    let database_error = error
        .as_database_error()
        .expect("database error details should exist");
    assert_eq!(database_error.code().as_deref(), Some("23503"));
}
