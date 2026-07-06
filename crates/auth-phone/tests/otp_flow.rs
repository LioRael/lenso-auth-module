use auth_phone::config::AuthPhoneConfig;
use auth_phone::migrations::AUTH_PHONE_MIGRATIONS;
use auth_phone::otp::hash_otp_code;
use auth_phone::repositories::{PhoneAuthRepository, PhoneOtpPurpose, StartOtpInput};
use chrono::{Duration, Utc};
use platform_core::{ClientRequestMetadata, Migration, PLATFORM_MIGRATIONS, apply_migrations};
use platform_testing::TestDatabase;

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

    let config = AuthPhoneConfig::default();
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
