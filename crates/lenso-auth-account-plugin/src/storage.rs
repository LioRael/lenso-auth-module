use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use lenso_postgres_kit::OwnedPostgres;
use serde_json::Value;
use sha2::Sha256;
use sqlx::Row;
use time::OffsetDateTime;

use crate::AccountError;

#[derive(Clone, Debug)]
pub(crate) struct StoredSession {
    pub subject: String,
    pub status: String,
    pub actor_kind: String,
    pub assurance: String,
    pub audience: Vec<String>,
    pub claims: BTreeMap<String, Value>,
    pub expires_at: OffsetDateTime,
    pub revoked: bool,
}

pub(crate) async fn ensure_identity(
    postgres: &OwnedPostgres,
    provider: &str,
    external_subject: &str,
    new_subject: &str,
) -> Result<(String, String, bool), AccountError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(db("begin identity"))?;
    let existing = sqlx::query(
        "SELECT b.subject_id, CASE WHEN s.status = 'disabled' AND (s.disabled_until IS NULL OR s.disabled_until > transaction_timestamp()) THEN 'disabled' ELSE 'active' END AS status FROM identity_bindings b JOIN identity_subjects s ON s.subject_id = b.subject_id WHERE b.provider = $1 AND b.external_subject = $2 FOR UPDATE",
    )
    .bind(provider).bind(external_subject).fetch_optional(&mut *transaction).await
    .map_err(db("read identity binding"))?;
    if let Some(row) = existing {
        transaction
            .commit()
            .await
            .map_err(db("commit identity read"))?;
        return Ok((
            row.try_get("subject_id").map_err(db("decode subject"))?,
            row.try_get("status").map_err(db("decode status"))?,
            false,
        ));
    }
    sqlx::query("INSERT INTO identity_subjects (subject_id) VALUES ($1)")
        .bind(new_subject)
        .execute(&mut *transaction)
        .await
        .map_err(db("create subject"))?;
    let inserted = sqlx::query("INSERT INTO identity_bindings (provider, external_subject, subject_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(provider).bind(external_subject).bind(new_subject).execute(&mut *transaction).await.map_err(db("create identity binding"))?;
    if inserted.rows_affected() == 0 {
        transaction
            .rollback()
            .await
            .map_err(db("rollback identity race"))?;
        let row = sqlx::query("SELECT b.subject_id, s.status FROM identity_bindings b JOIN identity_subjects s ON s.subject_id = b.subject_id WHERE b.provider = $1 AND b.external_subject = $2")
            .bind(provider).bind(external_subject).fetch_one(postgres.pool()).await.map_err(db("read raced identity"))?;
        return Ok((
            row.try_get("subject_id").map_err(db("decode subject"))?,
            row.try_get("status").map_err(db("decode status"))?,
            false,
        ));
    }
    transaction.commit().await.map_err(db("commit identity"))?;
    Ok((new_subject.to_owned(), "active".to_owned(), true))
}

pub(crate) async fn subject_status(
    postgres: &OwnedPostgres,
    subject: &str,
) -> Result<Option<String>, AccountError> {
    sqlx::query_scalar("SELECT CASE WHEN status = 'disabled' AND (disabled_until IS NULL OR disabled_until > transaction_timestamp()) THEN 'disabled' ELSE 'active' END FROM identity_subjects WHERE subject_id = $1")
        .bind(subject)
        .fetch_optional(postgres.pool())
        .await
        .map_err(db("read subject status"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_session(
    postgres: &OwnedPostgres,
    session_id: &str,
    digest: &[u8],
    subject: &str,
    actor_kind: &str,
    assurance: &str,
    audience: &[String],
    claims: &BTreeMap<String, Value>,
    expires_at: OffsetDateTime,
) -> Result<(), AccountError> {
    sqlx::query("INSERT INTO auth_sessions (session_id, token_digest, subject_id, actor_kind, assurance, audience, claims, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(session_id).bind(digest).bind(subject).bind(actor_kind).bind(assurance).bind(audience).bind(sqlx::types::Json(claims)).bind(expires_at)
        .execute(postgres.pool()).await.map_err(db("issue session"))?;
    Ok(())
}

pub(crate) async fn revoke_session(
    postgres: &OwnedPostgres,
    session_id: &str,
) -> Result<Option<bool>, AccountError> {
    let exists: Option<bool> = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM auth_sessions WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_optional(postgres.pool())
    .await
    .map_err(db("read session"))?;
    let Some(already_revoked) = exists else {
        return Ok(None);
    };
    if !already_revoked {
        sqlx::query("UPDATE auth_sessions SET revoked_at = transaction_timestamp() WHERE session_id = $1 AND revoked_at IS NULL")
            .bind(session_id).execute(postgres.pool()).await.map_err(db("revoke session"))?;
    }
    Ok(Some(!already_revoked))
}

pub(crate) async fn load_session(
    postgres: &OwnedPostgres,
    digest: &[u8],
) -> Result<Option<StoredSession>, AccountError> {
    let row = sqlx::query("SELECT s.subject_id, i.status, s.actor_kind, s.assurance, s.audience, s.claims, s.expires_at, s.revoked_at IS NOT NULL AS revoked FROM auth_sessions s JOIN identity_subjects i ON i.subject_id = s.subject_id WHERE s.token_digest = $1")
        .bind(digest).fetch_optional(postgres.pool()).await.map_err(db("load session"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let claims: sqlx::types::Json<BTreeMap<String, Value>> =
        row.try_get("claims").map_err(db("decode claims"))?;
    Ok(Some(StoredSession {
        subject: row.try_get("subject_id").map_err(db("decode subject"))?,
        status: row.try_get("status").map_err(db("decode status"))?,
        actor_kind: row.try_get("actor_kind").map_err(db("decode actor kind"))?,
        assurance: row.try_get("assurance").map_err(db("decode assurance"))?,
        audience: row.try_get("audience").map_err(db("decode audience"))?,
        claims: claims.0,
        expires_at: row.try_get("expires_at").map_err(db("decode expiry"))?,
        revoked: row.try_get("revoked").map_err(db("decode revocation"))?,
    }))
}

pub(crate) fn token_digest(pepper: &[u8], token: &str) -> Result<Vec<u8>, AccountError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(pepper).map_err(|_| AccountError::InvalidSecretMaterial)?;
    mac.update(token.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn db(operation: &'static str) -> impl FnOnce(sqlx::Error) -> AccountError {
    move |source| AccountError::Database { operation, source }
}
