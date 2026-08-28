use lenso_postgres_kit::OwnedPostgres;
use sqlx::Row;
use time::OffsetDateTime;

use crate::PasswordPluginError;

pub(crate) async fn insert_credential(
    postgres: &OwnedPostgres,
    identifier: &str,
    subject: &str,
    hash: &str,
) -> Result<bool, PasswordPluginError> {
    let result = sqlx::query("INSERT INTO password_credentials (identifier, subject_id, password_hash) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING")
        .bind(identifier).bind(subject).bind(hash).execute(postgres.pool()).await.map_err(db("store password credential"))?;
    Ok(result.rows_affected() == 1)
}

pub(crate) async fn load_credential(
    postgres: &OwnedPostgres,
    identifier: &str,
) -> Result<Option<(String, String)>, PasswordPluginError> {
    let row = sqlx::query(
        "SELECT subject_id, password_hash FROM password_credentials WHERE identifier = $1",
    )
    .bind(identifier)
    .fetch_optional(postgres.pool())
    .await
    .map_err(db("load password credential"))?;
    row.map(|row| {
        Ok((
            row.try_get("subject_id")
                .map_err(db("decode password subject"))?,
            row.try_get("password_hash")
                .map_err(db("decode password hash"))?,
        ))
    })
    .transpose()
}

pub(crate) async fn failure_count(
    postgres: &OwnedPostgres,
    identifier: &str,
    since: OffsetDateTime,
) -> Result<i64, PasswordPluginError> {
    sqlx::query("DELETE FROM password_login_failures WHERE failed_at < $1")
        .bind(since)
        .execute(postgres.pool())
        .await
        .map_err(db("prune login failures"))?;
    sqlx::query_scalar(
        "SELECT count(*) FROM password_login_failures WHERE identifier = $1 AND failed_at >= $2",
    )
    .bind(identifier)
    .bind(since)
    .fetch_one(postgres.pool())
    .await
    .map_err(db("count login failures"))
}

pub(crate) async fn record_failure(
    postgres: &OwnedPostgres,
    identifier: &str,
) -> Result<(), PasswordPluginError> {
    sqlx::query("INSERT INTO password_login_failures (identifier) VALUES ($1)")
        .bind(identifier)
        .execute(postgres.pool())
        .await
        .map_err(db("record login failure"))?;
    Ok(())
}

pub(crate) async fn clear_failures(
    postgres: &OwnedPostgres,
    identifier: &str,
) -> Result<(), PasswordPluginError> {
    sqlx::query("DELETE FROM password_login_failures WHERE identifier = $1")
        .bind(identifier)
        .execute(postgres.pool())
        .await
        .map_err(db("clear login failures"))?;
    Ok(())
}

fn db(operation: &'static str) -> impl FnOnce(sqlx::Error) -> PasswordPluginError {
    move |source| PasswordPluginError::Database { operation, source }
}
