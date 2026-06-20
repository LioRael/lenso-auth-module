use crate::resolver::{CachedSession, SessionCache};
use chrono::{DateTime, Utc};
use platform_core::{AppError, AppResult, ErrorCode};
use redis::AsyncCommands;
use std::time::Duration;

const DEFAULT_KEY_PREFIX: &str = "auth:sessions:";

#[derive(Debug, Clone)]
pub struct RedisSessionCache {
    connection: redis::aio::ConnectionManager,
    key_prefix: String,
    max_ttl: Duration,
}

impl RedisSessionCache {
    #[must_use]
    pub fn new(connection: redis::aio::ConnectionManager, max_ttl: Duration) -> Self {
        Self {
            connection,
            key_prefix: DEFAULT_KEY_PREFIX.to_owned(),
            max_ttl,
        }
    }

    pub async fn connect(url: &str, max_ttl: Duration) -> AppResult<Self> {
        let client = redis::Client::open(url).map_err(map_redis_error)?;
        let connection = redis::aio::ConnectionManager::new(client)
            .await
            .map_err(map_redis_error)?;
        Ok(Self::new(connection, max_ttl))
    }

    #[must_use]
    pub fn with_key_prefix(mut self, key_prefix: impl Into<String>) -> Self {
        self.key_prefix = key_prefix.into();
        self
    }

    fn key(&self, token_hash: &str) -> String {
        format!("{}{}", self.key_prefix, token_hash)
    }
}

#[async_trait::async_trait]
impl SessionCache for RedisSessionCache {
    async fn get(&self, token_hash: &str) -> AppResult<Option<CachedSession>> {
        let mut connection = self.connection.clone();
        let value: Option<String> = connection
            .get(self.key(token_hash))
            .await
            .map_err(map_redis_error)?;
        value
            .map(|raw| serde_json::from_str(&raw))
            .transpose()
            .map_err(|source| {
                AppError::new(ErrorCode::Internal, "Invalid cached auth session")
                    .with_source(source)
            })
    }

    async fn put(&self, token_hash: &str, session: CachedSession) -> AppResult<()> {
        let Some(ttl_seconds) = ttl_seconds(session.expires_at, self.max_ttl, Utc::now()) else {
            return Ok(());
        };
        let value = serde_json::to_string(&session).map_err(|source| {
            AppError::new(ErrorCode::Internal, "Failed to encode cached auth session")
                .with_source(source)
        })?;
        let mut connection = self.connection.clone();
        let _: () = connection
            .set_ex(self.key(token_hash), value, ttl_seconds)
            .await
            .map_err(map_redis_error)?;
        Ok(())
    }

    async fn delete(&self, token_hash: &str) -> AppResult<()> {
        let mut connection = self.connection.clone();
        let _: usize = connection
            .del(self.key(token_hash))
            .await
            .map_err(map_redis_error)?;
        Ok(())
    }
}

fn ttl_seconds(expires_at: DateTime<Utc>, max_ttl: Duration, now: DateTime<Utc>) -> Option<u64> {
    let session_ttl = (expires_at - now).to_std().ok()?;
    let ttl = session_ttl.min(max_ttl).as_secs();
    (ttl > 0).then_some(ttl)
}

fn map_redis_error(source: redis::RedisError) -> AppError {
    AppError::new(ErrorCode::ExternalDependency, "Redis operation failed")
        .with_source(source)
        .retryable()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    #[test]
    fn ttl_uses_lower_of_session_and_cache_limits() {
        let now = Utc::now();
        assert_eq!(
            ttl_seconds(
                now + ChronoDuration::seconds(120),
                Duration::from_secs(300),
                now
            ),
            Some(120)
        );
        assert_eq!(
            ttl_seconds(
                now + ChronoDuration::seconds(120),
                Duration::from_secs(30),
                now
            ),
            Some(30)
        );
        assert_eq!(
            ttl_seconds(
                now - ChronoDuration::seconds(1),
                Duration::from_secs(30),
                now
            ),
            None
        );
    }
}
