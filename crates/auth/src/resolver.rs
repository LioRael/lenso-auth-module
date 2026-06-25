use chrono::{DateTime, Utc};
use platform_core::{ActorContext, ActorResolutionRequest, ActorResolver, AppResult, DbPool};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

pub const SESSION_COOKIE_NAME: &str = "lenso_session";

#[derive(Debug, Clone)]
pub struct AuthActorResolver {
    pool: DbPool,
    fallback: Arc<dyn ActorResolver>,
    session_cache: Option<Arc<dyn SessionCache>>,
    user_scopes: BTreeMap<String, Vec<String>>,
}

impl AuthActorResolver {
    #[must_use]
    pub fn new(pool: DbPool, fallback: Arc<dyn ActorResolver>) -> Self {
        Self {
            pool,
            fallback,
            session_cache: None,
            user_scopes: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn new_with_session_cache(
        pool: DbPool,
        fallback: Arc<dyn ActorResolver>,
        session_cache: Option<Arc<dyn SessionCache>>,
    ) -> Self {
        Self {
            pool,
            fallback,
            session_cache,
            user_scopes: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_user_scopes(mut self, user_scopes: BTreeMap<String, Vec<String>>) -> Self {
        self.user_scopes = user_scopes;
        self
    }

    async fn resolve_session_token(&self, token: &str) -> AppResult<Option<String>> {
        let token_hash = session_token_hash(token);
        if let Some(cache) = &self.session_cache {
            match cache.get(&token_hash).await {
                Ok(Some(session)) if session.expires_at > Utc::now() => {
                    return Ok(Some(session.user_id));
                }
                Ok(Some(_)) => {
                    if let Err(error) = cache.delete(&token_hash).await {
                        tracing::warn!(error = ?error, "failed to delete expired auth session cache");
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(error = ?error, "failed to read auth session cache");
                }
            }
        }

        let row = sqlx::query_as::<_, (String, DateTime<Utc>)>(
            r#"
            select users.id, sessions.expires_at
            from auth.sessions sessions
            join auth.users users on users.id = sessions.user_id
            where sessions.token_hash = $1
              and sessions.expires_at > now()
              and sessions.revoked_at is null
              and (users.disabled_at is null or users.disabled_until <= now())
            limit 1
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|source| {
            platform_core::AppError::new(
                platform_core::ErrorCode::Internal,
                "Failed to resolve auth session",
            )
            .with_source(source)
        })?;

        if let Some((user_id, expires_at)) = row {
            if let Some(cache) = &self.session_cache {
                let session = CachedSession {
                    user_id: user_id.clone(),
                    expires_at,
                };
                if let Err(error) = cache.put(&token_hash, session).await {
                    tracing::warn!(error = ?error, "failed to write auth session cache");
                }
            }
            return Ok(Some(user_id));
        }

        Ok(None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedSession {
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
}

#[async_trait::async_trait]
pub trait SessionCache: std::fmt::Debug + Send + Sync {
    async fn get(&self, token_hash: &str) -> AppResult<Option<CachedSession>>;
    async fn put(&self, token_hash: &str, session: CachedSession) -> AppResult<()>;
    async fn delete(&self, token_hash: &str) -> AppResult<()>;
}

#[async_trait::async_trait]
impl ActorResolver for AuthActorResolver {
    async fn resolve_actor(&self, request: ActorResolutionRequest) -> ActorContext {
        let tokens = session_tokens(&request);
        for token in tokens {
            match self.resolve_session_token(&token).await {
                Ok(Some(user_id)) => {
                    let scopes = self.user_scopes.get(&user_id).cloned().unwrap_or_default();
                    return ActorContext::User { user_id, scopes };
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(error = ?error, "failed to resolve auth session");
                }
            }
        }

        self.fallback.resolve_actor(request).await
    }
}

pub fn session_token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut encoded = String::with_capacity("sha256:".len() + digest.len() * 2);
    encoded.push_str("sha256:");
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

pub fn first_session_token(request: &ActorResolutionRequest) -> Option<String> {
    session_tokens(request).into_iter().next()
}

fn session_tokens(request: &ActorResolutionRequest) -> Vec<String> {
    let mut tokens = Vec::new();
    if let Some(token) = request
        .authorization
        .as_deref()
        .and_then(bearer_token)
        .map(ToOwned::to_owned)
    {
        tokens.push(token);
    }
    if let Some(token) = request.cookie.as_deref().and_then(session_cookie) {
        tokens.push(token);
    }
    tokens
}

fn bearer_token(header: &str) -> Option<&str> {
    header
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .filter(|token| !token.starts_with("dev-user:") && !token.starts_with("dev-service:"))
}

fn session_cookie(header: &str) -> Option<String> {
    header.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == SESSION_COOKIE_NAME)
            .then(|| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[test]
    fn session_token_hash_is_sha256_hex() {
        assert_eq!(
            session_token_hash("session-secret"),
            "sha256:135fa7d67146ca540f17e51e101d45de5b1edde8ea8a13f9c7b93b71aa21f8a4"
        );
    }

    #[test]
    fn extracts_bearer_and_cookie_session_tokens() {
        let request = ActorResolutionRequest {
            authorization: Some("Bearer bearer-token".to_owned()),
            cookie: Some("theme=dark; lenso_session=cookie-token".to_owned()),
        };

        assert_eq!(
            session_tokens(&request),
            vec!["bearer-token".to_owned(), "cookie-token".to_owned()]
        );
    }

    #[test]
    fn leaves_dev_bearer_tokens_for_fallback_resolver() {
        let request = ActorResolutionRequest {
            authorization: Some("Bearer dev-user:user_123".to_owned()),
            cookie: None,
        };

        assert!(session_tokens(&request).is_empty());
    }

    #[tokio::test]
    async fn cache_hit_resolves_user_without_database() {
        let token_hash = session_token_hash("cached-token");
        let cache = Arc::new(FakeSessionCache::new([(
            token_hash,
            CachedSession {
                user_id: "usr_cached".to_owned(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        )]));
        let resolver = AuthActorResolver::new_with_session_cache(
            DbPool::connect_lazy("postgres://localhost/unused").expect("lazy pool"),
            Arc::new(AnonymousResolver),
            Some(cache.clone()),
        );

        let actor = resolver
            .resolve_actor(ActorResolutionRequest {
                authorization: Some("Bearer cached-token".to_owned()),
                cookie: None,
            })
            .await;

        match actor {
            ActorContext::User { user_id, scopes } => {
                assert_eq!(user_id, "usr_cached");
                assert!(scopes.is_empty());
            }
            other => panic!("expected cached user actor, got {other:?}"),
        }
        assert_eq!(*cache.gets.lock().expect("gets"), 1);
    }

    #[tokio::test]
    async fn configured_user_scopes_are_attached_to_session_users() {
        let token_hash = session_token_hash("admin-token");
        let cache = Arc::new(FakeSessionCache::new([(
            token_hash,
            CachedSession {
                user_id: "usr_admin".to_owned(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        )]));
        let resolver = AuthActorResolver::new_with_session_cache(
            DbPool::connect_lazy("postgres://localhost/unused").expect("lazy pool"),
            Arc::new(AnonymousResolver),
            Some(cache),
        )
        .with_user_scopes(BTreeMap::from([(
            "usr_admin".to_owned(),
            vec!["console.admin".to_owned(), "auth.users.read".to_owned()],
        )]));

        let actor = resolver
            .resolve_actor(ActorResolutionRequest {
                authorization: Some("Bearer admin-token".to_owned()),
                cookie: None,
            })
            .await;

        match actor {
            ActorContext::User { user_id, scopes } => {
                assert_eq!(user_id, "usr_admin");
                assert_eq!(scopes, vec!["console.admin", "auth.users.read"]);
            }
            other => panic!("expected configured user actor, got {other:?}"),
        }
    }

    #[derive(Debug)]
    struct AnonymousResolver;

    #[async_trait::async_trait]
    impl ActorResolver for AnonymousResolver {
        async fn resolve_actor(&self, _request: ActorResolutionRequest) -> ActorContext {
            ActorContext::Anonymous
        }
    }

    #[derive(Debug)]
    struct FakeSessionCache {
        values: Mutex<HashMap<String, CachedSession>>,
        gets: Mutex<usize>,
    }

    impl FakeSessionCache {
        fn new(entries: impl IntoIterator<Item = (String, CachedSession)>) -> Self {
            Self {
                values: Mutex::new(entries.into_iter().collect()),
                gets: Mutex::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl SessionCache for FakeSessionCache {
        async fn get(&self, token_hash: &str) -> AppResult<Option<CachedSession>> {
            *self.gets.lock().expect("gets") += 1;
            Ok(self.values.lock().expect("values").get(token_hash).cloned())
        }

        async fn put(&self, token_hash: &str, session: CachedSession) -> AppResult<()> {
            self.values
                .lock()
                .expect("values")
                .insert(token_hash.to_owned(), session);
            Ok(())
        }

        async fn delete(&self, token_hash: &str) -> AppResult<()> {
            self.values.lock().expect("values").remove(token_hash);
            Ok(())
        }
    }
}
