//! Password authentication as a removable Module over Directory and Credential Issuer contracts.

mod operator;
mod schema;
mod storage;

use std::{cell::RefCell, collections::BTreeMap, fmt, rc::Rc, time::Duration as StdDuration};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use lenso_capability_credential_issuer::{
    CredentialIssuerClient, CredentialIssuerIssueInvocationError, IssueError, IssueRequest,
};
use lenso_capability_identity_directory::{
    DirectoryClient, DirectoryEnsureIdentityInvocationError, EnsureIdentityError,
    EnsureIdentityRequest,
};
use lenso_capability_password_auth::{
    LoginError, LoginRequest, LoginResponse, PasswordEndpoint, PasswordLogin, PasswordProvider,
    PasswordRegister, RegisterError, RegisterRequest, RegisterResponse,
};
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{
    ActivateContext, DeactivateContext, InvocationContext, ModuleFuture, ModuleLifecycle,
    NativeRequestEndpoint, NativeRequestFuture, PrepareContext, RuntimeFailure,
};
use lenso_native_adapter::{NativeModuleFactoryContext, NativeModuleInstance};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::schema::schema_plan;

pub use operator::{PasswordAuthOperator, PasswordOperatorError};

const DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordAuthConfig {
    schema: String,
    database_url_secret: String,
    audience: Vec<String>,
    session_ttl_seconds: u64,
    max_failures: u32,
    failure_window_seconds: u64,
}

impl PasswordAuthConfig {
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        audience: Vec<String>,
        session_ttl_seconds: u64,
        max_failures: u32,
        failure_window_seconds: u64,
    ) -> Result<Self, PasswordConfigError> {
        let value = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            audience,
            session_ttl_seconds,
            max_failures,
            failure_window_seconds,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), PasswordConfigError> {
        schema_plan(self.schema.clone()).map_err(|_| PasswordConfigError::InvalidSchema)?;
        if self.database_url_secret.is_empty() || self.database_url_secret.len() > 256 {
            return Err(PasswordConfigError::InvalidSecretReference);
        }
        if self.audience.is_empty() || self.audience.iter().any(|value| !valid_name(value)) {
            return Err(PasswordConfigError::InvalidAudience);
        }
        if self.session_ttl_seconds == 0 || self.session_ttl_seconds > 2_592_000 {
            return Err(PasswordConfigError::InvalidSessionTtl);
        }
        if self.max_failures == 0
            || self.max_failures > 100
            || self.failure_window_seconds == 0
            || self.failure_window_seconds > 86_400
        {
            return Err(PasswordConfigError::InvalidRateLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PasswordConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("invalid database secret reference")]
    InvalidSecretReference,
    #[error("at least one valid audience is required")]
    InvalidAudience,
    #[error("session TTL must be between 1 and 2592000 seconds")]
    InvalidSessionTtl,
    #[error("invalid login rate limit")]
    InvalidRateLimit,
}

#[lenso::module]
fn instantiate_auth_module(
    context: NativeModuleFactoryContext<'_>,
) -> Result<NativeModuleInstance, RuntimeFailure> {
    let config: PasswordAuthConfig =
        serde_json::from_str(context.configuration()).map_err(|error| {
            RuntimeFailure::InvalidResolvedPlan {
                detail: format!("Password Auth configuration is invalid: {error}"),
            }
        })?;
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: error.to_string(),
        })?;
    let postgres = Rc::new(RefCell::new(None));
    let active = Rc::new(RefCell::new(None));
    let endpoint = Rc::new(PasswordEndpoint::new(PasswordAuthProvider {
        active: active.clone(),
    })) as Rc<dyn NativeRequestEndpoint>;
    Ok(NativeModuleInstance::with_lifecycle(
        vec![endpoint],
        PasswordLifecycle {
            config,
            postgres,
            active,
        },
    ))
}

struct ActivePassword {
    postgres: OwnedPostgres,
    directory: DirectoryClient,
    issuer: CredentialIssuerClient,
    config: PasswordAuthConfig,
}
impl fmt::Debug for ActivePassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActivePassword")
            .field("schema", &self.postgres.schema())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct PasswordAuthProvider {
    active: Rc<RefCell<Option<Rc<ActivePassword>>>>,
}
impl fmt::Debug for PasswordAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordAuthProvider")
            .field("active", &self.active.borrow().is_some())
            .finish()
    }
}
impl PasswordAuthProvider {
    fn active(&self) -> Result<Rc<ActivePassword>, RuntimeFailure> {
        self.active
            .borrow()
            .clone()
            .ok_or(RuntimeFailure::ModuleFailure {
                detail: "Password Auth is not active".to_owned(),
            })
    }
}

impl PasswordProvider for PasswordAuthProvider {
    fn register(
        &self,
        context: InvocationContext,
        request: RegisterRequest,
    ) -> NativeRequestFuture<PasswordRegister> {
        let active = self.active();
        Box::pin(async move {
            let active = active?;
            let identifier =
                normalize_identifier(&request.identifier).ok_or(RegisterError::InvalidIdentifier);
            let identifier = match identifier {
                Ok(value) => value,
                Err(error) => return Ok(Err(error)),
            };
            if !valid_password(&request.password) {
                return Ok(Err(RegisterError::WeakPassword));
            }
            let hash = hash_password(&request.password).map_err(runtime)?;
            let identity = active
                .directory
                .ensure_identity_with_context(
                    context.clone(),
                    EnsureIdentityRequest {
                        provider: "password".to_owned(),
                        external_subject: identifier.clone(),
                    },
                )
                .await;
            let identity = match identity {
                Ok(value) => value,
                Err(DirectoryEnsureIdentityInvocationError::Domain(
                    EnsureIdentityError::Disabled,
                )) => return Ok(Err(RegisterError::Disabled)),
                Err(DirectoryEnsureIdentityInvocationError::Domain(_)) => {
                    return Ok(Err(RegisterError::InvalidIdentifier));
                }
                Err(DirectoryEnsureIdentityInvocationError::Runtime(error)) => return Err(error),
            };
            if !storage::insert_credential(&active.postgres, &identifier, &identity.subject, &hash)
                .await
                .map_err(runtime)?
            {
                return Ok(Err(RegisterError::IdentifierTaken));
            }
            let issued = issue(&active, context, &identity.subject).await;
            match issued {
                Ok(value) => Ok(Ok(RegisterResponse {
                    subject: identity.subject,
                    credential: value.credential,
                    session_id: value.session_id,
                    expires_at: value.expires_at,
                })),
                Err(IssueCallError::Disabled) => Ok(Err(RegisterError::Disabled)),
                Err(IssueCallError::Runtime(error)) => Err(error),
            }
        })
    }

    fn login(
        &self,
        context: InvocationContext,
        request: LoginRequest,
    ) -> NativeRequestFuture<PasswordLogin> {
        let active = self.active();
        Box::pin(async move {
            let active = active?;
            let Some(identifier) = normalize_identifier(&request.identifier) else {
                return Ok(Err(LoginError::InvalidIdentifier));
            };
            let since = OffsetDateTime::now_utc()
                - Duration::seconds(
                    i64::try_from(active.config.failure_window_seconds).expect("validated"),
                );
            if storage::failure_count(&active.postgres, &identifier, since)
                .await
                .map_err(runtime)?
                >= i64::from(active.config.max_failures)
            {
                return Ok(Err(LoginError::RateLimited));
            }
            let credential = storage::load_credential(&active.postgres, &identifier)
                .await
                .map_err(runtime)?;
            let valid = credential
                .as_ref()
                .is_some_and(|(_, hash)| verify_password(&request.password, hash));
            if !valid {
                storage::record_failure(&active.postgres, &identifier)
                    .await
                    .map_err(runtime)?;
                return Ok(Err(LoginError::InvalidCredentials));
            }
            storage::clear_failures(&active.postgres, &identifier)
                .await
                .map_err(runtime)?;
            let subject = credential.expect("checked").0;
            match issue(&active, context, &subject).await {
                Ok(value) => Ok(Ok(LoginResponse {
                    subject,
                    credential: value.credential,
                    session_id: value.session_id,
                    expires_at: value.expires_at,
                })),
                Err(IssueCallError::Disabled) => Ok(Err(LoginError::Disabled)),
                Err(IssueCallError::Runtime(error)) => Err(error),
            }
        })
    }
}

async fn issue(
    active: &ActivePassword,
    context: InvocationContext,
    subject: &str,
) -> Result<lenso_capability_credential_issuer::IssueResponse, IssueCallError> {
    let expires_at = (OffsetDateTime::now_utc()
        + Duration::seconds(i64::try_from(active.config.session_ttl_seconds).expect("validated")))
    .format(&Rfc3339)
    .map_err(|error| {
        IssueCallError::Runtime(RuntimeFailure::ModuleFailure {
            detail: error.to_string(),
        })
    })?;
    active
        .issuer
        .issue_with_context(
            context,
            IssueRequest {
                subject: subject.to_owned(),
                actor_kind: "user".to_owned(),
                assurance: "password".to_owned(),
                audience: active.config.audience.clone(),
                claims: BTreeMap::default(),
                expires_at,
            },
        )
        .await
        .map_err(|error| match error {
            CredentialIssuerIssueInvocationError::Domain(IssueError::Disabled) => {
                IssueCallError::Disabled
            }
            CredentialIssuerIssueInvocationError::Domain(error) => {
                IssueCallError::Runtime(RuntimeFailure::ModuleFailure {
                    detail: format!("credential issuer rejected password session: {error:?}"),
                })
            }
            CredentialIssuerIssueInvocationError::Runtime(error) => IssueCallError::Runtime(error),
        })
}

enum IssueCallError {
    Disabled,
    Runtime(RuntimeFailure),
}

#[derive(Debug)]
struct PasswordLifecycle {
    config: PasswordAuthConfig,
    postgres: Rc<RefCell<Option<OwnedPostgres>>>,
    active: Rc<RefCell<Option<Rc<ActivePassword>>>>,
}
impl ModuleLifecycle for PasswordLifecycle {
    fn prepare(&self, context: PrepareContext) -> ModuleFuture {
        let config = self.config.clone();
        let state = self.postgres.clone();
        let dependencies = context.dependencies().clone();
        let cancellation = context.cancellation();
        Box::pin(async move {
            let secrets = SecretsClient::from_dependencies(&dependencies)?;
            let invocation =
                dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
            let database_url = secrets
                .resolve_with_context(
                    invocation,
                    ResolveRequest {
                        reference: config.database_url_secret.clone(),
                    },
                )
                .await
                .map(|value| Zeroizing::new(value.value))
                .map_err(|error| match error {
                    SecretsInvocationError::Domain(_) => RuntimeFailure::ModuleFailure {
                        detail: "password database secret was rejected".to_owned(),
                    },
                    SecretsInvocationError::Runtime(error) => error,
                })?;
            let postgres = OwnedPostgres::prepare(
                &database_url,
                schema_plan(config.schema).map_err(|error| {
                    RuntimeFailure::InvalidResolvedPlan {
                        detail: error.to_string(),
                    }
                })?,
            )
            .await
            .map_err(|error| RuntimeFailure::ModuleFailure {
                detail: error.to_string(),
            })?;
            state.replace(Some(postgres));
            Ok(())
        })
    }
    fn activate(&self, context: ActivateContext) -> ModuleFuture {
        let postgres = self.postgres.borrow().clone();
        let active = self.active.clone();
        let config = self.config.clone();
        let dependencies = context.dependencies().clone();
        Box::pin(async move {
            let postgres = postgres.ok_or(RuntimeFailure::ModuleFailure {
                detail: "Password Auth was not prepared".to_owned(),
            })?;
            active.replace(Some(Rc::new(ActivePassword {
                postgres,
                directory: DirectoryClient::from_dependencies(&dependencies)?,
                issuer: CredentialIssuerClient::from_dependencies(&dependencies)?,
                config,
            })));
            Ok(())
        })
    }
    fn deactivate(&self, _context: DeactivateContext) -> ModuleFuture {
        self.active.borrow_mut().take();
        let postgres = self.postgres.borrow_mut().take();
        Box::pin(async move {
            if let Some(postgres) = postgres {
                postgres.pool().close().await;
            }
            Ok(())
        })
    }
}

#[derive(Debug, Error)]
enum PasswordModuleError {
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("password hashing failed")]
    Hash,
    #[error("random source unavailable")]
    Random,
}
fn runtime(error: impl fmt::Display) -> RuntimeFailure {
    RuntimeFailure::ModuleFailure {
        detail: error.to_string(),
    }
}
fn normalize_identifier(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        None
    } else {
        Some(value.to_lowercase())
    }
}
fn valid_password(value: &str) -> bool {
    (8..=1024).contains(&value.len())
}
fn hash_password(value: &str) -> Result<String, PasswordModuleError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| PasswordModuleError::Random)?;
    let salt = SaltString::encode_b64(&bytes).map_err(|_| PasswordModuleError::Hash)?;
    Argon2::default()
        .hash_password(value.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| PasswordModuleError::Hash)
}
fn verify_password(value: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded).is_ok_and(|hash| {
        Argon2::default()
            .verify_password(value.as_bytes(), &hash)
            .is_ok()
    })
}
fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_never_contains_plaintext_and_verifies() {
        let password = "correct horse battery staple";
        let hash = hash_password(password).unwrap();
        assert!(!hash.contains(password));
        assert!(verify_password(password, &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn identifiers_are_canonicalized_before_storage() {
        assert_eq!(
            normalize_identifier(" User@Example.COM "),
            Some("user@example.com".to_owned())
        );
        assert_eq!(normalize_identifier("\n"), None);
    }
}
