//! Anonymous authentication over the shared Directory and Credential Issuer roles.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lenso::{Port, provides};
use lenso_capability_anonymous_auth as anonymous;
use lenso_capability_anonymous_auth::{
    Anonymous, AnonymousProvider, SignInError, SignInRequest, SignInResponse,
};
use lenso_capability_credential_issuer as credential_issuer;
use lenso_capability_credential_issuer::{
    CredentialIssuerIssueInvocationError, IssueError, IssueRequest,
};
use lenso_capability_identity_directory as directory;
use lenso_capability_identity_directory::{
    DirectoryEnsureIdentityInvocationError, EnsureIdentityError, EnsureIdentityRequest,
};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, lenso::ModuleConfig)]
#[serde(deny_unknown_fields)]
pub struct AnonymousAuthConfig {
    audience: Vec<String>,
    session_ttl_seconds: u64,
}
impl AnonymousAuthConfig {
    pub fn new(audience: Vec<String>, session_ttl_seconds: u64) -> Result<Self, RuntimeFailure> {
        if audience.is_empty()
            || audience.iter().any(|value| !valid_name(value))
            || !(1..=604_800).contains(&session_ttl_seconds)
        {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "invalid Anonymous Auth audience or session TTL".to_owned(),
            });
        }
        Ok(Self {
            audience,
            session_ttl_seconds,
        })
    }
}

fn validate_config(config: &AnonymousAuthConfig) -> Result<(), RuntimeFailure> {
    AnonymousAuthConfig::new(config.audience.clone(), config.session_ttl_seconds).map(|_| ())
}

#[lenso::module(validate = validate_config)]
#[derive(Clone, Debug)]
struct AnonymousAuthModule {
    #[config]
    config: AnonymousAuthConfig,
    directory: Port<directory::DirectoryClient>,
    issuer: Port<credential_issuer::CredentialIssuerClient>,
}

#[provides(anonymous::Anonymous)]
impl AnonymousProvider for AnonymousAuthModule {
    fn sign_in(
        &self,
        context: InvocationContext,
        request: SignInRequest,
    ) -> NativeRequestFuture<Anonymous> {
        let directory = self.directory.clone();
        let issuer = self.issuer.clone();
        let config = self.config.clone();
        Box::pin(async move {
            let external_subject = match request.device_id {
                Some(value) if valid_device(&value) => format!("device:{value}"),
                Some(_) => return Ok(Err(SignInError::InvalidDevice)),
                None => random_external()?,
            };
            let identity = directory
                .ensure_identity_with_context(
                    context.clone(),
                    EnsureIdentityRequest {
                        provider: "anonymous".to_owned(),
                        external_subject,
                    },
                )
                .await;
            let identity = match identity {
                Ok(value) => value,
                Err(DirectoryEnsureIdentityInvocationError::Domain(
                    EnsureIdentityError::Disabled,
                )) => return Ok(Err(SignInError::Disabled)),
                Err(DirectoryEnsureIdentityInvocationError::Domain(_)) => {
                    return Ok(Err(SignInError::InvalidDevice));
                }
                Err(DirectoryEnsureIdentityInvocationError::Runtime(error)) => return Err(error),
            };
            let expires_at = (OffsetDateTime::now_utc()
                + Duration::seconds(i64::try_from(config.session_ttl_seconds).expect("validated")))
            .format(&Rfc3339)
            .map_err(|error| RuntimeFailure::ModuleFailure {
                detail: error.to_string(),
            })?;
            let credential = issuer
                .issue_with_context(
                    context,
                    IssueRequest {
                        subject: identity.subject.clone(),
                        actor_kind: "anonymous".to_owned(),
                        assurance: "anonymous".to_owned(),
                        audience: config.audience.clone(),
                        claims: BTreeMap::default(),
                        expires_at,
                    },
                )
                .await;
            match credential {
                Ok(value) => Ok(Ok(SignInResponse {
                    subject: identity.subject,
                    session_id: value.session_id,
                    credential: value.credential,
                    expires_at: value.expires_at,
                    created: identity.created,
                })),
                Err(CredentialIssuerIssueInvocationError::Domain(IssueError::Disabled)) => {
                    Ok(Err(SignInError::Disabled))
                }
                Err(CredentialIssuerIssueInvocationError::Domain(error)) => {
                    Err(RuntimeFailure::ModuleFailure {
                        detail: format!("credential issuer rejected anonymous session: {error:?}"),
                    })
                }
                Err(CredentialIssuerIssueInvocationError::Runtime(error)) => Err(error),
            }
        })
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
fn valid_device(value: &str) -> bool {
    valid_name(value)
}
fn random_external() -> Result<String, RuntimeFailure> {
    let mut bytes = [0_u8; 24];
    getrandom::fill(&mut bytes).map_err(|_| RuntimeFailure::ModuleFailure {
        detail: "random source unavailable".to_owned(),
    })?;
    Ok(format!("ephemeral:{}", URL_SAFE_NO_PAD.encode(bytes)))
}
