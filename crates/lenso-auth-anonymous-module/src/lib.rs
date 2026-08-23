//! Anonymous authentication over the shared Directory and Credential Issuer roles.

use std::{cell::RefCell, collections::BTreeMap, fmt, rc::Rc};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lenso_capability_anonymous_auth::{
    Anonymous, AnonymousEndpoint, AnonymousProvider, SignInError, SignInRequest, SignInResponse,
};
use lenso_capability_credential_issuer::{
    CredentialIssuerClient, CredentialIssuerIssueInvocationError, IssueError, IssueRequest,
};
use lenso_capability_identity_directory::{
    DirectoryClient, DirectoryEnsureIdentityInvocationError, EnsureIdentityError,
    EnsureIdentityRequest,
};
use lenso_kernel::{
    ActivateContext, DeactivateContext, InvocationContext, ModuleFuture, ModuleLifecycle,
    NativeRequestEndpoint, NativeRequestFuture, RuntimeFailure,
};
use lenso_native_adapter::{NativeModuleFactory, NativeModuleFactoryContext, NativeModuleInstance};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

pub const PACKAGE_ID: &str = "lenso.auth.anonymous";
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Debug, Default)]
pub struct AnonymousAuthFactory;
impl NativeModuleFactory for AnonymousAuthFactory {
    fn package_id(&self) -> &'static str {
        PACKAGE_ID
    }
    fn package_version(&self) -> &'static str {
        PACKAGE_VERSION
    }
    fn instantiate(
        &self,
        context: NativeModuleFactoryContext<'_>,
    ) -> Result<NativeModuleInstance, RuntimeFailure> {
        let config: AnonymousAuthConfig =
            serde_json::from_str(context.configuration()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?;
        AnonymousAuthConfig::new(config.audience.clone(), config.session_ttl_seconds)?;
        let active = Rc::new(RefCell::new(None));
        let endpoint = Rc::new(AnonymousEndpoint::new(AnonymousAuthProvider {
            active: active.clone(),
        })) as Rc<dyn NativeRequestEndpoint>;
        Ok(NativeModuleInstance::with_lifecycle(
            vec![endpoint],
            AnonymousLifecycle { config, active },
        ))
    }
}

struct Active {
    directory: DirectoryClient,
    issuer: CredentialIssuerClient,
    config: AnonymousAuthConfig,
}
impl fmt::Debug for Active {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Active").finish_non_exhaustive()
    }
}
#[derive(Clone)]
struct AnonymousAuthProvider {
    active: Rc<RefCell<Option<Rc<Active>>>>,
}
impl fmt::Debug for AnonymousAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnonymousAuthProvider")
            .field("active", &self.active.borrow().is_some())
            .finish()
    }
}

impl AnonymousProvider for AnonymousAuthProvider {
    fn sign_in(
        &self,
        context: InvocationContext,
        request: SignInRequest,
    ) -> NativeRequestFuture<Anonymous> {
        let active = self.active.borrow().clone();
        Box::pin(async move {
            let active = active.ok_or(RuntimeFailure::ModuleFailure {
                detail: "Anonymous Auth is not active".to_owned(),
            })?;
            let external_subject = match request.device_id {
                Some(value) if valid_device(&value) => format!("device:{value}"),
                Some(_) => return Ok(Err(SignInError::InvalidDevice)),
                None => random_external()?,
            };
            let identity = active
                .directory
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
                + Duration::seconds(
                    i64::try_from(active.config.session_ttl_seconds).expect("validated"),
                ))
            .format(&Rfc3339)
            .map_err(|error| RuntimeFailure::ModuleFailure {
                detail: error.to_string(),
            })?;
            let issued = active
                .issuer
                .issue_with_context(
                    context,
                    IssueRequest {
                        subject: identity.subject.clone(),
                        actor_kind: "anonymous".to_owned(),
                        assurance: "anonymous".to_owned(),
                        audience: active.config.audience.clone(),
                        claims: BTreeMap::default(),
                        expires_at,
                    },
                )
                .await;
            match issued {
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

#[derive(Debug)]
struct AnonymousLifecycle {
    config: AnonymousAuthConfig,
    active: Rc<RefCell<Option<Rc<Active>>>>,
}
impl ModuleLifecycle for AnonymousLifecycle {
    fn activate(&self, context: ActivateContext) -> ModuleFuture {
        let dependencies = context.dependencies().clone();
        let active = self.active.clone();
        let config = self.config.clone();
        Box::pin(async move {
            active.replace(Some(Rc::new(Active {
                directory: DirectoryClient::from_dependencies(&dependencies)?,
                issuer: CredentialIssuerClient::from_dependencies(&dependencies)?,
                config,
            })));
            Ok(())
        })
    }
    fn deactivate(&self, _context: DeactivateContext) -> ModuleFuture {
        self.active.borrow_mut().take();
        Box::pin(futures::future::ready(Ok(())))
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
