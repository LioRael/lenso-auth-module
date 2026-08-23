//! GitHub and Google OAuth login as keyed instances over HTTP Egress.
use lenso_capability_credential_issuer::{
    CredentialIssuerClient, CredentialIssuerIssueInvocationError, IssueError, IssueRequest,
};
use lenso_capability_federated_auth::{
    CompleteError, CompleteRequest, CompleteResponse, FederatedComplete, FederatedEndpoint,
    FederatedProvider, FederatedStart, StartError, StartRequest, StartResponse,
};
use lenso_capability_http_client::{
    ClientClient as HttpClient, ClientInvocationError, SendRequest, SendRequestHeadersItem,
};
use lenso_capability_identity_directory::{
    DirectoryClient, DirectoryEnsureIdentityInvocationError, EnsureIdentityError,
    EnsureIdentityRequest,
};
use lenso_capability_oauth_flow::{
    ConsumeRequest, CreateRequest, OauthFlowClient, OauthFlowConsumeInvocationError,
    OauthFlowCreateInvocationError,
};
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{
    ActivateContext, DeactivateContext, InvocationContext, ModuleFuture, ModuleLifecycle,
    NativeRequestEndpoint, NativeRequestFuture, PrepareContext, RuntimeFailure,
};
use lenso_native_adapter::{NativeModuleFactory, NativeModuleFactoryContext, NativeModuleInstance};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{cell::RefCell, collections::BTreeMap, fmt, rc::Rc, time::Duration as StdDuration};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use zeroize::Zeroizing;
pub const PACKAGE_ID: &str = "lenso.auth.federated";
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
const TIMEOUT: StdDuration = StdDuration::from_secs(10);
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Github,
    Google,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederatedAuthConfig {
    provider: ProviderKind,
    authorization_endpoint: String,
    token_endpoint: String,
    user_endpoint: String,
    client_id: String,
    client_secret_ref: String,
    redirect_uri: String,
    scopes: Vec<String>,
    audience: Vec<String>,
    flow_ttl_seconds: u64,
    session_ttl_seconds: u64,
}
impl FederatedAuthConfig {
    fn validate(&self) -> Result<(), RuntimeFailure> {
        for endpoint in [
            &self.authorization_endpoint,
            &self.token_endpoint,
            &self.user_endpoint,
            &self.redirect_uri,
        ] {
            Url::parse(endpoint).map_err(|_| failure("invalid federated OAuth URL"))?;
        }
        if self.client_id.is_empty()
            || self.client_secret_ref.is_empty()
            || self.scopes.is_empty()
            || self.audience.is_empty()
            || !(30..=900).contains(&self.flow_ttl_seconds)
            || !(1..=2_592_000).contains(&self.session_ttl_seconds)
        {
            return Err(failure("invalid federated OAuth configuration"));
        }
        Ok(())
    }
    fn name(&self) -> &'static str {
        match self.provider {
            ProviderKind::Github => "github",
            ProviderKind::Google => "google",
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct FederatedAuthFactory;
impl NativeModuleFactory for FederatedAuthFactory {
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
        let config: FederatedAuthConfig =
            serde_json::from_str(context.configuration()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?;
        config.validate()?;
        let secret = Rc::new(RefCell::new(None));
        let active = Rc::new(RefCell::new(None));
        let endpoint = Rc::new(FederatedEndpoint::new(Provider {
            active: active.clone(),
        })) as Rc<dyn NativeRequestEndpoint>;
        Ok(NativeModuleInstance::with_lifecycle(
            vec![endpoint],
            Lifecycle {
                config,
                secret,
                active,
            },
        ))
    }
}
struct Active {
    config: FederatedAuthConfig,
    client_secret: Zeroizing<String>,
    flow: OauthFlowClient,
    http: HttpClient,
    directory: DirectoryClient,
    issuer: CredentialIssuerClient,
}
impl fmt::Debug for Active {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Active")
            .field("provider", &self.config.provider)
            .finish_non_exhaustive()
    }
}
#[derive(Clone)]
struct Provider {
    active: Rc<RefCell<Option<Rc<Active>>>>,
}
impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FederatedProvider").finish_non_exhaustive()
    }
}
impl FederatedProvider for Provider {
    fn start(
        &self,
        context: InvocationContext,
        request: StartRequest,
    ) -> NativeRequestFuture<FederatedStart> {
        let active = self.active.borrow().clone();
        Box::pin(async move {
            let active = active.ok_or_else(|| failure("Federated Auth is not active"))?;
            if !valid_return(&request.return_to) {
                return Ok(Err(StartError::InvalidReturnTo));
            }
            let expires_at = (OffsetDateTime::now_utc()
                + Duration::seconds(
                    i64::try_from(active.config.flow_ttl_seconds).expect("validated"),
                ))
            .format(&Rfc3339)
            .map_err(|error| failure(&error.to_string()))?;
            let flow = active
                .flow
                .create_with_context(
                    context,
                    CreateRequest {
                        provider: active.config.name().to_owned(),
                        return_to: request.return_to,
                        expires_at: expires_at.clone(),
                    },
                )
                .await;
            let flow = match flow {
                Ok(value) => value,
                Err(OauthFlowCreateInvocationError::Domain(_)) => {
                    return Ok(Err(StartError::ProviderUnavailable));
                }
                Err(OauthFlowCreateInvocationError::Runtime(error)) => return Err(error),
            };
            let mut url = Url::parse(&active.config.authorization_endpoint)
                .map_err(|_| failure("invalid authorization endpoint"))?;
            {
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("client_id", &active.config.client_id)
                    .append_pair("redirect_uri", &active.config.redirect_uri)
                    .append_pair("response_type", "code")
                    .append_pair("scope", &active.config.scopes.join(" "))
                    .append_pair("state", &flow.state)
                    .append_pair("code_challenge", &flow.code_challenge)
                    .append_pair("code_challenge_method", "S256");
            }
            Ok(Ok(StartResponse {
                provider: active.config.name().to_owned(),
                authorization_url: url.into(),
                expires_at,
            }))
        })
    }
    #[allow(clippy::too_many_lines)]
    fn complete(
        &self,
        context: InvocationContext,
        request: CompleteRequest,
    ) -> NativeRequestFuture<FederatedComplete> {
        let active = self.active.borrow().clone();
        Box::pin(async move {
            let active = active.ok_or_else(|| failure("Federated Auth is not active"))?;
            if request.code.is_empty() || request.code.len() > 4096 {
                return Ok(Err(CompleteError::InvalidCallback));
            }
            let flow = active
                .flow
                .consume_with_context(
                    context.clone(),
                    ConsumeRequest {
                        provider: active.config.name().to_owned(),
                        state: request.state,
                    },
                )
                .await;
            let flow = match flow {
                Ok(value) => value,
                Err(OauthFlowConsumeInvocationError::Domain(_)) => {
                    return Ok(Err(CompleteError::InvalidState));
                }
                Err(OauthFlowConsumeInvocationError::Runtime(error)) => return Err(error),
            };
            let token =
                match exchange_token(&active, &context, &request.code, &flow.code_verifier).await {
                    Ok(value) => value,
                    Err(ProviderCall::Rejected) => {
                        return Ok(Err(CompleteError::ProviderRejected));
                    }
                    Err(ProviderCall::Runtime(error)) => return Err(error),
                };
            let profile = match load_profile(&active, &context, &token).await {
                Ok(value) => value,
                Err(ProviderCall::Rejected) => {
                    return Ok(Err(CompleteError::ProviderRejected));
                }
                Err(ProviderCall::Runtime(error)) => return Err(error),
            };
            let external = profile_subject(&active.config.provider, &profile)
                .ok_or_else(|| failure("OAuth profile lacks a verified identity"))?;
            let identity = active
                .directory
                .ensure_identity_with_context(
                    context.clone(),
                    EnsureIdentityRequest {
                        provider: active.config.name().to_owned(),
                        external_subject: external,
                    },
                )
                .await;
            let identity = match identity {
                Ok(value) => value,
                Err(DirectoryEnsureIdentityInvocationError::Domain(
                    EnsureIdentityError::Disabled,
                )) => return Ok(Err(CompleteError::Disabled)),
                Err(DirectoryEnsureIdentityInvocationError::Domain(_)) => {
                    return Ok(Err(CompleteError::UnverifiedIdentity));
                }
                Err(DirectoryEnsureIdentityInvocationError::Runtime(error)) => return Err(error),
            };
            let expires_at = (OffsetDateTime::now_utc()
                + Duration::seconds(
                    i64::try_from(active.config.session_ttl_seconds).expect("validated"),
                ))
            .format(&Rfc3339)
            .map_err(|error| failure(&error.to_string()))?;
            let mut claims = BTreeMap::new();
            claims.insert(
                "provider".to_owned(),
                Value::String(active.config.name().to_owned()),
            );
            let issued = active
                .issuer
                .issue_with_context(
                    context,
                    IssueRequest {
                        subject: identity.subject.clone(),
                        actor_kind: "user".to_owned(),
                        assurance: "federated".to_owned(),
                        audience: active.config.audience.clone(),
                        claims,
                        expires_at,
                    },
                )
                .await;
            match issued {
                Ok(value) => Ok(Ok(CompleteResponse {
                    provider: active.config.name().to_owned(),
                    subject: identity.subject,
                    session_id: value.session_id,
                    credential: value.credential,
                    expires_at: value.expires_at,
                    return_to: flow.return_to,
                })),
                Err(CredentialIssuerIssueInvocationError::Domain(IssueError::Disabled)) => {
                    Ok(Err(CompleteError::Disabled))
                }
                Err(CredentialIssuerIssueInvocationError::Domain(_)) => {
                    Ok(Err(CompleteError::ProviderRejected))
                }
                Err(CredentialIssuerIssueInvocationError::Runtime(error)) => Err(error),
            }
        })
    }
}
async fn exchange_token(
    active: &Active,
    context: &InvocationContext,
    code: &str,
    verifier: &str,
) -> Result<String, ProviderCall> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("client_id", &active.config.client_id)
        .append_pair("client_secret", &active.client_secret)
        .append_pair("redirect_uri", &active.config.redirect_uri)
        .append_pair("code_verifier", verifier)
        .finish();
    let response = active
        .http
        .send_with_context(
            context.clone(),
            SendRequest {
                method: "POST".to_owned(),
                url: active.config.token_endpoint.clone(),
                headers: vec![
                    SendRequestHeadersItem {
                        name: "content-type".to_owned(),
                        value: "application/x-www-form-urlencoded".to_owned(),
                    },
                    SendRequestHeadersItem {
                        name: "accept".to_owned(),
                        value: "application/json".to_owned(),
                    },
                ],
                body: body.into_bytes().into(),
            },
        )
        .await
        .map_err(provider_call)?;
    if !(200..300).contains(&response.status) {
        return Err(ProviderCall::Rejected);
    }
    let body = response.body.into_vec();
    let value: Value = serde_json::from_slice(&body).map_err(|_| ProviderCall::Rejected)?;
    value
        .get("access_token")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(ProviderCall::Rejected)
}
async fn load_profile(
    active: &Active,
    context: &InvocationContext,
    token: &str,
) -> Result<Value, ProviderCall> {
    let response = active
        .http
        .send_with_context(
            context.clone(),
            SendRequest {
                method: "GET".to_owned(),
                url: active.config.user_endpoint.clone(),
                headers: vec![
                    SendRequestHeadersItem {
                        name: "authorization".to_owned(),
                        value: format!("Bearer {token}"),
                    },
                    SendRequestHeadersItem {
                        name: "accept".to_owned(),
                        value: "application/json".to_owned(),
                    },
                ],
                body: Vec::new().into(),
            },
        )
        .await
        .map_err(provider_call)?;
    if !(200..300).contains(&response.status) {
        return Err(ProviderCall::Rejected);
    }
    let body = response.body.into_vec();
    serde_json::from_slice(&body).map_err(|_| ProviderCall::Rejected)
}
fn profile_subject(kind: &ProviderKind, value: &Value) -> Option<String> {
    match kind {
        ProviderKind::Github => value.get("id").and_then(|v| {
            v.as_i64()
                .map(|id| id.to_string())
                .or_else(|| v.as_str().map(ToOwned::to_owned))
        }),
        ProviderKind::Google => value
            .get("email_verified")
            .and_then(Value::as_bool)
            .filter(|v| *v)
            .and_then(|_| value.get("sub")?.as_str().map(ToOwned::to_owned)),
    }
}
#[derive(Debug)]
struct Lifecycle {
    config: FederatedAuthConfig,
    secret: Rc<RefCell<Option<Zeroizing<String>>>>,
    active: Rc<RefCell<Option<Rc<Active>>>>,
}
impl ModuleLifecycle for Lifecycle {
    fn prepare(&self, context: PrepareContext) -> ModuleFuture {
        let config = self.config.clone();
        let secret = self.secret.clone();
        let deps = context.dependencies().clone();
        let cancel = context.cancellation();
        Box::pin(async move {
            let secrets = SecretsClient::from_dependencies(&deps)?;
            let invocation = deps.invocation_context_after(TIMEOUT, cancel)?;
            let value = secrets
                .resolve_with_context(
                    invocation,
                    ResolveRequest {
                        reference: config.client_secret_ref,
                    },
                )
                .await
                .map_err(|error| match error {
                    SecretsInvocationError::Domain(_) => {
                        failure("OAuth client secret was rejected")
                    }
                    SecretsInvocationError::Runtime(error) => error,
                })?;
            if value.value.is_empty() {
                return Err(failure("OAuth client secret is empty"));
            }
            secret.replace(Some(Zeroizing::new(value.value)));
            Ok(())
        })
    }
    fn activate(&self, context: ActivateContext) -> ModuleFuture {
        let config = self.config.clone();
        let secret = self.secret.borrow_mut().take();
        let active = self.active.clone();
        let deps = context.dependencies().clone();
        Box::pin(async move {
            active.replace(Some(Rc::new(Active {
                config,
                client_secret: secret.ok_or_else(|| failure("Federated Auth was not prepared"))?,
                flow: OauthFlowClient::from_dependencies(&deps)?,
                http: HttpClient::from_dependencies(&deps)?,
                directory: DirectoryClient::from_dependencies(&deps)?,
                issuer: CredentialIssuerClient::from_dependencies(&deps)?,
            })));
            Ok(())
        })
    }
    fn deactivate(&self, _: DeactivateContext) -> ModuleFuture {
        self.active.borrow_mut().take();
        self.secret.borrow_mut().take();
        Box::pin(futures::future::ready(Ok(())))
    }
}
fn valid_return(v: &str) -> bool {
    v.starts_with('/') && !v.starts_with("//") && v.len() <= 2048
}
fn failure(detail: &str) -> RuntimeFailure {
    RuntimeFailure::ModuleFailure {
        detail: detail.to_owned(),
    }
}
enum ProviderCall {
    Rejected,
    Runtime(RuntimeFailure),
}

fn provider_call(error: ClientInvocationError) -> ProviderCall {
    match error {
        ClientInvocationError::Runtime(error) => ProviderCall::Runtime(error),
        ClientInvocationError::Domain(_) => ProviderCall::Rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_targets_are_app_local() {
        assert!(valid_return("/settings/security?connected=github"));
        assert!(!valid_return("https://attacker.example"));
        assert!(!valid_return("//attacker.example"));
    }

    #[test]
    fn google_requires_verified_subject_and_github_uses_stable_id() {
        assert_eq!(
            profile_subject(&ProviderKind::Github, &serde_json::json!({"id": 42})),
            Some("42".to_owned())
        );
        assert_eq!(
            profile_subject(
                &ProviderKind::Google,
                &serde_json::json!({"sub": "google-1", "email_verified": true})
            ),
            Some("google-1".to_owned())
        );
        assert_eq!(
            profile_subject(
                &ProviderKind::Google,
                &serde_json::json!({"sub": "google-1", "email_verified": false})
            ),
            None
        );
    }
}
