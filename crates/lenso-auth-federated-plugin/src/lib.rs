//! GitHub and Google OAuth login as keyed instances over HTTP Egress.
use lenso::{ActivateContext, DeactivateContext, Lifecycle, Port, provides};
use lenso_capability_credential_issuer as credential_issuer;
use lenso_capability_credential_issuer::{
    CredentialIssuerIssueInvocationError, IssueError, IssueRequest,
};
use lenso_capability_federated_auth as federated;
use lenso_capability_federated_auth::{
    CompleteError, CompleteRequest, CompleteResponse, FederatedComplete, FederatedProvider,
    FederatedStart, StartError, StartRequest, StartResponse,
};
use lenso_capability_http_client as http_client;
use lenso_capability_http_client::{
    ClientClient as HttpClient, ClientInvocationError, SendRequest, SendRequestHeadersItem,
};
use lenso_capability_identity_directory as directory;
use lenso_capability_identity_directory::{
    DirectoryEnsureIdentityInvocationError, EnsureIdentityError, EnsureIdentityRequest,
};
use lenso_capability_oauth_flow as oauth_flow;
use lenso_capability_oauth_flow::{
    ConsumeRequest, CreateRequest, OauthFlowConsumeInvocationError, OauthFlowCreateInvocationError,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsInvocationError};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{cell::RefCell, collections::BTreeMap, fmt, rc::Rc, time::Duration as StdDuration};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use zeroize::Zeroizing;
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
        ] {
            outbound_oauth_url(endpoint)?;
        }
        redirect_oauth_url(&self.redirect_uri)?;
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

fn outbound_oauth_url(value: &str) -> Result<Url, RuntimeFailure> {
    let url = Url::parse(value).map_err(|_| failure("invalid federated OAuth URL"))?;
    if value.len() > 2048
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(failure("invalid federated OAuth URL"));
    }
    let secure = url.scheme() == "https"
        || (url.scheme() == "http" && url.host_str().is_some_and(is_loopback_host));
    if !secure {
        return Err(failure(
            "federated OAuth endpoints must use HTTPS or loopback HTTP",
        ));
    }
    Ok(url)
}

fn redirect_oauth_url(value: &str) -> Result<Url, RuntimeFailure> {
    let url = Url::parse(value).map_err(|_| failure("invalid federated OAuth redirect URL"))?;
    if value.len() > 2048
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(failure("invalid federated OAuth redirect URL"));
    }
    let allowed = match url.scheme() {
        "https" => !url.cannot_be_a_base() && url.host_str().is_some(),
        "http" => !url.cannot_be_a_base() && url.host_str().is_some_and(is_loopback_host),
        scheme => valid_private_redirect_scheme(scheme) && valid_private_redirect_path(&url),
    };
    if !allowed {
        return Err(failure("invalid federated OAuth redirect URL"));
    }
    Ok(url)
}

fn valid_private_redirect_scheme(scheme: &str) -> bool {
    let labels = scheme.split('.').collect::<Vec<_>>();
    labels.len() >= 2
        && labels[0].len() >= 2
        && labels[0].bytes().all(|byte| byte.is_ascii_lowercase())
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn valid_private_redirect_path(url: &Url) -> bool {
    !url.cannot_be_a_base()
        && url.host_str().is_none()
        && url.path().starts_with('/')
        && url.path().len() > 1
        && !url
            .path()
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "[::1]"
        || host == "::1"
}
fn validate_config(config: &FederatedAuthConfig) -> Result<(), RuntimeFailure> {
    config.validate()
}
struct Active {
    config: FederatedAuthConfig,
    client_secret: Zeroizing<String>,
}
impl fmt::Debug for Active {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Active")
            .field("provider", &self.config.provider)
            .finish_non_exhaustive()
    }
}
#[lenso::plugin(
    lifecycle,
    validate = validate_config,
    configuration_schema = "configuration.schema.json"
)]
#[derive(Clone)]
struct FederatedAuthPlugin {
    #[config]
    config: FederatedAuthConfig,
    secrets: Port<secrets::SecretsClient>,
    flow: Port<oauth_flow::OauthFlowClient>,
    http: Port<http_client::ClientClient>,
    directory: Port<directory::DirectoryClient>,
    issuer: Port<credential_issuer::CredentialIssuerClient>,
    active: Rc<RefCell<Option<Rc<Active>>>>,
}
impl fmt::Debug for FederatedAuthPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FederatedProvider").finish_non_exhaustive()
    }
}
#[provides(federated::Federated)]
impl FederatedProvider for FederatedAuthPlugin {
    fn start(
        &self,
        context: InvocationContext,
        request: StartRequest,
    ) -> NativeRequestFuture<FederatedStart> {
        let active = self.active.borrow().clone();
        let flow_client = self.flow.clone();
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
            let flow = flow_client
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
        let flow_client = self.flow.clone();
        let http = self.http.clone();
        let directory = self.directory.clone();
        let issuer = self.issuer.clone();
        Box::pin(async move {
            let active = active.ok_or_else(|| failure("Federated Auth is not active"))?;
            if request.code.is_empty() || request.code.len() > 4096 {
                return Ok(Err(CompleteError::InvalidCallback));
            }
            let flow = flow_client
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
                match exchange_token(&active, &http, &context, &request.code, &flow.code_verifier)
                    .await
                {
                    Ok(value) => value,
                    Err(ProviderCall::Rejected) => {
                        return Ok(Err(CompleteError::ProviderRejected));
                    }
                    Err(ProviderCall::Runtime(error)) => return Err(error),
                };
            let profile = match load_profile(&active, &http, &context, &token).await {
                Ok(value) => value,
                Err(ProviderCall::Rejected) => {
                    return Ok(Err(CompleteError::ProviderRejected));
                }
                Err(ProviderCall::Runtime(error)) => return Err(error),
            };
            let external = profile_subject(&active.config.provider, &profile)
                .ok_or_else(|| failure("OAuth profile lacks a verified identity"))?;
            let identity = directory
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
            let credential = issuer
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
            match credential {
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
    http: &HttpClient,
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
    let response = http
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
    http: &HttpClient,
    context: &InvocationContext,
    token: &str,
) -> Result<Value, ProviderCall> {
    let response = http
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
#[allow(unknown_lints, clippy::unused_async_trait_impl)]
impl Lifecycle for FederatedAuthPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let config = self.config.clone();
        let deps = context.dependencies().clone();
        let cancel = context.cancellation();
        let invocation = deps.invocation_context_after(TIMEOUT, cancel)?;
        let value = self
            .secrets
            .resolve_with_context(
                invocation,
                ResolveRequest {
                    reference: config.client_secret_ref.clone(),
                },
            )
            .await
            .map_err(|error| match error {
                SecretsInvocationError::Domain(_) => failure("OAuth client secret was rejected"),
                SecretsInvocationError::Runtime(error) => error,
            })?;
        if value.value.is_empty() {
            return Err(failure("OAuth client secret is empty"));
        }
        let active = self.active.clone();
        active.replace(Some(Rc::new(Active {
            config,
            client_secret: Zeroizing::new(value.value),
        })));
        Ok(())
    }

    async fn deactivate(&self, _: DeactivateContext) -> Result<(), RuntimeFailure> {
        self.active.borrow_mut().take();
        Ok(())
    }
}
fn valid_return(v: &str) -> bool {
    v.starts_with('/')
        && !v.starts_with("//")
        && v.len() <= 2048
        && !v
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
}
fn failure(detail: &str) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
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

    fn config() -> FederatedAuthConfig {
        FederatedAuthConfig {
            provider: ProviderKind::Github,
            authorization_endpoint: "https://provider.example/authorize".to_owned(),
            token_endpoint: "https://provider.example/token".to_owned(),
            user_endpoint: "https://provider.example/user".to_owned(),
            client_id: "lenso-console".to_owned(),
            client_secret_ref: "oauth/client-secret".to_owned(),
            redirect_uri: "https://console.example/oauth/callback".to_owned(),
            scopes: vec!["profile".to_owned()],
            audience: vec!["console.app@1".to_owned()],
            flow_ttl_seconds: 300,
            session_ttl_seconds: 3600,
        }
    }

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

    #[test]
    fn configuration_rejects_unsafe_outbound_endpoints() {
        assert!(config().validate().is_ok());

        let mut insecure = config();
        insecure.token_endpoint = "http://provider.example/token".to_owned();
        assert!(insecure.validate().is_err());

        let mut userinfo = config();
        userinfo.user_endpoint = "https://user@provider.example/profile".to_owned();
        assert!(userinfo.validate().is_err());

        let mut fragment = config();
        fragment.authorization_endpoint = "https://provider.example/authorize#fragment".to_owned();
        assert!(fragment.validate().is_err());

        let mut loopback = config();
        loopback.token_endpoint = "http://127.0.0.1:38421/token".to_owned();
        loopback.user_endpoint = "http://[::1]:38421/user".to_owned();
        assert!(loopback.validate().is_ok());
    }

    #[test]
    fn redirects_allow_native_schemes_and_only_loopback_http() {
        let mut native = config();
        native.redirect_uri = "com.example.app:/oauth/callback".to_owned();
        assert!(native.validate().is_ok());

        let mut loopback = config();
        loopback.redirect_uri = "http://localhost:38421/oauth/callback".to_owned();
        assert!(loopback.validate().is_ok());

        let mut remote_http = config();
        remote_http.redirect_uri = "http://console.example/oauth/callback".to_owned();
        assert!(remote_http.validate().is_err());

        let mut fragment = config();
        fragment.redirect_uri = "com.example.app:/oauth/callback#fragment".to_owned();
        assert!(fragment.validate().is_err());

        for dangerous in [
            "javascript:alert(1)",
            "data:text/html,callback",
            "file:///tmp/callback",
            "ftp://console.example/callback",
            "custom:callback",
            "com.example.app://authority/callback",
        ] {
            let mut config = config();
            config.redirect_uri = dangerous.to_owned();
            assert!(config.validate().is_err(), "accepted {dangerous}");
        }
    }
}
