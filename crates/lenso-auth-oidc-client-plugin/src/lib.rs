//! External `OpenID Connect` authorization-code client over explicit Lenso capabilities.

use hmac::{Hmac, Mac};
use jsonwebtoken::jwk::{
    AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
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
use sha2::Sha256;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    rc::Rc,
    time::Duration as StdDuration,
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use zeroize::Zeroizing;

const DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const CLOCK_SKEW_SECONDS: u64 = 30;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcClientConfig {
    provider: String,
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    client_id: String,
    client_secret_ref: String,
    redirect_uri: String,
    scopes: Vec<String>,
    audience: Vec<String>,
    flow_ttl_seconds: u64,
    session_ttl_seconds: u64,
}

impl OidcClientConfig {
    fn validate(&self) -> Result<(), RuntimeFailure> {
        if !valid_name(&self.provider) {
            return Err(invalid("invalid OIDC provider name"));
        }
        secure_url(&self.issuer, false, true)?;
        secure_url(&self.authorization_endpoint, false, false)?;
        secure_url(&self.token_endpoint, false, false)?;
        secure_url(&self.jwks_uri, false, false)?;
        secure_url(&self.redirect_uri, true, false)?;
        if self.client_id.is_empty()
            || self.client_id.len() > 1024
            || !valid_secret_reference(&self.client_secret_ref)
            || self.scopes.is_empty()
            || self.scopes.len() > 32
            || !self.scopes.iter().any(|scope| scope == "openid")
            || self.scopes.iter().any(|scope| !valid_scope(scope))
            || self.scopes.iter().collect::<BTreeSet<_>>().len() != self.scopes.len()
            || self.audience.is_empty()
            || self.audience.len() > 64
            || self.audience.iter().any(|value| !valid_audience(value))
            || self.audience.iter().collect::<BTreeSet<_>>().len() != self.audience.len()
            || !(30..=900).contains(&self.flow_ttl_seconds)
            || !(1..=2_592_000).contains(&self.session_ttl_seconds)
        {
            return Err(invalid("invalid OIDC client configuration"));
        }
        Ok(())
    }
}

fn validate_config(config: &OidcClientConfig) -> Result<(), RuntimeFailure> {
    config.validate()
}

struct Active {
    config: OidcClientConfig,
    client_secret: Zeroizing<String>,
}

impl fmt::Debug for Active {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Active")
            .field("provider", &self.config.provider)
            .field("issuer", &self.config.issuer)
            .finish_non_exhaustive()
    }
}

#[lenso::plugin(
    lifecycle,
    validate = validate_config,
    configuration_schema = "configuration.schema.json"
)]
#[derive(Clone)]
struct OidcClientPlugin {
    #[config]
    config: OidcClientConfig,
    secrets: Port<secrets::SecretsClient>,
    flow: Port<oauth_flow::OauthFlowClient>,
    http: Port<http_client::ClientClient>,
    directory: Port<directory::DirectoryClient>,
    issuer: Port<credential_issuer::CredentialIssuerClient>,
    active: Rc<RefCell<Option<Rc<Active>>>>,
}

impl fmt::Debug for OidcClientPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcClientPlugin")
            .field("active", &self.active.borrow().is_some())
            .finish_non_exhaustive()
    }
}

#[provides(federated::Federated)]
impl FederatedProvider for OidcClientPlugin {
    fn start(
        &self,
        context: InvocationContext,
        request: StartRequest,
    ) -> NativeRequestFuture<FederatedStart> {
        let active = self.active.borrow().clone();
        let flow = self.flow.clone();
        Box::pin(async move {
            let active = active.ok_or_else(|| failure("OIDC Client is not active"))?;
            if !valid_return(&request.return_to) {
                return Ok(Err(StartError::InvalidReturnTo));
            }
            let expires_at = format_time(
                OffsetDateTime::now_utc()
                    + Duration::seconds(
                        i64::try_from(active.config.flow_ttl_seconds).expect("validated"),
                    ),
            )?;
            let flow = match flow
                .create_with_context(
                    context,
                    CreateRequest {
                        provider: active.config.provider.clone(),
                        return_to: request.return_to,
                        expires_at,
                    },
                )
                .await
            {
                Ok(flow) => flow,
                Err(OauthFlowCreateInvocationError::Domain(_)) => {
                    return Ok(Err(StartError::ProviderUnavailable));
                }
                Err(OauthFlowCreateInvocationError::Runtime(error)) => return Err(error),
            };
            let Some(Some(nonce)) = flow.nonce else {
                return Ok(Err(StartError::ProviderUnavailable));
            };
            if !valid_correlation_value(&flow.state)
                || !valid_correlation_value(&nonce)
                || !valid_pkce_challenge(&flow.code_challenge)
            {
                return Ok(Err(StartError::ProviderUnavailable));
            }
            let mut authorization_url = Url::parse(&active.config.authorization_endpoint)
                .map_err(|_| failure("invalid configured authorization endpoint"))?;
            authorization_url
                .query_pairs_mut()
                .append_pair("response_type", "code")
                .append_pair("client_id", &active.config.client_id)
                .append_pair("redirect_uri", &active.config.redirect_uri)
                .append_pair("scope", &active.config.scopes.join(" "))
                .append_pair("state", &flow.state)
                .append_pair("code_challenge", &flow.code_challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("nonce", &nonce);
            Ok(Ok(StartResponse {
                provider: active.config.provider.clone(),
                authorization_url: authorization_url.into(),
                expires_at: flow.expires_at,
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
        let flow = self.flow.clone();
        let http = self.http.clone();
        let directory = self.directory.clone();
        let issuer = self.issuer.clone();
        Box::pin(async move {
            let active = active.ok_or_else(|| failure("OIDC Client is not active"))?;
            if request.code.is_empty()
                || request.code.len() > 4096
                || request.state.is_empty()
                || request.state.len() > 256
            {
                return Ok(Err(CompleteError::InvalidCallback));
            }
            let flow = match flow
                .consume_with_context(
                    context.clone(),
                    ConsumeRequest {
                        provider: active.config.provider.clone(),
                        state: request.state,
                    },
                )
                .await
            {
                Ok(flow) => flow,
                Err(OauthFlowConsumeInvocationError::Domain(_)) => {
                    return Ok(Err(CompleteError::InvalidState));
                }
                Err(OauthFlowConsumeInvocationError::Runtime(error)) => return Err(error),
            };
            let Some(Some(expected_nonce)) = flow.nonce else {
                return Ok(Err(CompleteError::InvalidState));
            };
            if !valid_correlation_value(&expected_nonce)
                || !valid_pkce_verifier(&flow.code_verifier)
                || !valid_return(&flow.return_to)
            {
                return Ok(Err(CompleteError::InvalidState));
            }
            let id_token =
                match exchange_token(&active, &http, &context, &request.code, &flow.code_verifier)
                    .await
                {
                    Ok(token) => token,
                    Err(ProviderCall::Rejected) => {
                        return Ok(Err(CompleteError::ProviderRejected));
                    }
                    Err(ProviderCall::Runtime(error)) => return Err(error),
                };
            let jwks = match load_jwks(&active, &http, &context).await {
                Ok(jwks) => jwks,
                Err(ProviderCall::Rejected) => {
                    return Ok(Err(CompleteError::ProviderRejected));
                }
                Err(ProviderCall::Runtime(error)) => return Err(error),
            };
            let Ok(subject) = validate_id_token(&active.config, &id_token, &jwks, &expected_nonce)
            else {
                return Ok(Err(CompleteError::ProviderRejected));
            };
            let identity = match directory
                .ensure_identity_with_context(
                    context.clone(),
                    EnsureIdentityRequest {
                        provider: active.config.provider.clone(),
                        external_subject: subject,
                    },
                )
                .await
            {
                Ok(identity) => identity,
                Err(DirectoryEnsureIdentityInvocationError::Domain(
                    EnsureIdentityError::Disabled,
                )) => return Ok(Err(CompleteError::Disabled)),
                Err(DirectoryEnsureIdentityInvocationError::Domain(_)) => {
                    return Ok(Err(CompleteError::UnverifiedIdentity));
                }
                Err(DirectoryEnsureIdentityInvocationError::Runtime(error)) => return Err(error),
            };
            let expires_at = format_time(
                OffsetDateTime::now_utc()
                    + Duration::seconds(
                        i64::try_from(active.config.session_ttl_seconds).expect("validated"),
                    ),
            )?;
            let claims = BTreeMap::from([
                (
                    "provider".to_owned(),
                    Value::String(active.config.provider.clone()),
                ),
                (
                    "oidc_issuer".to_owned(),
                    Value::String(active.config.issuer.clone()),
                ),
            ]);
            match issuer
                .issue_with_context(
                    context,
                    IssueRequest {
                        subject: identity.subject.clone(),
                        actor_kind: "user".to_owned(),
                        assurance: "oidc".to_owned(),
                        audience: active.config.audience.clone(),
                        claims,
                        expires_at,
                    },
                )
                .await
            {
                Ok(credential) => Ok(Ok(CompleteResponse {
                    provider: active.config.provider.clone(),
                    subject: identity.subject,
                    session_id: credential.session_id,
                    credential: credential.credential,
                    expires_at: credential.expires_at,
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
    let value: TokenResponse =
        serde_json::from_slice(&response.body.into_vec()).map_err(|_| ProviderCall::Rejected)?;
    if value.id_token.is_empty() || value.id_token.len() > 65_536 {
        return Err(ProviderCall::Rejected);
    }
    Ok(value.id_token)
}

async fn load_jwks(
    active: &Active,
    http: &HttpClient,
    context: &InvocationContext,
) -> Result<JwkSet, ProviderCall> {
    let response = http
        .send_with_context(
            context.clone(),
            SendRequest {
                method: "GET".to_owned(),
                url: active.config.jwks_uri.clone(),
                headers: vec![SendRequestHeadersItem {
                    name: "accept".to_owned(),
                    value: "application/json".to_owned(),
                }],
                body: Vec::new().into(),
            },
        )
        .await
        .map_err(provider_call)?;
    if !(200..300).contains(&response.status) {
        return Err(ProviderCall::Rejected);
    }
    let jwks: JwkSet =
        serde_json::from_slice(&response.body.into_vec()).map_err(|_| ProviderCall::Rejected)?;
    if jwks.keys.is_empty() || jwks.keys.len() > 128 {
        return Err(ProviderCall::Rejected);
    }
    Ok(jwks)
}

fn validate_id_token(
    config: &OidcClientConfig,
    token: &str,
    jwks: &JwkSet,
    expected_nonce: &str,
) -> Result<String, ()> {
    let header = decode_header(token).map_err(|_| ())?;
    if header.alg != Algorithm::RS256
        || header
            .crit
            .as_ref()
            .is_some_and(|fields| !fields.is_empty())
        || header.jku.is_some()
        || header.jwk.is_some()
        || header.x5u.is_some()
        || header.x5c.is_some()
        || header.cty.is_some()
    {
        return Err(());
    }
    if header.typ.as_deref().is_some_and(|value| value != "JWT") {
        return Err(());
    }
    let kid = header
        .kid
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(())?;
    let mut matching = jwks
        .keys
        .iter()
        .filter(|key| key.common.key_id.as_deref() == Some(kid));
    let key = matching.next().ok_or(())?;
    if matching.next().is_some() || !usable_signing_key(key) {
        return Err(());
    }
    let decoding_key = DecodingKey::from_jwk(key).map_err(|_| ())?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = CLOCK_SKEW_SECONDS;
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.set_issuer(&[&config.issuer]);
    validation.set_audience(&[&config.client_id]);
    let claims = decode::<IdTokenClaims>(token, &decoding_key, &validation)
        .map_err(|_| ())?
        .claims;
    if claims.iss != config.issuer
        || claims.sub.trim().is_empty()
        || claims.sub.len() > 512
        || claims.sub.chars().any(char::is_control)
        || !claims.aud.contains(&config.client_id)
        || !constant_time_equal(&claims.nonce, expected_nonce)
    {
        return Err(());
    }
    if claims
        .azp
        .as_deref()
        .is_some_and(|authorized_party| authorized_party != config.client_id)
        || (claims.aud.len() > 1 && claims.azp.as_deref() != Some(config.client_id.as_str()))
    {
        return Err(());
    }
    let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).map_err(|_| ())?;
    if claims.iat > now.saturating_add(CLOCK_SKEW_SECONDS)
        || claims.exp.saturating_add(CLOCK_SKEW_SECONDS) <= now
    {
        return Err(());
    }
    Ok(claims.sub)
}

fn usable_signing_key(key: &Jwk) -> bool {
    matches!(&key.algorithm, AlgorithmParameters::RSA(_))
        && key
            .common
            .public_key_use
            .as_ref()
            .is_none_or(|value| value == &PublicKeyUse::Signature)
        && key
            .common
            .key_algorithm
            .is_none_or(|value| value == KeyAlgorithm::RS256)
        && key.common.key_operations.as_ref().is_none_or(|operations| {
            operations
                .iter()
                .any(|operation| operation == &KeyOperations::Verify)
        })
}

fn constant_time_equal(actual: &str, expected: &str) -> bool {
    let mut actual_mac = Hmac::<Sha256>::new_from_slice(b"lenso.auth.oidc-client.nonce")
        .expect("fixed HMAC key is valid");
    actual_mac.update(actual.as_bytes());
    let actual_digest = actual_mac.finalize().into_bytes();
    let mut expected_mac = Hmac::<Sha256>::new_from_slice(b"lenso.auth.oidc-client.nonce")
        .expect("fixed HMAC key is valid");
    expected_mac.update(expected.as_bytes());
    expected_mac.verify_slice(&actual_digest).is_ok()
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[derive(Clone, Debug, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: TokenAudience,
    exp: u64,
    iat: u64,
    nonce: String,
    #[serde(default)]
    azp: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum TokenAudience {
    One(String),
    Many(Vec<String>),
}

impl TokenAudience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(values) => values.len(),
        }
    }
}

#[allow(unknown_lints, clippy::unused_async_trait_impl)]
impl Lifecycle for OidcClientPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let config = self.config.clone();
        let invocation = context
            .dependencies()
            .invocation_context_after(DEPENDENCY_TIMEOUT, context.cancellation())?;
        let secret = self
            .secrets
            .resolve_with_context(
                invocation,
                ResolveRequest {
                    reference: config.client_secret_ref.clone(),
                },
            )
            .await
            .map_err(|error| match error {
                SecretsInvocationError::Domain(_) => failure("OIDC client secret was rejected"),
                SecretsInvocationError::Runtime(error) => error,
            })?;
        if secret.value.is_empty() {
            return Err(failure("OIDC client secret is empty"));
        }
        self.active.replace(Some(Rc::new(Active {
            config,
            client_secret: Zeroizing::new(secret.value),
        })));
        Ok(())
    }

    async fn deactivate(&self, _: DeactivateContext) -> Result<(), RuntimeFailure> {
        self.active.borrow_mut().take();
        Ok(())
    }
}

fn secure_url(value: &str, allow_loopback_http: bool, issuer: bool) -> Result<Url, RuntimeFailure> {
    let url = Url::parse(value).map_err(|_| invalid("invalid OIDC URL"))?;
    if value.len() > 2048
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (issuer && url.query().is_some())
    {
        return Err(invalid("invalid OIDC URL"));
    }
    let secure = url.scheme() == "https"
        || (allow_loopback_http
            && url.scheme() == "http"
            && url.host_str().is_some_and(is_loopback_host));
    if !secure {
        return Err(invalid("OIDC URL must use HTTPS or a loopback redirect"));
    }
    Ok(url)
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "[::1]"
        || host == "::1"
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_audience(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@')
        })
}

fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}

fn valid_secret_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= 256
        && !reference.starts_with('/')
        && !reference.ends_with('/')
        && !reference.contains("//")
        && reference
            .split('/')
            .all(|segment| segment != "." && segment != "..")
        && reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}

fn valid_correlation_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_pkce_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_pkce_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn valid_return(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && value.len() <= 2048
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
}

fn format_time(value: OffsetDateTime) -> Result<String, RuntimeFailure> {
    value
        .format(&Rfc3339)
        .map_err(|error| failure(&error.to_string()))
}

fn provider_call(error: ClientInvocationError) -> ProviderCall {
    match error {
        ClientInvocationError::Domain(_) => ProviderCall::Rejected,
        ClientInvocationError::Runtime(error) => ProviderCall::Runtime(error),
    }
}

enum ProviderCall {
    Rejected,
    Runtime(RuntimeFailure),
}

fn invalid(detail: &str) -> RuntimeFailure {
    RuntimeFailure::InvalidResolvedPlan {
        detail: detail.to_owned(),
    }
}

fn failure(detail: &str) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OidcClientConfig {
        OidcClientConfig {
            provider: "work-sso".to_owned(),
            issuer: "https://issuer.example/tenant".to_owned(),
            authorization_endpoint: "https://issuer.example/authorize".to_owned(),
            token_endpoint: "https://issuer.example/token".to_owned(),
            jwks_uri: "https://issuer.example/jwks".to_owned(),
            client_id: "lenso-console".to_owned(),
            client_secret_ref: "oidc/client-secret".to_owned(),
            redirect_uri: "https://console.example/auth/oidc/callback".to_owned(),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            audience: vec!["console.app@1".to_owned()],
            flow_ttl_seconds: 300,
            session_ttl_seconds: 3600,
        }
    }

    #[test]
    fn configuration_requires_openid_and_secure_provider_urls() {
        assert!(config().validate().is_ok());
        let mut missing_openid = config();
        missing_openid.scopes = vec!["profile".to_owned()];
        assert!(missing_openid.validate().is_err());
        let mut insecure = config();
        insecure.token_endpoint = "http://issuer.example/token".to_owned();
        assert!(insecure.validate().is_err());
        let mut loopback_redirect = config();
        loopback_redirect.redirect_uri = "http://127.0.0.1:38421/callback".to_owned();
        assert!(loopback_redirect.validate().is_ok());
    }

    #[test]
    fn callback_targets_are_app_local() {
        assert!(valid_return("/settings/security?connected=work-sso"));
        assert!(!valid_return("https://attacker.example"));
        assert!(!valid_return("//attacker.example"));
        assert!(!valid_return("/\\attacker.example"));
        assert!(!valid_return("/after\r\nlocation:https://attacker.example"));
    }

    #[test]
    fn nonce_comparison_rejects_mismatch() {
        assert!(constant_time_equal("nonce-1", "nonce-1"));
        assert!(!constant_time_equal("nonce-1", "nonce-2"));
    }
}
