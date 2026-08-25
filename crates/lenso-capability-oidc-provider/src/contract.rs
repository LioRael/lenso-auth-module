//! Authoritative source for this Auth Capability contract.

use lenso_contract_authoring as lenso;

#[derive(serde::Deserialize)]
pub struct Nullable<T>(Option<T>);

impl<T: lenso::JsonSchema> lenso::JsonSchema for Nullable<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("Nullable_{}", T::schema_name()).into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        format!("Nullable<{}>", T::schema_id()).into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <Option<T> as lenso::JsonSchema>::json_schema(generator)
    }
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct EmptyRequest {}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct MetadataResponse {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    pub scopes_supported: Vec<String>,
}

#[derive(lenso::DomainError)]
pub enum ReadError {
    Disabled,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct JwksResponse {
    pub jwks: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct AuthorizeRequest {
    pub subject: String,
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Nullable<String>,
    pub nonce: Nullable<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct AuthorizeResponse {
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub code: String,
    pub redirect_uri: String,
    pub state: Nullable<String>,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}

#[derive(lenso::DomainError)]
pub enum AuthorizeError {
    Forbidden,
    InvalidRequest,
    InvalidClient,
    InvalidRedirectUri,
    InvalidScope,
    InvalidPkce,
    DisabledSubject,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ExchangeRequest {
    pub grant_type: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub code_verifier: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ExchangeResponse {
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub id_token: String,
    pub scope: String,
    pub session_id: String,
}

#[derive(lenso::DomainError)]
pub enum ExchangeError {
    InvalidRequest,
    InvalidGrant,
    DisabledSubject,
}

#[lenso::capability(
    id = "lenso.auth.oidc-provider",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait OidcProvider {
    async fn metadata(
        &self,
        context: lenso::Ctx<'_>,
        request: EmptyRequest,
    ) -> Result<MetadataResponse, ReadError>;
    async fn jwks(
        &self,
        context: lenso::Ctx<'_>,
        request: EmptyRequest,
    ) -> Result<JwksResponse, ReadError>;
    async fn authorize(
        &self,
        context: lenso::Ctx<'_>,
        request: AuthorizeRequest,
    ) -> Result<AuthorizeResponse, AuthorizeError>;
    async fn exchange(
        &self,
        context: lenso::Ctx<'_>,
        request: ExchangeRequest,
    ) -> Result<ExchangeResponse, ExchangeError>;
}
