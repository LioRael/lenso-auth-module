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
pub struct StartRequest {
    pub return_to: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct StartResponse {
    pub provider: String,
    pub authorization_url: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}

#[derive(lenso::DomainError)]
pub enum StartError {
    InvalidReturnTo,
    ProviderUnavailable,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct CompleteRequest {
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub code: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub state: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct CompleteResponse {
    pub provider: String,
    pub subject: String,
    pub session_id: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub credential: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
    pub return_to: String,
}

#[derive(lenso::DomainError)]
pub enum CompleteError {
    InvalidCallback,
    InvalidState,
    ProviderRejected,
    UnverifiedIdentity,
    Disabled,
}

#[lenso::capability(
    id = "lenso.auth.federated",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait Federated {
    async fn start(
        &self,
        context: lenso::Ctx<'_>,
        request: StartRequest,
    ) -> Result<StartResponse, StartError>;
    async fn complete(
        &self,
        context: lenso::Ctx<'_>,
        request: CompleteRequest,
    ) -> Result<CompleteResponse, CompleteError>;
}
