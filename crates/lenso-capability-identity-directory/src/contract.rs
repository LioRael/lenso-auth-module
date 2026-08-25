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
pub struct EnsureIdentityRequest {
    pub provider: String,
    pub external_subject: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct EnsureIdentityResponse {
    pub subject: String,
    pub created: bool,
}

#[derive(lenso::DomainError)]
pub enum EnsureIdentityError {
    InvalidIdentity,
    Disabled,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ReadStatusRequest {
    pub subject: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadStatusResponseStatus {
    Active,
    Disabled,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ReadStatusResponse {
    pub subject: String,
    pub status: ReadStatusResponseStatus,
}

#[derive(lenso::DomainError)]
pub enum ReadStatusError {
    InvalidSubject,
    NotFound,
}

#[lenso::capability(
    id = "lenso.identity.directory",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait Directory {
    async fn ensure_identity(
        &self,
        context: lenso::Ctx<'_>,
        request: EnsureIdentityRequest,
    ) -> Result<EnsureIdentityResponse, EnsureIdentityError>;
    async fn read_status(
        &self,
        context: lenso::Ctx<'_>,
        request: ReadStatusRequest,
    ) -> Result<ReadStatusResponse, ReadStatusError>;
}
