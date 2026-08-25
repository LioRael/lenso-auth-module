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
pub struct IssueRequest {
    pub subject: String,
    pub actor_kind: String,
    pub assurance: String,
    pub audience: Vec<String>,
    pub claims: std::collections::BTreeMap<String, serde_json::Value>,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct IssueResponse {
    pub session_id: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub credential: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}

#[derive(lenso::DomainError)]
pub enum IssueError {
    InvalidSubject,
    Disabled,
    InvalidAuthority,
    Expired,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokeRequest {
    pub session_id: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokeResponse {
    pub changed: bool,
}

#[derive(lenso::DomainError)]
pub enum RevokeError {
    InvalidSession,
    NotFound,
}

#[lenso::capability(
    id = "lenso.auth.credential-issuer",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait CredentialIssuer {
    async fn issue(
        &self,
        context: lenso::Ctx<'_>,
        request: IssueRequest,
    ) -> Result<IssueResponse, IssueError>;
    async fn revoke(
        &self,
        context: lenso::Ctx<'_>,
        request: RevokeRequest,
    ) -> Result<RevokeResponse, RevokeError>;
}
