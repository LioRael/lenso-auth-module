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
pub struct AuthenticateRequestCredential {
    pub scheme: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub value: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct AuthenticateRequest {
    pub credential: Nullable<AuthenticateRequestCredential>,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticateResponseKind {
    Absent,
    Authenticated,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct AuthenticateResponseAssertion {
    pub issuer: String,
    pub subject: String,
    pub actor_kind: String,
    pub assurance: String,
    pub audience: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")]
    pub claims: Option<std::collections::BTreeMap<String, serde_json::Value>>,
    #[schemars(extend("format" = "date-time"))]
    pub issued_at: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub parent_provenance: Option<String>,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub proof: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct AuthenticateResponse {
    pub kind: AuthenticateResponseKind,
    pub assertion: Nullable<AuthenticateResponseAssertion>,
}

#[derive(lenso::DomainError)]
pub enum AuthenticateError {
    Invalid,
    Expired,
    Revoked,
    Unsupported,
}

#[lenso::capability(
    id = "lenso.auth",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = false
)]
pub trait Auth {
    async fn authenticate(
        &self,
        context: lenso::Ctx<'_>,
        request: AuthenticateRequest,
    ) -> Result<AuthenticateResponse, AuthenticateError>;
}
