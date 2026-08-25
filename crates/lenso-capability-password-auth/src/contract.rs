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
pub struct RegisterRequest {
    pub identifier: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub password: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RegisterResponse {
    pub subject: String,
    pub session_id: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub credential: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}

#[derive(lenso::DomainError)]
pub enum RegisterError {
    InvalidIdentifier,
    WeakPassword,
    IdentifierTaken,
    Disabled,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct LoginRequest {
    pub identifier: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub password: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct LoginResponse {
    pub subject: String,
    pub session_id: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub credential: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}

#[derive(lenso::DomainError)]
pub enum LoginError {
    InvalidIdentifier,
    InvalidCredentials,
    RateLimited,
    Disabled,
}

#[lenso::capability(
    id = "lenso.auth.password",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait Password {
    async fn register(
        &self,
        context: lenso::Ctx<'_>,
        request: RegisterRequest,
    ) -> Result<RegisterResponse, RegisterError>;
    async fn login(
        &self,
        context: lenso::Ctx<'_>,
        request: LoginRequest,
    ) -> Result<LoginResponse, LoginError>;
}
