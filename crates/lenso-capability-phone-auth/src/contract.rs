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
#[serde(rename_all = "snake_case")]
pub enum StartOtpRequestPurpose {
    Login,
    Register,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct StartOtpRequest {
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub phone: String,
    pub purpose: StartOtpRequestPurpose,
    pub client_ip: Nullable<String>,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct StartOtpResponse {
    pub challenge_id: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
    #[schemars(extend("format" = "date-time"))]
    pub resend_after: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub debug_code: Nullable<String>,
}

#[derive(lenso::DomainError)]
pub enum StartOtpError {
    InvalidPhone,
    InvalidPurpose,
    RateLimited,
    ResendTooSoon,
    DeliveryRejected,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct VerifyOtpRequest {
    pub challenge_id: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub code: String,
    pub device_id: Nullable<String>,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct SessionResponse {
    pub subject: String,
    pub session_id: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub credential: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
    pub masked_phone: String,
}

#[derive(lenso::DomainError)]
pub enum VerifyOtpError {
    InvalidChallenge,
    InvalidCode,
    Expired,
    TooManyAttempts,
    Disabled,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct SetPasswordRequest {
    pub subject: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub password: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct SetPasswordResponse {
    pub updated: bool,
}

#[derive(lenso::DomainError)]
pub enum SetPasswordError {
    Forbidden,
    InvalidSubject,
    WeakPassword,
    NotFound,
    Disabled,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PasswordLoginRequest {
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub phone: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub password: String,
    pub device_id: Nullable<String>,
}

#[derive(lenso::DomainError)]
pub enum PasswordLoginError {
    InvalidPhone,
    InvalidCredentials,
    RateLimited,
    Disabled,
}

#[lenso::capability(
    id = "lenso.auth.phone",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait Phone {
    async fn start_otp(
        &self,
        context: lenso::Ctx<'_>,
        request: StartOtpRequest,
    ) -> Result<StartOtpResponse, StartOtpError>;
    async fn verify_otp(
        &self,
        context: lenso::Ctx<'_>,
        request: VerifyOtpRequest,
    ) -> Result<SessionResponse, VerifyOtpError>;
    async fn set_password(
        &self,
        context: lenso::Ctx<'_>,
        request: SetPasswordRequest,
    ) -> Result<SetPasswordResponse, SetPasswordError>;
    async fn password_login(
        &self,
        context: lenso::Ctx<'_>,
        request: PasswordLoginRequest,
    ) -> Result<SessionResponse, PasswordLoginError>;
}
