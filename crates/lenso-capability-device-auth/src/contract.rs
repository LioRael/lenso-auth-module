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
pub struct ObserveRequest {
    pub subject: String,
    pub device_id: String,
    pub client_ip: Nullable<String>,
    pub user_agent: Nullable<String>,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ObserveResponse {
    pub device_id: String,
    pub created: bool,
    pub trusted: bool,
}

#[derive(lenso::DomainError)]
pub enum ObserveError {
    InvalidDevice,
    InvalidSubject,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListRequest {
    pub subject: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListResponseDevicesItem {
    pub device_id: String,
    pub trusted: bool,
    pub primary: bool,
    pub last_seen_ip: Nullable<String>,
    pub last_seen_user_agent: Nullable<String>,
    #[schemars(extend("format" = "date-time"))]
    pub updated_at: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListResponse {
    pub devices: Vec<ListResponseDevicesItem>,
}

#[derive(lenso::DomainError)]
pub enum ListError {
    InvalidSubject,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct SetTrustRequest {
    pub subject: String,
    pub device_id: String,
    pub trusted: bool,
    pub primary: bool,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct SetTrustResponse {
    pub changed: bool,
}

#[derive(lenso::DomainError)]
pub enum SetTrustError {
    InvalidDevice,
    InvalidSubject,
    NotFound,
}

#[lenso::capability(
    id = "lenso.auth.device",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait Device {
    async fn observe(
        &self,
        context: lenso::Ctx<'_>,
        request: ObserveRequest,
    ) -> Result<ObserveResponse, ObserveError>;
    async fn list(
        &self,
        context: lenso::Ctx<'_>,
        request: ListRequest,
    ) -> Result<ListResponse, ListError>;
    async fn set_trust(
        &self,
        context: lenso::Ctx<'_>,
        request: SetTrustRequest,
    ) -> Result<SetTrustResponse, SetTrustError>;
}
