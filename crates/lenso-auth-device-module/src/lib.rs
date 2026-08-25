//! Durable device observations and trust facts.
mod operator;
mod schema;

use lenso_capability_device_auth::{
    DeviceEndpoint, DeviceList, DeviceObserve, DeviceProvider, DeviceSetTrust, ListError,
    ListRequest, ListResponse, ListResponseDevicesItem, ObserveError, ObserveRequest,
    ObserveResponse, SetTrustError, SetTrustRequest, SetTrustResponse,
};
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{
    DeactivateContext, InvocationContext, ModuleFuture, ModuleLifecycle, NativeRequestEndpoint,
    NativeRequestFuture, PrepareContext, RuntimeFailure,
};
use lenso_native_adapter::{NativeModuleFactoryContext, NativeModuleInstance};
use lenso_postgres_kit::OwnedPostgres;
pub use operator::{DeviceAuthOperator, DeviceOperatorError};
use schema::schema_plan;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::{cell::RefCell, fmt, rc::Rc, time::Duration as StdDuration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

const DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthConfig {
    schema: String,
    database_url_secret: String,
}
impl DeviceAuthConfig {
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
    ) -> Result<Self, RuntimeFailure> {
        let value = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
        };
        schema_plan(value.schema.clone()).map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: error.to_string(),
        })?;
        if value.database_url_secret.is_empty() {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "device database secret reference is empty".to_owned(),
            });
        }
        Ok(value)
    }
}

#[lenso::module]
fn instantiate_auth_module(
    context: NativeModuleFactoryContext<'_>,
) -> Result<NativeModuleInstance, RuntimeFailure> {
    let config: DeviceAuthConfig =
        serde_json::from_str(context.configuration()).map_err(|error| {
            RuntimeFailure::InvalidResolvedPlan {
                detail: error.to_string(),
            }
        })?;
    DeviceAuthConfig::new(config.schema.clone(), config.database_url_secret.clone())?;
    let state = Rc::new(RefCell::new(None));
    let endpoint = Rc::new(DeviceEndpoint::new(DeviceAuthProvider {
        state: state.clone(),
    })) as Rc<dyn NativeRequestEndpoint>;
    Ok(NativeModuleInstance::with_lifecycle(
        vec![endpoint],
        DeviceLifecycle { config, state },
    ))
}

#[derive(Clone)]
struct DeviceAuthProvider {
    state: Rc<RefCell<Option<OwnedPostgres>>>,
}
impl fmt::Debug for DeviceAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthProvider")
            .field("prepared", &self.state.borrow().is_some())
            .finish()
    }
}
impl DeviceAuthProvider {
    fn postgres(&self) -> Result<OwnedPostgres, RuntimeFailure> {
        self.state
            .borrow()
            .clone()
            .ok_or(RuntimeFailure::ModuleFailure {
                detail: "Device Auth is not prepared".to_owned(),
            })
    }
}
impl DeviceProvider for DeviceAuthProvider {
    fn observe(
        &self,
        _context: InvocationContext,
        request: ObserveRequest,
    ) -> NativeRequestFuture<DeviceObserve> {
        let postgres = self.postgres();
        Box::pin(async move {
            let postgres = postgres?;
            if !valid(&request.subject) {
                return Ok(Err(ObserveError::InvalidSubject));
            }
            if !valid(&request.device_id) {
                return Ok(Err(ObserveError::InvalidDevice));
            }
            let row=sqlx::query("INSERT INTO auth_devices(subject_id,device_id,last_seen_ip,last_seen_user_agent) VALUES($1,$2,$3,$4) ON CONFLICT(subject_id,device_id) DO UPDATE SET last_seen_ip=EXCLUDED.last_seen_ip,last_seen_user_agent=EXCLUDED.last_seen_user_agent,updated_at=transaction_timestamp() RETURNING (created_at=updated_at) AS created,trusted_at IS NOT NULL AS trusted").bind(&request.subject).bind(&request.device_id).bind(&request.client_ip).bind(&request.user_agent).fetch_one(postgres.pool()).await.map_err(db)?;
            Ok(Ok(ObserveResponse {
                device_id: request.device_id,
                created: row.try_get("created").map_err(db)?,
                trusted: row.try_get("trusted").map_err(db)?,
            }))
        })
    }
    fn list(
        &self,
        _context: InvocationContext,
        request: ListRequest,
    ) -> NativeRequestFuture<DeviceList> {
        let postgres = self.postgres();
        Box::pin(async move {
            let postgres = postgres?;
            if !valid(&request.subject) {
                return Ok(Err(ListError::InvalidSubject));
            }
            let rows=sqlx::query("SELECT device_id,trusted_at IS NOT NULL AS trusted,primary_at IS NOT NULL AS primary,last_seen_ip,last_seen_user_agent,updated_at FROM auth_devices WHERE subject_id=$1 ORDER BY updated_at DESC LIMIT 200").bind(&request.subject).fetch_all(postgres.pool()).await.map_err(db)?;
            let devices = rows
                .into_iter()
                .map(|row| -> Result<_, RuntimeFailure> {
                    let updated: OffsetDateTime = row.try_get("updated_at").map_err(db)?;
                    Ok(ListResponseDevicesItem {
                        device_id: row.try_get("device_id").map_err(db)?,
                        trusted: row.try_get("trusted").map_err(db)?,
                        primary: row.try_get("primary").map_err(db)?,
                        last_seen_ip: row.try_get("last_seen_ip").map_err(db)?,
                        last_seen_user_agent: row.try_get("last_seen_user_agent").map_err(db)?,
                        updated_at: updated.format(&Rfc3339).map_err(|error| {
                            RuntimeFailure::ModuleFailure {
                                detail: error.to_string(),
                            }
                        })?,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Ok(ListResponse { devices }))
        })
    }
    fn set_trust(
        &self,
        _context: InvocationContext,
        request: SetTrustRequest,
    ) -> NativeRequestFuture<DeviceSetTrust> {
        let postgres = self.postgres();
        Box::pin(async move {
            let postgres = postgres?;
            if !valid(&request.subject) {
                return Ok(Err(SetTrustError::InvalidSubject));
            }
            if !valid(&request.device_id) {
                return Ok(Err(SetTrustError::InvalidDevice));
            }
            let mut transaction = postgres.pool().begin().await.map_err(db)?;
            if request.primary {
                sqlx::query("UPDATE auth_devices SET primary_at=NULL WHERE subject_id=$1 AND primary_at IS NOT NULL").bind(&request.subject).execute(&mut*transaction).await.map_err(db)?;
            }
            let result=sqlx::query("UPDATE auth_devices SET trusted_at=CASE WHEN $3 THEN transaction_timestamp() ELSE NULL END,primary_at=CASE WHEN $4 THEN transaction_timestamp() ELSE NULL END,updated_at=transaction_timestamp() WHERE subject_id=$1 AND device_id=$2").bind(&request.subject).bind(&request.device_id).bind(request.trusted).bind(request.primary).execute(&mut*transaction).await.map_err(db)?;
            transaction.commit().await.map_err(db)?;
            if result.rows_affected() == 0 {
                return Ok(Err(SetTrustError::NotFound));
            }
            Ok(Ok(SetTrustResponse { changed: true }))
        })
    }
}

#[derive(Debug)]
struct DeviceLifecycle {
    config: DeviceAuthConfig,
    state: Rc<RefCell<Option<OwnedPostgres>>>,
}
impl ModuleLifecycle for DeviceLifecycle {
    fn prepare(&self, context: PrepareContext) -> ModuleFuture {
        let config = self.config.clone();
        let state = self.state.clone();
        let dependencies = context.dependencies().clone();
        let cancellation = context.cancellation();
        Box::pin(async move {
            let secrets = SecretsClient::from_dependencies(&dependencies)?;
            let invocation =
                dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
            let database_url = secrets
                .resolve_with_context(
                    invocation,
                    ResolveRequest {
                        reference: config.database_url_secret,
                    },
                )
                .await
                .map(|value| Zeroizing::new(value.value))
                .map_err(|error| match error {
                    SecretsInvocationError::Domain(_) => RuntimeFailure::ModuleFailure {
                        detail: "device database secret was rejected".to_owned(),
                    },
                    SecretsInvocationError::Runtime(error) => error,
                })?;
            let postgres = OwnedPostgres::prepare(
                &database_url,
                schema_plan(config.schema).map_err(|error| {
                    RuntimeFailure::InvalidResolvedPlan {
                        detail: error.to_string(),
                    }
                })?,
            )
            .await
            .map_err(|error| RuntimeFailure::ModuleFailure {
                detail: error.to_string(),
            })?;
            state.replace(Some(postgres));
            Ok(())
        })
    }
    fn deactivate(&self, _context: DeactivateContext) -> ModuleFuture {
        let postgres = self.state.borrow_mut().take();
        Box::pin(async move {
            if let Some(postgres) = postgres {
                postgres.pool().close().await;
            }
            Ok(())
        })
    }
}
fn valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
fn db(error: impl fmt::Display) -> RuntimeFailure {
    RuntimeFailure::ModuleFailure {
        detail: format!("Device Auth storage operation failed: {error}"),
    }
}
