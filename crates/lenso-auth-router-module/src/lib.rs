//! Explicit credential-scheme routing across named `many` Auth bindings.
use lenso_capability_auth::{
    AUTHENTICATE_OPERATION, Auth, AuthEndpoint, AuthProvider, AuthRequest, AuthResponse,
    AuthResponseKind, AuthenticateError,
};
use lenso_kernel::{
    ActivateContext, DeactivateContext, InvocationContext, ModuleFuture, ModuleLifecycle,
    NativeRequestEndpoint, NativeRequestFuture, NativeRequestHandle, RuntimeFailure,
};
use lenso_native_adapter::{NativeModuleFactoryContext, NativeModuleInstance};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    rc::Rc,
};
type RouteMap = Rc<BTreeMap<String, NativeRequestHandle<Auth>>>;
type RouteState = Rc<RefCell<Option<RouteMap>>>;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthRouterConfig {
    routes: BTreeMap<String, String>,
}
impl AuthRouterConfig {
    pub fn new(routes: BTreeMap<String, String>) -> Result<Self, RuntimeFailure> {
        if routes.is_empty()
            || routes
                .iter()
                .any(|(scheme, provider)| !valid(scheme) || !valid(provider))
            || routes.values().collect::<BTreeSet<_>>().len() != routes.len()
        {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "Auth Router routes must contain valid schemes and unique provider names"
                    .to_owned(),
            });
        }
        Ok(Self { routes })
    }
}
#[lenso::module]
fn instantiate_auth_module(
    context: NativeModuleFactoryContext<'_>,
) -> Result<NativeModuleInstance, RuntimeFailure> {
    let config: AuthRouterConfig =
        serde_json::from_str(context.configuration()).map_err(|error| {
            RuntimeFailure::InvalidResolvedPlan {
                detail: error.to_string(),
            }
        })?;
    AuthRouterConfig::new(config.routes.clone())?;
    let routes = Rc::new(RefCell::new(None));
    let endpoint = Rc::new(AuthEndpoint::new(Router {
        routes: routes.clone(),
    })) as Rc<dyn NativeRequestEndpoint>;
    Ok(NativeModuleInstance::with_lifecycle(
        vec![endpoint],
        Lifecycle { config, routes },
    ))
}
#[derive(Clone)]
struct Router {
    routes: RouteState,
}
impl fmt::Debug for Router {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Router")
            .field("active", &self.routes.borrow().is_some())
            .finish()
    }
}
impl AuthProvider for Router {
    fn authenticate(
        &self,
        context: InvocationContext,
        request: AuthRequest,
    ) -> NativeRequestFuture<Auth> {
        let routes = self.routes.borrow().clone();
        Box::pin(async move {
            let Some(credential) = request.credential.as_ref() else {
                return Ok(Ok(AuthResponse {
                    kind: AuthResponseKind::Absent,
                    assertion: None,
                }));
            };
            let routes = routes.ok_or(RuntimeFailure::ModuleFailure {
                detail: "Auth Router is not active".to_owned(),
            })?;
            let Some(handle) = routes.get(&credential.scheme) else {
                return Ok(Err(AuthenticateError::Unsupported));
            };
            handle
                .invoke_with_context(AUTHENTICATE_OPERATION, context, request)
                .await
        })
    }
}
#[derive(Debug)]
struct Lifecycle {
    config: AuthRouterConfig,
    routes: RouteState,
}
impl ModuleLifecycle for Lifecycle {
    fn activate(&self, context: ActivateContext) -> ModuleFuture {
        let dependencies = context.dependencies().clone();
        let routes = self.routes.clone();
        let configured = self.config.routes.clone();
        Box::pin(async move {
            let handles = dependencies.many::<Auth>()?;
            let provider_names = dependencies
                .bindings()
                .iter()
                .filter(|binding| binding.capability_id() == lenso_capability_auth::CAPABILITY_ID)
                .map(|binding| binding.provider_instance().to_owned())
                .collect::<Vec<_>>();
            let mut by_provider = provider_names
                .into_iter()
                .zip(handles)
                .collect::<BTreeMap<_, _>>();
            let configured_providers = configured.values().cloned().collect::<BTreeSet<_>>();
            let bound_providers = by_provider.keys().cloned().collect::<BTreeSet<_>>();
            if configured_providers != bound_providers {
                return Err(RuntimeFailure::InvalidResolvedPlan {
                    detail: "Auth Router provider names must exactly match its Auth bindings"
                        .to_owned(),
                });
            }
            let resolved = configured
                .into_iter()
                .map(|(scheme, provider)| {
                    let handle = by_provider.remove(&provider).ok_or_else(|| {
                        RuntimeFailure::InvalidResolvedPlan {
                            detail: format!("Auth Router provider `{provider}` is not bound"),
                        }
                    })?;
                    Ok((scheme, handle))
                })
                .collect::<Result<BTreeMap<_, _>, RuntimeFailure>>()?;
            routes.replace(Some(Rc::new(resolved)));
            Ok(())
        })
    }
    fn deactivate(&self, _: DeactivateContext) -> ModuleFuture {
        self.routes.borrow_mut().take();
        Box::pin(futures::future::ready(Ok(())))
    }
}
fn valid(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
