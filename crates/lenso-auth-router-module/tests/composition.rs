use std::{collections::BTreeMap, rc::Rc, time::Duration};

use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    ModuleInstancePlan, ResolvedAppPlan,
};
use lenso_auth_router_module::{AuthRouterConfig, PACKAGE_ID};
use lenso_capability_auth::{
    AUTHENTICATE_OPERATION, Auth, AuthEndpoint, AuthProvider, AuthRequest, AuthResponse,
    AuthResponseKind, AuthenticateError, AuthenticateRequestCredential, CAPABILITY_ID,
    DESCRIPTOR_VERSION,
};
use lenso_kernel::{
    InvocationContext, Kernel, NativeRequestEndpoint, NativeRequestFuture, RuntimeFailure,
    ShutdownOutcome,
};
use lenso_native_adapter::{
    NativeModuleFactory, NativeModuleFactoryContext, NativeModuleInstance, NativeModuleRegistry,
};
use lenso_runner::TokioDriver;

const CALLER: &str = "test.auth-caller";
const SESSION: &str = "test.session-auth";
const BEARER: &str = "test.bearer-auth";

#[derive(Clone, Copy, Debug)]
struct EmptyFactory(&'static str);

impl NativeModuleFactory for EmptyFactory {
    fn package_id(&self) -> &'static str {
        self.0
    }

    fn instantiate(
        &self,
        _: NativeModuleFactoryContext<'_>,
    ) -> Result<NativeModuleInstance, RuntimeFailure> {
        Ok(NativeModuleInstance::default())
    }
}

#[derive(Clone, Debug)]
struct RejectingFactory {
    package_id: &'static str,
    error: AuthenticateError,
}

impl NativeModuleFactory for RejectingFactory {
    fn package_id(&self) -> &'static str {
        self.package_id
    }

    fn instantiate(
        &self,
        _: NativeModuleFactoryContext<'_>,
    ) -> Result<NativeModuleInstance, RuntimeFailure> {
        let endpoint = Rc::new(AuthEndpoint::new(RejectingProvider {
            error: self.error.clone(),
        })) as Rc<dyn NativeRequestEndpoint>;
        Ok(NativeModuleInstance::new(vec![endpoint]))
    }
}

#[derive(Clone, Debug)]
struct RejectingProvider {
    error: AuthenticateError,
}

impl AuthProvider for RejectingProvider {
    fn authenticate(&self, _: InvocationContext, _: AuthRequest) -> NativeRequestFuture<Auth> {
        Box::pin(std::future::ready(Ok(Err(self.error.clone()))))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn ordered_many_bindings_route_by_explicit_scheme() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let app = Kernel::start_native(router_plan(), TokioDriver::new(), full_registry())
                .await
                .unwrap();

            let absent = invoke(&app, None).await.unwrap();
            assert_eq!(absent.kind, AuthResponseKind::Absent);
            assert_eq!(
                invoke(&app, Some(("session", "s"))).await.unwrap_err(),
                AuthenticateError::Invalid
            );
            assert_eq!(
                invoke(&app, Some(("bearer", "b"))).await.unwrap_err(),
                AuthenticateError::Revoked
            );
            assert_eq!(
                invoke(&app, Some(("basic", "x"))).await.unwrap_err(),
                AuthenticateError::Unsupported
            );

            assert_eq!(
                app.shutdown(Duration::from_secs(2)).await,
                ShutdownOutcome::Clean
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn router_and_optional_provider_can_be_deleted_from_composition() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let app = Kernel::start_native(
                direct_plan(),
                TokioDriver::new(),
                NativeModuleRegistry::new()
                    .with_factory(EmptyFactory(CALLER))
                    .with_factory(RejectingFactory {
                        package_id: SESSION,
                        error: AuthenticateError::Invalid,
                    }),
            )
            .await
            .unwrap();

            assert_eq!(
                invoke(&app, Some(("session", "s"))).await.unwrap_err(),
                AuthenticateError::Invalid
            );
            assert_eq!(
                app.shutdown(Duration::from_secs(2)).await,
                ShutdownOutcome::Clean
            );
        })
        .await;
}

async fn invoke(
    app: &lenso_kernel::NativeApp,
    credential: Option<(&str, &str)>,
) -> Result<AuthResponse, AuthenticateError> {
    app.invoke::<Auth>(
        "caller",
        AUTHENTICATE_OPERATION,
        AuthRequest {
            credential: credential.map(|(scheme, value)| AuthenticateRequestCredential {
                scheme: scheme.to_owned(),
                value: value.to_owned(),
            }),
        },
    )
    .await
    .unwrap()
}

fn caller() -> ModuleInstancePlan {
    ModuleInstancePlan::new("caller", CALLER).with_requirement(CapabilityRequirementPlan::one(
        CAPABILITY_ID,
        DESCRIPTOR_VERSION,
    ))
}

fn provider(instance: &str, package: &str) -> ModuleInstancePlan {
    ModuleInstancePlan::new(instance, package).with_capability(CapabilityEndpointPlan::new(
        CAPABILITY_ID,
        DESCRIPTOR_VERSION,
        [AUTHENTICATE_OPERATION],
    ))
}

fn router_plan() -> ResolvedAppPlan {
    let router = ModuleInstancePlan::new("router", PACKAGE_ID)
        .with_configuration(
            serde_json::to_string(
                &AuthRouterConfig::new(BTreeMap::from([
                    ("session".into(), "session".into()),
                    ("bearer".into(), "bearer".into()),
                ]))
                .unwrap(),
            )
            .unwrap(),
        )
        .with_requirement(CapabilityRequirementPlan::many(
            CAPABILITY_ID,
            DESCRIPTOR_VERSION,
        ))
        .with_capability(CapabilityEndpointPlan::new(
            CAPABILITY_ID,
            DESCRIPTOR_VERSION,
            [AUTHENTICATE_OPERATION],
        ));
    AppComposition::new(
        vec![
            caller(),
            router,
            provider("session", SESSION),
            provider("bearer", BEARER),
        ],
        vec![
            CapabilityBinding::new("caller", CAPABILITY_ID, DESCRIPTOR_VERSION, "router"),
            CapabilityBinding::new("router", CAPABILITY_ID, DESCRIPTOR_VERSION, "session"),
            CapabilityBinding::new("router", CAPABILITY_ID, DESCRIPTOR_VERSION, "bearer"),
        ],
    )
    .resolve()
    .unwrap()
}

fn direct_plan() -> ResolvedAppPlan {
    AppComposition::new(
        vec![caller(), provider("session", SESSION)],
        vec![CapabilityBinding::new(
            "caller",
            CAPABILITY_ID,
            DESCRIPTOR_VERSION,
            "session",
        )],
    )
    .resolve()
    .unwrap()
}

fn full_registry() -> NativeModuleRegistry {
    NativeModuleRegistry::new()
        .with_linked_factories()
        .with_factory(EmptyFactory(CALLER))
        .with_factory(RejectingFactory {
            package_id: SESSION,
            error: AuthenticateError::Invalid,
        })
        .with_factory(RejectingFactory {
            package_id: BEARER,
            error: AuthenticateError::Revoked,
        })
}
