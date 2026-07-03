use crate::migrations::AUTH_GOOGLE_MIGRATIONS;
use platform_core::AppContext;
use platform_http::ApiOpenApiRouter;
use platform_module::{
    ConsoleArea, ConsoleNavigation, ConsolePackage, ConsoleSurface, ConsoleWorkspaceRef,
    HostLinkedModule, LinkedBinding, LinkedHttpContribution, Module, ModuleHttpMethod,
    ModuleHttpRoute, ModuleManifest,
};

pub const MODULE_NAME: &str = "auth-google";

fn auth_workspace() -> ConsoleWorkspaceRef {
    ConsoleWorkspaceRef {
        id: "auth".to_owned(),
        label: "Auth".to_owned(),
        icon: Some("shield".to_owned()),
    }
}

pub fn http_routes() -> Vec<ModuleHttpRoute> {
    vec![
        ModuleHttpRoute {
            method: ModuleHttpMethod::Get,
            path: "/v1/auth/google/start".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Start Google Login".to_owned()),
            story_title: Some("Google Login Start".to_owned()),
        },
        ModuleHttpRoute {
            method: ModuleHttpMethod::Get,
            path: "/v1/auth/google/callback".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Complete Google Login".to_owned()),
            story_title: Some("Google Login Callback".to_owned()),
        },
    ]
}

pub fn console_surfaces() -> Vec<ConsoleSurface> {
    vec![ConsoleSurface {
        name: "google-provider".to_owned(),
        label: "Google".to_owned(),
        area: ConsoleArea::Data,
        route: "/data/auth/providers/google".to_owned(),
        package: ConsolePackage {
            name: "@lenso/auth-provider-console".to_owned(),
            export: "authProviderConsoleModule".to_owned(),
        },
        icon: Some("network".to_owned()),
        required_capabilities: Vec::new(),
        navigation: Some(ConsoleNavigation {
            workspace: auth_workspace(),
            group: None,
            order: Some(82),
        }),
    }]
}

pub fn manifest() -> ModuleManifest {
    ModuleManifest::builder(MODULE_NAME)
        .dependencies(vec![
            auth::module::MODULE_NAME.to_owned(),
            auth_oauth::module::MODULE_NAME.to_owned(),
        ])
        .http_routes(http_routes())
        .console(console_surfaces())
        .build()
}

pub fn merge_http(base: ApiOpenApiRouter) -> ApiOpenApiRouter {
    base.merge(crate::routes::router())
}

pub fn binding() -> LinkedBinding {
    LinkedBinding::builder()
        .http(LinkedHttpContribution {
            public_prefixes: &["/v1/auth/google/"],
            merge: merge_http,
        })
        .build()
}

pub fn module(_ctx: &AppContext) -> Module {
    Module::linked(manifest(), binding())
}

pub fn linked_module() -> HostLinkedModule {
    HostLinkedModule::linked(MODULE_NAME, manifest, module, AUTH_GOOGLE_MIGRATIONS)
        .with_http_binding(binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_module::{ModuleManifestLintSeverity, ModuleSource, lint_module_manifest};

    #[test]
    fn manifest_declares_google_routes_and_dependencies() {
        let manifest = manifest();

        assert_eq!(manifest.name, MODULE_NAME);
        assert_eq!(
            manifest.dependencies,
            vec![
                auth::module::MODULE_NAME.to_owned(),
                auth_oauth::module::MODULE_NAME.to_owned()
            ]
        );
        assert_eq!(manifest.http_routes, http_routes());
        assert_eq!(manifest.console, console_surfaces());

        let lints = lint_module_manifest(ModuleSource::Linked, &manifest);
        assert!(
            lints
                .iter()
                .all(|lint| lint.severity == ModuleManifestLintSeverity::Ok),
            "auth-google manifest should not have warning/error lints: {lints:?}"
        );
    }
}
