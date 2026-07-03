use crate::migrations::AUTH_OAUTH_MIGRATIONS;
use platform_core::AppContext;
use platform_module::{
    ConsoleArea, ConsoleNavigation, ConsolePackage, ConsoleSurface, ConsoleWorkspaceRef,
    HostLinkedModule, LinkedBinding, Module, ModuleManifest,
};

pub const MODULE_NAME: &str = "auth-oauth";

fn auth_workspace() -> ConsoleWorkspaceRef {
    ConsoleWorkspaceRef {
        id: "auth".to_owned(),
        label: "Auth".to_owned(),
        icon: Some("shield".to_owned()),
    }
}

pub fn console_surfaces() -> Vec<ConsoleSurface> {
    vec![ConsoleSurface {
        name: "providers".to_owned(),
        label: "Providers".to_owned(),
        area: ConsoleArea::Data,
        route: "/data/auth/providers".to_owned(),
        package: ConsolePackage {
            name: "@lenso/auth-provider-console".to_owned(),
            export: "authProviderConsoleModule".to_owned(),
        },
        icon: Some("network".to_owned()),
        required_capabilities: Vec::new(),
        navigation: Some(ConsoleNavigation {
            workspace: auth_workspace(),
            group: None,
            order: Some(80),
        }),
    }]
}

pub fn manifest() -> ModuleManifest {
    ModuleManifest::builder(MODULE_NAME)
        .dependencies(vec![auth::module::MODULE_NAME.to_owned()])
        .console(console_surfaces())
        .build()
}

pub fn module(_ctx: &AppContext) -> Module {
    Module::linked(manifest(), LinkedBinding::builder().build())
}

pub fn linked_module() -> HostLinkedModule {
    HostLinkedModule::linked(MODULE_NAME, manifest, module, AUTH_OAUTH_MIGRATIONS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_module::{ModuleManifestLintSeverity, ModuleSource, lint_module_manifest};

    #[test]
    fn manifest_declares_auth_dependency() {
        let manifest = manifest();

        assert_eq!(manifest.name, MODULE_NAME);
        assert_eq!(
            manifest.dependencies,
            vec![auth::module::MODULE_NAME.to_owned()]
        );
        assert_eq!(manifest.console, console_surfaces());

        let lints = lint_module_manifest(ModuleSource::Linked, &manifest);
        assert!(
            lints
                .iter()
                .all(|lint| lint.severity == ModuleManifestLintSeverity::Ok),
            "auth-oauth manifest should not have warning/error lints: {lints:?}"
        );
    }
}
