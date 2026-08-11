use crate::migrations::AUTH_OAUTH_MIGRATIONS;
use platform_core::AppContext;
use platform_module::{
    ConsoleNavigation, ConsoleSurface, ConsoleSurfacePresentation, ConsoleWorkspaceRef,
    HostLinkedModule, LinkedBinding, Module, ModuleManifest,
};

pub const MODULE_NAME: &str = "auth-oauth";
pub const AUTH_PROVIDERS_READ: &str = "auth.providers.read";

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
        route: "/data/auth/providers".to_owned(),
        presentation: ConsoleSurfacePresentation::Esm {
            entry: "providers".to_owned(),
        },
        icon: Some("network".to_owned()),
        required_capabilities: vec![AUTH_PROVIDERS_READ.to_owned()],
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
        .capabilities(vec![AUTH_PROVIDERS_READ.to_owned()])
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
    use platform_module::{ModuleManifestLintSeverity, lint_module_manifest};

    #[test]
    fn manifest_declares_auth_dependency() {
        let manifest = manifest();

        assert_eq!(manifest.module_id, format!("lenso/{MODULE_NAME}"));
        assert_eq!(
            manifest
                .requires
                .iter()
                .map(|requirement| requirement
                    .module_id
                    .strip_prefix("lenso/")
                    .unwrap_or(&requirement.module_id)
                    .to_owned())
                .collect::<Vec<_>>(),
            vec![auth::module::MODULE_NAME.to_owned()]
        );
        assert_eq!(manifest.console, console_surfaces());

        let lints = lint_module_manifest(&manifest);
        assert!(
            lints
                .iter()
                .all(|lint| lint.severity == ModuleManifestLintSeverity::Ok),
            "auth-oauth manifest should not have warning/error lints: {lints:?}"
        );
    }

    #[test]
    fn generated_console_manifest_matches_checked_in_artifact_manifest() {
        let generated =
            serde_json::to_value(manifest().console_module_manifest("^2.1.0", "^2.0.0"))
                .expect("console module manifest should serialize");
        let checked_in: serde_json::Value =
            serde_json::from_str(include_str!("../console-module.json"))
                .expect("console module manifest fixture should be valid JSON");

        assert_eq!(generated, checked_in);
    }
}
