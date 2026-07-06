use crate::admin::AuthPhoneAdminActions;
use crate::migrations::AUTH_PHONE_MIGRATIONS;
use platform_core::AppContext;
use platform_http::ApiOpenApiRouter;
use platform_module::{
    AdminAction, AdminActionDangerLevel, AdminActionInputField, AdminActionInputSchema,
    AdminDeclarativeSurface, ConsoleActionInputBinding, ConsoleActionInputValue,
    ConsoleContribution, ConsoleContributionAction, FieldType, HostLinkedModule, LinkedBinding,
    LinkedHttpContribution, Module, ModuleHttpMethod, ModuleHttpRoute, ModuleManifest,
};
use std::sync::Arc;

pub const MODULE_NAME: &str = "auth-phone";
pub const AUTH_PHONE_CREDENTIALS_WRITE: &str = "auth_phone.credentials.write";
pub const RESET_PHONE_PASSWORD_ACTION: &str = "reset_phone_password";

pub fn http_routes() -> Vec<ModuleHttpRoute> {
    vec![
        ModuleHttpRoute {
            method: ModuleHttpMethod::Post,
            path: "/v1/auth/phone/otp/start".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Start Phone OTP".to_owned()),
            story_title: Some("Phone OTP Start".to_owned()),
        },
        ModuleHttpRoute {
            method: ModuleHttpMethod::Post,
            path: "/v1/auth/phone/otp/verify".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Verify Phone OTP".to_owned()),
            story_title: Some("Phone OTP Verify".to_owned()),
        },
        ModuleHttpRoute {
            method: ModuleHttpMethod::Post,
            path: "/v1/auth/phone/password/set".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Set Phone Password".to_owned()),
            story_title: Some("Phone Password Set".to_owned()),
        },
        ModuleHttpRoute {
            method: ModuleHttpMethod::Post,
            path: "/v1/auth/phone/password/login".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Login With Phone Password".to_owned()),
            story_title: Some("Phone Password Login".to_owned()),
        },
    ]
}

pub fn manifest() -> ModuleManifest {
    ModuleManifest::builder(MODULE_NAME)
        .capabilities(vec![AUTH_PHONE_CREDENTIALS_WRITE.to_owned()])
        .dependencies(vec![auth::module::MODULE_NAME.to_owned()])
        .http_routes(http_routes())
        .declarative_admin(admin_surface())
        .console_contributions(console_contributions())
        .build()
}

pub fn admin_surface() -> AdminDeclarativeSurface {
    AdminDeclarativeSurface {
        pages: Vec::new(),
        actions: vec![reset_phone_password_action()],
        fallback_schema: None,
    }
}

fn reset_phone_password_action() -> AdminAction {
    AdminAction {
        name: RESET_PHONE_PASSWORD_ACTION.to_owned(),
        label: "Reset phone password".to_owned(),
        capability: AUTH_PHONE_CREDENTIALS_WRITE.to_owned(),
        input_schema: Some(AdminActionInputSchema {
            fields: vec![
                AdminActionInputField {
                    name: "user_id".to_owned(),
                    label: "User".to_owned(),
                    field_type: FieldType::String,
                    required: true,
                    description: None,
                },
                AdminActionInputField {
                    name: "new_password".to_owned(),
                    label: "New password".to_owned(),
                    field_type: FieldType::String,
                    required: true,
                    description: None,
                },
            ],
        }),
        confirmation: None,
        operation: None,
        danger_level: AdminActionDangerLevel::Medium,
    }
}

pub fn console_contributions() -> Vec<ConsoleContribution> {
    vec![ConsoleContribution {
        target: auth::module::AUTH_USERS_DETAIL_ACTIONS_SLOT.to_owned(),
        target_version: auth::module::AUTH_USERS_DETAIL_ACTIONS_SLOT_VERSION,
        label: "Reset phone password".to_owned(),
        action: ConsoleContributionAction::AdminAction {
            module: MODULE_NAME.to_owned(),
            name: RESET_PHONE_PASSWORD_ACTION.to_owned(),
            input_bindings: vec![ConsoleActionInputBinding {
                input: "user_id".to_owned(),
                value: ConsoleActionInputValue::SlotContext {
                    path: "selected_user.id".to_owned(),
                },
            }],
        },
        icon: Some("key-round".to_owned()),
        required_capabilities: vec![AUTH_PHONE_CREDENTIALS_WRITE.to_owned()],
    }]
}

pub fn merge_http(base: ApiOpenApiRouter) -> ApiOpenApiRouter {
    base.merge(crate::routes::router())
}

pub fn binding() -> LinkedBinding {
    LinkedBinding::builder()
        .http(LinkedHttpContribution {
            public_prefixes: &["/v1/auth/phone/"],
            merge: merge_http,
        })
        .build()
}

pub fn module(_ctx: &AppContext) -> Module {
    Module::linked(manifest(), binding())
        .with_runtime_config_groups(crate::config::RUNTIME_CONFIG_GROUPS.as_slice())
        .with_runtime_config(crate::config::RUNTIME_CONFIG.as_slice())
        .with_admin_actions(Arc::new(AuthPhoneAdminActions::new(_ctx.clone())))
}

pub fn linked_module() -> HostLinkedModule {
    HostLinkedModule::linked(MODULE_NAME, manifest, module, AUTH_PHONE_MIGRATIONS)
        .with_http_binding(binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_module::{
        AdminSurface, ConsoleContribution, ConsoleContributionAction, ModuleManifestLintSeverity,
        ModuleSource, lint_module_manifest,
    };

    #[test]
    fn manifest_declares_phone_routes_and_auth_dependency() {
        let manifest = manifest();

        assert_eq!(manifest.name, MODULE_NAME);
        assert_eq!(
            manifest.dependencies,
            vec![auth::module::MODULE_NAME.to_owned()]
        );
        assert_eq!(manifest.http_routes, http_routes());

        let paths: Vec<_> = manifest
            .http_routes
            .iter()
            .map(|route| route.path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec![
                "/v1/auth/phone/otp/start",
                "/v1/auth/phone/otp/verify",
                "/v1/auth/phone/password/set",
                "/v1/auth/phone/password/login",
            ]
        );

        let lints = lint_module_manifest(ModuleSource::Linked, &manifest);
        assert!(
            lints
                .iter()
                .all(|lint| lint.severity == ModuleManifestLintSeverity::Ok),
            "auth-phone manifest should not have warning/error lints: {lints:?}"
        );
    }

    #[test]
    fn manifest_declares_reset_phone_password_contribution() {
        let manifest = manifest();

        assert!(
            manifest
                .capabilities
                .iter()
                .any(|capability| capability == AUTH_PHONE_CREDENTIALS_WRITE)
        );
        let Some(AdminSurface::DeclarativeCustom(admin)) = &manifest.admin else {
            panic!("auth-phone should expose declarative admin actions");
        };
        assert_eq!(admin.actions.len(), 1);
        assert_eq!(admin.actions[0].name, RESET_PHONE_PASSWORD_ACTION);
        assert_eq!(manifest.console_contributions.len(), 1);
        assert_eq!(
            manifest.console_contributions[0],
            ConsoleContribution {
                target: auth::module::AUTH_USERS_DETAIL_ACTIONS_SLOT.to_owned(),
                target_version: auth::module::AUTH_USERS_DETAIL_ACTIONS_SLOT_VERSION,
                label: "Reset phone password".to_owned(),
                action: ConsoleContributionAction::AdminAction {
                    module: MODULE_NAME.to_owned(),
                    name: RESET_PHONE_PASSWORD_ACTION.to_owned(),
                    input_bindings: vec![platform_module::ConsoleActionInputBinding {
                        input: "user_id".to_owned(),
                        value: platform_module::ConsoleActionInputValue::SlotContext {
                            path: "selected_user.id".to_owned(),
                        },
                    }],
                },
                icon: Some("key-round".to_owned()),
                required_capabilities: vec![AUTH_PHONE_CREDENTIALS_WRITE.to_owned()],
            }
        );
    }
}
