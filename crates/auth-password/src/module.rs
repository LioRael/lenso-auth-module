use crate::admin::AuthPasswordAdminActions;
use crate::config::{AuthPasswordConfig, TokenStrategy};
use auth::module::{AUTH_USERS_DETAIL_ACTIONS_SLOT, AUTH_USERS_DETAIL_ACTIONS_SLOT_VERSION};
use platform_core::AppContext;
use platform_http::ApiOpenApiRouter;
use platform_module::{
    AdminAction, AdminActionDangerLevel, AdminActionInputField, AdminActionInputSchema,
    AdminDeclarativeSurface, ConsoleActionInputBinding, ConsoleActionInputValue,
    ConsoleContribution, ConsoleContributionAction, FieldType, LinkedBinding,
    LinkedHttpContribution, Module, ModuleHttpMethod, ModuleHttpRoute, ModuleManifest,
};
use std::sync::Arc;

pub const MODULE_NAME: &str = "auth-password";
pub const AUTH_MODULE_DEPENDENCY: &str = "auth";
pub const AUTH_PASSWORD_CREDENTIALS_WRITE: &str = "auth_password.credentials.write";
pub const RESET_PASSWORD_ACTION: &str = "reset_password";

pub fn http_routes() -> Vec<ModuleHttpRoute> {
    vec![
        ModuleHttpRoute {
            method: ModuleHttpMethod::Post,
            path: "/v1/auth/password/register".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Register With Password".to_owned()),
            story_title: Some("Password Registration".to_owned()),
        },
        ModuleHttpRoute {
            method: ModuleHttpMethod::Post,
            path: "/v1/auth/password/login".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Login With Password".to_owned()),
            story_title: Some("Password Login".to_owned()),
        },
    ]
}

pub fn manifest() -> ModuleManifest {
    ModuleManifest::builder(MODULE_NAME)
        .capabilities(vec![AUTH_PASSWORD_CREDENTIALS_WRITE.to_owned()])
        .dependencies(vec![AUTH_MODULE_DEPENDENCY.to_owned()])
        .http_routes(http_routes())
        .declarative_admin(admin_surface())
        .console_contributions(console_contributions())
        .build()
}

pub fn admin_surface() -> AdminDeclarativeSurface {
    AdminDeclarativeSurface {
        pages: Vec::new(),
        actions: vec![reset_password_action()],
        fallback_schema: None,
    }
}

fn reset_password_action() -> AdminAction {
    AdminAction {
        name: RESET_PASSWORD_ACTION.to_owned(),
        label: "Reset password".to_owned(),
        capability: AUTH_PASSWORD_CREDENTIALS_WRITE.to_owned(),
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
        target: AUTH_USERS_DETAIL_ACTIONS_SLOT.to_owned(),
        target_version: AUTH_USERS_DETAIL_ACTIONS_SLOT_VERSION,
        label: "Reset password".to_owned(),
        action: ConsoleContributionAction::AdminAction {
            module: MODULE_NAME.to_owned(),
            name: RESET_PASSWORD_ACTION.to_owned(),
            input_bindings: vec![ConsoleActionInputBinding {
                input: "user_id".to_owned(),
                value: ConsoleActionInputValue::SlotContext {
                    path: "selected_user.id".to_owned(),
                },
            }],
        },
        icon: Some("key-round".to_owned()),
        required_capabilities: vec![AUTH_PASSWORD_CREDENTIALS_WRITE.to_owned()],
    }]
}

pub fn merge_http(base: ApiOpenApiRouter) -> ApiOpenApiRouter {
    base.merge(crate::routes::router())
}

pub fn binding() -> LinkedBinding {
    LinkedBinding::builder()
        .http(LinkedHttpContribution {
            public_prefixes: &["/v1/auth/password/"],
            merge: merge_http,
        })
        .build()
}

pub fn module(_ctx: &AppContext) -> Module {
    Module::linked(manifest(), binding())
        .with_runtime_config_groups(crate::config::RUNTIME_CONFIG_GROUPS.as_slice())
        .with_runtime_config(crate::config::RUNTIME_CONFIG.as_slice())
        .with_admin_actions(Arc::new(AuthPasswordAdminActions::new(_ctx.clone())))
}

/// Build a [`JwtActorResolver`] if auth-password is configured with `token_strategy = "jwt"`.
///
/// Returns `Ok(None)` when the strategy is `"session"` (the default) or when
/// the auth-password module is not enabled. Returns `Ok(Some(..))` with the
/// resolver wrapping the given `fallback`.
pub fn jwt_actor_resolver(
    ctx: &AppContext,
    fallback: std::sync::Arc<dyn platform_core::ActorResolver>,
) -> platform_core::AppResult<Option<std::sync::Arc<dyn platform_core::ActorResolver>>> {
    let config = AuthPasswordConfig::from_context(ctx)?;
    if config.token_strategy == TokenStrategy::Jwt && config.jwt_secret.is_none() {
        return Ok(None);
    }
    let jwt_config = match config.jwt_config()? {
        Some(cfg) => cfg,
        None => return Ok(None),
    };
    Ok(Some(std::sync::Arc::new(
        crate::resolver::JwtActorResolver::new(jwt_config, fallback),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_module::{
        AdminSurface, ConsoleActionInputBinding, ConsoleActionInputValue, ConsoleContribution,
        ConsoleContributionAction, ModuleManifestLintSeverity, ModuleSource, lint_module_manifest,
    };

    #[test]
    fn manifest_declares_password_routes() {
        let manifest = manifest();

        assert_eq!(manifest.name, MODULE_NAME);
        assert_eq!(manifest.http_routes, http_routes());
        assert_eq!(
            manifest.admin,
            Some(AdminSurface::DeclarativeCustom(admin_surface()))
        );
        assert_eq!(manifest.capabilities, vec![AUTH_PASSWORD_CREDENTIALS_WRITE]);
        assert_eq!(manifest.console_contributions, console_contributions());

        let lints = lint_module_manifest(ModuleSource::Linked, &manifest);
        assert!(
            lints
                .iter()
                .all(|lint| lint.severity == ModuleManifestLintSeverity::Ok),
            "auth-password manifest should not have warning/error lints: {lints:?}"
        );
    }

    #[test]
    fn manifest_contributes_reset_password_to_auth_user_actions() {
        assert_eq!(
            console_contributions(),
            vec![ConsoleContribution {
                target: AUTH_USERS_DETAIL_ACTIONS_SLOT.to_owned(),
                target_version: AUTH_USERS_DETAIL_ACTIONS_SLOT_VERSION,
                label: "Reset password".to_owned(),
                action: ConsoleContributionAction::AdminAction {
                    module: MODULE_NAME.to_owned(),
                    name: RESET_PASSWORD_ACTION.to_owned(),
                    input_bindings: vec![ConsoleActionInputBinding {
                        input: "user_id".to_owned(),
                        value: ConsoleActionInputValue::SlotContext {
                            path: "selected_user.id".to_owned(),
                        },
                    }],
                },
                icon: Some("key-round".to_owned()),
                required_capabilities: vec![AUTH_PASSWORD_CREDENTIALS_WRITE.to_owned()],
            }]
        );
    }
}
