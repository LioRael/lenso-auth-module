use crate::admin::AuthAdminData;
use crate::repositories::PostgresAuthUserRepository;
use contracts::{ServiceOperationIdempotency, ServiceOperationMetadata};
use platform_core::AppContext;
use platform_http::ApiOpenApiRouter;
use platform_module::{
    AdminAction, AdminActionDangerLevel, AdminActionInputField, AdminActionInputSchema,
    AdminDeclarativeComponent, AdminDeclarativePage, AdminDeclarativeSection,
    AdminDeclarativeSurface, AdminSchema, ConsoleContributionKind, ConsoleNavigation,
    ConsoleNavigationGroup, ConsoleSlot, ConsoleSlotContext, ConsoleSlotContextField,
    ConsoleSlotContextFieldType, ConsoleSurface, ConsoleSurfacePresentation, ConsoleWorkspaceRef,
    EntitySchema, FieldSchema, FieldType, LinkedBinding, LinkedHttpContribution, Module,
    ModuleHttpMethod, ModuleHttpRoute, ModuleManifest,
};
use std::sync::Arc;

pub const MODULE_NAME: &str = "auth";
pub const AUTH_USERS_READ: &str = "auth.users.read";
pub const AUTH_USERS_MANAGE: &str = "auth.users.manage";
pub const AUTH_SESSIONS_READ: &str = "auth.sessions.read";
pub const AUTH_SESSIONS_REVOKE: &str = "auth.sessions.revoke";
pub const AUTH_USERS_DETAIL_ACTIONS_SLOT: &str = "auth.users.detail.actions";
pub const AUTH_USERS_DETAIL_ACTIONS_SLOT_VERSION: u32 = 1;

pub fn http_routes() -> Vec<ModuleHttpRoute> {
    vec![
        ModuleHttpRoute {
            method: ModuleHttpMethod::Post,
            path: "/v1/auth/dev/sessions".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Create Development Session".to_owned()),
            story_title: Some("Development Auth Session".to_owned()),
        },
        ModuleHttpRoute {
            method: ModuleHttpMethod::Post,
            path: "/v1/auth/sessions/revoke".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Revoke Session".to_owned()),
            story_title: Some("Auth Session Revoked".to_owned()),
        },
        business_route(
            ModuleHttpMethod::Get,
            "/v1/auth/console/users",
            AUTH_USERS_READ,
            crate::console_api::LIST_USERS_OPERATION,
            "List Auth Users",
        ),
        business_route(
            ModuleHttpMethod::Get,
            "/v1/auth/console/sessions",
            AUTH_SESSIONS_READ,
            crate::console_api::LIST_SESSIONS_OPERATION,
            "List Auth Sessions",
        ),
        business_route(
            ModuleHttpMethod::Post,
            "/v1/auth/console/users/{user_id}/disable",
            AUTH_USERS_MANAGE,
            crate::console_api::DISABLE_USER_OPERATION,
            "Disable Auth User",
        ),
        business_route(
            ModuleHttpMethod::Post,
            "/v1/auth/console/users/{user_id}/enable",
            AUTH_USERS_MANAGE,
            crate::console_api::ENABLE_USER_OPERATION,
            "Enable Auth User",
        ),
        business_route(
            ModuleHttpMethod::Post,
            "/v1/auth/console/sessions/{session_id}/revoke",
            AUTH_SESSIONS_REVOKE,
            crate::console_api::REVOKE_SESSION_OPERATION,
            "Revoke Auth Session From Console",
        ),
    ]
}

fn business_route(
    method: ModuleHttpMethod,
    path: &str,
    capability: &str,
    operation_id: &str,
    display_name: &str,
) -> ModuleHttpRoute {
    ModuleHttpRoute {
        method,
        path: path.to_owned(),
        capability: Some(capability.to_owned()),
        display_name: Some(display_name.to_owned()),
        story_title: Some(display_name.to_owned()),
        operation: Some(ServiceOperationMetadata {
            operation_id: Some(operation_id.to_owned()),
            summary: Some(display_name.to_owned()),
            idempotency: Some(ServiceOperationIdempotency::Idempotent),
            timeout_ms: Some(10_000),
            ..ServiceOperationMetadata::default()
        }),
    }
}

pub fn user_schema() -> AdminSchema {
    AdminSchema {
        entities: vec![
            EntitySchema {
                name: "users".to_owned(),
                label: "Users".to_owned(),
                read_capability: AUTH_USERS_READ.to_owned(),
                fields: vec![
                    FieldSchema {
                        name: "id".to_owned(),
                        label: "ID".to_owned(),
                        field_type: FieldType::String,
                        nullable: false,
                    },
                    FieldSchema {
                        name: "is_anonymous".to_owned(),
                        label: "Anonymous".to_owned(),
                        field_type: FieldType::Boolean,
                        nullable: false,
                    },
                    FieldSchema {
                        name: "device_id".to_owned(),
                        label: "Device".to_owned(),
                        field_type: FieldType::String,
                        nullable: true,
                    },
                    FieldSchema {
                        name: "created_at".to_owned(),
                        label: "Created".to_owned(),
                        field_type: FieldType::Timestamp,
                        nullable: false,
                    },
                    FieldSchema {
                        name: "disabled_at".to_owned(),
                        label: "Disabled".to_owned(),
                        field_type: FieldType::Timestamp,
                        nullable: true,
                    },
                    FieldSchema {
                        name: "disabled_reason".to_owned(),
                        label: "Reason".to_owned(),
                        field_type: FieldType::String,
                        nullable: true,
                    },
                    FieldSchema {
                        name: "disabled_until".to_owned(),
                        label: "Until".to_owned(),
                        field_type: FieldType::Timestamp,
                        nullable: true,
                    },
                ],
            },
            EntitySchema {
                name: "sessions".to_owned(),
                label: "Sessions".to_owned(),
                read_capability: AUTH_SESSIONS_READ.to_owned(),
                fields: vec![
                    FieldSchema {
                        name: "id".to_owned(),
                        label: "ID".to_owned(),
                        field_type: FieldType::String,
                        nullable: false,
                    },
                    FieldSchema {
                        name: "user_id".to_owned(),
                        label: "User".to_owned(),
                        field_type: FieldType::String,
                        nullable: false,
                    },
                    FieldSchema {
                        name: "device_id".to_owned(),
                        label: "Device".to_owned(),
                        field_type: FieldType::String,
                        nullable: true,
                    },
                    FieldSchema {
                        name: "client_ip".to_owned(),
                        label: "IP".to_owned(),
                        field_type: FieldType::String,
                        nullable: true,
                    },
                    FieldSchema {
                        name: "user_agent".to_owned(),
                        label: "User agent".to_owned(),
                        field_type: FieldType::String,
                        nullable: true,
                    },
                    FieldSchema {
                        name: "created_at".to_owned(),
                        label: "Created".to_owned(),
                        field_type: FieldType::Timestamp,
                        nullable: false,
                    },
                    FieldSchema {
                        name: "expires_at".to_owned(),
                        label: "Expires".to_owned(),
                        field_type: FieldType::Timestamp,
                        nullable: false,
                    },
                    FieldSchema {
                        name: "revoked_at".to_owned(),
                        label: "Revoked".to_owned(),
                        field_type: FieldType::Timestamp,
                        nullable: true,
                    },
                ],
            },
        ],
    }
}

pub fn admin_surface() -> AdminDeclarativeSurface {
    AdminDeclarativeSurface {
        pages: vec![AdminDeclarativePage {
            name: "sessions".to_owned(),
            label: "Sessions".to_owned(),
            sections: vec![AdminDeclarativeSection {
                name: "sessions".to_owned(),
                label: "Sessions".to_owned(),
                component: AdminDeclarativeComponent::EntityTable {
                    entity: "sessions".to_owned(),
                },
            }],
        }],
        actions: vec![
            action_with_string_input(
                "revoke_session",
                "Revoke session",
                "session_id",
                "Session",
                AUTH_SESSIONS_REVOKE,
                AdminActionDangerLevel::Medium,
            ),
            disable_user_action(),
            action_with_string_input(
                "enable_user",
                "Enable user",
                "user_id",
                "User",
                AUTH_USERS_MANAGE,
                AdminActionDangerLevel::Low,
            ),
        ],
        fallback_schema: Some(user_schema()),
    }
}

fn action_with_string_input(
    name: &str,
    label: &str,
    input_name: &str,
    input_label: &str,
    capability: &str,
    danger_level: AdminActionDangerLevel,
) -> AdminAction {
    AdminAction {
        name: name.to_owned(),
        label: label.to_owned(),
        capability: capability.to_owned(),
        input_schema: Some(AdminActionInputSchema {
            fields: vec![AdminActionInputField {
                name: input_name.to_owned(),
                label: input_label.to_owned(),
                field_type: FieldType::String,
                required: true,
                description: None,
            }],
        }),
        confirmation: None,
        operation: None,
        danger_level,
    }
}

fn disable_user_action() -> AdminAction {
    AdminAction {
        name: "disable_user".to_owned(),
        label: "Disable user".to_owned(),
        capability: AUTH_USERS_MANAGE.to_owned(),
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
                    name: "reason".to_owned(),
                    label: "Reason".to_owned(),
                    field_type: FieldType::String,
                    required: false,
                    description: None,
                },
                AdminActionInputField {
                    name: "disabled_until".to_owned(),
                    label: "Until".to_owned(),
                    field_type: FieldType::Timestamp,
                    required: false,
                    description: Some("RFC3339 timestamp; omit for permanent".to_owned()),
                },
            ],
        }),
        confirmation: None,
        operation: None,
        danger_level: AdminActionDangerLevel::Medium,
    }
}

fn auth_workspace() -> ConsoleWorkspaceRef {
    ConsoleWorkspaceRef {
        id: "auth".to_owned(),
        label: "Auth".to_owned(),
        icon: Some("shield".to_owned()),
    }
}

fn auth_directory_group() -> ConsoleNavigationGroup {
    ConsoleNavigationGroup {
        id: "directory".to_owned(),
        label: "Directory".to_owned(),
        icon: None,
        order: Some(10),
    }
}

pub fn console_surfaces() -> Vec<ConsoleSurface> {
    vec![
        ConsoleSurface {
            name: "users".to_owned(),
            label: "Users".to_owned(),
            route: "/auth/users".to_owned(),
            presentation: ConsoleSurfacePresentation::Esm {
                entry: "users".to_owned(),
            },
            icon: Some("shield".to_owned()),
            required_capabilities: vec![AUTH_USERS_READ.to_owned()],
            navigation: Some(ConsoleNavigation {
                workspace: auth_workspace(),
                group: Some(auth_directory_group()),
                order: Some(50),
            }),
        },
        ConsoleSurface {
            name: "sessions".to_owned(),
            label: "Sessions".to_owned(),
            route: "/auth/sessions".to_owned(),
            presentation: ConsoleSurfacePresentation::Esm {
                entry: "sessions".to_owned(),
            },
            icon: Some("shield".to_owned()),
            required_capabilities: vec![AUTH_SESSIONS_READ.to_owned()],
            navigation: Some(ConsoleNavigation {
                workspace: auth_workspace(),
                group: Some(auth_directory_group()),
                order: Some(60),
            }),
        },
    ]
}

pub fn console_slots() -> Vec<ConsoleSlot> {
    vec![ConsoleSlot {
        id: AUTH_USERS_DETAIL_ACTIONS_SLOT.to_owned(),
        version: AUTH_USERS_DETAIL_ACTIONS_SLOT_VERSION,
        label: "User detail actions".to_owned(),
        accepts: vec![ConsoleContributionKind::AdminAction],
        context: vec![ConsoleSlotContext {
            name: "selected_user".to_owned(),
            fields: vec![ConsoleSlotContextField {
                name: "id".to_owned(),
                field_type: ConsoleSlotContextFieldType::String,
                required: true,
            }],
        }],
    }]
}

pub fn manifest() -> ModuleManifest {
    ModuleManifest::builder(MODULE_NAME)
        .capabilities(vec![
            AUTH_USERS_READ.to_owned(),
            AUTH_USERS_MANAGE.to_owned(),
            AUTH_SESSIONS_READ.to_owned(),
            AUTH_SESSIONS_REVOKE.to_owned(),
        ])
        .http_routes(http_routes())
        .declarative_admin(admin_surface())
        .console(console_surfaces())
        .console_slots(console_slots())
        .build()
}

pub fn merge_http(base: ApiOpenApiRouter) -> ApiOpenApiRouter {
    base.merge(crate::routes::router())
        .merge(crate::console_api::router())
}

pub fn binding() -> LinkedBinding {
    LinkedBinding::builder()
        .http(LinkedHttpContribution {
            public_prefixes: &["/v1/auth/console/", "/v1/auth/dev/", "/v1/auth/sessions/"],
            merge: merge_http,
        })
        .build()
}

pub fn module(ctx: &AppContext) -> Module {
    let repository = Arc::new(PostgresAuthUserRepository::from_context(ctx));
    let admin = Arc::new(AuthAdminData::new(repository));
    Module::linked(manifest(), binding())
        .with_runtime_config(crate::config::RUNTIME_CONFIG.as_slice())
        .with_admin_data(admin.clone())
        .with_admin_actions(admin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_module::{ModuleManifestLintSeverity, lint_module_manifest};

    #[test]
    fn manifest_declares_auth_user_anchor() {
        let manifest = manifest();

        assert_eq!(manifest.module_id, format!("lenso/{MODULE_NAME}"));
        assert_eq!(
            manifest.capabilities,
            vec![
                "auth.sessions.read",
                "auth.sessions.revoke",
                "auth.users.manage",
                "auth.users.read"
            ]
        );
        assert_eq!(manifest.http_routes, http_routes());
        assert_eq!(
            manifest.admin,
            Some(platform_module::AdminSurface::DeclarativeCustom(
                admin_surface()
            ))
        );
        assert_eq!(manifest.console, console_surfaces());
        assert_eq!(manifest.console_slots, console_slots());

        let lints = lint_module_manifest(&manifest);
        assert!(
            lints
                .iter()
                .all(|lint| lint.severity == ModuleManifestLintSeverity::Ok),
            "auth manifest should not have warning/error lints: {lints:?}"
        );
    }

    #[test]
    fn admin_actions_require_narrow_mutation_capabilities() {
        let actions = admin_surface().actions;

        assert_eq!(
            actions
                .iter()
                .find(|action| action.name == "revoke_session")
                .expect("revoke action")
                .capability,
            "auth.sessions.revoke"
        );
        assert_eq!(
            actions
                .iter()
                .find(|action| action.name == "disable_user")
                .expect("disable action")
                .capability,
            "auth.users.manage"
        );
        assert_eq!(
            actions
                .iter()
                .find(|action| action.name == "enable_user")
                .expect("enable action")
                .capability,
            "auth.users.manage"
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
