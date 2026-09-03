//! Agent-facing Tools over an explicitly bound Auth Account Admin capability.

use lenso::prelude::*;
use lenso_capability_account_admin::{
    self as account_admin, ListSessionsRequest, ListSubjectsRequest, SetSubjectStatusRequest,
};
use lenso_capability_agent_tool_provider::{
    self as tool_contract, CatalogRequest, CatalogResponse, ContentType, ExecuteError,
    ExecuteRequest, ExecuteResponse, ExecutionFailedPayload, ToolDefinition, ToolExecutionClass,
};
use lenso_kernel::RuntimeFailure;
use serde::{Serialize, de::DeserializeOwned};

pub const LIST_SUBJECTS_TOOL: &str = "auth_account_admin_list_subjects";
pub const LIST_SESSIONS_TOOL: &str = "auth_account_admin_list_sessions";
pub const SET_SUBJECT_STATUS_TOOL: &str = "auth_account_admin_set_subject_status";

#[lenso::plugin]
#[derive(Clone, Debug)]
struct AuthAccountAdminAgentToolsPlugin {
    account_admin: Port<account_admin::AccountAdminClient>,
}

#[lenso::provides(tool_contract::ToolProvider)]
impl AuthAccountAdminAgentToolsPlugin {
    fn catalog(
        &self,
        _context: Ctx,
        _request: CatalogRequest,
    ) -> impl std::future::Future<Output = PluginResult<CatalogResponse, tool_contract::CatalogError>>
    {
        let _ = self;
        futures::future::ready(Ok(CatalogResponse {
            tools: tool_definitions(),
        }))
    }

    async fn execute(
        &self,
        context: Ctx,
        request: ExecuteRequest,
    ) -> PluginResult<ExecuteResponse, ExecuteError> {
        match request.name.as_str() {
            LIST_SUBJECTS_TOOL => {
                let arguments = decode::<ListSubjectsRequest>(&request)?;
                match self
                    .account_admin
                    .list_subjects_with_context(context, arguments)
                    .await
                {
                    Ok(response) => success(LIST_SUBJECTS_TOOL, &response),
                    Err(account_admin::AccountAdminListSubjectsInvocationError::Domain(error)) => {
                        Err(PluginError::domain(map_list_subjects_error(&error)))
                    }
                    Err(account_admin::AccountAdminListSubjectsInvocationError::Runtime(error)) => {
                        Err(PluginError::runtime(error))
                    }
                }
            }
            LIST_SESSIONS_TOOL => {
                let arguments = decode::<ListSessionsRequest>(&request)?;
                match self
                    .account_admin
                    .list_sessions_with_context(context, arguments)
                    .await
                {
                    Ok(response) => success(LIST_SESSIONS_TOOL, &response),
                    Err(account_admin::AccountAdminListSessionsInvocationError::Domain(error)) => {
                        Err(PluginError::domain(map_list_sessions_error(&error)))
                    }
                    Err(account_admin::AccountAdminListSessionsInvocationError::Runtime(error)) => {
                        Err(PluginError::runtime(error))
                    }
                }
            }
            SET_SUBJECT_STATUS_TOOL => {
                let arguments = decode::<SetSubjectStatusRequest>(&request)?;
                match self
                    .account_admin
                    .set_subject_status_with_context(context, arguments)
                    .await
                {
                    Ok(response) => success(SET_SUBJECT_STATUS_TOOL, &response),
                    Err(account_admin::AccountAdminSetSubjectStatusInvocationError::Domain(
                        error,
                    )) => Err(PluginError::domain(map_set_subject_status_error(&error))),
                    Err(account_admin::AccountAdminSetSubjectStatusInvocationError::Runtime(
                        error,
                    )) => Err(PluginError::runtime(error)),
                }
            }
            _ => Err(PluginError::domain(ExecuteError::NotFound)),
        }
    }
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            LIST_SUBJECTS_TOOL,
            "List canonical Auth subjects and their effective active or disabled status with bounded cursor pagination.",
            include_str!(
                "../../lenso-capability-account-admin/schemas/list-subjects-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            LIST_SESSIONS_TOOL,
            "List Auth sessions, optionally scoped to one subject, without returning credential material.",
            include_str!(
                "../../lenso-capability-account-admin/schemas/list-sessions-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            SET_SUBJECT_STATUS_TOOL,
            "Enable or disable one Auth subject. Disabling a subject revokes all of its active sessions atomically.",
            include_str!(
                "../../lenso-capability-account-admin/schemas/set-subject-status-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
    ]
}

fn tool(
    name: &str,
    description: &str,
    schema: &str,
    execution: ToolExecutionClass,
) -> ToolDefinition {
    let schema: serde_json::Value =
        serde_json::from_str(schema).expect("Auth Account Admin Tool schema must be valid JSON");
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema_json: schema
            .to_string()
            .try_into()
            .expect("Auth Account Admin Tool schema must remain valid JSON"),
        execution,
    }
}

fn decode<T: DeserializeOwned>(request: &ExecuteRequest) -> PluginResult<T, ExecuteError> {
    serde_json::from_str(request.arguments_json.as_str())
        .map_err(|_| PluginError::domain(ExecuteError::InvalidArguments))
}

fn success<T: Serialize>(
    tool_name: &str,
    response: &T,
) -> PluginResult<ExecuteResponse, ExecuteError> {
    let content = serde_json::to_string_pretty(response).map_err(|error| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!("Auth Account Admin Tool could not serialize its response: {error}"),
        })
    })?;
    Ok(ExecuteResponse {
        content_blocks: None,
        content,
        content_type: ContentType::Text,
        metadata_json: serde_json::json!({ "tool": tool_name })
            .to_string()
            .try_into()
            .expect("Auth Account Admin Tool metadata must be valid JSON"),
    })
}

fn map_list_subjects_error(error: &account_admin::ListSubjectsError) -> ExecuteError {
    match error {
        account_admin::ListSubjectsError::InvalidPage => ExecuteError::InvalidArguments,
        account_admin::ListSubjectsError::Forbidden => ExecuteError::PermissionDenied,
        account_admin::ListSubjectsError::Unknown(_) => rejected("unknown_domain_error"),
    }
}

fn map_list_sessions_error(error: &account_admin::ListSessionsError) -> ExecuteError {
    match error {
        account_admin::ListSessionsError::InvalidPage
        | account_admin::ListSessionsError::InvalidSubject => ExecuteError::InvalidArguments,
        account_admin::ListSessionsError::Forbidden => ExecuteError::PermissionDenied,
        account_admin::ListSessionsError::Unknown(_) => rejected("unknown_domain_error"),
    }
}

fn map_set_subject_status_error(error: &account_admin::SetSubjectStatusError) -> ExecuteError {
    match error {
        account_admin::SetSubjectStatusError::InvalidSubject
        | account_admin::SetSubjectStatusError::InvalidStatus => ExecuteError::InvalidArguments,
        account_admin::SetSubjectStatusError::NotFound => ExecuteError::NotFound,
        account_admin::SetSubjectStatusError::Forbidden => ExecuteError::PermissionDenied,
        account_admin::SetSubjectStatusError::Unknown(_) => rejected("unknown_domain_error"),
    }
}

fn rejected(reason_code: &str) -> ExecuteError {
    ExecuteError::ExecutionFailed {
        payload: ExecutionFailedPayload {
            reason_code: reason_code.to_owned(),
            message: "Auth Account Admin rejected the requested operation.".to_owned(),
            details_json: serde_json::json!({ "domain_error": reason_code })
                .to_string()
                .try_into()
                .expect("Auth Account Admin Tool error metadata must be valid JSON"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: &str, arguments: &str) -> ExecuteRequest {
        ExecuteRequest {
            name: name.to_owned(),
            arguments_json: arguments.try_into().unwrap(),
        }
    }

    #[test]
    fn descriptor_is_a_removable_account_admin_only_adapter() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(
            descriptor["plugin_id"],
            "lenso.auth.account-admin.agent-tools"
        );
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            "lenso.agent.tool-provider@2"
        );
        let required = descriptor["required_capabilities"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0]["capability_id"], "lenso.auth.account-admin@1");
    }

    #[test]
    fn catalog_has_two_reads_and_one_mutation_without_credentials() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 3);
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::ParallelSafe)
                .count(),
            2
        );
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::Exclusive)
                .count(),
            1
        );
        assert!(tools.iter().all(|tool| {
            !tool.name.contains("credential")
                && !tool.input_schema_json.as_str().contains("credential")
        }));
    }

    #[test]
    fn exact_requests_decode_and_domain_failures_remain_distinct() {
        let list = decode::<ListSessionsRequest>(&request(
            LIST_SESSIONS_TOOL,
            r#"{"subject":null,"limit":50,"cursor":null}"#,
        ))
        .unwrap();
        assert_eq!(list.limit, 50);
        assert!(
            decode::<ListSessionsRequest>(&request(
                LIST_SESSIONS_TOOL,
                r#"{"subject":null,"limit":"50","cursor":null}"#,
            ))
            .is_err()
        );

        assert_eq!(
            map_list_subjects_error(&account_admin::ListSubjectsError::Forbidden),
            ExecuteError::PermissionDenied
        );
        assert_eq!(
            map_set_subject_status_error(&account_admin::SetSubjectStatusError::NotFound),
            ExecuteError::NotFound
        );
        assert_eq!(
            map_set_subject_status_error(&account_admin::SetSubjectStatusError::InvalidStatus),
            ExecuteError::InvalidArguments
        );
    }
}
