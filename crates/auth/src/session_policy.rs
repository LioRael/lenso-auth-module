use crate::models::AuthUserId;
use chrono::{DateTime, Utc};
use platform_core::{AppContext, AppResult, ClientRequestMetadata};
use std::sync::Arc;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionCreateOptions {
    pub device_id: Option<String>,
    pub client: ClientRequestMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCreateInput {
    pub user_id: AuthUserId,
    pub session_id: String,
    pub proposed_device_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub client: ClientRequestMetadata,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionCreateDecision {
    pub device_id: Option<String>,
}

#[async_trait::async_trait]
pub trait AuthSessionPolicy: std::fmt::Debug + Send + Sync {
    async fn before_session_create(
        &self,
        input: &SessionCreateInput,
    ) -> AppResult<SessionCreateDecision>;
}

pub type AuthSessionPolicyFactory = fn(&AppContext) -> Arc<dyn AuthSessionPolicy>;

#[derive(Debug, Clone, Copy)]
pub struct AuthHostExtension {
    session_policy: Option<AuthSessionPolicyFactory>,
}

impl AuthHostExtension {
    #[must_use]
    pub const fn session_policy(factory: AuthSessionPolicyFactory) -> Self {
        Self {
            session_policy: Some(factory),
        }
    }

    #[must_use]
    pub const fn session_policy_factory(self) -> Option<AuthSessionPolicyFactory> {
        self.session_policy
    }
}

#[derive(Debug, Clone)]
pub struct AuthSessionPolicyHandle {
    policy: Arc<dyn AuthSessionPolicy>,
}

impl AuthSessionPolicyHandle {
    #[must_use]
    pub fn new(policy: Arc<dyn AuthSessionPolicy>) -> Self {
        Self { policy }
    }

    #[must_use]
    pub fn allow() -> Self {
        Self::new(Arc::new(AllowSessionPolicy))
    }

    #[must_use]
    pub fn policy(&self) -> &dyn AuthSessionPolicy {
        self.policy.as_ref()
    }

    #[must_use]
    pub fn into_policy(self) -> Arc<dyn AuthSessionPolicy> {
        self.policy
    }
}

impl Default for AuthSessionPolicyHandle {
    fn default() -> Self {
        Self::allow()
    }
}

#[derive(Debug, Clone)]
pub struct AuthSessionPolicyChain {
    policies: Vec<Arc<dyn AuthSessionPolicy>>,
}

impl AuthSessionPolicyChain {
    #[must_use]
    pub fn new(policies: Vec<Arc<dyn AuthSessionPolicy>>) -> Self {
        Self { policies }
    }

    #[must_use]
    pub fn handle(policies: Vec<Arc<dyn AuthSessionPolicy>>) -> AuthSessionPolicyHandle {
        if policies.is_empty() {
            AuthSessionPolicyHandle::allow()
        } else {
            AuthSessionPolicyHandle::new(Arc::new(Self::new(policies)))
        }
    }
}

#[async_trait::async_trait]
impl AuthSessionPolicy for AuthSessionPolicyChain {
    async fn before_session_create(
        &self,
        input: &SessionCreateInput,
    ) -> AppResult<SessionCreateDecision> {
        let mut next_input = input.clone();
        let mut decision = AllowSessionPolicy
            .before_session_create(&next_input)
            .await?;

        for policy in &self.policies {
            next_input.proposed_device_id = decision.device_id;
            decision = policy.before_session_create(&next_input).await?;
        }

        Ok(decision)
    }
}

#[derive(Debug, Default)]
pub struct AllowSessionPolicy;

#[async_trait::async_trait]
impl AuthSessionPolicy for AllowSessionPolicy {
    async fn before_session_create(
        &self,
        input: &SessionCreateInput,
    ) -> AppResult<SessionCreateDecision> {
        Ok(SessionCreateDecision {
            device_id: input.proposed_device_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::sync::Arc;

    #[tokio::test]
    async fn policy_chain_applies_session_policies_in_order() {
        let chain = AuthSessionPolicyChain::new(vec![
            Arc::new(SuffixPolicy("-trusted")),
            Arc::new(SuffixPolicy("-primary")),
        ]);
        let now = Utc::now();

        let decision = chain
            .before_session_create(&SessionCreateInput {
                user_id: AuthUserId("usr_policy".to_owned()),
                session_id: "sess_policy".to_owned(),
                proposed_device_id: Some("device".to_owned()),
                created_at: now,
                expires_at: now,
                client: Default::default(),
            })
            .await
            .expect("policy chain should allow session");

        assert_eq!(
            decision.device_id.as_deref(),
            Some("device-trusted-primary")
        );
    }

    #[derive(Debug)]
    struct SuffixPolicy(&'static str);

    #[async_trait::async_trait]
    impl AuthSessionPolicy for SuffixPolicy {
        async fn before_session_create(
            &self,
            input: &SessionCreateInput,
        ) -> AppResult<SessionCreateDecision> {
            Ok(SessionCreateDecision {
                device_id: input
                    .proposed_device_id
                    .as_ref()
                    .map(|device_id| format!("{device_id}{}", self.0)),
            })
        }
    }
}
