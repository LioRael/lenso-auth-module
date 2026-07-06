use crate::config::AuthPhoneConfig;
use crate::module::RESET_PHONE_PASSWORD_ACTION;
use crate::repositories::{PhoneAuthRepository, SetPhonePasswordOptions};
use auth::public::AuthUserId;
use platform_core::{AppContext, AppError, AppResult, ErrorCode};
use platform_module::AdminActionSource;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct AuthPhoneAdminActions {
    ctx: AppContext,
    repository: PhoneAuthRepository,
}

impl AuthPhoneAdminActions {
    #[must_use]
    pub fn new(ctx: AppContext) -> Self {
        Self {
            repository: PhoneAuthRepository::new(ctx.db.clone()),
            ctx,
        }
    }
}

#[async_trait::async_trait]
impl AdminActionSource for AuthPhoneAdminActions {
    async fn invoke(&self, action: &str, input: Value) -> AppResult<Value> {
        match action {
            RESET_PHONE_PASSWORD_ACTION => {
                let user_id = AuthUserId(required_string(&input, "user_id")?.to_owned());
                let new_password = required_string(&input, "new_password")?;
                let config = AuthPhoneConfig::from_context(&self.ctx)?;
                let updated = self
                    .repository
                    .set_password(SetPhonePasswordOptions {
                        user_id: &user_id,
                        password: new_password,
                        now: self.ctx.clock.now(),
                        config: &config,
                    })
                    .await?;
                if !updated {
                    return Err(AppError::new(
                        ErrorCode::NotFound,
                        "phone identity not found for user",
                    ));
                }
                Ok(serde_json::json!({
                    "reset": true,
                    "user_id": user_id.0,
                }))
            }
            other => Err(AppError::new(
                ErrorCode::NotFound,
                format!("Unknown auth-phone admin action `{other}`"),
            )),
        }
    }
}

fn required_string<'a>(input: &'a Value, name: &str) -> AppResult<&'a str> {
    input
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::new(ErrorCode::Validation, format!("{name} is required")))
}
