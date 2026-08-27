//! Phone OTP and phone-password authentication with private durable state.
mod operator;
mod schema;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use lenso::{ActivateContext, DeactivateContext, Lifecycle, Port, provides};
use lenso_capability_credential_issuer as credential_issuer;
use lenso_capability_credential_issuer::{
    CredentialIssuerClient, CredentialIssuerIssueInvocationError, IssueError, IssueRequest,
    IssueResponse,
};
use lenso_capability_identity_directory as directory;
use lenso_capability_identity_directory::{
    DirectoryEnsureIdentityInvocationError, DirectoryReadStatusInvocationError,
    EnsureIdentityError, EnsureIdentityRequest, ReadStatusError, ReadStatusRequest,
    ReadStatusResponseStatus,
};
use lenso_capability_phone_auth as phone;
use lenso_capability_phone_auth::{
    PasswordLoginError, PasswordLoginRequest, PhonePasswordLogin, PhoneProvider, PhoneSetPassword,
    PhoneStartOtp, PhoneVerifyOtp, SessionResponse, SetPasswordError, SetPasswordRequest,
    SetPasswordResponse, StartOtpError, StartOtpRequest, StartOtpRequestPurpose, StartOtpResponse,
    VerifyOtpError, VerifyOtpRequest,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_capability_sms_delivery as sms;
use lenso_capability_sms_delivery::{SendRequest, SmsInvocationError};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
pub use operator::{PhoneOperator, PhoneOperatorError};
use schema::schema_plan;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::Row;
use std::{cell::RefCell, collections::BTreeMap, fmt, rc::Rc, time::Duration as StdDuration};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;
const TIMEOUT: StdDuration = StdDuration::from_secs(10);
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Environment {
    Development,
    Production,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneConfig {
    schema: String,
    database_url_secret: String,
    otp_secret_ref: String,
    environment: Environment,
    return_debug_code: bool,
    set_password_callers: Vec<String>,
    audience: Vec<String>,
    otp_code_length: usize,
    otp_ttl_seconds: u64,
    resend_cooldown_seconds: u64,
    otp_max_attempts: i32,
    start_window_seconds: u64,
    max_starts_per_ip: i64,
    max_password_failures: i64,
    password_failure_window_seconds: u64,
    session_ttl_seconds: u64,
}
impl PhoneConfig {
    fn validate(&self) -> Result<(), RuntimeFailure> {
        schema_plan(self.schema.clone()).map_err(|e| invalid(&e.to_string()))?;
        if self.database_url_secret.is_empty()
            || self.otp_secret_ref.is_empty()
            || self.database_url_secret == self.otp_secret_ref
            || self.set_password_callers.is_empty()
            || self.set_password_callers.iter().any(|v| !valid_name(v))
            || self.audience.is_empty()
            || !(4..=10).contains(&self.otp_code_length)
            || !(60..=3600).contains(&self.otp_ttl_seconds)
            || self.resend_cooldown_seconds > 3600
            || !(1..=20).contains(&self.otp_max_attempts)
            || !(60..=3600).contains(&self.start_window_seconds)
            || !(1..=100).contains(&self.max_starts_per_ip)
            || !(1..=100).contains(&self.max_password_failures)
            || !(60..=86400).contains(&self.password_failure_window_seconds)
            || !(1..=2_592_000).contains(&self.session_ttl_seconds)
            || self.return_debug_code && self.environment != Environment::Development
        {
            return Err(invalid("invalid Phone Auth configuration"));
        }
        Ok(())
    }
}
fn validate_config(config: &PhoneConfig) -> Result<(), RuntimeFailure> {
    config.validate()
}
#[derive(Clone)]
struct Prepared {
    postgres: OwnedPostgres,
    otp_secret: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("schema", &self.postgres.schema())
            .finish_non_exhaustive()
    }
}
struct Active {
    prepared: Prepared,
    config: PhoneConfig,
}
impl fmt::Debug for Active {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Active").finish_non_exhaustive()
    }
}
#[lenso::plugin(
    lifecycle,
    validate = validate_config,
    configuration_schema = "configuration.schema.json"
)]
#[derive(Clone)]
struct PhoneAuthPlugin {
    #[config]
    config: PhoneConfig,
    secrets: Port<secrets::SecretsClient>,
    directory: Port<directory::DirectoryClient>,
    issuer: Port<credential_issuer::CredentialIssuerClient>,
    sms: Port<sms::SmsClient>,
    prepared: Rc<RefCell<Option<Prepared>>>,
    active: Rc<RefCell<Option<Rc<Active>>>>,
}
#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for PhoneAuthPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhoneProvider")
            .field("active", &self.active.borrow().is_some())
            .finish()
    }
}
impl PhoneAuthPlugin {
    fn active(&self) -> Result<Rc<Active>, RuntimeFailure> {
        self.active
            .borrow()
            .clone()
            .ok_or_else(|| failure("Phone Auth is not active"))
    }
}
#[provides(phone::Phone)]
impl PhoneProvider for PhoneAuthPlugin {
    fn start_otp(
        &self,
        context: InvocationContext,
        r: StartOtpRequest,
    ) -> NativeRequestFuture<PhoneStartOtp> {
        let active = self.active();
        let sms = self.sms.clone();
        Box::pin(async move {
            let a = active?;
            let Some(phone) = normalize_phone(&r.phone) else {
                return Ok(Err(StartOtpError::InvalidPhone));
            };
            let purpose = match r.purpose {
                StartOtpRequestPurpose::Login => "login",
                StartOtpRequestPurpose::Register => "register",
            };
            let now = OffsetDateTime::now_utc();
            if let Some(ip) = r.client_ip.as_ref() {
                if ip.len() > 128 {
                    return Ok(Err(StartOtpError::RateLimited));
                }
                let since = now
                    - Duration::seconds(
                        i64::try_from(a.config.start_window_seconds).expect("validated"),
                    );
                let count:i64=sqlx::query_scalar("SELECT count(*) FROM phone_otp_challenges WHERE client_ip=$1 AND created_at>=$2").bind(ip).bind(since).fetch_one(a.prepared.postgres.pool()).await.map_err(db)?;
                if count >= a.config.max_starts_per_ip {
                    return Ok(Err(StartOtpError::RateLimited));
                }
            }
            let resend:Option<OffsetDateTime>=sqlx::query_scalar("SELECT resend_after FROM phone_otp_challenges WHERE phone=$1 ORDER BY created_at DESC LIMIT 1").bind(&phone).fetch_optional(a.prepared.postgres.pool()).await.map_err(db)?;
            if resend.is_some_and(|v| v > now) {
                return Ok(Err(StartOtpError::ResendTooSoon));
            }
            let code = random_digits(a.config.otp_code_length)?;
            let challenge_id = random_id("otp_")?;
            let digest = otp_digest(&a.prepared.otp_secret, &challenge_id, &code)?;
            let expires = now
                + Duration::seconds(i64::try_from(a.config.otp_ttl_seconds).expect("validated"));
            let resend_after = now
                + Duration::seconds(
                    i64::try_from(a.config.resend_cooldown_seconds).expect("validated"),
                );
            sqlx::query("INSERT INTO phone_otp_challenges(challenge_id,phone,purpose,code_digest,client_ip,expires_at,resend_after)VALUES($1,$2,$3,$4,$5,$6,$7)").bind(&challenge_id).bind(&phone).bind(purpose).bind(digest).bind(&r.client_ip).bind(expires).bind(resend_after).execute(a.prepared.postgres.pool()).await.map_err(db)?;
            let delivery = sms
                .send_with_context(
                    context,
                    SendRequest {
                        destination: phone.clone(),
                        body: format!("Your Lenso verification code is {code}"),
                    },
                )
                .await;
            if !matches!(delivery,Ok(ref v)if v.accepted) {
                sqlx::query("DELETE FROM phone_otp_challenges WHERE challenge_id=$1")
                    .bind(&challenge_id)
                    .execute(a.prepared.postgres.pool())
                    .await
                    .map_err(db)?;
                return match delivery {
                    Err(SmsInvocationError::Runtime(e)) => Err(e),
                    _ => Ok(Err(StartOtpError::DeliveryRejected)),
                };
            }
            Ok(Ok(StartOtpResponse {
                challenge_id,
                expires_at: format_time(expires)?,
                resend_after: format_time(resend_after)?,
                debug_code: a.config.return_debug_code.then_some(code),
            }))
        })
    }
    fn verify_otp(
        &self,
        context: InvocationContext,
        r: VerifyOtpRequest,
    ) -> NativeRequestFuture<PhoneVerifyOtp> {
        let active = self.active();
        let directory = self.directory.clone();
        let issuer = self.issuer.clone();
        Box::pin(async move {
            let a = active?;
            if !valid_name(&r.challenge_id)
                || r.code.len() != a.config.otp_code_length
                || !r.code.bytes().all(|b| b.is_ascii_digit())
            {
                return Ok(Err(VerifyOtpError::InvalidChallenge));
            }
            let mut tx = a.prepared.postgres.pool().begin().await.map_err(db)?;
            let row=sqlx::query("SELECT phone,code_digest,attempts,expires_at,consumed_at IS NOT NULL AS consumed FROM phone_otp_challenges WHERE challenge_id=$1 FOR UPDATE").bind(&r.challenge_id).fetch_optional(&mut*tx).await.map_err(db)?;
            let Some(row) = row else {
                return Ok(Err(VerifyOtpError::InvalidChallenge));
            };
            if row.try_get::<bool, _>("consumed").map_err(db)? {
                return Ok(Err(VerifyOtpError::InvalidChallenge));
            }
            let attempts: i32 = row.try_get("attempts").map_err(db)?;
            if attempts >= a.config.otp_max_attempts {
                return Ok(Err(VerifyOtpError::TooManyAttempts));
            }
            let expires: OffsetDateTime = row.try_get("expires_at").map_err(db)?;
            if expires <= OffsetDateTime::now_utc() {
                return Ok(Err(VerifyOtpError::Expired));
            }
            let stored: Vec<u8> = row.try_get("code_digest").map_err(db)?;
            if !otp_matches(&a.prepared.otp_secret, &r.challenge_id, &r.code, &stored)? {
                sqlx::query(
                    "UPDATE phone_otp_challenges SET attempts=attempts+1 WHERE challenge_id=$1",
                )
                .bind(&r.challenge_id)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
                tx.commit().await.map_err(db)?;
                return Ok(Err(if attempts + 1 >= a.config.otp_max_attempts {
                    VerifyOtpError::TooManyAttempts
                } else {
                    VerifyOtpError::InvalidCode
                }));
            }
            sqlx::query("UPDATE phone_otp_challenges SET consumed_at=transaction_timestamp() WHERE challenge_id=$1").bind(&r.challenge_id).execute(&mut*tx).await.map_err(db)?;
            tx.commit().await.map_err(db)?;
            let phone: String = row.try_get("phone").map_err(db)?;
            let identity = directory
                .ensure_identity_with_context(
                    context.clone(),
                    EnsureIdentityRequest {
                        provider: "phone".to_owned(),
                        external_subject: phone.clone(),
                    },
                )
                .await;
            let identity = match identity {
                Ok(v) => v,
                Err(DirectoryEnsureIdentityInvocationError::Domain(
                    EnsureIdentityError::Disabled,
                )) => return Ok(Err(VerifyOtpError::Disabled)),
                Err(DirectoryEnsureIdentityInvocationError::Domain(_)) => {
                    return Ok(Err(VerifyOtpError::InvalidChallenge));
                }
                Err(DirectoryEnsureIdentityInvocationError::Runtime(e)) => return Err(e),
            };
            sqlx::query("INSERT INTO phone_identities(phone,subject_id)VALUES($1,$2)ON CONFLICT(phone)DO UPDATE SET subject_id=EXCLUDED.subject_id").bind(&phone).bind(&identity.subject).execute(a.prepared.postgres.pool()).await.map_err(db)?;
            let credential = match issue(
                &a,
                &issuer,
                context,
                &identity.subject,
                "phone-otp",
                r.device_id,
            )
            .await
            {
                Ok(value) => value,
                Err(IssueCall::Disabled) => return Ok(Err(VerifyOtpError::Disabled)),
                Err(IssueCall::Runtime(error)) => return Err(error),
            };
            Ok(Ok(SessionResponse {
                subject: identity.subject,
                session_id: credential.session_id,
                credential: credential.credential,
                expires_at: credential.expires_at,
                masked_phone: mask_phone(&phone),
            }))
        })
    }
    fn set_password(
        &self,
        context: InvocationContext,
        r: SetPasswordRequest,
    ) -> NativeRequestFuture<PhoneSetPassword> {
        let active = self.active();
        let directory = self.directory.clone();
        Box::pin(async move {
            let a = active?;
            if !context
                .caller_instance()
                .is_some_and(|c| a.config.set_password_callers.iter().any(|v| v == c))
            {
                return Ok(Err(SetPasswordError::Forbidden));
            }
            if !valid_name(&r.subject) {
                return Ok(Err(SetPasswordError::InvalidSubject));
            }
            if !valid_password(&r.password) {
                return Ok(Err(SetPasswordError::WeakPassword));
            }
            match directory
                .read_status_with_context(
                    context,
                    ReadStatusRequest {
                        subject: r.subject.clone(),
                    },
                )
                .await
            {
                Ok(v) if v.status == ReadStatusResponseStatus::Active => {}
                Ok(_) => return Ok(Err(SetPasswordError::Disabled)),
                Err(DirectoryReadStatusInvocationError::Domain(ReadStatusError::NotFound)) => {
                    return Ok(Err(SetPasswordError::NotFound));
                }
                Err(DirectoryReadStatusInvocationError::Domain(_)) => {
                    return Ok(Err(SetPasswordError::InvalidSubject));
                }
                Err(DirectoryReadStatusInvocationError::Runtime(e)) => return Err(e),
            }
            let phone: Option<String> =
                sqlx::query_scalar("SELECT phone FROM phone_identities WHERE subject_id=$1")
                    .bind(&r.subject)
                    .fetch_optional(a.prepared.postgres.pool())
                    .await
                    .map_err(db)?;
            let Some(phone) = phone else {
                return Ok(Err(SetPasswordError::NotFound));
            };
            let hash = hash_password(&r.password)?;
            sqlx::query("INSERT INTO phone_passwords(subject_id,phone,password_hash)VALUES($1,$2,$3)ON CONFLICT(subject_id)DO UPDATE SET password_hash=EXCLUDED.password_hash,updated_at=transaction_timestamp()").bind(&r.subject).bind(phone).bind(hash).execute(a.prepared.postgres.pool()).await.map_err(db)?;
            Ok(Ok(SetPasswordResponse { updated: true }))
        })
    }
    fn password_login(
        &self,
        context: InvocationContext,
        r: PasswordLoginRequest,
    ) -> NativeRequestFuture<PhonePasswordLogin> {
        let active = self.active();
        let issuer = self.issuer.clone();
        Box::pin(async move {
            let a = active?;
            let Some(phone) = normalize_phone(&r.phone) else {
                return Ok(Err(PasswordLoginError::InvalidPhone));
            };
            let since = OffsetDateTime::now_utc()
                - Duration::seconds(
                    i64::try_from(a.config.password_failure_window_seconds).expect("validated"),
                );
            let failures: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM phone_login_failures WHERE phone=$1 AND failed_at>=$2",
            )
            .bind(&phone)
            .bind(since)
            .fetch_one(a.prepared.postgres.pool())
            .await
            .map_err(db)?;
            if failures >= a.config.max_password_failures {
                return Ok(Err(PasswordLoginError::RateLimited));
            }
            let row =
                sqlx::query("SELECT subject_id,password_hash FROM phone_passwords WHERE phone=$1")
                    .bind(&phone)
                    .fetch_optional(a.prepared.postgres.pool())
                    .await
                    .map_err(db)?;
            let valid = row.as_ref().is_some_and(|row| {
                row.try_get::<String, _>("password_hash")
                    .is_ok_and(|hash| verify_password(&r.password, &hash))
            });
            if !valid {
                sqlx::query("INSERT INTO phone_login_failures(phone)VALUES($1)")
                    .bind(&phone)
                    .execute(a.prepared.postgres.pool())
                    .await
                    .map_err(db)?;
                return Ok(Err(PasswordLoginError::InvalidCredentials));
            }
            sqlx::query("DELETE FROM phone_login_failures WHERE phone=$1")
                .bind(&phone)
                .execute(a.prepared.postgres.pool())
                .await
                .map_err(db)?;
            let subject: String = row
                .expect("verified row")
                .try_get("subject_id")
                .map_err(db)?;
            let credential = match issue(
                &a,
                &issuer,
                context,
                &subject,
                "phone-password",
                r.device_id,
            )
            .await
            {
                Ok(v) => v,
                Err(IssueCall::Disabled) => return Ok(Err(PasswordLoginError::Disabled)),
                Err(IssueCall::Runtime(e)) => return Err(e),
            };
            Ok(Ok(SessionResponse {
                subject,
                session_id: credential.session_id,
                credential: credential.credential,
                expires_at: credential.expires_at,
                masked_phone: mask_phone(&phone),
            }))
        })
    }
}
enum IssueCall {
    Disabled,
    Runtime(RuntimeFailure),
}
async fn issue(
    a: &Active,
    issuer: &CredentialIssuerClient,
    context: InvocationContext,
    subject: &str,
    assurance: &str,
    device: Option<String>,
) -> Result<IssueResponse, IssueCall> {
    let expires = OffsetDateTime::now_utc()
        + Duration::seconds(i64::try_from(a.config.session_ttl_seconds).expect("validated"));
    let mut claims = BTreeMap::new();
    if let Some(device) = device {
        claims.insert("device_id".to_owned(), serde_json::Value::String(device));
    }
    issuer
        .issue_with_context(
            context,
            IssueRequest {
                subject: subject.to_owned(),
                actor_kind: "user".to_owned(),
                assurance: assurance.to_owned(),
                audience: a.config.audience.clone(),
                claims,
                expires_at: format_time(expires).map_err(IssueCall::Runtime)?,
            },
        )
        .await
        .map_err(|e| match e {
            CredentialIssuerIssueInvocationError::Domain(IssueError::Disabled) => {
                IssueCall::Disabled
            }
            CredentialIssuerIssueInvocationError::Domain(e) => IssueCall::Runtime(failure(
                &format!("credential issuer rejected phone session: {e:?}"),
            )),
            CredentialIssuerIssueInvocationError::Runtime(e) => IssueCall::Runtime(e),
        })
}
impl Lifecycle for PhoneAuthPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let c = self.config.clone();
        let deps = context.dependencies().clone();
        let cancel = context.cancellation();
        let state = self.prepared.clone();
        let dbs = resolve(&self.secrets, &deps, cancel.clone(), &c.database_url_secret).await?;
        let otp = resolve(&self.secrets, &deps, cancel, &c.otp_secret_ref).await?;
        if otp.len() < 32 {
            return Err(failure("OTP secret must contain at least 32 bytes"));
        }
        let postgres = OwnedPostgres::prepare(
            &dbs,
            schema_plan(c.schema.clone()).map_err(|e| invalid(&e.to_string()))?,
        )
        .await
        .map_err(|e| failure(&e.to_string()))?;
        let prepared = Prepared {
            postgres,
            otp_secret: Zeroizing::new(otp.as_bytes().to_vec()),
        };
        state.replace(Some(prepared.clone()));
        let active = self.active.clone();
        active.replace(Some(Rc::new(Active {
            prepared,
            config: c,
        })));
        Ok(())
    }

    async fn deactivate(&self, _: DeactivateContext) -> Result<(), RuntimeFailure> {
        self.active.borrow_mut().take();
        let prepared = self.prepared.borrow_mut().take();
        if let Some(p) = prepared {
            p.postgres.pool().close().await;
        }
        Ok(())
    }
}
async fn resolve(
    client: &SecretsClient,
    deps: &lenso_kernel::PluginDependencies,
    cancel: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = deps.invocation_context_after(TIMEOUT, cancel)?;
    client
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|v| Zeroizing::new(v.value))
        .map_err(|e| match e {
            SecretsInvocationError::Domain(_) => failure("Phone Auth secret was rejected"),
            SecretsInvocationError::Runtime(e) => e,
        })
}
fn normalize_phone(v: &str) -> Option<String> {
    let mut out = String::new();
    for (c, i) in v.trim().chars().zip(0..) {
        if (c == '+' && i == 0) || c.is_ascii_digit() {
            out.push(c);
        } else if !matches!(c, ' ' | '-' | '(' | ')') {
            return None;
        }
    }
    let digits = out.trim_start_matches('+');
    ((8..=15).contains(&digits.len())).then(|| format!("+{digits}"))
}
fn mask_phone(v: &str) -> String {
    let d = v.trim_start_matches('+');
    let keep = d.len().min(4);
    format!("+{}{}", "*".repeat(d.len() - keep), &d[d.len() - keep..])
}
fn random_digits(n: usize) -> Result<String, RuntimeFailure> {
    let mut out = String::with_capacity(n);
    while out.len() < n {
        let mut b = [0u8; 1];
        getrandom::fill(&mut b).map_err(|_| failure("random source unavailable"))?;
        if b[0] < 250 {
            out.push(char::from(b'0' + b[0] % 10));
        }
    }
    Ok(out)
}
fn random_id(prefix: &str) -> Result<String, RuntimeFailure> {
    let mut b = [0u8; 18];
    getrandom::fill(&mut b).map_err(|_| failure("random source unavailable"))?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(b)))
}
fn otp_digest(key: &[u8], id: &str, code: &str) -> Result<Vec<u8>, RuntimeFailure> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| failure("invalid OTP secret"))?;
    mac.update(id.as_bytes());
    mac.update(b":");
    mac.update(code.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}
fn otp_matches(key: &[u8], id: &str, code: &str, expected: &[u8]) -> Result<bool, RuntimeFailure> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| failure("invalid OTP secret"))?;
    mac.update(id.as_bytes());
    mac.update(b":");
    mac.update(code.as_bytes());
    Ok(mac.verify_slice(expected).is_ok())
}
fn valid_name(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 256
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}
fn valid_password(v: &str) -> bool {
    (8..=1024).contains(&v.len())
}
fn hash_password(v: &str) -> Result<String, RuntimeFailure> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| failure("random source unavailable"))?;
    let salt = SaltString::encode_b64(&b).map_err(|_| failure("password salt failed"))?;
    Argon2::default()
        .hash_password(v.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| failure("password hashing failed"))
}
fn verify_password(v: &str, h: &str) -> bool {
    PasswordHash::new(h).is_ok_and(|p| Argon2::default().verify_password(v.as_bytes(), &p).is_ok())
}
fn format_time(v: OffsetDateTime) -> Result<String, RuntimeFailure> {
    v.format(&Rfc3339).map_err(|e| failure(&e.to_string()))
}
fn invalid(d: &str) -> RuntimeFailure {
    RuntimeFailure::InvalidResolvedPlan {
        detail: d.to_owned(),
    }
}
fn failure(d: &str) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: d.to_owned(),
    }
}
#[allow(clippy::needless_pass_by_value)]
fn db(e: sqlx::Error) -> RuntimeFailure {
    failure(&format!("Phone Auth storage operation failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_normalization_is_canonical_and_rejects_invalid_input() {
        assert_eq!(
            normalize_phone("+86 138-0013-8000"),
            Some("+8613800138000".into())
        );
        assert_eq!(normalize_phone("13800138000"), Some("+13800138000".into()));
        assert_eq!(normalize_phone("+12.ext"), None);
        assert_eq!(normalize_phone("123"), None);
        assert_eq!(mask_phone("+8613800138000"), "+*********8000");
    }

    #[test]
    fn otp_digest_binds_code_to_challenge() {
        let key = [7_u8; 32];
        let first = otp_digest(&key, "otp_a", "123456").unwrap();
        assert_eq!(first, otp_digest(&key, "otp_a", "123456").unwrap());
        assert_ne!(first, otp_digest(&key, "otp_b", "123456").unwrap());
        assert_ne!(first, otp_digest(&key, "otp_a", "654321").unwrap());
        assert!(otp_matches(&key, "otp_a", "123456", &first).unwrap());
        assert!(!otp_matches(&key, "otp_a", "654321", &first).unwrap());
    }

    #[test]
    fn password_hash_round_trip_does_not_store_plaintext() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(!hash.contains("correct horse battery staple"));
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong", &hash));
    }
}
