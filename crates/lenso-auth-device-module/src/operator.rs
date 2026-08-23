use crate::schema::schema_plan;
use lenso_postgres_kit::{PostgresKitError, SchemaOperator, SetupOutcome, UpgradeOutcome};
use thiserror::Error;
#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceAuthOperator;
impl DeviceAuthOperator {
    pub async fn setup(
        database_url: &str,
        schema: &str,
    ) -> Result<SetupOutcome, DeviceOperatorError> {
        Ok(SchemaOperator::connect(database_url, schema_plan(schema)?)
            .await?
            .setup()
            .await?)
    }
    pub async fn upgrade(
        database_url: &str,
        schema: &str,
    ) -> Result<UpgradeOutcome, DeviceOperatorError> {
        Ok(SchemaOperator::connect(database_url, schema_plan(schema)?)
            .await?
            .upgrade()
            .await?)
    }
}
#[derive(Debug, Error)]
pub enum DeviceOperatorError {
    #[error(transparent)]
    Plan(#[from] lenso_postgres_kit::PlanError),
    #[error(transparent)]
    Postgres(#[from] PostgresKitError),
}
