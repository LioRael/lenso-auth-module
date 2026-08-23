use lenso_postgres_kit::{Migration, PlanError, SchemaPlan};

const MIGRATIONS: &[Migration] = &[Migration::new(
    1,
    "create-api-token-sessions",
    "CREATE TABLE auth_sessions (\n\
       session_id text PRIMARY KEY,\n\
       subject text NOT NULL,\n\
       actor_kind text NOT NULL,\n\
       assurance text NOT NULL,\n\
       audience text[] NOT NULL,\n\
       claims jsonb NOT NULL,\n\
       expires_at timestamptz NOT NULL,\n\
       revoked_at timestamptz,\n\
       created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),\n\
       CHECK (cardinality(audience) > 0),\n\
       CHECK (expires_at > created_at)\n\
     );\n\
     CREATE TABLE api_tokens (\n\
       token_id text PRIMARY KEY,\n\
       token_digest bytea UNIQUE NOT NULL,\n\
       session_id text NOT NULL REFERENCES auth_sessions(session_id),\n\
       expires_at timestamptz NOT NULL,\n\
       revoked_at timestamptz,\n\
       created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),\n\
       CHECK (expires_at > created_at)\n\
     );\n\
     CREATE INDEX api_tokens_session_id_idx ON api_tokens(session_id)",
)];

pub(crate) fn schema_plan(schema: impl Into<std::sync::Arc<str>>) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, MIGRATIONS)
}
