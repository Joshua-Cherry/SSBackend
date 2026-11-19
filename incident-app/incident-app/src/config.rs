//! Database connection settings.
//!
//! In production the credentials come from AWS Secrets Manager (SR-14): the
//! secret named by `APP_SECRET_ID` is read with the EC2 instance role, so no
//! password is stored on disk, in the repo or in the systemd unit.
//! `DATABASE_URL` is accepted only for local development.

use anyhow::Context;
use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::PgPool;

/// Shape of the `incident-app/config` secret. Deliberately has no `Debug`
/// implementation so it cannot be printed or logged by accident (SR-9).
/// Other keys in the secret (such as `session_key`) are ignored.
#[derive(Deserialize)]
struct DbSecret {
    db_host: String,
    db_port: serde_json::Value,
    db_name: String,
    db_user: String,
    db_password: String,
}

/// Opens the connection pool. Fails at startup (rather than on the first
/// request) if the database is unreachable or the credentials are wrong.
pub async fn connect_db() -> anyhow::Result<PgPool> {
    let options = match std::env::var("APP_SECRET_ID") {
        Ok(secret_id) => options_from_secret(&secret_id).await?,
        Err(_) => {
            tracing::warn!("APP_SECRET_ID not set; using DATABASE_URL (development only)");
            let url = std::env::var("DATABASE_URL")
                .context("set APP_SECRET_ID (production) or DATABASE_URL (local development)")?;
            url.parse::<PgConnectOptions>()
                .context("DATABASE_URL is not a valid PostgreSQL URL")?
        }
    };

    let pool = PgPoolOptions::new()
        // db.t4g.micro allows ~80 connections; 10 easily serves 50 users (NFR-4).
        .max_connections(10)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(options)
        .await
        .context("could not connect to the database")?;
    tracing::info!("connected to the database");
    Ok(pool)
}

/// Reads the secret and builds TLS-only connection options.
async fn options_from_secret(secret_id: &str) -> anyhow::Result<PgConnectOptions> {
    let aws = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&aws);

    let response = client
        .get_secret_value()
        .secret_id(secret_id)
        .send()
        .await
        .with_context(|| format!("could not read secret {secret_id} from Secrets Manager"))?;
    let raw = response
        .secret_string()
        .context("the secret has no string value")?;
    let secret: DbSecret =
        serde_json::from_str(raw).context("the secret is not the expected JSON key/value set")?;

    Ok(PgConnectOptions::new()
        .host(&secret.db_host)
        .port(parse_port(&secret.db_port)?)
        .database(&secret.db_name)
        .username(&secret.db_user)
        .password(&secret.db_password)
        // Encrypt the connection to RDS; plain-text connections are refused.
        .ssl_mode(PgSslMode::Require))
}

/// Secrets Manager stores key/value pairs as strings, but accept a number too.
fn parse_port(value: &serde_json::Value) -> anyhow::Result<u16> {
    match value {
        serde_json::Value::String(s) => Ok(s.trim().parse().context("db_port is not a number")?),
        serde_json::Value::Number(n) => n
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .context("db_port is out of range"),
        _ => anyhow::bail!("db_port must be a number"),
    }
}
