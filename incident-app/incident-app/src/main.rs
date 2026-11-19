//! Secure Incident-Reporting Application - backend API.
//!
//! Apache terminates HTTPS and forwards `/api/*` to this process, which listens
//! on 127.0.0.1 only (BIND_ADDR). The browser never talks to this process
//! directly, and no security group exposes its port.
//!
//! Environment variables (set in the systemd unit):
//! - `APP_SECRET_ID`  Secrets Manager secret holding the database credentials
//! - `AWS_REGION`     region of that secret (us-east-2)
//! - `BIND_ADDR`      listen address, default `127.0.0.1:3000`
//! - `LOG_DIR`        directory for `app.log`; logs go to stdout when unset
//! - `RUST_LOG`       log level filter, default `info`
//! - `DATABASE_URL`   local development only, used when `APP_SECRET_ID` is unset

mod audit;
mod auth;
mod config;
mod error;
mod routes;
mod validate;

use std::sync::Arc;

use axum::{extract::DefaultBodyLimit, Router};
use sqlx::PgPool;
use tower_http::{
    catch_panic::CatchPanicLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

/// Shared state available to every request handler.
#[derive(Clone)]
pub struct AppState {
    /// Connection pool to RDS PostgreSQL, logged in as the limited `app_user`.
    pub db: PgPool,
    /// Argon2 hash of a random value. Login verifies against it when the
    /// username does not exist, so a failed login takes the same time either
    /// way and response timing does not reveal which usernames exist.
    pub dummy_hash: Arc<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Helper mode, used once to create the first admin by hand:
    //   echo 'the-password' | ./incident-app hash-password
    if std::env::args().nth(1).as_deref() == Some("hash-password") {
        return print_password_hash();
    }

    // The guard must live until the end of main so buffered log lines are flushed.
    let _log_guard = init_logging();

    let db = config::connect_db().await?;
    let dummy_hash = Arc::new(auth::hash_password(&auth::random_token())?);
    let state = AppState { db, dummy_hash };

    spawn_session_cleanup(state.db.clone());

    let app = Router::new()
        .nest("/api", routes::router())
        .with_state(state)
        // Largest valid body is ~10 KB (incident description); reject anything over 64 KB.
        .layer(DefaultBodyLimit::max(64 * 1024))
        // One log line per request: method, path, status, latency.
        // Request headers (and therefore cookies) are not logged (SR-9).
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        // A panic inside a handler becomes a generic 500 response instead of a
        // dropped connection, and the server keeps running (NFR-6).
        .layer(CatchPanicLayer::custom(error::panic_response));

    let addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "incident-app listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("incident-app stopped");
    Ok(())
}

/// Reads one line from stdin and prints its Argon2id hash.
fn print_password_hash() -> anyhow::Result<()> {
    let mut password = String::new();
    std::io::stdin().read_line(&mut password)?;
    let password = password.trim_end_matches(['\r', '\n']);
    validate::password(password)?;
    println!("{}", auth::hash_password(password)?);
    Ok(())
}

/// Sends logs to `$LOG_DIR/app.log` (picked up by the CloudWatch agent) or,
/// when LOG_DIR is unset, to stdout for local development.
fn init_logging() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match std::env::var("LOG_DIR") {
        Ok(dir) => {
            let file = tracing_appender::rolling::never(dir, "app.log");
            let (writer, guard) = tracing_appender::non_blocking(file);
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(writer)
                .with_ansi(false)
                .init();
            Some(guard)
        }
        Err(_) => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
            None
        }
    }
}

/// Deletes expired sessions once an hour so the table does not grow forever.
fn spawn_session_cleanup(db: PgPool) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            if let Err(e) = sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
                .execute(&db)
                .await
            {
                tracing::warn!(error = %e, "expired-session cleanup failed");
            }
        }
    });
}

/// Completes on Ctrl+C or SIGTERM (sent by `systemctl stop`), letting
/// in-flight requests finish before the process exits.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
