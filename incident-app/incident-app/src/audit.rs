//! Audit trail (FR-11, FR-12, SR-9, SR-10, SR-11).
//!
//! The app inserts only who, what and which target. The database trigger fills
//! in the id, the timestamp and the hash chain, and other triggers reject any
//! UPDATE, DELETE or TRUNCATE on the table. `app_user` has only SELECT and
//! INSERT on it, so the application itself cannot alter history.
//!
//! Each insert is made in the same transaction as the action it records, so an
//! action and its audit row are committed together or not at all.
//!
//! IMPORTANT: the insert trigger takes a lock that serialises the hash chain.
//! Always record audit rows as the LAST statements of a transaction, so the
//! lock is never held while waiting for other row locks (avoids deadlocks).
//!
//! Never put passwords, tokens or incident descriptions in an audit row (SR-9).

use sqlx::PgConnection;

pub const LOGIN_SUCCESS: &str = "LOGIN_SUCCESS";
pub const LOGIN_FAILED: &str = "LOGIN_FAILED";
pub const LOGOUT: &str = "LOGOUT";
pub const PASSWORD_CHANGED: &str = "PASSWORD_CHANGED";
pub const PASSWORD_RESET: &str = "PASSWORD_RESET";
pub const USER_CREATED: &str = "USER_CREATED";
pub const ROLE_CHANGED: &str = "ROLE_CHANGED";
pub const USER_DEACTIVATED: &str = "USER_DEACTIVATED";
pub const USER_REACTIVATED: &str = "USER_REACTIVATED";
pub const INCIDENT_CREATED: &str = "INCIDENT_CREATED";
pub const STATUS_CHANGED: &str = "STATUS_CHANGED";
pub const COMMENT_CREATED: &str = "COMMENT_CREATED";

/// Appends one audit row.
///
/// - `actor_id`: the user who acted (`None` when unknown, e.g. a failed login)
/// - `action`: one of the constants above
/// - `target_type` / `target_id`: what was acted on
pub async fn record(
    conn: &mut PgConnection,
    actor_id: Option<i64>,
    action: &str,
    target_type: &str,
    target_id: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_logs (user_id, action, target_type, target_id)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(actor_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}
