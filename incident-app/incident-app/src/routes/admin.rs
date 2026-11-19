//! User management and audit log access (FR-1 to FR-3, FR-11, FR-12, SR-6).
//! Every handler here requires the admin role.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, patch},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    audit,
    auth::{self, AuthUser, Role},
    error::{AppError, AppJson},
    validate, AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/users", get(list_users).post(create_user))
        .route("/admin/users/{id}", patch(update_user))
        .route("/admin/audit", get(list_audit))
        .route("/admin/audit/verify", get(verify_audit))
}

#[derive(Serialize, sqlx::FromRow)]
struct UserView {
    id: i64,
    username: String,
    role: String,
    is_active: bool,
    locked_until: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

/// GET /api/admin/users  (never returns password hashes)
async fn list_users(
    State(state): State<AppState>,
    admin: AuthUser,
) -> Result<Json<Vec<UserView>>, AppError> {
    admin.require(&[Role::Admin])?;
    let users: Vec<UserView> = sqlx::query_as(
        "SELECT u.id, u.username, r.name AS role, u.is_active, u.locked_until, u.created_at
           FROM users u
           JOIN roles r ON r.id = u.role_id
          ORDER BY u.id",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(users))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewUser {
    username: String,
    password: String,
    role: String,
}

/// POST /api/admin/users  `{ "username": "...", "password": "...", "role": "user" }`  (FR-1, FR-2)
async fn create_user(
    State(state): State<AppState>,
    admin: AuthUser,
    AppJson(req): AppJson<NewUser>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    admin.require(&[Role::Admin])?;
    let username = req.username.trim().to_string();
    validate::username(&username)?;
    validate::password(&req.password)?;
    if req.password.eq_ignore_ascii_case(&username) {
        return Err(AppError::BadRequest(
            "The password must not be the same as the username.".to_string(),
        ));
    }
    let role = validate::role(&req.role)?;
    // Hash before opening the transaction (it is slow).
    let hash = auth::hash_password_async(req.password).await?;

    let mut tx = state.db.begin().await?;
    let inserted: Result<(i64,), sqlx::Error> = sqlx::query_as(
        "INSERT INTO users (username, password_hash, role_id)
         VALUES ($1, $2, $3)
         RETURNING id",
    )
    .bind(&username)
    .bind(&hash)
    .bind(role.id())
    .fetch_one(&mut *tx)
    .await;
    let (id,) = match inserted {
        Ok(row) => row,
        // Unique index on lower(username): "Admin" and "admin" collide.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(AppError::Conflict(
                "That username is already taken.".to_string(),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    audit::record(
        &mut tx,
        Some(admin.id),
        audit::USER_CREATED,
        "user",
        Some(id),
    )
    .await?;
    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserChange {
    role: Option<String>,
    is_active: Option<bool>,
    /// Admin password reset.
    password: Option<String>,
}

/// PATCH /api/admin/users/{id}
/// `{ "role": "reviewer" }`, `{ "is_active": false }`, `{ "password": "..." }`
/// or any combination (FR-2, FR-3).
async fn update_user(
    State(state): State<AppState>,
    admin: AuthUser,
    Path(id): Path<i64>,
    AppJson(req): AppJson<UserChange>,
) -> Result<Json<Value>, AppError> {
    admin.require(&[Role::Admin])?;

    // SR-6: nobody changes their own role or deactivates themselves. Admins
    // change their own password through /api/auth/password instead.
    if id == admin.id {
        tracing::warn!(
            user_id = admin.id,
            "blocked attempt to modify own account via admin endpoint"
        );
        return Err(AppError::Forbidden);
    }
    if req.role.is_none() && req.is_active.is_none() && req.password.is_none() {
        return Err(AppError::BadRequest("Nothing to update.".to_string()));
    }

    let new_role = req.role.as_deref().map(validate::role).transpose()?;
    let new_hash = match req.password {
        Some(password) => {
            validate::password(&password)?;
            Some(auth::hash_password_async(password).await?)
        }
        None => None,
    };

    let mut tx = state.db.begin().await?;
    // Lock the user row so concurrent admin edits apply one after the other (NFR-5).
    let current: Option<(i16, bool)> =
        sqlx::query_as("SELECT role_id, is_active FROM users WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let (current_role_id, current_active) = current.ok_or(AppError::NotFound)?;

    // Audit rows are written at the end (see audit.rs), so collect them first.
    let mut changes: Vec<&'static str> = Vec::new();

    if let Some(role) = new_role {
        if role.id() != current_role_id {
            sqlx::query("UPDATE users SET role_id = $1, updated_at = now() WHERE id = $2")
                .bind(role.id())
                .bind(id)
                .execute(&mut *tx)
                .await?;
            changes.push(audit::ROLE_CHANGED);
        }
    }

    if let Some(active) = req.is_active {
        if active != current_active {
            sqlx::query("UPDATE users SET is_active = $1, updated_at = now() WHERE id = $2")
                .bind(active)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            if !active {
                // Deactivation logs the user out everywhere immediately.
                sqlx::query("DELETE FROM sessions WHERE user_id = $1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
            }
            changes.push(if active {
                audit::USER_REACTIVATED
            } else {
                audit::USER_DEACTIVATED
            });
        }
    }

    if let Some(hash) = new_hash {
        sqlx::query(
            "UPDATE users
                SET password_hash = $1, failed_logins = 0, locked_until = NULL, updated_at = now()
              WHERE id = $2",
        )
        .bind(&hash)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        changes.push(audit::PASSWORD_RESET);
    }

    for action in &changes {
        audit::record(&mut tx, Some(admin.id), action, "user", Some(id)).await?;
    }
    tx.commit().await?;

    Ok(Json(json!({ "id": id, "changes": changes })))
}

#[derive(Deserialize)]
struct AuditParams {
    limit: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
struct AuditView {
    id: i64,
    user_id: Option<i64>,
    username: Option<String>,
    action: String,
    target_type: String,
    target_id: Option<i64>,
    created_at: DateTime<Utc>,
    hash: String,
}

/// GET /api/admin/audit?limit=200 - newest first.
async fn list_audit(
    State(state): State<AppState>,
    admin: AuthUser,
    Query(params): Query<AuditParams>,
) -> Result<Json<Vec<AuditView>>, AppError> {
    admin.require(&[Role::Admin])?;
    let limit = params.limit.unwrap_or(200).clamp(1, 1000);
    let rows: Vec<AuditView> = sqlx::query_as(
        "SELECT a.id, a.user_id, u.username, a.action, a.target_type, a.target_id,
                a.created_at, a.hash
           FROM audit_logs a
           LEFT JOIN users u ON u.id = a.user_id
          ORDER BY a.id DESC
          LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

/// GET /api/admin/audit/verify - recomputes the hash chain (SR-11).
///
/// Uses the same formula as the database trigger. Any edited, inserted or
/// removed row breaks the chain from that point on.
async fn verify_audit(
    State(state): State<AppState>,
    admin: AuthUser,
) -> Result<Json<Value>, AppError> {
    admin.require(&[Role::Admin])?;

    let first_bad: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM (
            SELECT id, hash, prev_hash,
                   lag(hash) OVER (ORDER BY id) AS expected_prev,
                   encode(digest(
                       coalesce(prev_hash, '') || '|' || coalesce(user_id::text, '') || '|' ||
                       action || '|' || target_type || '|' || coalesce(target_id::text, '') || '|' ||
                       created_at::text, 'sha256'), 'hex') AS recomputed
              FROM audit_logs
         ) chain
         WHERE hash <> recomputed OR prev_hash IS DISTINCT FROM expected_prev
         ORDER BY id
         LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await?;

    let (rows_checked,): (i64,) = sqlx::query_as("SELECT count(*) FROM audit_logs")
        .fetch_one(&state.db)
        .await?;

    Ok(Json(json!({
        "rows_checked": rows_checked,
        "valid": first_bad.is_none(),
        "first_bad_id": first_bad.map(|(id,)| id),
    })))
}
