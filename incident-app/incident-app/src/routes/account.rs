//! Login, logout, current user and password change (FR-4, FR-5, FR-11).

use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    audit,
    auth::{self, AuthUser, Role},
    error::{AppError, AppJson},
    validate, AppState,
};

/// After this many wrong passwords in a row the account is locked...
const MAX_FAILED_LOGINS: i32 = 5;
/// ...for this many minutes (OWASP ASVS anti-automation).
const LOCK_MINUTES: i32 = 15;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/auth/password", post(change_password))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(sqlx::FromRow)]
struct LoginRow {
    id: i64,
    username: String,
    password_hash: String,
    role_id: i16,
    is_active: bool,
    locked_until: Option<DateTime<Utc>>,
}

/// POST /api/auth/login  `{ "username": "...", "password": "..." }`
///
/// Every failure returns the same message and status, whatever the reason,
/// and takes about the same time, so attackers cannot tell which usernames exist.
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    AppJson(req): AppJson<LoginRequest>,
) -> Result<(CookieJar, Json<Value>), AppError> {
    let ip = client_ip(&headers);

    // Cheap sanity limits before any database or hashing work.
    if req.username.len() > 50 || req.password.len() > 512 {
        return Err(AppError::InvalidLogin);
    }

    let row: Option<LoginRow> = sqlx::query_as(
        "SELECT id, username, password_hash, role_id, is_active, locked_until
           FROM users
          WHERE lower(username) = lower($1)",
    )
    .bind(&req.username)
    .fetch_optional(&state.db)
    .await?;

    let Some(user) = row else {
        // Do the same hashing work as a real check (constant-ish timing).
        let _ = auth::verify_password_async(req.password, state.dummy_hash.to_string()).await;
        let mut tx = state.db.begin().await?;
        audit::record(&mut tx, None, audit::LOGIN_FAILED, "user", None).await?;
        tx.commit().await?;
        tracing::warn!(%ip, "login failed: unknown username");
        return Err(AppError::InvalidLogin);
    };

    let locked = user.locked_until.is_some_and(|until| until > Utc::now());
    let password_ok = auth::verify_password_async(req.password, user.password_hash.clone()).await?;

    if !password_ok || locked || !user.is_active {
        let mut tx = state.db.begin().await?;
        if !password_ok {
            // Count the failure; on the 5th, lock the account and reset the counter.
            sqlx::query(
                "UPDATE users
                    SET failed_logins = CASE WHEN failed_logins + 1 >= $2 THEN 0
                                             ELSE failed_logins + 1 END,
                        locked_until  = CASE WHEN failed_logins + 1 >= $2
                                             THEN now() + make_interval(mins => $3)
                                             ELSE locked_until END
                  WHERE id = $1",
            )
            .bind(user.id)
            .bind(MAX_FAILED_LOGINS)
            .bind(LOCK_MINUTES)
            .execute(&mut *tx)
            .await?;
        }
        audit::record(&mut tx, None, audit::LOGIN_FAILED, "user", Some(user.id)).await?;
        tx.commit().await?;
        tracing::warn!(
            %ip,
            user_id = user.id,
            wrong_password = !password_ok,
            locked,
            inactive = !user.is_active,
            "login failed"
        );
        return Err(AppError::InvalidLogin);
    }

    let role = Role::from_id(user.role_id)
        .ok_or_else(|| anyhow::anyhow!("user {} has unknown role id {}", user.id, user.role_id))?;

    // New random token on every login (prevents session fixation).
    let token = auth::random_token();
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, expires_at)
         VALUES ($1, $2, now() + make_interval(hours => $3))",
    )
    .bind(auth::token_hash(&token))
    .bind(user.id)
    .bind(auth::SESSION_HOURS)
    .execute(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        Some(user.id),
        audit::LOGIN_SUCCESS,
        "user",
        Some(user.id),
    )
    .await?;
    tx.commit().await?;

    tracing::info!(%ip, user_id = user.id, "login succeeded");
    Ok((
        jar.add(auth::session_cookie(token)),
        Json(user_json(user.id, &user.username, role)),
    ))
}

/// POST /api/auth/logout
///
/// Deletes the session on the server, so the old cookie is useless even if it
/// was copied, then tells the browser to delete the cookie (FR-5).
async fn logout(
    State(state): State<AppState>,
    user: AuthUser,
    jar: CookieJar,
) -> Result<(CookieJar, Json<Value>), AppError> {
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(&user.token_hash)
        .execute(&mut *tx)
        .await?;
    audit::record(&mut tx, Some(user.id), audit::LOGOUT, "user", Some(user.id)).await?;
    tx.commit().await?;
    Ok((jar.add(auth::removal_cookie()), Json(json!({ "ok": true }))))
}

/// GET /api/auth/me - who is logged in (the frontend uses this on page load).
async fn me(user: AuthUser) -> Json<Value> {
    Json(user_json(user.id, &user.username, user.role))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

/// POST /api/auth/password  `{ "current_password": "...", "new_password": "..." }`
///
/// Requires the current password, then signs out every other session.
async fn change_password(
    State(state): State<AppState>,
    user: AuthUser,
    AppJson(req): AppJson<ChangePasswordRequest>,
) -> Result<Json<Value>, AppError> {
    validate::password(&req.new_password)?;
    if req.new_password == req.current_password {
        return Err(AppError::BadRequest(
            "The new password must be different from the current one.".to_string(),
        ));
    }
    if req.new_password.eq_ignore_ascii_case(&user.username) {
        return Err(AppError::BadRequest(
            "The password must not be the same as the username.".to_string(),
        ));
    }

    let (current_hash,): (String,) =
        sqlx::query_as("SELECT password_hash FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&state.db)
            .await?;
    if !auth::verify_password_async(req.current_password, current_hash).await? {
        tracing::warn!(
            user_id = user.id,
            "password change rejected: wrong current password"
        );
        return Err(AppError::BadRequest(
            "The current password is incorrect.".to_string(),
        ));
    }

    let new_hash = auth::hash_password_async(req.new_password).await?;

    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2")
        .bind(&new_hash)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2")
        .bind(user.id)
        .bind(&user.token_hash)
        .execute(&mut *tx)
        .await?;
    audit::record(
        &mut tx,
        Some(user.id),
        audit::PASSWORD_CHANGED,
        "user",
        Some(user.id),
    )
    .await?;
    tx.commit().await?;

    Ok(Json(json!({ "ok": true })))
}

fn user_json(id: i64, username: &str, role: Role) -> Value {
    json!({ "id": id, "username": username, "role": role })
}

/// Client address for logs. Apache appends the real address as the LAST entry
/// of X-Forwarded-For; earlier entries could be forged by the client.
fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
