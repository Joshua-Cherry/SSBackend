//! Authentication and authorization (FR-4, FR-5, SR-1 to SR-6).
//!
//! - Passwords are hashed with Argon2id (SR-2).
//! - A login creates a random 256-bit session token. The browser gets it in a
//!   `__Host-session` cookie (Secure, HttpOnly, SameSite=Strict, Path=/), and
//!   the database stores only its SHA-256 hash, so a database leak does not
//!   expose usable tokens (SR-3).
//! - `AuthUser` is an extractor: any handler that takes it requires a valid
//!   session (SR-1). The user's role is re-read from the database on every
//!   request, so role changes and deactivation take effect immediately (SR-5).

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{extract::FromRequestParts, http::request::Parts};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{error::AppError, AppState};

/// The `__Host-` prefix makes browsers reject the cookie unless it is Secure,
/// has Path=/ and no Domain, so a subdomain cannot overwrite it.
pub const SESSION_COOKIE: &str = "__Host-session";
/// Sessions expire 8 hours after login.
pub const SESSION_HOURS: i32 = 8;

/// The three roles. Ids match the rows in the `roles` table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Reviewer,
    Admin,
}

impl Role {
    pub fn from_id(id: i16) -> Option<Role> {
        match id {
            1 => Some(Role::User),
            2 => Some(Role::Reviewer),
            3 => Some(Role::Admin),
            _ => None,
        }
    }

    pub fn id(self) -> i16 {
        match self {
            Role::User => 1,
            Role::Reviewer => 2,
            Role::Admin => 3,
        }
    }

    pub fn parse(name: &str) -> Option<Role> {
        match name {
            "user" => Some(Role::User),
            "reviewer" => Some(Role::Reviewer),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

/// Argon2id with the crate defaults (19 MiB memory, 2 iterations, 1 lane),
/// which match the OWASP Password Storage Cheat Sheet minimum.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("password hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// Returns false for a wrong password or a malformed stored hash.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Argon2 is deliberately slow; run it off the async worker threads so other
/// requests are not held up (NFR-3).
pub async fn hash_password_async(password: String) -> Result<String, AppError> {
    let hash = tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(anyhow::Error::from)??;
    Ok(hash)
}

pub async fn verify_password_async(
    password: String,
    stored_hash: String,
) -> Result<bool, AppError> {
    let ok = tokio::task::spawn_blocking(move || verify_password(&password, &stored_hash))
        .await
        .map_err(anyhow::Error::from)?;
    Ok(ok)
}

// ---------------------------------------------------------------------------
// Session tokens and cookies
// ---------------------------------------------------------------------------

/// 32 random bytes from the operating system's CSPRNG, base64url-encoded.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// What the `sessions` table stores instead of the token itself.
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn session_cookie(token: String) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::hours(SESSION_HOURS as i64))
        .build()
}

/// Same attributes as the session cookie, empty and already expired, so the
/// browser deletes it on logout.
pub fn removal_cookie() -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::ZERO)
        .build()
}

// ---------------------------------------------------------------------------
// The logged-in user
// ---------------------------------------------------------------------------

/// The authenticated user making the request.
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: i64,
    pub username: String,
    pub role: Role,
    /// Hash of this request's session token (used by logout and password change).
    pub token_hash: String,
}

impl AuthUser {
    /// Role check used at the top of every restricted handler (SR-4, SR-5).
    pub fn require(&self, allowed: &[Role]) -> Result<(), AppError> {
        if allowed.contains(&self.role) {
            Ok(())
        } else {
            tracing::warn!(user_id = self.id, role = ?self.role, "forbidden: role not allowed");
            Err(AppError::Forbidden)
        }
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get(SESSION_COOKIE)
            .map(|c| c.value().to_owned())
            .ok_or(AppError::Unauthorized)?;
        let hash = token_hash(&token);

        // Valid only if the session exists, has not expired and the account is active.
        let row: Option<(i64, String, i16)> = sqlx::query_as(
            "SELECT u.id, u.username, u.role_id
               FROM sessions s
               JOIN users u ON u.id = s.user_id
              WHERE s.token_hash = $1
                AND s.expires_at > now()
                AND u.is_active",
        )
        .bind(&hash)
        .fetch_optional(&state.db)
        .await?;

        let (id, username, role_id) = row.ok_or(AppError::Unauthorized)?;
        let role = Role::from_id(role_id)
            .ok_or_else(|| anyhow::anyhow!("user {id} has unknown role id {role_id}"))?;
        Ok(AuthUser {
            id,
            username,
            role,
            token_hash: hash,
        })
    }
}
