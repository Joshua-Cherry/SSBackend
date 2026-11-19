//! Error handling (NFR-2, NFR-6, SR-12, SR-13).
//!
//! Every handler returns `Result<_, AppError>`. Users get a short, generic JSON
//! message; the detailed cause (database errors and so on) is written only to
//! the server log, never to the response. SQL text is never included anywhere.

use axum::{
    extract::{rejection::JsonRejection, FromRequest},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Shown for every failed login, whatever the reason (wrong password, unknown
/// user, locked or deactivated account), so the response reveals nothing.
pub const LOGIN_FAILED_MESSAGE: &str =
    "Invalid username or password, or the account is temporarily locked.";

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Input failed validation; the message is safe to show to the user.
    #[error("{0}")]
    BadRequest(String),
    /// No valid session cookie.
    #[error("not authenticated")]
    Unauthorized,
    /// Login failed for any reason.
    #[error("login failed")]
    InvalidLogin,
    /// Authenticated, but the role or ownership check failed.
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    /// The request conflicts with current data; the message is safe to show.
    #[error("{0}")]
    Conflict(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        const GENERIC: &str = "Something went wrong. Please try again later.";

        let (status, message) = match &self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Please log in.".to_string()),
            AppError::InvalidLogin => (StatusCode::UNAUTHORIZED, LOGIN_FAILED_MESSAGE.to_string()),
            AppError::Forbidden => (
                StatusCode::FORBIDDEN,
                "You do not have permission to do that.".to_string(),
            ),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found.".to_string()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            AppError::Db(e) => {
                // Detailed cause goes to the log only (SR-13).
                tracing::error!(error = %e, "database error");
                (StatusCode::INTERNAL_SERVER_ERROR, GENERIC.to_string())
            }
            AppError::Internal(e) => {
                tracing::error!(error = %format!("{e:#}"), "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, GENERIC.to_string())
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

/// JSON body extractor whose errors use `AppError` instead of axum's default
/// plain-text rejection. Because it requires `Content-Type: application/json`,
/// a plain HTML form on another site cannot submit to the API (CSRF defence,
/// together with the SameSite=Strict session cookie).
#[derive(FromRequest)]
#[from_request(via(Json), rejection(AppError))]
pub struct AppJson<T>(pub T);

impl From<JsonRejection> for AppError {
    fn from(rejection: JsonRejection) -> Self {
        tracing::debug!(error = %rejection, "rejected request body");
        AppError::BadRequest(
            "The request body is missing, has unexpected fields, or is not valid JSON.".to_string(),
        )
    }
}

/// Used by `CatchPanicLayer`: a panic becomes a generic 500 response.
pub fn panic_response(_panic: Box<dyn std::any::Any + Send + 'static>) -> Response {
    tracing::error!("a request handler panicked");
    AppError::Internal(anyhow::anyhow!("handler panic")).into_response()
}
